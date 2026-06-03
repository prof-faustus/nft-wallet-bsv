package tee

import (
	"encoding/hex"
	"testing"
)

// rep32 builds a [32]byte of a repeated byte (the KAT seeds).
func rep32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// INTEROP KAT — these values are the deterministic known-answer vector
// emitted by the REAL Property/tee-sim binary (`tee-sim kat`):
//
//	dk_seed=01*32  measurement=7e*32  root_seed=42*32
//	nonce="idattr-kat-nonce"  transcript="idattr-kat-transcript"
//
// The Go enclave reconstructed from the same seeds MUST reproduce every one
// of these bytes, and the Go verifier MUST accept them. That proves this
// package is wire-compatible with the actual (Rust) tee-sim device — a quote
// from the real enclave verifies here byte-for-byte.
//
//trace:test HH-1
func TestInteropKAT_MatchesRealTeeSim(t *testing.T) {
	const (
		wantDevicePub  = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
		wantDeviceCert = "467c88c3034146ef5a3b993156a3ceac61501696dd6783a6b36c3bf1c037fd58"
		wantAttestSig  = "d95164bdf1b2c9999c7fcb084f02a4c7474f7615dd94b0e1bcbd27a2954e0ce16b65670d867aef539ad15d76fd30712ba1418a370b2181e4a235651d907cae0f"
		wantBindingSig = "0f2f41fb63cc1acd672f0be23ed1069f4a43158a04c9f0143af68fe69f32006d368efed4c333fc9628ac705b7a3bc82a737f8334e0408d7cc5209a7a61913503"
		wantRootPub    = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
		wantBindDigest = "de30d5e74c689865570526453bae3468ccb38dde01d38979f081100170ce272d"
	)
	nonce := []byte("idattr-kat-nonce")
	transcript := []byte("idattr-kat-transcript")
	e := FromSeeds(rep32(0x01), rep32(0x7e), rep32(0x42))

	dp := e.DevicePub()
	if hex.EncodeToString(dp[:]) != wantDevicePub {
		t.Fatalf("device_pub mismatch:\n got %x\nwant %s", dp, wantDevicePub)
	}
	dc := e.DeviceCert()
	if hex.EncodeToString(dc[:]) != wantDeviceCert {
		t.Fatalf("device_cert mismatch")
	}
	rp := e.RootPub()
	if hex.EncodeToString(rp[:]) != wantRootPub {
		t.Fatalf("root_pub mismatch")
	}
	bd := BindingDigest(nonce, transcript)
	if hex.EncodeToString(bd[:]) != wantBindDigest {
		t.Fatalf("binding_digest mismatch")
	}
	att := e.Attest(nonce)
	if hex.EncodeToString(att.Signature) != wantAttestSig {
		t.Fatalf("attest_sig mismatch:\n got %x\nwant %s", att.Signature, wantAttestSig)
	}
	bind := e.Bind(nonce, transcript)
	if hex.EncodeToString(bind.BindingSig) != wantBindingSig {
		t.Fatalf("binding_sig mismatch")
	}

	// And the verifier accepts the real-sim-format quote + binding.
	pol := Policy{MeasurementAllowlist: [][32]byte{e.Measurement()}, RootPub: e.RootPub()}
	if !VerifyAttestation(att, pol, nonce) {
		t.Fatal("verifier rejected a valid attestation")
	}
	if !VerifyBinding(bind, pol, nonce, transcript) {
		t.Fatal("verifier rejected a valid binding")
	}
	_ = mustHex
}

// Fail-closed: every tamper / replay / wrong-policy path is rejected.
//
//trace:test HH-1
func TestVerifierFailClosed(t *testing.T) {
	e := FromSeeds(rep32(0x01), rep32(0x7e), rep32(0x42))
	nonce := []byte("fresh-nonce")
	transcript := []byte("released K to bob; zeroized seller copy")
	pol := Policy{MeasurementAllowlist: [][32]byte{e.Measurement()}, RootPub: e.RootPub()}

	att := e.Attest(nonce)
	bind := e.Bind(nonce, transcript)

	// baseline accepts
	if !VerifyAttestation(att, pol, nonce) || !VerifyBinding(bind, pol, nonce, transcript) {
		t.Fatal("baseline should verify")
	}
	// replay: a different expected nonce
	if VerifyAttestation(att, pol, []byte("other-nonce")) {
		t.Fatal("accepted a replayed nonce")
	}
	// wrong app: measurement not allowlisted
	polBadMeas := Policy{MeasurementAllowlist: [][32]byte{rep32(0xaa)}, RootPub: e.RootPub()}
	if VerifyAttestation(att, polBadMeas, nonce) {
		t.Fatal("accepted a non-allowlisted measurement")
	}
	// wrong root: a different attestation root pubkey
	other := FromSeeds(rep32(0x09), rep32(0x7e), rep32(0x10))
	polBadRoot := Policy{MeasurementAllowlist: [][32]byte{e.Measurement()}, RootPub: other.RootPub()}
	if VerifyAttestation(att, polBadRoot, nonce) {
		t.Fatal("accepted under the wrong attestation root")
	}
	// tampered attestation signature
	att2 := att
	att2.Signature = append([]byte(nil), att.Signature...)
	att2.Signature[0] ^= 0xff
	if VerifyAttestation(att2, pol, nonce) {
		t.Fatal("accepted a tampered attestation signature")
	}
	// binding over a DIFFERENT transcript must fail
	if VerifyBinding(bind, pol, nonce, []byte("a different statement")) {
		t.Fatal("accepted a binding for the wrong transcript")
	}
	// wrong-device binding: device sig from another enclave
	bindMix := DeviceBinding{Attestation: att, BindingSig: other.Bind(nonce, transcript).BindingSig}
	if VerifyBinding(bindMix, pol, nonce, transcript) {
		t.Fatal("accepted a binding signed by a different device")
	}
}

// Round-trip with a freshly generated enclave (random keys).
//
//trace:test HH-1
func TestGeneratedEnclaveRoundTrip(t *testing.T) {
	e, err := Generate(rep32(0x55))
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("n")
	tr := []byte("t")
	pol := Policy{MeasurementAllowlist: [][32]byte{e.Measurement()}, RootPub: e.RootPub()}
	if !VerifyBinding(e.Bind(nonce, tr), pol, nonce, tr) {
		t.Fatal("generated enclave binding did not verify")
	}
}
