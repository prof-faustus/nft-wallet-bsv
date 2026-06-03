// Package tee is the Stage-2+ T-element: an attested secure-enclave layer
// for the crypto-shred "enforced" path (docs/04 §4.6, docs/08; OD-1). It is
// wire-compatible with the project's `tee-sim` device (Property/tee-sim) and
// the `idattr-device` attestation/binding format v1, so a quote from the
// real (simulated) enclave verifies here byte-for-byte — proven by a pinned
// known-answer vector captured from the actual `tee-sim` binary (tee_test).
//
// This package contains TWO things:
//   - The VERIFIER (VerifyAttestation / VerifyBinding) — the relying-party
//     code. It MUST live here, in SPVNFT: a device never verifies its own
//     attestation. Fail-closed: a quote is accepted only with a matching
//     fresh nonce, an allowlisted measurement, and valid signatures.
//   - A wire-compatible software Enclave — the in-process stand-in device,
//     identical on the wire to tee-sim, so the sidecar can run an enclave
//     without the external Rust binary while staying interoperable with it.
//
// ⚠️ SIMULATION, not hardware. The enclave key and attestation root are
// ordinary Ed25519 keys; "non-exportable" only means this API never returns
// the private halves. A quote here proves the API flow and the verifier's
// checks — NOT genuine hardware isolation. Real attestation needs a real
// secure element with the VENDOR root verified off-device (docs/07 OD-1).
// Nothing in SPVNFT may present this as hardware-attested deletion.
//
// MUST NOT: import BTC; emit OP_RETURN (no scripts here). BSV-only project.
//
//trace:impl HH-1
package tee

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// Domain separators — identical to tee-sim / idattr-device v1.
const (
	attestDomain = "idattr-device/attestation/v1"
	bindDomain   = "idattr-device/binding/v1"
	certDomain   = "idattr-device/device-cert/v1"
)

// Attestation is a hardware-style attestation quote (SIMULATED). Signature
// is the platform attestation root's Ed25519 signature over body().
type Attestation struct {
	Measurement   [32]byte
	DevicePub     [32]byte
	Nonce         []byte
	NonExportable bool
	Signature     []byte
}

// body is the canonical signed layout (matches tee-sim Attestation::body):
//
//	DOMAIN ‖ measurement(32) ‖ device_pub(32) ‖ non_exportable(1) ‖ len(nonce) u64 LE ‖ nonce
func (a Attestation) body() []byte {
	b := make([]byte, 0, len(attestDomain)+32+32+1+8+len(a.Nonce))
	b = append(b, attestDomain...)
	b = append(b, a.Measurement[:]...)
	b = append(b, a.DevicePub[:]...)
	if a.NonExportable {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(a.Nonce)))
	b = append(b, n[:]...)
	b = append(b, a.Nonce...)
	return b
}

// DeviceBinding is an Attestation plus the device key's signature over
// BindingDigest(nonce, transcript).
type DeviceBinding struct {
	Attestation Attestation
	BindingSig  []byte
}

// Policy is the relying party's verification policy.
type Policy struct {
	MeasurementAllowlist [][32]byte // approved application measurements
	RootPub              [32]byte   // pinned platform attestation-root pubkey
}

// BindingDigest = SHA-256( BIND_DOMAIN ‖ len(nonce) u64 LE ‖ nonce ‖ len(transcript) u64 LE ‖ transcript ).
func BindingDigest(nonce, transcript []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(bindDomain))
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(nonce)))
	h.Write(n[:])
	h.Write(nonce)
	binary.LittleEndian.PutUint64(n[:], uint64(len(transcript)))
	h.Write(n[:])
	h.Write(transcript)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// DeviceCertCommitment = SHA-256( CERT_DOMAIN ‖ device_pub ‖ measurement ).
func DeviceCertCommitment(devicePub, measurement [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(certDomain))
	h.Write(devicePub[:])
	h.Write(measurement[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyAttestation is fail-closed: the nonce must equal the verifier's
// fresh challenge, the measurement must be allowlisted, and the signature
// must verify under the pinned attestation root. Returns false on any
// mismatch (anti-replay, wrong-app, forged-root).
//
//trace:impl HH-1
func VerifyAttestation(att Attestation, pol Policy, expectedNonce []byte) bool {
	if len(att.Signature) != ed25519.SignatureSize {
		return false
	}
	if !ctEqual(att.Nonce, expectedNonce) {
		return false
	}
	if !measurementAllowed(att.Measurement, pol.MeasurementAllowlist) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pol.RootPub[:]), att.body(), att.Signature)
}

// VerifyBinding checks the attestation AND that the attested device key
// signed BindingDigest(expectedNonce, transcript). Fail-closed.
//
//trace:impl HH-1
func VerifyBinding(b DeviceBinding, pol Policy, expectedNonce, transcript []byte) bool {
	if !VerifyAttestation(b.Attestation, pol, expectedNonce) {
		return false
	}
	if len(b.BindingSig) != ed25519.SignatureSize {
		return false
	}
	d := BindingDigest(expectedNonce, transcript)
	return ed25519.Verify(ed25519.PublicKey(b.Attestation.DevicePub[:]), d[:], b.BindingSig)
}

// Enclave is the wire-compatible software device (SIMULATION). Its private
// keys are never returned by any method (the simulated non-exportability).
type Enclave struct {
	dk          ed25519.PrivateKey
	root        ed25519.PrivateKey
	devicePub   [32]byte
	measurement [32]byte
}

// FromSeeds reconstructs a deterministic enclave (used for sealing and the
// KAT). dkSeed/rootSeed are the 32-byte Ed25519 seeds (RFC 8032), identical
// to tee-sim's SigningKey::from_bytes.
func FromSeeds(dkSeed, measurement, rootSeed [32]byte) *Enclave {
	dk := ed25519.NewKeyFromSeed(dkSeed[:])
	root := ed25519.NewKeyFromSeed(rootSeed[:])
	e := &Enclave{dk: dk, root: root, measurement: measurement}
	copy(e.devicePub[:], dk.Public().(ed25519.PublicKey))
	return e
}

// Generate provisions a fresh enclave with random keys for the given
// application measurement.
func Generate(measurement [32]byte) (*Enclave, error) {
	var dkSeed, rootSeed [32]byte
	if _, err := rand.Read(dkSeed[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(rootSeed[:]); err != nil {
		return nil, err
	}
	return FromSeeds(dkSeed, measurement, rootSeed), nil
}

func (e *Enclave) DevicePub() [32]byte   { return e.devicePub }
func (e *Enclave) Measurement() [32]byte { return e.measurement }

// RootPub is the platform attestation-root verifying key a relying party
// pins in its Policy.
func (e *Enclave) RootPub() [32]byte {
	var p [32]byte
	copy(p[:], e.root.Public().(ed25519.PublicKey))
	return p
}

// DeviceCert is this enclave's device-certificate commitment.
func (e *Enclave) DeviceCert() [32]byte {
	return DeviceCertCommitment(e.devicePub, e.measurement)
}

// Attest produces a fresh attestation quote over nonce.
func (e *Enclave) Attest(nonce []byte) Attestation {
	att := Attestation{
		Measurement:   e.measurement,
		DevicePub:     e.devicePub,
		Nonce:         append([]byte(nil), nonce...),
		NonExportable: true,
	}
	att.Signature = ed25519.Sign(e.root, att.body())
	return att
}

// Bind attests over nonce and signs BindingDigest(nonce, transcript) with
// the device key.
func (e *Enclave) Bind(nonce, transcript []byte) DeviceBinding {
	att := e.Attest(nonce)
	d := BindingDigest(nonce, transcript)
	return DeviceBinding{Attestation: att, BindingSig: ed25519.Sign(e.dk, d[:])}
}

func measurementAllowed(m [32]byte, allow [][32]byte) bool {
	for _, a := range allow {
		if a == m {
			return true
		}
	}
	return false
}

// ctEqual is a length-checked byte compare (nonces are public; plain compare
// is fine, but keep it explicit).
func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
