package tstage

import (
	"crypto/sha256"
	"testing"

	"github.com/prof-faustus/nft-wallet-bsv/internal/tee"
)

func meas() [32]byte { return sha256.Sum256([]byte("nft-wallet-bsv/enclave/v1")) }

func policyFor(e *tee.Enclave) tee.Policy {
	return tee.Policy{MeasurementAllowlist: [][32]byte{e.Measurement()}, RootPub: e.RootPub()}
}

// A genuine enclave attestation over the wipe statement classifies as an
// AttestedWipe; the cooperative-only paths and every tamper/replay are
// CooperativeOnly (fail-closed).
//
//trace:test HH-1 SC-1
func TestAttestedWipe(t *testing.T) {
	enc, err := tee.Generate(meas())
	if err != nil {
		t.Fatal(err)
	}
	tokenID := []byte("token-id-32-bytes-or-whatever-xx")
	swap := "deadbeefcafe"
	hp := sha256.Sum256([]byte("the payload"))
	nonce := []byte("fresh-wipe-nonce")
	pol := policyFor(enc)

	b := AttestWipe(enc, nonce, tokenID, swap, hp[:])
	if VerifyWipe(b, pol, nonce, tokenID, swap, hp[:]) != AttestedWipe {
		t.Fatal("valid attested wipe not recognized")
	}

	// replay: different nonce
	if VerifyWipe(b, pol, []byte("other"), tokenID, swap, hp[:]) != CooperativeOnly {
		t.Fatal("accepted replayed nonce")
	}
	// wrong token
	if VerifyWipe(b, pol, nonce, []byte("different-token-id-bytes-here!!!"), swap, hp[:]) != CooperativeOnly {
		t.Fatal("accepted wrong token")
	}
	// wrong swap
	if VerifyWipe(b, pol, nonce, tokenID, "different-swap", hp[:]) != CooperativeOnly {
		t.Fatal("accepted wrong swap")
	}
	// wrong payload hash
	other := sha256.Sum256([]byte("other payload"))
	if VerifyWipe(b, pol, nonce, tokenID, swap, other[:]) != CooperativeOnly {
		t.Fatal("accepted wrong payload hash")
	}
	// wrong enclave (different root/measurement policy)
	other2, _ := tee.Generate(meas())
	if VerifyWipe(b, policyFor(other2), nonce, tokenID, swap, hp[:]) != CooperativeOnly {
		t.Fatal("accepted under a different enclave's policy")
	}
	// tampered binding signature
	bad := b
	bad.BindingSig = append([]byte(nil), b.BindingSig...)
	bad.BindingSig[0] ^= 0xff
	if VerifyWipe(bad, pol, nonce, tokenID, swap, hp[:]) != CooperativeOnly {
		t.Fatal("accepted a tampered wipe binding")
	}
}
