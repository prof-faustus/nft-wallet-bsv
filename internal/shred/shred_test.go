package shred

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

var payload = []byte("the unique NFT payload — stage 2 real encryption")

// I-CS-2 (Bob opens post-swap) + tamper robustness, for every scheme.
//
//trace:test I-CS-2
func TestAllSchemes_BobOpens(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			sc, _ := ForName(name)
			bob, _ := ec.NewPrivateKey()
			sealed, _, err := sc.Seal(payload, bob.PubKey())
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			// Bob opens with his PRIVATE key.
			out, err := sc.Open(sealed, bob)
			if err != nil || !bytes.Equal(out, payload) {
				t.Fatalf("bob open: %v / %q", err, out)
			}
			// Tampering the ciphertext breaks authentication.
			sealed.Ciphertext[len(sealed.Ciphertext)-1] ^= 0xff
			if _, err := sc.Open(sealed, bob); err == nil {
				t.Fatalf("tampered ciphertext opened")
			}
		})
	}
}

// Wrong recipient key cannot open the ECDH-based schemes.
//
//trace:test I-CS-1
func TestWrongKeyCannotOpen(t *testing.T) {
	for _, name := range []string{"ecdh-singleuse", "reencrypt", "tee-attested"} {
		t.Run(name, func(t *testing.T) {
			sc, _ := ForName(name)
			bob, _ := ec.NewPrivateKey()
			mallory, _ := ec.NewPrivateKey()
			sealed, _, err := sc.Seal(payload, bob.PubKey())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sc.Open(sealed, mallory); err == nil {
				t.Fatalf("%s: wrong key opened", name)
			}
		})
	}
}

// I-CS-1 crypto-shred: a COOPERATIVE seller can open her retained
// ciphertext BEFORE shredding, but NOT after; the ENFORCED (tee) scheme
// gives the seller no recovery path at all.
//
//trace:test I-CS-1 I-CS-3
func TestSellerShred(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			sc, _ := ForName(name)
			bob, _ := ec.NewPrivateKey()
			sealed, secret, err := sc.Seal(payload, bob.PubKey())
			if err != nil {
				t.Fatal(err)
			}
			if sc.Strength() == Enforced {
				// Alice never held K (enclave-held): no recovery, even pre-shred.
				if _, err := secret.TryOpen(sealed); err == nil {
					t.Fatalf("%s (enforced): seller could open — should never hold K", name)
				}
				return
			}
			// Cooperative: she can open now …
			if out, err := secret.TryOpen(sealed); err != nil || !bytes.Equal(out, payload) {
				t.Fatalf("%s: seller pre-shred open: %v", name, err)
			}
			// … but not after she shreds her key material.
			secret.Shred()
			if _, err := secret.TryOpen(sealed); err == nil {
				t.Fatalf("%s: seller still opened AFTER shred (crypto-shred failed)", name)
			}
		})
	}
}

// I-CS-3: only the enforced scheme carries a verifiable attestation;
// cooperative schemes carry none and must not be presented as enforced.
//
//trace:test I-CS-3
func TestAttestationOnlyEnforced(t *testing.T) {
	bob, _ := ec.NewPrivateKey()
	tee, _ := ForName("tee-attested")
	sealed, _, err := tee.Seal(payload, bob.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if tee.Strength() != Enforced {
		t.Fatal("tee-attested must be Enforced")
	}
	if !VerifyTEEAttestation(sealed, bob.PubKey()) {
		t.Fatal("tee attestation did not verify")
	}
	// A different recipient's pubkey must not validate the attestation.
	other, _ := ec.NewPrivateKey()
	if VerifyTEEAttestation(sealed, other.PubKey()) {
		t.Fatal("tee attestation verified for the wrong recipient")
	}
	for _, name := range []string{"ecdh-singleuse", "key-surrender", "reencrypt", "threshold"} {
		sc, _ := ForName(name)
		if sc.Strength() != Cooperative {
			t.Fatalf("%s must be Cooperative", name)
		}
		s, _, _ := sc.Seal(payload, bob.PubKey())
		if len(s.Attestation) != 0 || VerifyTEEAttestation(s, bob.PubKey()) {
			t.Fatalf("%s must not carry a TEE attestation", name)
		}
	}
}

func TestRegistry(t *testing.T) {
	if len(Names()) != 5 {
		t.Fatalf("want 5 schemes, got %v", Names())
	}
	if _, err := ForName(DefaultScheme); err != nil {
		t.Fatalf("default scheme: %v", err)
	}
	if _, err := ForName("nope"); err == nil {
		t.Fatal("unknown scheme accepted")
	}
}

// I-CS-4: the dealerless-threshold scheme distributes K as t-of-n shares;
// Bob reconstructs from the t shares the swap delivers (no recipient key),
// and FEWER than t shares cannot recover the payload.
//
//trace:test I-CS-4
func TestThresholdSchemeSharing(t *testing.T) {
	sc, err := ForName("threshold")
	if err != nil {
		t.Fatal(err)
	}
	bob, _ := ec.NewPrivateKey()
	sealed, _, err := sc.Seal(payload, bob.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed.Shares) != thresholdT {
		t.Fatalf("want %d shares delivered, got %d", thresholdT, len(sealed.Shares))
	}
	// Bob reconstructs from the t shares — his private key is irrelevant.
	out, err := sc.Open(sealed, nil)
	if err != nil || !bytes.Equal(out, payload) {
		t.Fatalf("threshold open: %v / %q", err, out)
	}
	// One fewer than t shares cannot reconstruct K.
	short := &Sealed{Scheme: "threshold", Ciphertext: sealed.Ciphertext, Shares: sealed.Shares[:thresholdT-1]}
	if _, err := sc.Open(short, nil); err == nil {
		t.Fatalf("opened with only %d shares — threshold broken", thresholdT-1)
	}
}
