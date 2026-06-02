package deletion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
)

func sampleCDA(t *testing.T) (CDA, Expectation, *ec.PrivateKey) {
	t.Helper()
	alice, _ := ec.NewPrivateKey()
	tokenId := make([]byte, 32)
	tokenId[0] = 0xAB
	hp := make([]byte, 32)
	hp[0] = 0xCD
	txid := strings.Repeat("11", 32)
	swap := strings.Repeat("22", 32)
	c, err := BuildCDA(tokenId, txid, 0, swap, hp, 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	exp := Expectation{TokenId: tokenId, TokenOutpointTxID: txid, TokenOutpointVout: 0, SwapTxID: swap, HPayload: hp}
	return c, exp, alice
}

//trace:test HH-1
func TestCDA_SignVerifyRoundTrip(t *testing.T) {
	c, exp, alice := sampleCDA(t)
	sig, err := c.Sign(alice)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(c, sig, alice.PubKey(), exp); err != nil {
		t.Fatalf("valid CDA rejected: %v", err)
	}
	if got := ClassifyReceived(&c, sig, alice.PubKey(), exp); got != AttestValid {
		t.Fatalf("classify valid = %s", got)
	}
}

// F-15: a forged sigCDA (signed by someone else / garbage) is rejected.
//
//trace:test HH-1
func TestF15_ForgedCDARejected(t *testing.T) {
	c, exp, alice := sampleCDA(t)
	imposter, _ := ec.NewPrivateKey()
	sig, _ := c.Sign(imposter) // wrong signer
	if err := Verify(c, sig, alice.PubKey(), exp); err == nil {
		t.Fatal("CDA signed by the wrong key verified (F-15)")
	}
	if got := ClassifyReceived(&c, sig, alice.PubKey(), exp); got != AttestInvalid {
		t.Fatalf("forged classify = %s, want invalid", got)
	}
	// Garbage signature bytes too.
	if err := Verify(c, []byte{0x30, 0x02, 0x01, 0x01}, alice.PubKey(), exp); err == nil {
		t.Fatal("garbage sig verified (F-15)")
	}
}

// F-17: a CDA referencing the wrong swapTxid/tokenOutpoint is rejected
// even with a valid signature.
//
//trace:test HH-1
func TestF17_WrongBindingRejected(t *testing.T) {
	c, exp, alice := sampleCDA(t)
	sig, _ := c.Sign(alice)
	// Bob expected a DIFFERENT swap txid.
	exp.SwapTxID = strings.Repeat("33", 32)
	if err := Verify(c, sig, alice.PubKey(), exp); err == nil {
		t.Fatal("CDA with mismatched swapTxid verified (F-17)")
	}
}

// F-16: a missing CDA is a missing CLAIM (AttestAbsent), NOT a transfer
// failure — settlement is independent of the CDA (docs/04 §4.2).
//
//trace:test PL-1
func TestF16_MissingCDAIsAbsentNotFailure(t *testing.T) {
	_, exp, alice := sampleCDA(t)
	if got := ClassifyReceived(nil, nil, alice.PubKey(), exp); got != AttestAbsent {
		t.Fatalf("missing CDA classified %s, want absent (missing claim)", got)
	}
}

// E2E-7 integration: a valid CDA drives the buyer engine CONFIRMED→DONE;
// an invalid/missing one leaves it CONFIRMED (owns the token; F-15/F-16).
//
//trace:test HH-1
func TestE2E7_CDADrivesEngine(t *testing.T) {
	c, exp, alice := sampleCDA(t)
	sig, _ := c.Sign(alice)

	confirmedBuyer := func() *engine.Engine {
		e := engine.New(engine.Buyer)
		for _, ev := range []engine.EventType{
			engine.EvStartPairing, engine.EvHelloAckValid, engine.EvOffer, engine.EvAcceptMatches,
			engine.EvPayloadDeliveredOK, engine.EvSwapAssembled, engine.EvTermsVerifyOK,
			engine.EvPeerPartialReceived, engine.EvOwnSigned, engine.EvBroadcastAccepted, engine.EvConfirmedAtDepth,
		} {
			if _, err := e.Apply(engine.Event{Type: ev}); err != nil {
				t.Fatalf("drive: %v", err)
			}
		}
		return e
	}

	// Valid CDA -> DONE.
	e := confirmedBuyer()
	switch ClassifyReceived(&c, sig, alice.PubKey(), exp) {
	case AttestValid:
		e.Apply(engine.Event{Type: engine.EvDeletionAttestValid})
	default:
		t.Fatal("valid CDA misclassified")
	}
	if e.State() != engine.StateDone {
		t.Fatalf("valid CDA: want DONE, got %s", e.State())
	}

	// Invalid CDA -> stays CONFIRMED (still owns token).
	e2 := confirmedBuyer()
	bad, _ := c.Sign(mustOther(t))
	if ClassifyReceived(&c, bad, alice.PubKey(), exp) == AttestValid {
		t.Fatal("invalid CDA classified valid")
	}
	e2.Apply(engine.Event{Type: engine.EvDeletionAttestInvalid})
	if e2.State() != engine.StateConfirmed {
		t.Fatalf("invalid CDA: want CONFIRMED (owns token), got %s", e2.State())
	}
}

func mustOther(t *testing.T) *ec.PrivateKey {
	t.Helper()
	k, _ := ec.NewPrivateKey()
	return k
}

//trace:test PL-1
func TestLocalDeleteBestEffort(t *testing.T) {
	p := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(p, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LocalDelete(p); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file not deleted")
	}
	// Deleting a non-existent file is not an error (idempotent best-effort).
	if err := LocalDelete(p); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}
