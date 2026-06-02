package uistate

import (
	"strings"
	"testing"

	"github.com/prof-faustus/nft-wallet-bsv/internal/deletion"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
)

// No success/complete before CONFIRMED (docs/03 §3.5 no silent success).
func TestNoSuccessBeforeConfirmed(t *testing.T) {
	preConfirmed := []engine.State{
		engine.StateIdle, engine.StatePairing, engine.StateConnected, engine.StateNegotiating,
		engine.StatePriceAgreed, engine.StatePayloadDelivered, engine.StateSwapAssembled,
		engine.StateSwapSigned, engine.StateBroadcast,
	}
	for _, s := range preConfirmed {
		d := ForExchange(s, engine.ReasonNone, 0, 1)
		if d.Success {
			t.Errorf("state %s marked Success before CONFIRMED", s)
		}
		low := strings.ToLower(d.Label)
		if strings.Contains(low, "success") || strings.Contains(low, "complete") || strings.Contains(low, "confirmed —") && s != engine.StateConfirmed {
			t.Errorf("state %s label implies success: %q", s, d.Label)
		}
	}
	// BROADCAST is explicitly pending, not confirmed.
	b := ForExchange(engine.StateBroadcast, engine.ReasonNone, 0, 1)
	if !b.Pending || b.Success {
		t.Errorf("BROADCAST should be Pending, not Success: %+v", b)
	}
}

func TestConfirmedIsSuccess(t *testing.T) {
	for _, s := range []engine.State{engine.StateConfirmed, engine.StateAttested, engine.StateDone} {
		if !ForExchange(s, engine.ReasonNone, 1, 1).Success {
			t.Errorf("state %s should be Success", s)
		}
	}
}

// No state label, and no deletion label, ever claims "verified" deletion
// (docs/04 §4.7).
func TestNeverClaimsVerifiedDeletion(t *testing.T) {
	states := []engine.State{
		engine.StateConfirmed, engine.StateAttested, engine.StateDone,
		engine.StateBroadcast, engine.StateAborted, engine.StateFailed,
	}
	for _, s := range states {
		if ForbidsVerifiedDeletion(ForExchange(s, engine.ReasonNone, 1, 1).Label) {
			t.Errorf("state %s label contains 'verified'", s)
		}
	}
	for _, st := range []deletion.AttestStatus{deletion.AttestValid, deletion.AttestInvalid, deletion.AttestAbsent} {
		if ForbidsVerifiedDeletion(DeletionLabel(st)) {
			t.Errorf("deletion label for %s contains 'verified': %q", st, DeletionLabel(st))
		}
	}
}

func TestTerminalsCarryReason(t *testing.T) {
	d := ForExchange(engine.StateFailed, engine.ReasonDoubleSpent, 0, 1)
	if !d.Failed || !strings.Contains(d.Label, string(engine.ReasonDoubleSpent)) {
		t.Errorf("failed label missing reason: %+v", d)
	}
}
