package engine

import "testing"

// drive applies a sequence, failing on any unexpected error.
func drive(t *testing.T, e *Engine, evs ...EventType) {
	t.Helper()
	for _, et := range evs {
		if _, err := e.Apply(Event{Type: et}); err != nil {
			t.Fatalf("event %v in state %s: %v", et, e.State(), err)
		}
	}
}

func has(cmds []Command, want Command) bool {
	for _, c := range cmds {
		if c == want {
			return true
		}
	}
	return false
}

// E2E-2..E2E-7 happy progression for the seller, ending ATTESTED.
func TestHappyPathSeller(t *testing.T) {
	e := New(Seller)
	drive(t, e, EvStartPairing, EvHelloAckValid) // -> CONNECTED (E2E-2)
	if e.State() != StateConnected {
		t.Fatalf("want CONNECTED, got %s", e.State())
	}
	drive(t, e, EvOffer, EvAcceptMatches) // -> PRICE_AGREED (E2E-3)
	if e.State() != StatePriceAgreed {
		t.Fatalf("want PRICE_AGREED, got %s", e.State())
	}
	cmds, _ := e.Apply(Event{Type: EvPayloadDeliveredOK}) // -> PAYLOAD_DELIVERED (E2E-4)
	if e.State() != StatePayloadDelivered || !has(cmds, CmdAssembleSwap) {
		t.Fatalf("want PAYLOAD_DELIVERED+assemble, got %s %v", e.State(), cmds)
	}
	drive(t, e, EvSwapAssembled, EvTermsVerifyOK, EvPeerPartialReceived) // still assembling
	if e.State() != StateSwapAssembled {
		t.Fatalf("should still be SWAP_ASSEMBLED before own signature, got %s", e.State())
	}
	cmds, _ = e.Apply(Event{Type: EvOwnSigned}) // all three -> SWAP_SIGNED (E2E-5)
	if e.State() != StateSwapSigned || !has(cmds, CmdBroadcast) {
		t.Fatalf("want SWAP_SIGNED+broadcast, got %s %v", e.State(), cmds)
	}
	drive(t, e, EvBroadcastAccepted, EvConfirmedAtDepth) // -> CONFIRMED (E2E-6)
	if e.State() != StateConfirmed {
		t.Fatalf("want CONFIRMED, got %s", e.State())
	}
	cmds, _ = e.Apply(Event{Type: EvLocalDeleteDone}) // -> ATTESTED (E2E-7 seller)
	if e.State() != StateAttested || !has(cmds, CmdSendAttest) {
		t.Fatalf("want ATTESTED+attest, got %s %v", e.State(), cmds)
	}
}

// Buyer reaches DONE on a valid CDA.
func TestHappyPathBuyerToDone(t *testing.T) {
	e := New(Buyer)
	drive(t, e, EvStartPairing, EvHelloAckValid, EvOffer, EvAcceptMatches,
		EvPayloadDeliveredOK, EvSwapAssembled, EvTermsVerifyOK, EvPeerPartialReceived, EvOwnSigned,
		EvBroadcastAccepted, EvConfirmedAtDepth, EvDeletionAttestValid)
	if e.State() != StateDone {
		t.Fatalf("buyer want DONE, got %s", e.State())
	}
}

func toSwapAssembled(t *testing.T, role Role) *Engine {
	t.Helper()
	e := New(role)
	drive(t, e, EvStartPairing, EvHelloAckValid, EvOffer, EvAcceptMatches,
		EvPayloadDeliveredOK, EvSwapAssembled)
	return e
}

func TestFaultRows(t *testing.T) {
	cases := []struct {
		name       string
		build      func(t *testing.T) *Engine
		ev         EventType
		wantState  State
		wantReason Reason
	}{
		{"F-1/F-2 sign timeout", func(t *testing.T) *Engine { return toSwapAssembled(t, Seller) }, EvTimeoutSign, StateAborted, ReasonTimeoutSign},
		{"F-3 terms mismatch", func(t *testing.T) *Engine { return toSwapAssembled(t, Buyer) }, EvTermsVerifyFail, StateAborted, ReasonTermsMismatch},
		{"F-4 hash mismatch", func(t *testing.T) *Engine {
			e := New(Buyer)
			drive(t, e, EvStartPairing, EvHelloAckValid, EvOffer, EvAcceptMatches)
			return e
		}, EvPayloadHashMismatch, StateAborted, ReasonHashMismatch},
		{"F-5 user abort", func(t *testing.T) *Engine { return toSwapAssembled(t, Seller) }, EvAbort, StateAborted, ReasonUserAbort},
		{"pair timeout", func(t *testing.T) *Engine {
			e := New(Buyer)
			drive(t, e, EvStartPairing)
			return e
		}, EvTimeoutPair, StateAborted, ReasonTimeoutPair},
		{"deliver timeout", func(t *testing.T) *Engine {
			e := New(Seller)
			drive(t, e, EvStartPairing, EvHelloAckValid, EvOffer, EvAcceptMatches)
			return e
		}, EvTimeoutDeliver, StateAborted, ReasonTimeoutDeliver},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := c.build(t)
			if _, err := e.Apply(Event{Type: c.ev}); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if e.State() != c.wantState || e.Reason() != c.wantReason {
				t.Fatalf("got %s/%s, want %s/%s", e.State(), e.Reason(), c.wantState, c.wantReason)
			}
		})
	}
}

// toBroadcast drives an engine to BROADCAST.
func toBroadcast(t *testing.T, role Role) *Engine {
	t.Helper()
	e := New(role)
	drive(t, e, EvStartPairing, EvHelloAckValid, EvOffer, EvAcceptMatches,
		EvPayloadDeliveredOK, EvSwapAssembled, EvTermsVerifyOK, EvPeerPartialReceived, EvOwnSigned, EvBroadcastAccepted)
	return e
}

// F-7: node rejects the broadcast -> FAILED with reason; no silent retry.
func TestF7_BroadcastRejected(t *testing.T) {
	e := New(Seller)
	drive(t, e, EvStartPairing, EvHelloAckValid, EvOffer, EvAcceptMatches,
		EvPayloadDeliveredOK, EvSwapAssembled, EvTermsVerifyOK, EvPeerPartialReceived, EvOwnSigned)
	if e.State() != StateSwapSigned {
		t.Fatalf("want SWAP_SIGNED, got %s", e.State())
	}
	cmds, _ := e.Apply(Event{Type: EvBroadcastRejected})
	if e.State() != StateFailed || e.Reason() != ReasonBroadcastRejected || !has(cmds, CmdTeardown) {
		t.Fatalf("F-7: got %s/%s %v", e.State(), e.Reason(), cmds)
	}
}

// F-6: conflicting spend confirms -> FAILED/DOUBLE_SPENT.
func TestF6_DoubleSpent(t *testing.T) {
	e := toBroadcast(t, Buyer)
	e.Apply(Event{Type: EvConflictConfirmed})
	if e.State() != StateFailed || e.Reason() != ReasonDoubleSpent {
		t.Fatalf("F-6: got %s/%s", e.State(), e.Reason())
	}
}

// F-9 + no-silent-success: a confirm timeout keeps BROADCAST (pending),
// never auto-advances to CONFIRMED.
func TestF9_NoSilentSuccess(t *testing.T) {
	e := toBroadcast(t, Buyer)
	cmds, _ := e.Apply(Event{Type: EvConfirmTimeout})
	if e.State() != StateBroadcast || !has(cmds, CmdSurfacePending) {
		t.Fatalf("F-9: want stay BROADCAST+pending, got %s %v", e.State(), cmds)
	}
	// The ONLY route to CONFIRMED is an explicit confirmation event.
	e.Apply(Event{Type: EvConfirmedAtDepth})
	if e.State() != StateConfirmed {
		t.Fatalf("confirm: got %s", e.State())
	}
}

// F-8: reorg below CONF_DEPTH regresses CONFIRMED -> BROADCAST, surfaced,
// never a quiet success.
func TestF8_ReorgRegression(t *testing.T) {
	e := toBroadcast(t, Buyer)
	e.Apply(Event{Type: EvConfirmedAtDepth})
	cmds, _ := e.Apply(Event{Type: EvReorgBelowDepth})
	if e.State() != StateBroadcast || !has(cmds, CmdRegressPending) {
		t.Fatalf("F-8: want regress to BROADCAST, got %s %v", e.State(), cmds)
	}
}

// F-16: buyer owns the token after CONFIRMED regardless of the CDA; a
// missing/invalid CDA leaves it CONFIRMED (a missing CLAIM), not a
// transfer failure.
func TestF16_SettlementIndependentOfCDA(t *testing.T) {
	e := toBroadcast(t, Buyer)
	e.Apply(Event{Type: EvConfirmedAtDepth})
	// An invalid CDA (F-15/F-17) does not advance to DONE nor regress.
	e.Apply(Event{Type: EvDeletionAttestInvalid})
	if e.State() != StateConfirmed {
		t.Fatalf("F-16: invalid/missing CDA must leave buyer CONFIRMED, got %s", e.State())
	}
}

// Illegal events do not change state (no illegal advance).
func TestIllegalEventRejected(t *testing.T) {
	e := New(Seller)
	if _, err := e.Apply(Event{Type: EvConfirmedAtDepth}); err == nil {
		t.Fatal("CONFIRMED-at-depth accepted from IDLE")
	}
	if e.State() != StateIdle {
		t.Fatalf("illegal event mutated state to %s", e.State())
	}
}

// Determinism: the same event sequence yields the same final state.
func TestDeterministicReplay(t *testing.T) {
	seq := []EventType{EvStartPairing, EvHelloAckValid, EvOffer, EvAcceptMatches}
	a, b := New(Buyer), New(Buyer)
	drive(t, a, seq...)
	drive(t, b, seq...)
	if a.State() != b.State() {
		t.Fatalf("non-deterministic: %s vs %s", a.State(), b.State())
	}
}
