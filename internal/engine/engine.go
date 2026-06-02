// Package engine is the exchange protocol engine (docs/03 §3.5): a
// DETERMINISTIC state machine driven by typed events. State transitions
// are pure functions of (current state, event); side effects (sign,
// broadcast, send, delete) are emitted as Commands for the adapters to
// execute. This makes the engine unit-testable without a network and
// replayable from a transcript (docs/01 §1.3).
//
// Implements: docs/03 §3.5 (state machine), §3.3 (message-driven events),
// §3.6 (timeouts). Milestone M2 (E2E-2..6, faults F-1..F-14).
//
// Two load-bearing rules from §3.5 are enforced HERE:
//   - No silent success: the engine never reaches CONFIRMED/DONE except
//     via an explicit confirmation/attestation event; a confirm timeout
//     keeps it at BROADCAST ("pending"), never auto-advances.
//   - Reorg awareness: a confirmed swap reorged below CONF_DEPTH regresses
//     CONFIRMED -> BROADCAST with a surfaced event, never a quiet success.
//
// NG watch: NG-1 (one seller, one buyer), NG-3 (single on-chain swap; no
// channels). MUST NOT import BTC (CLAUDE.md §1).
package engine

import "fmt"

// Role distinguishes the two parties (NG-1: exactly these two).
type Role int

const (
	Seller Role = iota // Alice — holds the token
	Buyer              // Bob — pays
)

// State is an exchange state (docs/03 §3.5).
type State string

const (
	StateIdle             State = "IDLE"
	StatePairing          State = "PAIRING"
	StateConnected        State = "CONNECTED"
	StateNegotiating      State = "NEGOTIATING"
	StatePriceAgreed      State = "PRICE_AGREED"
	StatePayloadDelivered State = "PAYLOAD_DELIVERED"
	StateSwapAssembled    State = "SWAP_ASSEMBLED"
	StateSwapSigned       State = "SWAP_SIGNED"
	StateBroadcast        State = "BROADCAST"
	StateConfirmed        State = "CONFIRMED"
	StateAttested         State = "ATTESTED"
	StateDone             State = "DONE"
	StateAborted          State = "ABORTED"
	StateFailed           State = "FAILED"
)

// EventType is a typed input to the engine (peer message, chain event,
// user action, or timer firing — docs/01 §1.3).
type EventType int

const (
	EvStartPairing EventType = iota
	EvHelloAckValid
	EvOffer
	EvCounter
	EvAcceptMatches
	EvAbort              // user/peer ABORT
	EvPayloadDeliveredOK // seller sent + buyer ack with matching hash
	EvPayloadHashMismatch
	EvSwapAssembled
	EvTermsVerifyOK
	EvTermsVerifyFail
	EvPeerPartialReceived
	EvOwnSigned
	EvBroadcastAccepted
	EvBroadcastRejected
	EvConfirmedAtDepth // depth >= CONF_DEPTH
	EvConflictConfirmed
	EvReorgBelowDepth
	EvConfirmTimeout
	EvLocalDeleteDone       // seller
	EvDeletionAttestValid   // buyer
	EvDeletionAttestInvalid // buyer
	EvTimeoutPair
	EvTimeoutDeliver
	EvTimeoutSign
)

// Reason is a terminal-state reason code (docs/03 §3.5).
type Reason string

const (
	ReasonNone              Reason = ""
	ReasonUserAbort         Reason = "ABORT"
	ReasonTimeoutPair       Reason = "TIMEOUT_PAIR"
	ReasonTimeoutDeliver    Reason = "TIMEOUT_DELIVER"
	ReasonTimeoutSign       Reason = "TIMEOUT_SIGN"
	ReasonTermsMismatch     Reason = "TERMS_MISMATCH"
	ReasonHashMismatch      Reason = "HASH_MISMATCH"
	ReasonDoubleSpent       Reason = "DOUBLE_SPENT"
	ReasonBroadcastRejected Reason = "BROADCAST_REJECTED"
)

// Command is a side effect the engine asks an adapter to perform. The
// engine itself performs no I/O.
type Command string

const (
	CmdSendHello      Command = "SEND_HELLO"
	CmdOpenChat       Command = "OPEN_CHAT"
	CmdAssembleSwap   Command = "ASSEMBLE_SWAP"
	CmdCombineAndSign Command = "COMBINE_AND_SIGN"
	CmdBroadcast      Command = "BROADCAST"
	CmdWatchChain     Command = "WATCH_CHAIN"
	CmdSurfacePending Command = "SURFACE_PENDING"    // no silent success
	CmdRegressPending Command = "REGRESS_TO_PENDING" // reorg
	CmdSendAttest     Command = "SEND_DELETION_ATTEST"
	CmdStoreAttest    Command = "STORE_ATTEST"
	CmdTeardown       Command = "TEARDOWN"
)

// Event carries a type plus the minimal fields some transitions need.
type Event struct {
	Type EventType
}

// Engine is one party's exchange state machine instance.
type Engine struct {
	role   Role
	state  State
	reason Reason

	// SWAP_ASSEMBLED phase flags (the §3.5 guard: terms verified AND own
	// signature produced AND peer SWAP_PARTIAL received).
	termsOK     bool
	peerPartial bool
	ownSigned   bool
}

// New returns an engine in IDLE for a role.
func New(role Role) *Engine { return &Engine{role: role, state: StateIdle} }

// State / Reason / Role accessors.
func (e *Engine) State() State   { return e.state }
func (e *Engine) Reason() Reason { return e.reason }
func (e *Engine) Role() Role     { return e.role }

// Apply applies one event, returning the commands to perform. An event
// illegal for the current state returns an error and does NOT change
// state (idempotence / no illegal advance — docs/03 §3.5).
func (e *Engine) Apply(ev Event) ([]Command, error) {
	// ABORT is accepted from any non-terminal state (clean teardown).
	if ev.Type == EvAbort && !e.terminal() {
		return e.abort(ReasonUserAbort)
	}
	switch e.state {
	case StateIdle:
		if ev.Type == EvStartPairing {
			e.state = StatePairing
			return []Command{CmdSendHello}, nil
		}
	case StatePairing:
		switch ev.Type {
		case EvHelloAckValid:
			e.state = StateConnected
			return []Command{CmdOpenChat}, nil
		case EvTimeoutPair:
			return e.abortTimeout(ReasonTimeoutPair)
		}
	case StateConnected, StateNegotiating:
		switch ev.Type {
		case EvOffer, EvCounter:
			e.state = StateNegotiating
			return nil, nil
		case EvAcceptMatches:
			e.state = StatePriceAgreed
			return nil, nil
		}
	case StatePriceAgreed:
		switch ev.Type {
		case EvPayloadDeliveredOK:
			e.state = StatePayloadDelivered
			return []Command{CmdAssembleSwap}, nil
		case EvPayloadHashMismatch: // F-4 (buyer)
			return e.abort(ReasonHashMismatch)
		case EvTimeoutDeliver:
			return e.abortTimeout(ReasonTimeoutDeliver)
		}
	case StatePayloadDelivered:
		if ev.Type == EvSwapAssembled {
			e.state = StateSwapAssembled
			return nil, nil
		}
	case StateSwapAssembled:
		switch ev.Type {
		case EvTermsVerifyOK:
			e.termsOK = true
			return e.maybeSigned()
		case EvTermsVerifyFail: // F-3
			return e.abort(ReasonTermsMismatch)
		case EvPeerPartialReceived:
			e.peerPartial = true
			return e.maybeSigned()
		case EvOwnSigned:
			e.ownSigned = true
			return e.maybeSigned()
		case EvTimeoutSign: // F-1 / F-2
			return e.abortTimeout(ReasonTimeoutSign)
		}
	case StateSwapSigned:
		switch ev.Type {
		case EvBroadcastAccepted:
			e.state = StateBroadcast
			return []Command{CmdWatchChain}, nil
		case EvBroadcastRejected: // F-7
			e.state = StateFailed
			e.reason = ReasonBroadcastRejected
			return []Command{CmdTeardown}, nil
		}
	case StateBroadcast:
		switch ev.Type {
		case EvConfirmedAtDepth:
			e.state = StateConfirmed
			return nil, nil
		case EvConflictConfirmed: // F-6
			e.state = StateFailed
			e.reason = ReasonDoubleSpent
			return []Command{CmdTeardown}, nil
		case EvConfirmTimeout: // F-9 — NO silent success
			return []Command{CmdSurfacePending}, nil // stays BROADCAST
		}
	case StateConfirmed:
		switch ev.Type {
		case EvReorgBelowDepth: // F-8 — regress, never quiet success
			e.state = StateBroadcast
			return []Command{CmdRegressPending, CmdWatchChain}, nil
		case EvLocalDeleteDone:
			if e.role == Seller {
				e.state = StateAttested
				return []Command{CmdSendAttest}, nil
			}
		case EvDeletionAttestValid:
			if e.role == Buyer {
				e.state = StateDone
				return []Command{CmdStoreAttest}, nil
			}
		case EvDeletionAttestInvalid: // F-15/F-17 — stay, don't store
			if e.role == Buyer {
				return nil, nil // remains CONFIRMED; missing valid CDA
			}
		}
	case StateAttested:
		if ev.Type == EvDeletionAttestValid && e.role == Buyer {
			e.state = StateDone
			return []Command{CmdStoreAttest}, nil
		}
	}
	return nil, fmt.Errorf("engine: event %v illegal in state %s (role %d)", ev.Type, e.state, e.role)
}

// maybeSigned advances SWAP_ASSEMBLED -> SWAP_SIGNED once terms are
// verified AND both signatures are present (docs/03 §3.5 guard).
func (e *Engine) maybeSigned() ([]Command, error) {
	if e.termsOK && e.peerPartial && e.ownSigned {
		e.state = StateSwapSigned
		return []Command{CmdCombineAndSign, CmdBroadcast}, nil
	}
	return nil, nil
}

func (e *Engine) abort(r Reason) ([]Command, error) {
	e.state = StateAborted
	e.reason = r
	return []Command{CmdTeardown}, nil
}

func (e *Engine) abortTimeout(r Reason) ([]Command, error) {
	e.state = StateAborted
	e.reason = r
	return []Command{CmdTeardown}, nil
}

func (e *Engine) terminal() bool {
	return e.state == StateDone || e.state == StateAborted || e.state == StateFailed
}
