// Package uistate is the AUTHORITATIVE honest-state model for the UI
// (docs/01 §1.5, docs/03 §3.5, docs/04 §4.7, docs/06 WS7). The .NET/C#
// shell renders exactly what this Go (sidecar) code says — the honest
// distinctions live here, in testable code, not in GUI strings that
// could drift.
//
// Two non-negotiable honesty rules (WS7 DoD):
//  1. NEVER report "complete"/"success" before CONFIRMED. Between
//     BROADCAST and CONFIRMED the status is "pending", distinct from
//     "confirmed" (docs/03 §3.5 no silent success).
//  2. NEVER say deletion is "verified" — Stage 1 deletion is an
//     ATTESTATION (a signed claim), never verified (docs/04 §4.7).
//
// Implements: docs/06 WS7 honest-state surfacing.
package uistate

import (
	"fmt"
	"strings"

	"github.com/prof-faustus/nft-wallet-bsv/internal/deletion"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
)

// Display is the honest status the UI shows for an exchange.
type Display struct {
	EngineState string // raw engine state
	Label       string // human-facing label
	// Success is TRUE only once on-chain control transfer is CONFIRMED.
	// It is FALSE for every pre-CONFIRMED state — the UI must not show a
	// success/complete affordance while Success is false.
	Success bool
	// Pending is TRUE while broadcast-but-not-yet-confirmed.
	Pending bool
	// Terminal failure (ABORTED/FAILED).
	Failed bool
}

// ForExchange maps an engine state (+ current confirmation depth and the
// configured CONF_DEPTH) to the honest Display. confDepth/curDepth are
// only meaningful around BROADCAST/CONFIRMED.
func ForExchange(s engine.State, reason engine.Reason, curDepth, confDepth uint32) Display {
	switch s {
	case engine.StateBroadcast:
		return Display{EngineState: string(s), Pending: true, Label: fmt.Sprintf("Pending — broadcast, awaiting confirmation (%d/%d blocks)", curDepth, confDepth)}
	case engine.StateConfirmed:
		return Display{EngineState: string(s), Success: true, Label: "Confirmed — on-chain control transferred to the buyer"}
	case engine.StateAttested:
		return Display{EngineState: string(s), Success: true, Label: "Confirmed; seller sent a deletion attestation (a signed CLAIM, not proof the copy is gone)"}
	case engine.StateDone:
		return Display{EngineState: string(s), Success: true, Label: "Done — control transferred; deletion attestation stored (a CLAIM, not proof)"}
	case engine.StateAborted:
		return Display{EngineState: string(s), Failed: true, Label: "Aborted: " + reasonText(reason)}
	case engine.StateFailed:
		return Display{EngineState: string(s), Failed: true, Label: "Failed: " + reasonText(reason)}
	default:
		// All pre-broadcast states: in progress, never a success.
		return Display{EngineState: string(s), Label: "In progress: " + string(s)}
	}
}

// DeletionLabel renders an attestation status. It NEVER contains the word
// "verified" — Stage 1 deletion is a claim (docs/04 §4.7).
func DeletionLabel(status deletion.AttestStatus) string {
	switch status {
	case deletion.AttestValid:
		return "Deletion attested by the seller — a signed, non-repudiable CLAIM (NOT proof the copy is gone)"
	case deletion.AttestInvalid:
		return "Deletion attestation INVALID (rejected; not stored)"
	default:
		return "No deletion attestation received (claim absent — settlement is unaffected)"
	}
}

func reasonText(r engine.Reason) string {
	if r == engine.ReasonNone {
		return "(no reason)"
	}
	return string(r)
}

// ForbidsVerifiedDeletion is a self-check used by tests: it reports
// whether a label wrongly claims deletion is "verified".
func ForbidsVerifiedDeletion(label string) bool {
	l := strings.ToLower(label)
	return strings.Contains(l, "verified")
}
