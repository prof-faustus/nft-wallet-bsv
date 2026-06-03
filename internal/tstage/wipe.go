// Package tstage is the T-stage (docs/04 §4.6, OD-1): it turns the
// cooperative deletion attestation (the Stage-1 CDA, a CLAIM) into a
// hardware-style ATTESTED WIPE — the enclave signs that it zeroized the
// plaintext payload after the sale, and that attestation rides WITH the CDA
// (docs/04 §4.5: "in the T-stage it additionally carries the attestation").
//
// What this closes (relative to Stage 1):
//   - SC-1 + the key-exfiltration part of HH-1: the enclave's signing key is
//     non-exportable (internal/tee never returns it), so settlement/wipe
//     attestations are produced inside the enclave.
//   - The deletion claim is upgraded from "the seller SAYS they deleted it"
//     to "an attested enclave with an approved measurement SIGNED that it
//     wiped the payload, bound to this token + swap + H(payload)".
//
// ⚠️ SIMULATION boundary (unchanged, stated loudly): internal/tee is a
// software enclave with a self-generated attestation root, not a vendor
// root. This proves the attested-wipe FLOW and the verifier with the
// identical interface real hardware uses — it is NOT, yet, hardware-verified
// deletion. Genuine hardware (verified vendor root) drops into the same
// verifier. Nothing here may be presented as hardware-attested in
// production (CLAUDE.md §4).
//
// MUST NOT: import BTC; emit OP_RETURN.
//
//trace:impl HH-1 SC-1
package tstage

import (
	"github.com/prof-faustus/nft-wallet-bsv/internal/tee"
)

// Status is the T-stage classification of a received deletion attestation.
type Status string

const (
	// AttestedWipe: a valid enclave attestation that it wiped the payload,
	// bound to this token + swap + H(payload). The strongest claim this
	// (simulated) stack makes.
	AttestedWipe Status = "enclave-attested wipe (SIMULATION — not hardware-verified)"
	// CooperativeOnly: no enclave attestation (or it failed) — the deletion
	// is only the cooperative CDA claim (Stage 1 semantics).
	CooperativeOnly Status = "cooperative claim only"
)

// WipeStatement is the canonical transcript the enclave signs to attest the
// payload wipe: domain ‖ tokenId ‖ swapTxid ‖ H(payload). Binding to the
// swap txid ties the wipe to THIS settlement.
func WipeStatement(tokenID []byte, swapTxID string, hPayload []byte) []byte {
	out := []byte("nftbsv/tstage/wipe/v1|")
	out = append(out, tokenID...)
	out = append(out, '|')
	out = append(out, []byte(swapTxID)...)
	out = append(out, '|')
	out = append(out, hPayload...)
	return out
}

// AttestWipe has the (enclave-custody) enclave sign the wipe statement,
// bound to a verifier-supplied fresh nonce (anti-replay). Returns the device
// binding that travels with the CDA.
//
//trace:impl HH-1
func AttestWipe(enc *tee.Enclave, nonce, tokenID []byte, swapTxID string, hPayload []byte) tee.DeviceBinding {
	return enc.Bind(nonce, WipeStatement(tokenID, swapTxID, hPayload))
}

// VerifyWipe is fail-closed: returns AttestedWipe iff the binding is a
// genuine enclave attestation (allowlisted measurement, valid root sig,
// fresh nonce) over the EXACT wipe statement for this token+swap+H(payload);
// otherwise CooperativeOnly. The caller has already validated the
// cooperative CDA separately (deletion.ClassifyReceived).
//
//trace:impl HH-1 SC-1
func VerifyWipe(binding tee.DeviceBinding, pol tee.Policy, nonce, tokenID []byte, swapTxID string, hPayload []byte) Status {
	if tee.VerifyBinding(binding, pol, nonce, WipeStatement(tokenID, swapTxID, hPayload)) {
		return AttestedWipe
	}
	return CooperativeOnly
}
