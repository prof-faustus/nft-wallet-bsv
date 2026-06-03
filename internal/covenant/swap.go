// swap.go — the covenant-aware atomic swap. When the token is locked under
// the OP_PUSH_TX continuity covenant (CovenantLockingScript), transferring
// it inside the atomic price swap requires the covenant unlock on the token
// input (NOT a P2PKH signature):
//
//	in 0  — the covenant token UTXO, unlocked with <preimage> <newOwnerPKH>,
//	        committing under SIGHASH_SINGLE|FORKID so hashOutputs covers ONLY
//	        out 0 (the successor token), which the covenant enforces.
//	in 1+ — the buyer's payment UTXOs (P2PKH, SIGHASH_ALL|FORKID).
//	out 0 — the successor token carrier to the buyer (same identity + value).
//	out 1 — the price to the seller.
//	out 2 — the buyer's change.
//
// The token value passes straight through (NFT value invariant); fee+price
// come from the payment inputs. Atomicity is unchanged: the buyer's ALL
// signatures commit to every input+output, so the whole tx confirms or none
// of it does. The covenant additionally makes stripping/mutating the token
// IMPOSSIBLE in Script (verified in covenant_test + exec_test).
//
// MUST NOT emit OP_RETURN (§2). Output scripts go through the wallet builder
// which rejects 0x6a.
package covenant

import (
	"bytes"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

// CovenantSwapParams fully specify a covenant-token atomic swap.
type CovenantSwapParams struct {
	// in 0 — the covenant token UTXO. Vout MUST be 0 so SIGHASH_SINGLE's
	// hashOutputs (output at the input index) aligns with the token output.
	TokenPrevTxID string
	TokenPrevVout uint32
	TokenId       []byte
	Descriptor    []byte
	HPayload      []byte
	TokenValue    uint64 // the covenant value; out 0 value is fixed to this

	BobOwnerPKH []byte // new owner (spender's choice)

	SellerAddr string // out 1 — price to the seller
	PriceSats  uint64

	Payments      []token.PaymentInput // in 1.. — buyer payment
	BobChangeAddr string               // out 2 — buyer change
	ChangeSats    uint64
}

// AssembleCovenantSwap builds the swap with the covenant token input. The
// returned builder has the token input's covenant unlock already set; the
// caller signs the payment inputs by calling Sign() (bobKey was attached to
// them here). Returns an error if Vout != 0 (SINGLE alignment).
//
//trace:impl CN-1
func AssembleCovenantSwap(p CovenantSwapParams, bobKey *ec.PrivateKey) (*wallet.Builder, error) {
	if p.TokenPrevVout != 0 {
		return nil, fmt.Errorf("covenant-swap: token must be at input/output index 0 (SIGHASH_SINGLE alignment), got vout %d", p.TokenPrevVout)
	}
	cov, err := CovenantLockingScript(p.TokenId, p.Descriptor, p.HPayload, p.TokenValue)
	if err != nil {
		return nil, err
	}
	covHex := hex.EncodeToString(cov)

	b := wallet.NewBuilder()
	// in 0: covenant token input — no signer template; unlock set manually.
	if err := b.AddP2PKHInput(p.TokenPrevTxID, p.TokenPrevVout, covHex, p.TokenValue, nil, sighash.Flag(SighashFlag)); err != nil {
		return nil, fmt.Errorf("covenant-swap: token input: %w", err)
	}
	// in 1..: buyer payment (signed with ALL by bobKey at Sign()).
	for _, pay := range p.Payments {
		if err := b.AddP2PKHInput(pay.TxID, pay.Vout, pay.LockingScript, pay.Sats, bobKey, sighash.AllForkID); err != nil {
			return nil, fmt.Errorf("covenant-swap: payment input: %w", err)
		}
	}
	// out 0: successor token carrier to the buyer — SAME identity + value.
	carrier, err := token.LockingScriptHex(p.TokenId, p.Descriptor, p.HPayload, p.BobOwnerPKH)
	if err != nil {
		return nil, err
	}
	if err := b.AddOutputScript(carrier, p.TokenValue); err != nil {
		return nil, fmt.Errorf("covenant-swap: token output: %w", err)
	}
	// out 1: price to the seller.
	if err := b.AddP2PKHOutput(p.SellerAddr, p.PriceSats); err != nil {
		return nil, fmt.Errorf("covenant-swap: price output: %w", err)
	}
	// out 2: buyer change.
	if p.ChangeSats > 0 {
		if err := b.AddP2PKHOutput(p.BobChangeAddr, p.ChangeSats); err != nil {
			return nil, fmt.Errorf("covenant-swap: change output: %w", err)
		}
	}

	// EXPLICIT INDEX-ALIGNMENT INVARIANT (audit finding 6): validate the
	// assembled template BEFORE computing the SIGHASH_SINGLE preimage / signing.
	// The covenant only constrains the output at the SINGLE input's index, so
	// the token MUST be input 0 AND its successor MUST be output 0. We assert
	// that on the actually-assembled tx so any future reordering (extra earlier
	// inputs, moved outputs) fails loudly here instead of producing an unsafe
	// signature.
	if err := validateCovenantTemplate(b, p); err != nil {
		return nil, err
	}

	// Compute the token input's SINGLE|FORKID preimage and set the covenant
	// unlock <preimage> <newOwnerPKH>.
	preimage, err := b.SighashPreimage(0, sighash.Flag(SighashFlag))
	if err != nil {
		return nil, fmt.Errorf("covenant-swap: preimage: %w", err)
	}
	unlock, err := CovenantUnlockingScript(preimage, p.BobOwnerPKH)
	if err != nil {
		return nil, err
	}
	if err := b.SetInputUnlockingScript(0, unlock); err != nil {
		return nil, err
	}
	return b, nil
}

// validateCovenantTemplate asserts the SIGHASH_SINGLE index-alignment invariant
// on the ASSEMBLED transaction (audit finding 6): the token covenant input is
// at input index 0 spending (TokenPrevTxID, 0), and the successor token carrier
// — same identity (TokenId/Descriptor/HPayload) and value — is at OUTPUT index
// 0, so the SINGLE-committed output index equals the token input index. This is
// the structural guard that keeps the covenant a CONSTRAINED construction, not
// a general transfer that could move the token off index 0.
//
// # Errors
// A descriptive error if inputs/outputs are missing or index 0 is not the
// token on either side — the caller MUST NOT sign in that case.
func validateCovenantTemplate(b *wallet.Builder, p CovenantSwapParams) error {
	raw, err := b.Bytes()
	if err != nil {
		return fmt.Errorf("covenant-swap: serialize for template check: %w", err)
	}
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return fmt.Errorf("covenant-swap: parse for template check: %w", err)
	}
	if len(tx.Inputs) < 1 {
		return fmt.Errorf("covenant-swap: template has no inputs")
	}
	in0 := tx.Inputs[0]
	if in0.SourceTXID == nil || in0.SourceTXID.String() != p.TokenPrevTxID || in0.SourceTxOutIndex != 0 {
		return fmt.Errorf("covenant-swap: input 0 is not the token UTXO (%s:0) — SINGLE alignment broken", p.TokenPrevTxID)
	}
	if len(tx.Outputs) < 1 || tx.Outputs[0].LockingScript == nil {
		return fmt.Errorf("covenant-swap: template has no output 0")
	}
	out0 := tx.Outputs[0]
	if out0.Satoshis != p.TokenValue {
		return fmt.Errorf("covenant-swap: output 0 value %d != token value %d", out0.Satoshis, p.TokenValue)
	}
	id, err := token.ParseLockingScript(*out0.LockingScript)
	if err != nil {
		return fmt.Errorf("covenant-swap: output 0 is not a token carrier: %w", err)
	}
	if !bytes.Equal(id.TokenId, p.TokenId) || !bytes.Equal(id.PayloadDescriptor, p.Descriptor) ||
		!bytes.Equal(id.HPayload, p.HPayload) || !bytes.Equal(id.OwnerPKH, p.BobOwnerPKH) {
		return fmt.Errorf("covenant-swap: output 0 does not reproduce the token identity locked to the new owner")
	}
	return nil
}
