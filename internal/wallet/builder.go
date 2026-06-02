// General full-Script transaction builder (docs/01 §1.2, docs/02 §2.5,
// docs/06 WS2). Wraps the BSV Go SDK transaction with: arbitrary
// inputs/outputs, arbitrary locking/unlocking scripts, explicit SIGHASH
// control, and partial signing (each party signs only its own inputs —
// the atomic-swap co-signing flow, docs/02 §2.5 / docs/03 §3.3).
//
// MUST NOT (CLAUDE.md §2 — STRUCTURAL): this builder exposes NO OP_RETURN
// primitive. It has no method that appends a `0x6a` data output, never
// calls the SDK's AddOpReturnOutput, and AddOutputScript/Finalize REJECT
// any script containing opcode 0x6a. Data carriage is push-drop (WS3),
// never OP_RETURN (I-NFT-1).
//
// SIGHASH: the swap uses SIGHASH_ALL|FORKID (sighash.AllForkID, the
// canonical BSV flag) so each signature commits to ALL outputs — there
// is no take-the-money-change-the-output attack (docs/02 §2.5). The flag
// is explicit per input, never implicit.
//
// Implements: docs/06 WS2; the SIGHASH discipline of docs/02 §2.5.
package wallet

import (
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/bsvscript"
)

// Builder assembles a transaction. Inputs carry an unlocking-script
// template only for the inputs the local party can sign; Sign() fills
// those and leaves the rest for a counterparty (partial signing).
type Builder struct {
	tx *transaction.Transaction
}

// NewBuilder starts an empty transaction.
func NewBuilder() *Builder { return &Builder{tx: transaction.NewTransaction()} }

// AddP2PKHInput adds a P2PKH input that THIS party will sign with key,
// committing under the given SIGHASH flag. Use sighash.AllForkID for the
// swap. Pass a nil key to add the input WITHOUT a signing template
// (a counterparty will sign it later — partial signing).
//
// Preconditions: prevLockingScriptHex is the input's P2PKH locking script.
// Postconditions: the input is appended; signed by Sign() iff key != nil.
func (b *Builder) AddP2PKHInput(prevTxID string, vout uint32, prevLockingScriptHex string, sats uint64, key *ec.PrivateKey, flag sighash.Flag) error {
	var tmpl transaction.UnlockingScriptTemplate
	if key != nil {
		f := flag
		u, err := p2pkh.Unlock(key, &f)
		if err != nil {
			return fmt.Errorf("builder: p2pkh unlock: %w", err)
		}
		tmpl = u
	}
	if err := b.tx.AddInputFrom(prevTxID, vout, prevLockingScriptHex, sats, tmpl); err != nil {
		return fmt.Errorf("builder: add input: %w", err)
	}
	return nil
}

// SetInputSigner attaches a signing template to an already-added input
// (the counterparty side of partial signing): given the input index, the
// signer's key, and the flag.
func (b *Builder) SetInputSigner(idx int, key *ec.PrivateKey, flag sighash.Flag) error {
	if idx < 0 || idx >= b.tx.InputCount() {
		return fmt.Errorf("builder: input %d out of range", idx)
	}
	f := flag
	u, err := p2pkh.Unlock(key, &f)
	if err != nil {
		return err
	}
	b.tx.InputIdx(idx).UnlockingScriptTemplate = u
	return nil
}

// SetInputUnlockingScript sets a RAW unlocking script on an already-added
// input (the input must have been added without a signing template). This
// is how non-P2PKH spends — e.g. the OP_PUSH_TX covenant unlock
// (<preimage> <ownerPKH>) — provide their unlocking script directly.
// Sign() leaves such inputs untouched (it only fills templated inputs), so
// the manual script survives finalisation.
func (b *Builder) SetInputUnlockingScript(idx int, unlocking []byte) error {
	if idx < 0 || idx >= b.tx.InputCount() {
		return fmt.Errorf("builder: input %d out of range", idx)
	}
	b.tx.InputIdx(idx).UnlockingScript = script.NewFromBytes(unlocking)
	return nil
}

// AddP2PKHOutput locks sats to a P2PKH address.
func (b *Builder) AddP2PKHOutput(addr string, sats uint64) error {
	a, err := script.NewAddressFromString(addr)
	if err != nil {
		return fmt.Errorf("builder: bad address: %w", err)
	}
	ls, err := p2pkh.Lock(a)
	if err != nil {
		return err
	}
	return b.AddOutputScript(hex.EncodeToString(*ls), sats)
}

// AddOutputScript locks sats under an arbitrary locking script (hex).
// REJECTS any script containing OP_RETURN (0x6a) — the structural §2
// guard. This is the path the push-drop token output (WS3) uses.
func (b *Builder) AddOutputScript(lockingScriptHex string, sats uint64) error {
	raw, err := hex.DecodeString(lockingScriptHex)
	if err != nil {
		return fmt.Errorf("builder: locking script not hex: %w", err)
	}
	if containsOpReturn(raw) {
		return fmt.Errorf("builder: refusing output: locking script contains OP_RETURN (0x6a) — banned (CLAUDE.md §2, I-NFT-1)")
	}
	s := script.NewFromBytes(raw)
	b.tx.AddOutput(&transaction.TransactionOutput{Satoshis: sats, LockingScript: s})
	return nil
}

// Sign signs every input that has an unlocking-script template. Inputs
// without one are left for a counterparty (partial signing). It refuses
// to finalize a transaction whose any output script contains OP_RETURN.
func (b *Builder) Sign() error {
	if err := b.assertNoOpReturn(); err != nil {
		return err
	}
	return b.tx.Sign()
}

// SighashPreimage returns the signature preimage for an input under a
// flag — the exact bytes a signature commits to. Used to TEST that
// SIGHASH_ALL binds all outputs (docs/06 WS2 DoD).
func (b *Builder) SighashPreimage(inputIdx uint32, flag sighash.Flag) ([]byte, error) {
	return b.tx.CalcInputPreimage(inputIdx, flag)
}

// Bytes returns the serialized transaction, refusing if any output is an
// OP_RETURN (defense in depth over the emitted bytes — docs/05 §5.2).
func (b *Builder) Bytes() ([]byte, error) {
	if err := b.assertNoOpReturn(); err != nil {
		return nil, err
	}
	return b.tx.Bytes(), nil
}

// Hex is Bytes as hex.
func (b *Builder) Hex() (string, error) {
	raw, err := b.Bytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// TxID returns the transaction's display txid.
func (b *Builder) TxID() string { return b.tx.TxID().String() }

// assertNoOpReturn scans every output locking script for opcode 0x6a.
func (b *Builder) assertNoOpReturn() error {
	for i, out := range b.tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		if containsOpReturn(*out.LockingScript) {
			return fmt.Errorf("builder: output %d locking script contains OP_RETURN (0x6a) — banned", i)
		}
	}
	return nil
}

// containsOpReturn reports whether script bytes contain OP_RETURN as an
// OPCODE (not a 0x6a data byte inside a push) — see bsvscript.HasOpReturn.
func containsOpReturn(b []byte) bool { return bsvscript.HasOpReturn(b) }
