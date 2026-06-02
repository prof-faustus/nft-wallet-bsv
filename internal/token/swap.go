// The atomic swap (docs/02 §2.5) and its verifier. Tx_swap moves the
// token to Bob and pays Alice in ONE transaction, co-signed; valid only
// with both signatures, therefore atomic (I-NFT-4). The verifier is what
// lets each party check the assembled tx encodes EXACTLY the agreed
// terms before signing (docs/02 §2.5 step 2) and rejects every near-miss.
//
//trace:impl I-NFT-4
package token

import (
	"bytes"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

// PaymentInput is one of Bob's funding UTXOs spent into the swap.
type PaymentInput struct {
	TxID          string
	Vout          uint32
	LockingScript string // hex (P2PKH to Bob)
	Sats          uint64
}

// SwapParams fully specify Tx_swap (docs/02 §2.5 layout).
type SwapParams struct {
	// in 0 — Alice's token UTXO.
	TokenPrevTxID   string
	TokenPrevVout   uint32
	TokenLockScript string // the §2.3 carrier hex (Alice's)
	DustSats        uint64
	// identity carried unchanged into out 0.
	TokenId    []byte
	Descriptor []byte
	HPayload   []byte
	// out 0 — token to Bob.
	BobOwnerPKH []byte
	// out 1 — price to Alice.
	AliceAddr string
	PriceSats uint64
	// in 1.. — Bob's payment; out 2 — Bob's change.
	Payments      []PaymentInput
	BobChangeAddr string
	ChangeSats    uint64
}

// AssembleSwap builds the unsigned/partially-signable Tx_swap with the
// canonical layout. aliceKey signs in 0 (the token); pass bobKey to also
// sign Bob's payment inputs now, or nil to leave them for the
// counterparty (partial signing, docs/02 §2.5 step 3). SIGHASH_ALL|FORKID
// throughout so each signature commits to all inputs+outputs.
func AssembleSwap(p SwapParams, aliceKey, bobKey *ec.PrivateKey) (*wallet.Builder, error) {
	b := wallet.NewBuilder()
	// in 0: Alice spends the token (its gate is P2PKH on ownerPKH=Alice).
	if err := b.AddP2PKHInput(p.TokenPrevTxID, p.TokenPrevVout, p.TokenLockScript, p.DustSats, aliceKey, sighash.AllForkID); err != nil {
		return nil, fmt.Errorf("swap: token input: %w", err)
	}
	// in 1..: Bob's payment.
	for _, pay := range p.Payments {
		if err := b.AddP2PKHInput(pay.TxID, pay.Vout, pay.LockingScript, pay.Sats, bobKey, sighash.AllForkID); err != nil {
			return nil, fmt.Errorf("swap: payment input: %w", err)
		}
	}
	// out 0: token to Bob — SAME identity, ownerPKH = Bob.
	carrier, err := LockingScriptHex(p.TokenId, p.Descriptor, p.HPayload, p.BobOwnerPKH)
	if err != nil {
		return nil, err
	}
	if err := b.AddOutputScript(carrier, p.DustSats); err != nil {
		return nil, fmt.Errorf("swap: token output: %w", err)
	}
	// out 1: price to Alice.
	if err := b.AddP2PKHOutput(p.AliceAddr, p.PriceSats); err != nil {
		return nil, fmt.Errorf("swap: price output: %w", err)
	}
	// out 2: Bob's change (omit a dust/zero change).
	if p.ChangeSats > 0 {
		if err := b.AddP2PKHOutput(p.BobChangeAddr, p.ChangeSats); err != nil {
			return nil, fmt.Errorf("swap: change output: %w", err)
		}
	}
	return b, nil
}

// SwapExpectation is what a party checks an assembled Tx_swap against
// before signing (docs/02 §2.5 step 2).
type SwapExpectation struct {
	TokenId     []byte
	Descriptor  []byte
	HPayload    []byte
	BobOwnerPKH []byte
	AliceAddr   string
	PriceSats   uint64
	DustSats    uint64
	// MaxOutputs bounds the output count (3: token, price, change). No
	// surprise extra outputs (docs/02 §2.5 step 2).
	MaxOutputs int
}

// VerifySwapTx checks a raw Tx_swap encodes EXACTLY the agreed terms:
// out 0 reproduces the identity byte-for-byte and locks to Bob (I-NFT-2),
// out 1 pays the agreed price to Alice, no output carries OP_RETURN
// (I-NFT-1), and there are no surprise outputs. Returns the FIRST
// violation; a party that gets a non-nil error here does NOT sign.
//
//trace:impl I-NFT-2
func VerifySwapTx(rawTxHex string, exp SwapExpectation) error {
	tx, err := transaction.NewTransactionFromHex(rawTxHex)
	if err != nil {
		return fmt.Errorf("swap-verify: parse: %w", err)
	}
	if len(tx.Outputs) < 2 {
		return fmt.Errorf("swap-verify: need >=2 outputs (token, price), got %d", len(tx.Outputs))
	}
	if exp.MaxOutputs > 0 && len(tx.Outputs) > exp.MaxOutputs {
		return fmt.Errorf("swap-verify: too many outputs (%d > %d) — surprise output", len(tx.Outputs), exp.MaxOutputs)
	}
	// I-NFT-1: no OP_RETURN in any output.
	for i, o := range tx.Outputs {
		if o.LockingScript != nil && bytes.IndexByte(*o.LockingScript, opReturn) >= 0 {
			return fmt.Errorf("swap-verify: output %d contains OP_RETURN (I-NFT-1)", i)
		}
	}

	// out 0: token carrier, identity unchanged, owner = Bob.
	out0 := tx.Outputs[0]
	if out0.Satoshis != exp.DustSats {
		return fmt.Errorf("swap-verify: out0 value %d != dust %d", out0.Satoshis, exp.DustSats)
	}
	id, err := ParseLockingScript(*out0.LockingScript)
	if err != nil {
		return fmt.Errorf("swap-verify: out0 is not a token carrier: %w", err)
	}
	if !bytes.Equal(id.TokenId, exp.TokenId) {
		return fmt.Errorf("swap-verify: out0 TokenId changed (I-NFT-2)")
	}
	if !bytes.Equal(id.PayloadDescriptor, exp.Descriptor) {
		return fmt.Errorf("swap-verify: out0 payloadDescriptor changed (I-NFT-2)")
	}
	if !bytes.Equal(id.HPayload, exp.HPayload) {
		return fmt.Errorf("swap-verify: out0 H(payload) changed (I-NFT-2)")
	}
	if !bytes.Equal(id.OwnerPKH, exp.BobOwnerPKH) {
		return fmt.Errorf("swap-verify: out0 does not lock to Bob")
	}

	// out 1: price to Alice.
	wantAlice, err := p2pkhScriptHex(exp.AliceAddr)
	if err != nil {
		return err
	}
	out1 := tx.Outputs[1]
	if out1.Satoshis != exp.PriceSats {
		return fmt.Errorf("swap-verify: out1 price %d != agreed %d", out1.Satoshis, exp.PriceSats)
	}
	if hex.EncodeToString(*out1.LockingScript) != wantAlice {
		return fmt.Errorf("swap-verify: out1 does not pay Alice's address")
	}
	return nil
}

// p2pkhScriptHex returns the P2PKH locking script hex for an address.
func p2pkhScriptHex(addr string) (string, error) {
	a, err := script.NewAddressFromString(addr)
	if err != nil {
		return "", fmt.Errorf("swap-verify: bad alice address: %w", err)
	}
	ls, err := p2pkh.Lock(a)
	if err != nil {
		return "", err
	}
	return ls.String(), nil
}
