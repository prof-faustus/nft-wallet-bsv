// Mint — Stage-1 local provisioning of the token (docs/02 §2.4). Creates
// the first token UTXO (out 0, DUST) under Alice's key plus her change.
//
// mintOutpoint choice: TokenId binds the FIRST funding input's outpoint
// (a pre-existing, already-unique UTXO), NOT the token's own outpoint —
// the latter is self-referential (TokenId sits inside out 0's script,
// which determines the txid, which determines that outpoint). Binding a
// spent funding outpoint still gives global uniqueness (it can be spent
// once). Recorded as an assumption in docs/07.
//
//trace:impl I-NFT-3 I-NFT-5
package token

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

// FundingInput is one of Alice's UTXOs spent to mint.
type FundingInput struct {
	TxID          string
	Vout          uint32
	LockingScript string // hex (P2PKH to Alice)
	Sats          uint64
}

// MintParams specify a mint transaction.
type MintParams struct {
	Funding    []FundingInput
	OwnerKey   *ec.PrivateKey // Alice
	Descriptor []byte
	HPayload   []byte
	DustSats   uint64
	ChangeAddr string
	ChangeSats uint64
}

// MintResult carries the fixed TokenId, the token's carrier script, and
// the assembled (signable) transaction builder.
type MintResult struct {
	TokenId       []byte
	LockScriptHex string
	Builder       *wallet.Builder
}

// PubKeyHash returns HASH160 of a compressed public key (the ownerPKH).
func PubKeyHash(pub *ec.PublicKey) []byte { return hash160(pub.Compressed()) }

// Mint assembles the mint transaction and fixes the TokenId.
//
// Preconditions: at least one funding input; OwnerKey set.
// Postconditions: out 0 is the token carrier (DUST) for Alice; TokenId is
// determined and recoverable from out 0's script (I-NFT-2). The builder
// is signed for Alice's funding inputs.
func Mint(p MintParams) (*MintResult, error) {
	if len(p.Funding) == 0 {
		return nil, fmt.Errorf("mint: no funding inputs")
	}
	if p.OwnerKey == nil {
		return nil, fmt.Errorf("mint: nil owner key")
	}
	ownerPub := p.OwnerKey.PubKey().Compressed()
	ownerPKH := hash160(ownerPub)
	mintOutpoint := Outpoint{TxID: p.Funding[0].TxID, Vout: p.Funding[0].Vout}
	tokenId, err := ComputeTokenId(mintOutpoint, ownerPub, p.Descriptor, p.HPayload)
	if err != nil {
		return nil, err
	}
	carrier, err := LockingScriptHex(tokenId, p.Descriptor, p.HPayload, ownerPKH)
	if err != nil {
		return nil, err
	}

	b := wallet.NewBuilder()
	for _, f := range p.Funding {
		if err := b.AddP2PKHInput(f.TxID, f.Vout, f.LockingScript, f.Sats, p.OwnerKey, sighash.AllForkID); err != nil {
			return nil, fmt.Errorf("mint: funding input: %w", err)
		}
	}
	if err := b.AddOutputScript(carrier, p.DustSats); err != nil { // out 0: token
		return nil, fmt.Errorf("mint: token output: %w", err)
	}
	if p.ChangeSats > 0 { // out 1: Alice's change
		if err := b.AddP2PKHOutput(p.ChangeAddr, p.ChangeSats); err != nil {
			return nil, fmt.Errorf("mint: change output: %w", err)
		}
	}
	return &MintResult{TokenId: tokenId, LockScriptHex: carrier, Builder: b}, nil
}
