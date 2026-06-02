// mint.go — minting a token directly under the OP_PUSH_TX continuity
// covenant (instead of the plain push-drop carrier). The TokenId is derived
// identically to a carrier mint (token.ComputeTokenId over the funding
// outpoint + owner pubkey + descriptor + H(payload)), so identity is
// independent of whether the lock is a carrier or a covenant. out 0 is the
// covenant locking script at `tokenValue`; out 1 is the seller's change.
//
// MUST NOT emit OP_RETURN (§2) — output scripts go through the wallet
// builder, which rejects 0x6a.
package covenant

import (
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

// MintCovenantParams specify a covenant mint.
type MintCovenantParams struct {
	Funding    []token.FundingInput
	OwnerKey   *ec.PrivateKey // seller; signs the funding inputs + fixes TokenId
	Descriptor []byte
	HPayload   []byte
	TokenValue uint64 // out 0 value; the covenant fixes the successor to this
	ChangeAddr string
	ChangeSats uint64
}

// MintCovenantResult mirrors token.MintResult but the lock is the covenant.
type MintCovenantResult struct {
	TokenId       []byte
	LockScriptHex string // the covenant locking script
	Builder       *wallet.Builder
}

// MintCovenant assembles the mint transaction whose out 0 is the covenant
// lock. The builder is returned unsigned; the caller calls Sign() to sign
// the seller's funding inputs.
//
//trace:impl CN-1
func MintCovenant(p MintCovenantParams) (*MintCovenantResult, error) {
	if len(p.Funding) == 0 {
		return nil, fmt.Errorf("covenant-mint: no funding inputs")
	}
	if p.OwnerKey == nil {
		return nil, fmt.Errorf("covenant-mint: nil owner key")
	}
	ownerPub := p.OwnerKey.PubKey().Compressed()
	mintOutpoint := token.Outpoint{TxID: p.Funding[0].TxID, Vout: p.Funding[0].Vout}
	tokenId, err := token.ComputeTokenId(mintOutpoint, ownerPub, p.Descriptor, p.HPayload)
	if err != nil {
		return nil, err
	}
	cov, err := CovenantLockingScript(tokenId, p.Descriptor, p.HPayload, p.TokenValue)
	if err != nil {
		return nil, err
	}
	covHex := hex.EncodeToString(cov)

	b := wallet.NewBuilder()
	for _, f := range p.Funding {
		if err := b.AddP2PKHInput(f.TxID, f.Vout, f.LockingScript, f.Sats, p.OwnerKey, sighash.AllForkID); err != nil {
			return nil, fmt.Errorf("covenant-mint: funding input: %w", err)
		}
	}
	if err := b.AddOutputScript(covHex, p.TokenValue); err != nil { // out 0: covenant token
		return nil, fmt.Errorf("covenant-mint: token output: %w", err)
	}
	if p.ChangeSats > 0 { // out 1: change
		if err := b.AddP2PKHOutput(p.ChangeAddr, p.ChangeSats); err != nil {
			return nil, fmt.Errorf("covenant-mint: change output: %w", err)
		}
	}
	return &MintCovenantResult{TokenId: tokenId, LockScriptHex: covHex, Builder: b}, nil
}
