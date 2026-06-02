// SV Node adapter: maps the network-agnostic chain.Adapter and
// chain.RegtestControl operations onto pinned SV Node JSON-RPC methods.
//
// Pinned RPC method map (verified live against bitcoinsv/bitcoin-sv
// 1.1.0 regtest — resolves the WS1 TODO(verify) for the regtest profile):
//
//	Broadcast          -> sendrawtransaction [hex]
//	TxStatus           -> getrawtransaction [txid, true] (.confirmations)
//	OutputStatus       -> gettxout [txid, vout] (null => spent/unknown)
//	MerkleProof        -> gettxoutproof [[txid]]
//	Tip                -> getblockcount + getbestblockhash
//	MineBlocks         -> generatetoaddress [n, addr]
//	FundAddress        -> sendtoaddress [addr, amountBSV]
//	InvalidateToHeight -> getblockhash [h+1] + invalidateblock [hash]
//	NewAddress         -> getnewaddress
//
// Implements: docs/01 §1.4 (adapter), docs/05 §5.3 (regtest control),
// CH-1 (the MerkleProof source feeding chain.VerifyMerkleProof; reorg
// awareness via Tip + InvalidateToHeight).
//
// MUST NOT: leak node-specific method names outside this package; expose
// a mine/fund primitive on the production Adapter (it is on the separate
// RegtestControl); construct any OP_RETURN (CLAUDE.md §2 — N/A here).
package svnode

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/prof-faustus/nft-wallet-bsv/internal/chain"
)

// satsPerBSV is the integer satoshi base. Money is integer satoshis
// everywhere (CLAUDE.md §5); we format BSV decimal strings only at the
// node-RPC boundary, which is the one place the node insists on it.
const satsPerBSV = 100_000_000

// Adapter implements chain.Adapter and chain.RegtestControl over SV Node.
type Adapter struct {
	rpc *rpcClient
}

// Compile-time assertions that the adapter satisfies both interfaces.
var (
	_ chain.Adapter        = (*Adapter)(nil)
	_ chain.RegtestControl = (*Adapter)(nil)
)

// New returns an SV Node adapter for the given RPC config.
func New(cfg Config) *Adapter { return &Adapter{rpc: newRPCClient(cfg)} }

// Broadcast submits a signed raw transaction. A node reject (policy or
// consensus) surfaces as a non-nil error carrying the node's reason.
func (a *Adapter) Broadcast(ctx context.Context, rawTxHex string) (string, error) {
	res, err := a.rpc.call(ctx, "sendrawtransaction", rawTxHex)
	if err != nil {
		return "", fmt.Errorf("broadcast rejected: %w", err)
	}
	var txid string
	if err := json.Unmarshal(res, &txid); err != nil {
		return "", fmt.Errorf("broadcast: decode txid: %w", err)
	}
	return txid, nil
}

// rawTxVerbose is the subset of getrawtransaction (verbose) we read.
type rawTxVerbose struct {
	Confirmations int `json:"confirmations"`
}

// TxStatus reports a transaction's settlement state. A txid the node has
// never seen is TxUnknown; this is also how the losing side of a
// double-spend appears once the winner has displaced it from the mempool
// (the caller cross-checks OutputStatus to label it a conflict — see the
// WS1 integration test).
func (a *Adapter) TxStatus(ctx context.Context, txid string) (chain.TxStatus, error) {
	res, err := a.rpc.call(ctx, "getrawtransaction", txid, true)
	if err != nil {
		if isNotFound(err) {
			return chain.TxStatus{State: chain.TxUnknown}, nil
		}
		return chain.TxStatus{}, err
	}
	var v rawTxVerbose
	if err := json.Unmarshal(res, &v); err != nil {
		return chain.TxStatus{}, fmt.Errorf("txstatus decode: %w", err)
	}
	if v.Confirmations >= 1 {
		return chain.TxStatus{State: chain.TxConfirmed, Depth: uint32(v.Confirmations)}, nil
	}
	return chain.TxStatus{State: chain.TxMempool}, nil
}

// OutputStatus reports unspent/spent/unknown for an outpoint. gettxout
// returns a UTXO entry only for an UNSPENT output; a null result means
// the output is either spent or never existed. We disambiguate by asking
// whether the funding tx is known: if the tx exists but the output is no
// longer in the UTXO set, it has been spent (the conflict/double-spend
// signal); otherwise it is unknown.
func (a *Adapter) OutputStatus(ctx context.Context, op chain.Outpoint) (chain.OutputStatus, error) {
	res, err := a.rpc.call(ctx, "gettxout", op.TxID, op.Vout, true)
	if err != nil {
		return chain.OutputStatus{}, err
	}
	if string(res) != "null" && len(res) > 0 {
		return chain.OutputStatus{State: chain.OutUnspent}, nil
	}
	// Null: spent or never existed. Distinguish via tx existence.
	if _, terr := a.rpc.call(ctx, "getrawtransaction", op.TxID, true); terr == nil {
		// SpentBy is best-effort: SV Node has no outpoint->spender index
		// by default, so we report the spend without the spender txid.
		return chain.OutputStatus{State: chain.OutSpent}, nil
	}
	return chain.OutputStatus{State: chain.OutUnknown}, nil
}

// MerkleProof returns the CMerkleBlock proof hex for a confirmed tx.
// Verify it with chain.VerifyMerkleProof — never trust it unverified.
func (a *Adapter) MerkleProof(ctx context.Context, txid string) (string, error) {
	res, err := a.rpc.call(ctx, "gettxoutproof", []string{txid})
	if err != nil {
		return "", err
	}
	var proof string
	if err := json.Unmarshal(res, &proof); err != nil {
		return "", fmt.Errorf("merkleproof decode: %w", err)
	}
	return proof, nil
}

// Tip returns the current chain tip (height + hash) for reorg awareness.
func (a *Adapter) Tip(ctx context.Context) (chain.Tip, error) {
	hRes, err := a.rpc.call(ctx, "getblockcount")
	if err != nil {
		return chain.Tip{}, err
	}
	var height uint32
	if err := json.Unmarshal(hRes, &height); err != nil {
		return chain.Tip{}, fmt.Errorf("tip height decode: %w", err)
	}
	bRes, err := a.rpc.call(ctx, "getbestblockhash")
	if err != nil {
		return chain.Tip{}, err
	}
	var hash string
	if err := json.Unmarshal(bRes, &hash); err != nil {
		return chain.Tip{}, fmt.Errorf("tip hash decode: %w", err)
	}
	return chain.Tip{Height: height, Hash: hash}, nil
}

// --- RegtestControl (regtest only; docs/05 §5.3) ---------------------------

// MineBlocks mines n blocks to a fresh wallet address.
func (a *Adapter) MineBlocks(ctx context.Context, n int) ([]string, error) {
	addr, err := a.NewAddress(ctx)
	if err != nil {
		return nil, err
	}
	res, err := a.rpc.call(ctx, "generatetoaddress", n, addr)
	if err != nil {
		return nil, err
	}
	var hashes []string
	if err := json.Unmarshal(res, &hashes); err != nil {
		return nil, fmt.Errorf("mineblocks decode: %w", err)
	}
	return hashes, nil
}

// FundAddress sends sats to addr from the node's matured coinbase
// balance. sats is integer; only the RPC boundary uses a BSV decimal.
func (a *Adapter) FundAddress(ctx context.Context, addr string, sats uint64) (string, error) {
	res, err := a.rpc.call(ctx, "sendtoaddress", addr, satsToBSV(sats))
	if err != nil {
		return "", err
	}
	var txid string
	if err := json.Unmarshal(res, &txid); err != nil {
		return "", fmt.Errorf("fundaddress decode: %w", err)
	}
	return txid, nil
}

// InvalidateToHeight forces a reorg leaving the tip at height h: it
// invalidates the block at h+1, which discards it and all descendants.
func (a *Adapter) InvalidateToHeight(ctx context.Context, h uint32) error {
	res, err := a.rpc.call(ctx, "getblockhash", h+1)
	if err != nil {
		return err
	}
	var hash string
	if err := json.Unmarshal(res, &hash); err != nil {
		return fmt.Errorf("invalidate: blockhash decode: %w", err)
	}
	if _, err := a.rpc.call(ctx, "invalidateblock", hash); err != nil {
		return err
	}
	return nil
}

// NewAddress returns a fresh node-wallet address (test funding/mining).
func (a *Adapter) NewAddress(ctx context.Context) (string, error) {
	res, err := a.rpc.call(ctx, "getnewaddress")
	if err != nil {
		return "", err
	}
	var addr string
	if err := json.Unmarshal(res, &addr); err != nil {
		return "", fmt.Errorf("newaddress decode: %w", err)
	}
	return addr, nil
}

// satsToBSV formats integer satoshis as the fixed-8dp BSV decimal string
// the node RPC expects, without floating point.
func satsToBSV(sats uint64) string {
	whole := sats / satsPerBSV
	frac := sats % satsPerBSV
	return fmt.Sprintf("%d.%08d", whole, frac)
}

// isNotFound reports whether an RPC error means "transaction unknown".
func isNotFound(err error) bool {
	var re *rpcError
	if e, ok := err.(*rpcError); ok {
		re = e
	}
	if re == nil {
		return false
	}
	// SV Node returns code -5 ("No such mempool or blockchain
	// transaction") for an unknown txid.
	return re.Code == -5 || strings.Contains(strings.ToLower(re.Message), "no such")
}
