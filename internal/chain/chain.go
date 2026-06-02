// Package chain defines the network-agnostic interfaces the protocol
// engine and wallet depend on to reach BSV, plus the regtest control
// interface the test harness uses. The engine NEVER sees a node RPC:
// node-specific code lives only in subpackages (e.g. svnode), so the
// OD-4 node choice (docs/07) is swappable behind these interfaces and
// the scenario suite is identical across it (docs/05 §5.3).
//
// Implements: docs/01 §1.4 (chain adapter interface + the operation
// table); docs/05 §5.3 (regtest control interface). SPV verification of
// returned Merkle proofs (CH-1) lives in spv.go.
//
// MUST NOT: import any BTC library or BTC network parameter (CLAUDE.md
// §1). All addresses/params/encodings are BSV, sourced from
// internal/params. No OP_RETURN is constructed here (CLAUDE.md §2).
package chain

import "context"

// Outpoint identifies a transaction output: a txid (display/reversed hex)
// and the output index.
type Outpoint struct {
	TxID string
	Vout uint32
}

// TxState is the adapter's view of a transaction's settlement status.
type TxState int

const (
	// TxUnknown: the node has never seen this txid (or it was dropped).
	TxUnknown TxState = iota
	// TxMempool: accepted, unconfirmed.
	TxMempool
	// TxConfirmed: mined; Depth carries the confirmation depth.
	TxConfirmed
	// TxConflicted: a conflicting transaction confirmed instead — this
	// txid can no longer confirm. Surfaced, never hidden (CH-1).
	TxConflicted
)

func (s TxState) String() string {
	switch s {
	case TxMempool:
		return "mempool"
	case TxConfirmed:
		return "confirmed"
	case TxConflicted:
		return "conflicted"
	default:
		return "unknown"
	}
}

// TxStatus is a transaction's status; Depth is meaningful only when
// State == TxConfirmed.
type TxStatus struct {
	State TxState
	Depth uint32
}

// OutState is the spent/unspent status of an output.
type OutState int

const (
	// OutUnspent: the output exists and is currently a UTXO.
	OutUnspent OutState = iota
	// OutSpent: the output has been spent. SpentBy carries the spender
	// txid when the adapter can determine it.
	OutSpent
	// OutUnknown: the output is not in the UTXO set and the adapter
	// cannot confirm a spender (e.g. never existed, or pruned).
	OutUnknown
)

func (s OutState) String() string {
	switch s {
	case OutUnspent:
		return "unspent"
	case OutSpent:
		return "spent"
	default:
		return "unknown"
	}
}

// OutputStatus is the result of an outputStatus query (double-spend /
// conflict detection rides on this).
type OutputStatus struct {
	State   OutState
	SpentBy string // spender txid (display hex) when known
}

// Tip is the current chain tip — the basis for reorg awareness (CH-1).
type Tip struct {
	Height uint32
	Hash   string // display hex
}

// Adapter is the only surface through which the rest of the system
// reaches the BSV network (docs/01 §1.4). Implementations are network/
// node specific; callers are not.
type Adapter interface {
	// Broadcast submits a fully-signed raw transaction (hex). On success
	// returns the txid; on policy/consensus rejection returns a non-nil
	// error whose message carries the node's reject reason.
	Broadcast(ctx context.Context, rawTxHex string) (txid string, err error)
	// TxStatus reports a transaction's settlement state + depth.
	TxStatus(ctx context.Context, txid string) (TxStatus, error)
	// OutputStatus reports whether an outpoint is unspent/spent/unknown.
	OutputStatus(ctx context.Context, op Outpoint) (OutputStatus, error)
	// MerkleProof returns the SPV Merkle proof (CMerkleBlock hex) for a
	// confirmed transaction. Verify it with VerifyMerkleProof (CH-1)
	// rather than trusting the source.
	MerkleProof(ctx context.Context, txid string) (proofHex string, err error)
	// Tip returns the current chain tip.
	Tip(ctx context.Context) (Tip, error)
}

// RegtestControl is the regtest-only control surface (docs/05 §5.3). It
// is deliberately separate from Adapter so production network code never
// gains a mine/fund primitive. The scenario suite calls only this, never
// the raw node API.
type RegtestControl interface {
	// MineBlocks mines n blocks and returns their block hashes.
	MineBlocks(ctx context.Context, n int) (blockHashes []string, err error)
	// FundAddress sends sats to addr from the node's coinbase balance,
	// returning the funding txid. sats is integer satoshis (no float
	// money — CLAUDE.md §5).
	FundAddress(ctx context.Context, addr string, sats uint64) (txid string, err error)
	// InvalidateToHeight forces a reorg by invalidating the block at
	// height h+1 (and its descendants), leaving the chain tip at h.
	InvalidateToHeight(ctx context.Context, h uint32) error
	// NewAddress returns a fresh address from the node wallet (test use).
	NewAddress(ctx context.Context) (string, error)
}
