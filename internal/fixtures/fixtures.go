// Package fixtures is the SINGLE source of economic + timing constants
// for the project (docs/02 §2.8 "named constants, no magic numbers";
// docs/03 §3.6 timeouts). Per docs/06 §6.6, NO inline numeric literal for
// any of these may appear anywhere else in the codebase — every dust
// value, fee rate, timeout, confirmation depth, and funding amount
// resolves here. The `lint/format` gate + review enforce that.
//
// Implements: docs/02 §2.8 (DUST_SATS, FEE_RATE); docs/03 §3.6
// (T_pair/T_deliver/T_sign/T_confirm/CONF_DEPTH); docs/05 §5.3
// (deterministic funding amounts).
// Invariants: money is integer satoshis — there is no floating-point
// money type in this package or anywhere it feeds (docs/06 / CLAUDE.md
// §5 determinism).
//
// MUST NOT: hard-code a BTC fee market, BTC dust policy, or BTC dust
// constant. Dust on BSV is a node-policy value, not BTC's 546.
//
// Verification: the exact numeric values of DUST_SATS and FEE_RATE are
// node-policy and are marked TODO(verify) — they MUST be read from the
// pinned SV Node policy at Pre-flight/WS1, not assumed (CLAUDE.md §8).
// The placeholders below are clearly labelled and exist so dependent
// code compiles and references the single source; WS1 pins the real
// values against the running node and removes the TODO markers.
package fixtures

import "time"

// Satoshis is an integer satoshi amount. No floating point in money
// arithmetic (CLAUDE.md §5). 1 BSV = 100_000_000 satoshis.
type Satoshis uint64

const (
	// DUST_SATS is the value carried by the token (NFT) UTXO — the
	// minimum a 1-output is allowed to hold under node relay policy
	// (docs/00 §0.3 "1-satoshi (dust) UTXO"; docs/02 §2.1/§2.8).
	//
	// TODO(verify): read the dust threshold from the pinned SV Node
	// policy (`getnetworkinfo`/policy) at WS1 and replace this
	// placeholder. BSV dust policy is NOT BTC's 546-sat rule.
	DUST_SATS Satoshis = 1

	// FEE_RATE is the fee in satoshis per byte used by the single
	// fee-policy module (docs/02 §2.8).
	//
	// TODO(verify): pin against the running node's minimum relay fee at
	// WS1. BSV fee economics are not BTC's; do not carry a BTC fee market.
	FEE_RATE Satoshis = 1

	// FUND_ALICE_SATS / FUND_BOB_SATS are the deterministic regtest
	// funding amounts (docs/05 §5.3 "named amounts from a fixtures
	// file"). Alice mints + holds the NFT; Bob holds the payment funds.
	FUND_ALICE_SATS Satoshis = 100_000_000 // 1 BSV
	FUND_BOB_SATS   Satoshis = 100_000_000 // 1 BSV
)

// Confirmation policy.
const (
	// CONF_DEPTH is the block depth at which a swap is treated as
	// CONFIRMED (docs/03 §3.5/§3.6). Below this depth the UI says
	// "pending", never "confirmed" (docs/03 §3.5; WS7 honesty rule).
	//
	// TODO(verify): confirm the Stage 1 default depth with the owner;
	// the value below is the working default, sourced here only.
	CONF_DEPTH uint32 = 1
)

// Protocol timeouts (docs/03 §3.6). Each is the single source for its
// constant. These are working defaults; T_sign == the abandon window Δ.
//
// TODO(verify): confirm the exact durations with docs/03 §3.6 at WS5;
// they are named here so WS5's state machine never inlines a literal.
const (
	T_pair    = 60 * time.Second  // PAIRING completion deadline
	T_deliver = 300 * time.Second // payload delivery deadline
	T_sign    = 120 * time.Second // co-signing deadline (= abandon window Δ)
	T_confirm = 600 * time.Second // wait-for-CONF_DEPTH deadline
)
