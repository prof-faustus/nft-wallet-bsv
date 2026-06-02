// Package params is the SINGLE source of BSV network parameters for the
// whole project (docs/01 §1.4 network-params module; docs/00 §0.6
// network modes). Address encoding, network magic, and default P2P ports
// resolve here and ONLY here.
//
// Implements: docs/01 §1.4 (single network-params module); docs/00
// network modes (regtest/testnet/mainnet).
// Invariants preserved: the `bsv-only` gate (docs/05 §5.2) requires that
// no second, divergent source of network constants exists and that no
// address-version byte / magic / port is hard-coded elsewhere. Keeping
// every such constant in this one file is what makes that gate truthful.
//
// MUST NOT:
//   - import or mirror any BTC chainparams (no bitcoinjs/btcd/rust-bitcoin
//     values copied in). BSV and BTC share no codebase here (CLAUDE.md §1).
//   - introduce SegWit/Taproot/bech32 ("bc1") assumptions — BSV has none.
//   - carry an OP_RETURN data model (CLAUDE.md §2; not relevant here, but
//     the prohibition is project-wide).
//
// Provenance / verification: the version/port values below are the
// well-known BSV values; the 4-byte P2P message-start "magic" values are
// marked TODO(verify) because they MUST be confirmed against the pinned
// SV Node chainparams build rather than assumed from BTC tooling
// (CLAUDE.md §8). Nothing here is load-bearing for Stage 1 settlement
// until WS1 wires the chain adapter against the running node.
package params

import "fmt"

// Network is the selected BSV chain mode. Selected once, at process
// start, and threaded through; never re-derived ad hoc.
type Network string

const (
	// Regtest is the local, ephemeral private chain — the primary Stage 1
	// proving ground (docs/05 §5.3). Block-on-demand + forced reorg.
	Regtest Network = "regtest"
	// Testnet is the public BSV test chain.
	Testnet Network = "testnet"
	// Mainnet is live BSV.
	Mainnet Network = "mainnet"
)

// Params holds the network-specific constants. All BSV. No BTC values.
type Params struct {
	// Net is the mode these params describe.
	Net Network
	// P2PKHVersion is the address version byte prepended to a HASH160
	// before Base58Check for a pay-to-pubkey-hash address. BSV inherits
	// the legacy Base58 scheme (no bech32).
	P2PKHVersion byte
	// P2SHVersion is the pay-to-script-hash address version byte.
	P2SHVersion byte
	// WIFVersion is the Wallet Import Format private-key version byte.
	WIFVersion byte
	// MagicMessageStart is the 4-byte P2P protocol message-start prefix
	// ("pchMessageStart"). TODO(verify): confirm against the pinned SV
	// Node build's chainparams — do NOT assume BTC values.
	MagicMessageStart [4]byte
	// DefaultP2PPort is the default peer-to-peer port for this network.
	DefaultP2PPort uint16
}

var (
	// mainnet — BSV live network.
	mainnet = Params{
		Net:          Mainnet,
		P2PKHVersion: 0x00, // BSV mainnet P2PKH (Base58 leading '1')
		P2SHVersion:  0x05, // BSV mainnet P2SH (Base58 leading '3')
		WIFVersion:   0x80, // BSV mainnet WIF
		// TODO(verify): SV Node mainnet pchMessageStart (BSV forked BCH;
		// confirm bytes against the pinned chainparams, not BTC's f9beb4d9).
		MagicMessageStart: [4]byte{0xe3, 0xe1, 0xf3, 0xe8},
		DefaultP2PPort:    8333,
	}
	// testnet — BSV public test network.
	testnet = Params{
		Net:          Testnet,
		P2PKHVersion: 0x6f,
		P2SHVersion:  0xc4,
		WIFVersion:   0xef,
		// TODO(verify): SV Node testnet pchMessageStart.
		MagicMessageStart: [4]byte{0xf4, 0xe5, 0xf3, 0xf4},
		DefaultP2PPort:    18333,
	}
	// regtest — local private chain.
	regtest = Params{
		Net:          Regtest,
		P2PKHVersion: 0x6f, // regtest shares the testnet address scheme
		P2SHVersion:  0xc4,
		WIFVersion:   0xef,
		// TODO(verify): SV Node regtest pchMessageStart (commonly dab5bffa).
		MagicMessageStart: [4]byte{0xda, 0xb5, 0xbf, 0xfa},
		DefaultP2PPort:    18444,
	}
)

// For returns the parameters for a network mode.
//
// Preconditions: net is one of Regtest/Testnet/Mainnet.
// Postconditions: returns the single canonical Params for that mode.
// Errors: returns a non-nil error for an unknown mode rather than
// guessing — an unknown network must never silently fall back to a
// different chain's parameters.
func For(net Network) (Params, error) {
	switch net {
	case Mainnet:
		return mainnet, nil
	case Testnet:
		return testnet, nil
	case Regtest:
		return regtest, nil
	default:
		return Params{}, fmt.Errorf("params: unknown network %q (want regtest|testnet|mainnet)", net)
	}
}

// MustFor is For for callers that have already validated the mode (e.g.
// a constant). It panics on an unknown mode — use only with a literal.
func MustFor(net Network) Params {
	p, err := For(net)
	if err != nil {
		panic(err)
	}
	return p
}
