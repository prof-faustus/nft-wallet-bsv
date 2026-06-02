// sim.go — an in-memory, SCRIPT-VALIDATING simulation of the BSV regtest
// node, implementing the liveAdapter interface.
//
// SIMULATION / TEST-ONLY. This is NOT a default user path and NOT a real
// chain. Its sole purpose is to let the implementer EXHAUSTIVELY test every
// option combination (every crypto-shred scheme × covenant on/off × action
// ordering × fault) hermetically and fast, without a live node. A real user
// session always runs against a real node (cmd/sidecar --rpc-url …).
//
// Crucially, it is FAITHFUL where it matters: every Broadcast is validated
// by executing each input's unlocking+locking scripts through the REAL BSV
// script interpreter (the same engine that enforces consensus script rules).
// So a P2PKH with a bad signature, or a covenant spend that strips/mutates
// the token, is REJECTED here exactly as a node would reject it — which is
// what makes the exhaustive tests meaningful.
package sidecar

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain"
)

// simUTXO is one entry in the simulation ledger.
type simUTXO struct {
	script []byte
	sats   uint64
	spent  bool
	spider string // spender txid when spent
}

// SimNode is the in-memory, script-validating simulation node.
type SimNode struct {
	mu      sync.Mutex
	mainnet bool
	height  int
	utxos   map[string]*simUTXO // "txid:vout" -> utxo
	txs     map[string][]*transaction.TransactionOutput
}

// NewSimNode builds a fresh simulation node (regtest semantics).
func NewSimNode() *SimNode {
	return &SimNode{
		utxos: map[string]*simUTXO{},
		txs:   map[string][]*transaction.TransactionOutput{},
	}
}

func opKey(txid string, vout uint32) string { return fmt.Sprintf("%s:%d", txid, vout) }

// MineBlocks advances the simulated height. Broadcasts are already
// recorded; mining only bumps the tip (the exchange uses it for confirms).
func (n *SimNode) MineBlocks(_ context.Context, blocks int) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	hashes := make([]string, blocks)
	for i := 0; i < blocks; i++ {
		n.height++
		h := make([]byte, 32)
		_, _ = rand.Read(h)
		hashes[i] = hex.EncodeToString(h)
	}
	return hashes, nil
}

// FundAddress creates a synthetic funding UTXO (one P2PKH output to addr of
// `sats`) and returns its txid. This is the user-controlled funding entry
// point; the amount is whatever the caller chose.
func (n *SimNode) FundAddress(_ context.Context, addr string, sats uint64) (string, error) {
	a, err := script.NewAddressFromString(addr)
	if err != nil {
		return "", err
	}
	ls, err := p2pkh.Lock(a)
	if err != nil {
		return "", err
	}
	// Synthesise a unique funding txid.
	idb := make([]byte, 32)
	_, _ = rand.Read(idb)
	txid := hex.EncodeToString(idb)

	n.mu.Lock()
	defer n.mu.Unlock()
	n.utxos[opKey(txid, 0)] = &simUTXO{script: *ls, sats: sats}
	n.txs[txid] = []*transaction.TransactionOutput{{Satoshis: sats, LockingScript: ls}}
	return txid, nil
}

// FindVout locates the output index of a recorded tx whose locking script
// matches lockingScriptHex.
func (n *SimNode) FindVout(_ context.Context, txid, lockingScriptHex string) (uint32, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	outs, ok := n.txs[txid]
	if !ok {
		return 0, fmt.Errorf("sim: unknown txid %s", txid)
	}
	want, err := hex.DecodeString(lockingScriptHex)
	if err != nil {
		return 0, err
	}
	for i, o := range outs {
		if o.LockingScript != nil && hex.EncodeToString(*o.LockingScript) == hex.EncodeToString(want) {
			return uint32(i), nil
		}
	}
	return 0, fmt.Errorf("sim: no output in %s matches script", txid)
}

// Broadcast parses the raw tx, VALIDATES every input through the real BSV
// script interpreter against the ledger's prevouts, and on success records
// the spends and new UTXOs. A script failure (bad sig, covenant violation)
// is rejected exactly as a node would.
func (n *SimNode) Broadcast(_ context.Context, rawTxHex string) (string, error) {
	tx, err := transaction.NewTransactionFromHex(rawTxHex)
	if err != nil {
		return "", fmt.Errorf("sim: parse tx: %w", err)
	}
	txid := tx.TxID().String()

	n.mu.Lock()
	defer n.mu.Unlock()

	// Resolve + validate every input before mutating the ledger.
	type spend struct{ key string }
	var spends []spend
	for i, in := range tx.Inputs {
		key := opKey(in.SourceTXID.String(), in.SourceTxOutIndex)
		u, ok := n.utxos[key]
		if !ok {
			return "", fmt.Errorf("sim: input %d spends unknown/absent outpoint %s", i, key)
		}
		if u.spent {
			return "", fmt.Errorf("sim: input %d double-spends %s", i, key)
		}
		prevOut := &transaction.TransactionOutput{Satoshis: u.sats, LockingScript: script.NewFromBytes(u.script)}
		// Make the preimage/sighash machinery resolve this input's prevout.
		in.SetSourceTxOutput(prevOut)
		if err := interpreter.NewEngine().Execute(
			interpreter.WithTx(tx, i, prevOut),
			interpreter.WithForkID(),
			interpreter.WithAfterGenesis(),
		); err != nil {
			return "", fmt.Errorf("sim: input %d script validation failed: %w", i, err)
		}
		spends = append(spends, spend{key})
	}

	// All inputs valid: commit.
	for _, sp := range spends {
		n.utxos[sp.key].spent = true
		n.utxos[sp.key].spider = txid
	}
	outs := make([]*transaction.TransactionOutput, len(tx.Outputs))
	for i, o := range tx.Outputs {
		outs[i] = o
		n.utxos[opKey(txid, uint32(i))] = &simUTXO{script: *o.LockingScript, sats: o.Satoshis}
	}
	n.txs[txid] = outs
	return txid, nil
}

// OutputStatus reports spent/unspent/unknown from the ledger.
func (n *SimNode) OutputStatus(_ context.Context, op chain.Outpoint) (chain.OutputStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	u, ok := n.utxos[opKey(op.TxID, op.Vout)]
	if !ok {
		return chain.OutputStatus{State: chain.OutUnknown}, nil
	}
	if u.spent {
		return chain.OutputStatus{State: chain.OutSpent, SpentBy: u.spider}, nil
	}
	return chain.OutputStatus{State: chain.OutUnspent}, nil
}

// NewAddress returns a fresh P2PKH address (a throwaway sim key).
func (n *SimNode) NewAddress(_ context.Context) (string, error) {
	k, err := ec.NewPrivateKey()
	if err != nil {
		return "", err
	}
	a, err := script.NewAddressFromPublicKey(k.PubKey(), n.mainnet)
	if err != nil {
		return "", err
	}
	return a.AddressString, nil
}
