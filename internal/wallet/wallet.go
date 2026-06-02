// Wallet core: key management, UTXO tracking, coin selection, and fee
// policy (docs/01 §1.2, docs/06 WS2). Money is integer satoshis
// throughout (CLAUDE.md §5); fees come from the single fixtures source
// (fixtures.FEE_RATE), never an inline literal (docs/06 §6.6).
//
// Implements: docs/06 WS2. Uses SC-1 custody (keystore.go).
package wallet

import (
	"errors"
	"fmt"
	"sort"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/prof-faustus/nft-wallet-bsv/internal/fixtures"
	"github.com/prof-faustus/nft-wallet-bsv/internal/params"
)

// UTXO is a spendable output this wallet tracks (docs/01 §1.5 chain cache).
type UTXO struct {
	TxID          string // display hex
	Vout          uint32
	Sats          fixtures.Satoshis
	LockingScript string // hex
	KeyLabel      string // keystore label that can spend it (P2PKH)
}

// Wallet holds keys (via the keystore) and a tracked UTXO set for one
// network. It is non-custodial and local (docs/01 §1.1).
type Wallet struct {
	ks    Keystore
	net   params.Network
	utxos []UTXO
}

// New builds a wallet over a keystore for a network.
func New(ks Keystore, net params.Network) *Wallet {
	return &Wallet{ks: ks, net: net}
}

func (w *Wallet) mainnet() bool { return w.net == params.Mainnet }

// NewKey generates a fresh key, stores it under label, and returns its
// P2PKH address string.
func (w *Wallet) NewKey(label string) (string, error) {
	k, err := ec.NewPrivateKey()
	if err != nil {
		return "", err
	}
	if err := w.ks.Put(label, k); err != nil {
		return "", err
	}
	return w.AddressFor(label)
}

// AddressFor returns the P2PKH address for a stored key.
func (w *Wallet) AddressFor(label string) (string, error) {
	k, err := w.ks.Get(label)
	if err != nil {
		return "", err
	}
	addr, err := script.NewAddressFromPublicKey(k.PubKey(), w.mainnet())
	if err != nil {
		return "", err
	}
	return addr.AddressString, nil
}

// Key returns the private key for a label (for signing via the builder).
func (w *Wallet) Key(label string) (*ec.PrivateKey, error) { return w.ks.Get(label) }

// TrackUTXO records a spendable output.
func (w *Wallet) TrackUTXO(u UTXO) { w.utxos = append(w.utxos, u) }

// UTXOs returns a copy of the tracked set.
func (w *Wallet) UTXOs() []UTXO {
	out := make([]UTXO, len(w.utxos))
	copy(out, w.utxos)
	return out
}

// Balance is the sum of tracked UTXO values.
func (w *Wallet) Balance() fixtures.Satoshis {
	var s fixtures.Satoshis
	for _, u := range w.utxos {
		s += u.Sats
	}
	return s
}

// CoinSelect greedily selects UTXOs covering target, largest-first, and
// returns the chosen set and their total. Deterministic given the set.
//
// Preconditions: target > 0.
// Postconditions: sum(selected) >= target, or an "insufficient funds"
// error naming the shortfall.
func (w *Wallet) CoinSelect(target fixtures.Satoshis) (selected []UTXO, total fixtures.Satoshis, err error) {
	if target == 0 {
		return nil, 0, errors.New("wallet: zero target")
	}
	cand := w.UTXOs()
	sort.Slice(cand, func(i, j int) bool { return cand[i].Sats > cand[j].Sats })
	for _, u := range cand {
		selected = append(selected, u)
		total += u.Sats
		if total >= target {
			return selected, total, nil
		}
	}
	return nil, total, fmt.Errorf("wallet: insufficient funds (have %d, need %d)", total, target)
}

// EstimateFee returns the fee for a transaction of the given serialized
// size, from the single fee-policy source (fixtures.FEE_RATE, sat/byte).
func EstimateFee(sizeBytes int) fixtures.Satoshis {
	if sizeBytes < 0 {
		sizeBytes = 0
	}
	return fixtures.FEE_RATE * fixtures.Satoshis(sizeBytes)
}
