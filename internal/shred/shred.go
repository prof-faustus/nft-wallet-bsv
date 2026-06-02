// Package shred implements Stage-2 crypto-shredding as a PLUGGABLE,
// SELECTABLE set of schemes (docs/08 §8.3). Each scheme governs how the
// content key K reaches Bob (post-swap) and how Alice loses it. The
// choice is per-exchange; the owner asked for all of them + a TEE option,
// secure and robust.
//
// Honest strength (docs/08 §8.3, CLAUDE.md §4):
//   - COOPERATIVE: a retained ciphertext is useless IFF Alice destroys
//     her key material. Software on Alice's host cannot force that
//     (HH-1); the scheme makes key release single-use / swap-bound and
//     auditable, not enforced.
//   - ENFORCED: a TEE attests it released K to Bob and zeroized Alice's
//     copy. Removes the payload part of HH-1 — but requires a real
//     enclave. The implementation here is a clearly-labelled STAND-IN.
//
// Invariants: I-CS-1 (ciphertext useless without K; not recoverable from
// ciphertext+binding alone), I-CS-2 (post-swap Bob can always open),
// I-CS-3 (enforced shred is attested, cooperative is not).
//
//trace:impl I-CS-1 I-CS-2
package shred

import (
	"crypto/sha256"
	"fmt"
	"sort"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Strength classifies a scheme's shred guarantee.
type Strength string

const (
	Cooperative Strength = "cooperative"
	Enforced    Strength = "enforced"
)

// Sealed is what Bob holds AFTER the swap — everything needed to recover
// the payload. (For schemes whose binding is revealed by the swap, the
// post-swap view includes that material.)
type Sealed struct {
	Scheme      string
	Ciphertext  []byte // AEAD(K, payload), or AEAD(KEK, payload) for reencrypt
	WrappedKey  []byte // AEAD(KEK, K) for ecdh/tee; empty otherwise
	EphPub      []byte // ephemeral pubkey (ecdh/reencrypt/tee)
	Surrender   []byte // secret revealed by the swap (key-surrender)
	EnclavePub  []byte // tee-attested: the (stand-in) enclave pubkey
	Attestation []byte // tee-attested: DER sig over the release/zeroize statement
}

// SellerSecret is what Alice must SHRED. Shred() nils the recovery path
// and zeroizes captured key bytes; afterwards TryOpen fails (I-CS-1).
type SellerSecret struct {
	zeroize []func()
	recover func(*Sealed) ([]byte, error)
}

// Shred destroys Alice's ability to recover the payload.
func (s *SellerSecret) Shred() {
	for _, z := range s.zeroize {
		z()
	}
	s.zeroize = nil
	s.recover = nil
}

// TryOpen models Alice opening her RETAINED ciphertext with her retained
// secret. Before Shred it may succeed; after Shred it must fail — that is
// the crypto-shred property (I-CS-1).
func (s *SellerSecret) TryOpen(sealed *Sealed) ([]byte, error) {
	if s.recover == nil {
		return nil, fmt.Errorf("shred: seller key material destroyed — ciphertext is now useless")
	}
	return s.recover(sealed)
}

// Scheme is a pluggable crypto-shred strategy.
type Scheme interface {
	Name() string
	Strength() Strength
	// Seal: Alice encrypts payload for Bob; returns Bob's post-swap view
	// and Alice's shreddable secret.
	Seal(payload []byte, bobPub *ec.PublicKey) (*Sealed, *SellerSecret, error)
	// Open: Bob recovers the payload post-swap using his key + Sealed.
	Open(sealed *Sealed, bobPriv *ec.PrivateKey) ([]byte, error)
}

// --- registry -------------------------------------------------------------

// DefaultScheme is the recommended default (docs/08 §8.3).
const DefaultScheme = "ecdh-singleuse"

var registry = map[string]func() Scheme{
	"ecdh-singleuse": func() Scheme { return ecdhSingleUse{} },
	"key-surrender":  func() Scheme { return keySurrender{} },
	"reencrypt":      func() Scheme { return reencrypt{} },
	"tee-attested":   func() Scheme { return teeAttested{} },
}

// ForName returns the scheme by id.
func ForName(name string) (Scheme, error) {
	c, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("shred: unknown scheme %q (have %v)", name, Names())
	}
	return c(), nil
}

// Names lists the available scheme ids (sorted).
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func kdf(tag string, b []byte) []byte {
	h := sha256.Sum256(append([]byte(tag), b...))
	return h[:]
}
