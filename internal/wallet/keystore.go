// Package wallet is the wallet core (docs/01 §1.2, docs/06 WS2): key
// management + software custody (SC-1), UTXO tracking + coin selection,
// and a general full-Script transaction builder (builder.go).
//
// Implements: docs/06 WS2; SC-1 (software key custody).
// Assumptions/trust: SC-1 — keys are held in SOFTWARE custody. This file
// is the explicit Stage-1 stand-in for a TEE (HH-1, docs/04 §4.6): an
// honest host that does not exfiltrate its own keys. It is NOT
// hardware-backed and is NOT a confidentiality guarantee — labelled so
// here and everywhere SC-1 surfaces (CLAUDE.md §4 honesty).
//
// MUST NOT: log private key material (docs/01 §1.5 log gate); construct
// OP_RETURN (CLAUDE.md §2 — see builder.go); import BTC libs (CLAUDE.md
// §1). Keys/signing use the BSV Go SDK.
//
// Production note: on Windows the production sidecar backs this with the
// OS keystore / DPAPI (docs/01 §1.5); the portable encrypted-file backend
// here (scrypt + AES-256-GCM) is what runs cross-platform and under CI,
// and is the testable SC-1 reference. The DPAPI backend is a
// windows-tagged drop-in added with the WS7 packaging.
package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"golang.org/x/crypto/scrypt"
)

// Keystore is software key custody (SC-1). Implementations never expose
// raw key bytes through a logging path; callers request signing via the
// returned *ec.PrivateKey held only in memory.
//
//trace:impl SC-1
type Keystore interface {
	// Put stores a private key under a label, persisting encrypted.
	Put(label string, key *ec.PrivateKey) error
	// Get returns the private key for a label (in-memory only).
	Get(label string) (*ec.PrivateKey, error)
	// List returns the stored labels (never the keys).
	List() []string
}

// scrypt parameters (named, no magic numbers — docs/06 §6.6). These are
// the interactive-login class parameters; sized for a desktop wallet.
const (
	scryptN      = 1 << 15 // CPU/memory cost
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32 // AES-256
	saltLen      = 16
)

// FileKeystore is the portable, encrypted-file software keystore (SC-1).
// The whole store is sealed under one passphrase-derived key.
type FileKeystore struct {
	mu   sync.Mutex
	path string
	dk   []byte            // derived AES key (in memory)
	keys map[string]string // label -> priv hex (in memory)
}

// OpenFileKeystore opens (or creates) an encrypted keystore at path,
// unlocked with passphrase. A wrong passphrase on an existing store fails
// with an authentication error rather than returning garbage keys.
//
// Preconditions: passphrase non-empty.
// Postconditions: returns an unlocked store; new stores are empty.
// Errors: bad passphrase (GCM auth fail), corrupt file, IO.
func OpenFileKeystore(path, passphrase string) (*FileKeystore, error) {
	if passphrase == "" {
		return nil, errors.New("keystore: empty passphrase")
	}
	ks := &FileKeystore{path: path, keys: map[string]string{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// New store: derive a key against a fresh salt, persist empty.
		salt := make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		dk, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
		if err != nil {
			return nil, err
		}
		ks.dk = dk
		if err := ks.persist(salt); err != nil {
			return nil, err
		}
		return ks, nil
	}
	if err != nil {
		return nil, err
	}
	var blob storeBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("keystore: corrupt store: %w", err)
	}
	dk, err := scrypt.Key([]byte(passphrase), blob.Salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	plain, err := gcmOpen(dk, blob.Nonce, blob.Cipher)
	if err != nil {
		return nil, fmt.Errorf("keystore: unlock failed (wrong passphrase?): %w", err)
	}
	if err := json.Unmarshal(plain, &ks.keys); err != nil {
		return nil, fmt.Errorf("keystore: corrupt payload: %w", err)
	}
	ks.dk = dk
	return ks, nil
}

type storeBlob struct {
	Salt   []byte `json:"salt"`
	Nonce  []byte `json:"nonce"`
	Cipher []byte `json:"cipher"`
}

// Put stores key under label and re-seals the store.
func (k *FileKeystore) Put(label string, key *ec.PrivateKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[label] = key.Hex()
	// Re-read salt to keep it stable across writes.
	salt, err := k.currentSalt()
	if err != nil {
		return err
	}
	return k.persist(salt)
}

// Get returns the private key for label.
func (k *FileKeystore) Get(label string) (*ec.PrivateKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	h, ok := k.keys[label]
	if !ok {
		return nil, fmt.Errorf("keystore: no key %q", label)
	}
	return ec.PrivateKeyFromHex(h)
}

// List returns stored labels (never key material).
func (k *FileKeystore) List() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]string, 0, len(k.keys))
	for l := range k.keys {
		out = append(out, l)
	}
	return out
}

func (k *FileKeystore) currentSalt() ([]byte, error) {
	raw, err := os.ReadFile(k.path)
	if err != nil {
		return nil, err
	}
	var blob storeBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, err
	}
	return blob.Salt, nil
}

func (k *FileKeystore) persist(salt []byte) error {
	plain, err := json.Marshal(k.keys)
	if err != nil {
		return err
	}
	nonce, ciphertext, err := gcmSeal(k.dk, plain)
	if err != nil {
		return err
	}
	out, err := json.Marshal(storeBlob{Salt: salt, Nonce: nonce, Cipher: ciphertext})
	if err != nil {
		return err
	}
	// 0600: owner-only. Best-effort on Windows (SC-1 honesty note above).
	return os.WriteFile(k.path, out, 0o600)
}

func gcmSeal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, plaintext, nil), nil
}

func gcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ciphertext, nil)
}
