// Package crypto holds the Stage-2 real-encryption primitives (docs/08
// §8.2): AES-256-GCM authenticated encryption + secp256k1 ECDH key
// agreement (BSV Go SDK). These are the building blocks the crypto-shred
// schemes (internal/shred) compose; they replace the Stage-1 placeholder.
//
// MUST NOT: import BTC; roll a bespoke cipher. AEAD is AES-256-GCM
// (stdlib); the curve is the SDK's secp256k1.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// KeyLen is the AES-256 content-key length.
const KeyLen = 32

// NewContentKey returns a fresh random 256-bit content key.
func NewContentKey() ([]byte, error) {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// AEADSeal encrypts plaintext under a 32-byte key with AES-256-GCM,
// returning nonce||ciphertext (the nonce is random, 12 bytes).
//
// Preconditions: len(key) == 32.
func AEADSeal(key, plaintext []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, nil), nil
}

// AEADOpen reverses AEADSeal. A tampered blob or wrong key fails the GCM
// authentication and returns an error (never silent garbage).
func AEADOpen(key, blob []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	ns := g.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	return g.Open(nil, blob[:ns], blob[ns:], nil)
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ECDHKey derives a symmetric 32-byte key from an ECDH shared secret
// between priv and pub, hashed for domain separation. It is symmetric:
// ECDHKey(a, B) == ECDHKey(b, A).
func ECDHKey(priv *ec.PrivateKey, pub *ec.PublicKey) ([]byte, error) {
	shared, err := priv.DeriveSharedSecret(pub)
	if err != nil {
		return nil, fmt.Errorf("crypto: ECDH: %w", err)
	}
	h := sha256.Sum256(append([]byte("nftbsv/ecdh/v1"), shared.Compressed()...))
	return h[:], nil
}
