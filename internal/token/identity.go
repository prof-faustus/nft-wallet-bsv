// Package token implements the NFT object + transaction model (docs/02):
// the non-OP_RETURN push-drop carrier (§2.3), mint (§2.4), the atomic
// swap (§2.5) and its verifier, and token-status queries. It is the
// Stage-1 token rail on top of the WS2 wallet/builder and WS1 chain
// adapter.
//
// Implements: docs/02 §2.2 (identity), §2.3 (carrier), §2.4 (mint),
// §2.5 (swap). Invariants I-NFT-1..5.
// MUST NOT: emit OP_RETURN (I-NFT-1, CLAUDE.md §2) — the carrier is
// push-drop; import BTC (I-NFT-5/CLAUDE.md §1).
//
// This file: token identity (docs/02 §2.2). Canonical, deterministic
// serialization — ambiguous encoding is a defect (docs/02 §2.2). All
// hashes are BSV double-SHA-256.
package token

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // HASH160 = RIPEMD160(SHA256) is the consensus primitive
)

// EncScheme records how the payload bytes are protected. Stage 1 uses the
// placeholder scheme; Stage 2 swaps in real encryption WITHOUT changing
// the binding mechanism (docs/02 §2.2) — only this byte and the hashed
// bytes change.
type EncScheme uint8

const (
	// EncPlaceholderV1 is the Stage-1 placeholder "encryption" (docs/00
	// §0.2: payload confidentiality is NOT provided in Stage 1, PL-1).
	EncPlaceholderV1 EncScheme = 0
)

// descriptorVersion is the canonical payloadDescriptor format version.
const descriptorVersion uint8 = 1

// PayloadDescriptor is the canonical metadata bound into the token
// identity (docs/02 §2.2: { version, contentType, length, encScheme }).
type PayloadDescriptor struct {
	ContentType string
	Length      uint64
	EncScheme   EncScheme
}

// Bytes is the ONE canonical serialization of a PayloadDescriptor
// (docs/02 §2.2 "define it once"):
//
//	version:u8 || encScheme:u8 || length:u64LE || ctLen:u8 || contentType
//
// Preconditions: len(ContentType) <= 255.
// Postconditions: deterministic; identical descriptors -> identical bytes.
func (d PayloadDescriptor) Bytes() ([]byte, error) {
	if len(d.ContentType) > 255 {
		return nil, fmt.Errorf("token: contentType too long (%d > 255)", len(d.ContentType))
	}
	out := make([]byte, 0, 2+8+1+len(d.ContentType))
	out = append(out, descriptorVersion, byte(d.EncScheme))
	var l8 [8]byte
	binary.LittleEndian.PutUint64(l8[:], d.Length)
	out = append(out, l8[:]...)
	out = append(out, byte(len(d.ContentType)))
	out = append(out, []byte(d.ContentType)...)
	return out, nil
}

// sha256d is the BSV double-SHA-256.
func sha256d(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

// hash160 = RIPEMD160(SHA256(b)) — the public-key-hash primitive.
func hash160(b []byte) []byte {
	s := sha256.Sum256(b)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}

// HashPayload binds the off-chain file to the token: H(payload) =
// double-SHA-256 of the (Stage 1: placeholder-encrypted) payload bytes
// (docs/02 §2.2).
func HashPayload(payload []byte) []byte { return sha256d(payload) }

// Outpoint is a mint/spend reference (display txid hex + vout).
type Outpoint struct {
	TxID string
	Vout uint32
}

// internalBytes returns the outpoint as 32-byte internal txid || vout LE.
func (o Outpoint) internalBytes() ([]byte, error) {
	disp, err := hex.DecodeString(o.TxID)
	if err != nil || len(disp) != 32 {
		return nil, fmt.Errorf("token: bad outpoint txid %q", o.TxID)
	}
	internal := make([]byte, 32)
	for i := 0; i < 32; i++ {
		internal[i] = disp[31-i] // display -> internal byte order
	}
	var v4 [4]byte
	binary.LittleEndian.PutUint32(v4[:], o.Vout)
	return append(internal, v4[:]...), nil
}

// ComputeTokenId fixes the token identity at mint (docs/02 §2.2):
//
//	TokenId = H( mintOutpoint || ownerPubKey_at_mint || descriptor || H(payload) )
//
// where H is double-SHA-256 and mintOutpoint is internal txid || vout LE.
// Preconditions: ownerPubKey is the 33-byte compressed key; hPayload is 32.
//
//trace:impl I-NFT-2
func ComputeTokenId(mint Outpoint, ownerPubKey, descriptor, hPayload []byte) ([]byte, error) {
	op, err := mint.internalBytes()
	if err != nil {
		return nil, err
	}
	if len(hPayload) != 32 {
		return nil, fmt.Errorf("token: H(payload) must be 32 bytes, got %d", len(hPayload))
	}
	pre := make([]byte, 0, len(op)+len(ownerPubKey)+len(descriptor)+len(hPayload))
	pre = append(pre, op...)
	pre = append(pre, ownerPubKey...)
	pre = append(pre, descriptor...)
	pre = append(pre, hPayload...)
	return sha256d(pre), nil
}
