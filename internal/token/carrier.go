// The non-OP_RETURN push-drop token carrier (docs/02 §2.3, Construction A;
// OD-5 default). Identity data rides as a push-drop prefix on the token
// output's OWN locking script; on spend the pushes are dropped before a
// standard P2PKH ownership gate runs.
//
// Locking script template (opcode-by-opcode):
//
//	<TokenId>            ; 0x20 + 32 bytes  — push identity root
//	<payloadDescriptor>  ; push descriptor bytes
//	<H(payload)>         ; 0x20 + 32 bytes  — push payload hash
//	OP_DROP OP_DROP OP_DROP  ; 0x75 0x75 0x75 — drop the 3 data pushes
//	OP_DUP               ; 0x76 — duplicate the spender's pubkey
//	OP_HASH160           ; 0xa9 — HASH160(pubkey)
//	<ownerPKH>           ; 0x14 + 20 bytes — expected owner key hash
//	OP_EQUALVERIFY       ; 0x88 — require match
//	OP_CHECKSIG          ; 0xac — verify the spender's signature
//
// There is NO 0x6a (OP_RETURN) anywhere (I-NFT-1). Historical identity is
// recoverable from transaction history, the OP_RETURN-free equivalent of
// archival recovery (docs/02 §2.3).
//
// Continuity (CN-1): this template does not, by itself, force a spender
// to reproduce the identity on the next output — Stage 1 continuity is
// CONVENTION-enforced (the wallet/indexer + the swap verifier check it),
// not Script-enforced. The OP_PUSH_TX covenant (docs/02 §2.6, OD-3) that
// would make it Script-enforced is specified but not pulled into Stage 1.
//
//trace:impl I-NFT-1 CN-1
package token

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/prof-faustus/nft-wallet-bsv/internal/bsvscript"
)

// opcodes used by the carrier.
const (
	opDrop        = 0x75
	opDup         = 0x76
	opHash160     = 0xa9
	opEqualVerify = 0x88
	opCheckSig    = 0xac
	opReturn      = 0x6a // BANNED — asserted absent (I-NFT-1)
)

// pushData emits a canonical minimal push of b (length-prefixed). It uses
// the smallest valid encoding; it NEVER emits OP_RETURN.
func pushData(buf *bytes.Buffer, b []byte) error {
	n := len(b)
	switch {
	case n < 0x4c:
		buf.WriteByte(byte(n))
	case n <= 0xff:
		buf.WriteByte(0x4c)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(0x4d)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
	default:
		return fmt.Errorf("token: push too large (%d)", n)
	}
	buf.Write(b)
	return nil
}

// readPush reads one canonical push starting at offset off, returning the
// data and the next offset. Only direct (<0x4c) and OP_PUSHDATA1/2 forms
// are accepted (what pushData emits).
func readPush(s []byte, off int) (data []byte, next int, err error) {
	if off >= len(s) {
		return nil, 0, fmt.Errorf("token: push out of range")
	}
	op := s[off]
	off++
	var n int
	switch {
	case op < 0x4c:
		n = int(op)
	case op == 0x4c:
		if off >= len(s) {
			return nil, 0, fmt.Errorf("token: short PUSHDATA1")
		}
		n = int(s[off])
		off++
	case op == 0x4d:
		if off+1 >= len(s) {
			return nil, 0, fmt.Errorf("token: short PUSHDATA2")
		}
		n = int(s[off]) | int(s[off+1])<<8
		off += 2
	default:
		return nil, 0, fmt.Errorf("token: unexpected opcode 0x%02x where a push was expected", op)
	}
	if off+n > len(s) {
		return nil, 0, fmt.Errorf("token: push body exceeds script")
	}
	return s[off : off+n], off + n, nil
}

// Identity is the recovered token identity from a carrier locking script.
type Identity struct {
	TokenId           []byte
	PayloadDescriptor []byte
	HPayload          []byte
	OwnerPKH          []byte
}

// BuildLockingScript assembles the §2.3 carrier locking script bytes.
// Preconditions: tokenId 32, hPayload 32, ownerPKH 20 bytes.
// Postconditions: returns canonical script bytes containing no 0x6a.
func BuildLockingScript(tokenId, descriptor, hPayload, ownerPKH []byte) ([]byte, error) {
	if len(tokenId) != 32 || len(hPayload) != 32 || len(ownerPKH) != 20 {
		return nil, fmt.Errorf("token: bad sizes (tokenId=%d hPayload=%d pkh=%d)", len(tokenId), len(hPayload), len(ownerPKH))
	}
	var b bytes.Buffer
	if err := pushData(&b, tokenId); err != nil {
		return nil, err
	}
	if err := pushData(&b, descriptor); err != nil {
		return nil, err
	}
	if err := pushData(&b, hPayload); err != nil {
		return nil, err
	}
	b.WriteByte(opDrop)
	b.WriteByte(opDrop)
	b.WriteByte(opDrop)
	b.WriteByte(opDup)
	b.WriteByte(opHash160)
	if err := pushData(&b, ownerPKH); err != nil {
		return nil, err
	}
	b.WriteByte(opEqualVerify)
	b.WriteByte(opCheckSig)
	out := b.Bytes()
	if bsvscript.HasOpReturn(out) {
		// Defense in depth: assert no OP_RETURN OPCODE (not a 0x6a data
		// byte inside the identity pushes) — I-NFT-1.
		return nil, fmt.Errorf("token: refusing carrier with OP_RETURN opcode (I-NFT-1)")
	}
	return out, nil
}

// LockingScriptHex is BuildLockingScript as hex.
func LockingScriptHex(tokenId, descriptor, hPayload, ownerPKH []byte) (string, error) {
	b, err := BuildLockingScript(tokenId, descriptor, hPayload, ownerPKH)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ParseLockingScript recovers the identity bytes from a carrier locking
// script, BYTE-FOR-BYTE (the basis of I-NFT-2 verification). It fails on
// any script that is not the exact §2.3 template shape.
//
//trace:impl I-NFT-2
func ParseLockingScript(s []byte) (Identity, error) {
	var id Identity
	off := 0
	var err error
	if id.TokenId, off, err = readPush(s, off); err != nil {
		return id, err
	}
	if id.PayloadDescriptor, off, err = readPush(s, off); err != nil {
		return id, err
	}
	if id.HPayload, off, err = readPush(s, off); err != nil {
		return id, err
	}
	if len(id.TokenId) != 32 || len(id.HPayload) != 32 {
		return id, fmt.Errorf("token: identity push sizes wrong")
	}
	// Expect: OP_DROP OP_DROP OP_DROP OP_DUP OP_HASH160 <push20> OP_EQUALVERIFY OP_CHECKSIG
	want := []byte{opDrop, opDrop, opDrop, opDup, opHash160}
	if off+len(want) > len(s) || !bytes.Equal(s[off:off+len(want)], want) {
		return id, fmt.Errorf("token: not a push-drop+P2PKH carrier")
	}
	off += len(want)
	if id.OwnerPKH, off, err = readPush(s, off); err != nil {
		return id, err
	}
	if len(id.OwnerPKH) != 20 {
		return id, fmt.Errorf("token: ownerPKH must be 20 bytes")
	}
	tail := []byte{opEqualVerify, opCheckSig}
	if off+len(tail) != len(s) || !bytes.Equal(s[off:], tail) {
		return id, fmt.Errorf("token: carrier tail mismatch / trailing bytes")
	}
	return id, nil
}
