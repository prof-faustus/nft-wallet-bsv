// script.go — the Script EMISSION layer of the OP_PUSH_TX continuity
// covenant (docs/02 §2.6, docs/08 §8.4; OD-3). It assembles the locking
// and unlocking scripts opcode-by-opcode; pushtx.go provides the proven
// arithmetic the locking script reproduces on-stack.
//
// MUST NOT emit OP_RETURN (§2, I-NFT-1). The builder has no OP_RETURN path;
// CovenantLockingScript asserts the result is OP_RETURN-free.
//
// ---- Locking script, opcode-by-opcode ------------------------------------
//
// Unlocking script pushes:  <preimage> <newOwnerPKH>
// Initial stack (bottom→top): preimage, newOwnerPKH
//
// PART B — Script-enforced continuity (the spend MUST reproduce the token):
//
//	<CONST_FRONT>   ; value(8 LE)||varint(len)||identityPrefix||0x14 — all FIXED
//	OP_SWAP OP_CAT  ; CONST_FRONT || newOwnerPKH
//	<CONST_BACK>    ; 88 ac  (OP_EQUALVERIFY OP_CHECKSIG), FIXED
//	OP_CAT          ; = the byte-exact serialized successor token output (out0)
//	OP_HASH256      ; expectedHashOutputs = Hash256(out0)   [SIGHASH_SINGLE]
//	OP_SWAP OP_DUP  ; keep a copy of preimage for PART A
//	OP_SIZE 8  OP_SUB OP_SPLIT OP_DROP   ; strip trailing locktime+sighashtype (8B)
//	OP_SIZE 32 OP_SUB OP_SPLIT OP_NIP    ; take the last 32B = preimage.hashOutputs
//	OP_ROT OP_EQUALVERIFY                ; REQUIRE actual == expected (else abort)
//
// PART A — OP_PUSH_TX preimage authentication (forces the preimage genuine):
//
//	OP_HASH256                                   ; z-bytes = sighash digest
//	<reverse32> <0x00> OP_CAT OP_BIN2NUM         ; Z = big-endian integer of digest
//	<A> OP_MUL <B> OP_ADD <n> OP_MOD             ; s = (A·Z + B) mod n
//	OP_DUP <n/2> OP_GREATERTHAN OP_IF <n> OP_SWAP OP_SUB OP_ENDIF  ; low-S
//	32 OP_NUM2BIN <reverse32> <stripLeadingZeros> ; s → minimal big-endian (DER content)
//	OP_SIZE OP_2 OP_SWAP OP_CAT OP_SWAP OP_CAT    ; 02||slen||s
//	<RPART> OP_SWAP OP_CAT                         ; 02||rlen||r prepended
//	OP_SIZE <0x30> OP_SWAP OP_CAT OP_SWAP OP_CAT   ; 30||len||body
//	<0x43> OP_CAT                                  ; append SIGHASH_SINGLE|FORKID
//	<fixedPubKey> OP_CHECKSIG                      ; engine re-derives real sighash
//
// There is NO 0x6a anywhere. A defect here is a liveness failure (honest
// spend rejected), never a security failure — see pushtx.go.
package covenant

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/prof-faustus/nft-wallet-bsv/internal/bsvscript"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
)

// SighashFlag is the sighash type the covenant binds to: SIGHASH_SINGLE
// (0x03) | FORKID (0x40) = 0x43. SINGLE makes hashOutputs commit to ONLY
// the output at this input's index — so with the token at input/output
// index 0, the covenant constrains exactly its own successor output and
// leaves payment/change outputs free.
const SighashFlag = 0x43

// reverse32 emits opcodes that reverse the 32-byte string on top of the
// stack. It splits into 32 single bytes then concatenates them back in
// reverse order. Net stack effect: 1 → 1.
func reverse32(s *script.Script) {
	for i := 0; i < 31; i++ {
		_ = s.AppendOpcodes(script.Op1, script.OpSPLIT)
	}
	for i := 0; i < 31; i++ {
		_ = s.AppendOpcodes(script.OpSWAP, script.OpCAT)
	}
}

// stripOneLeadingZero removes a single leading 0x00 byte from the
// big-endian string on top, or restores it unchanged if the leading byte is
// non-zero. Net stack effect: 1 → 1.
//
// CRITICAL: the zero test is a BYTE comparison to 0x00 — NOT OP_BIN2NUM==0.
// In Script the byte 0x80 is "negative zero" (BIN2NUM(0x80)=0), so a numeric
// test would wrongly strip a significant 0x80 magnitude byte and corrupt s
// (seen as a CHECKSIG-false liveness failure on leading-zero-s spends). Byte
// equality treats 0x80 as the non-zero byte it is.
func stripOneLeadingZero(s *script.Script) {
	_ = s.AppendOpcodes(script.Op1, script.OpSPLIT) // head(1) tail
	_ = s.AppendOpcodes(script.OpSWAP)              // tail head
	_ = s.AppendOpcodes(script.OpDUP)               // tail head head
	_ = s.AppendPushData([]byte{0x00})
	_ = s.AppendOpcodes(script.OpEQUAL) // head == byte 0x00 ?
	_ = s.AppendOpcodes(script.OpIF)
	_ = s.AppendOpcodes(script.OpDROP) //   zero byte: drop it, keep tail
	_ = s.AppendOpcodes(script.OpELSE)
	_ = s.AppendOpcodes(script.OpSWAP, script.OpCAT) //   non-zero: restore head||tail
	_ = s.AppendOpcodes(script.OpENDIF)
}

// stripLeadingZeros removes up to 31 leading zero bytes — enough to reduce
// any 32-byte big-endian magnitude to its minimal MAGNITUDE. Once the
// leading byte is non-zero every further pass is a no-op.
func stripLeadingZeros(s *script.Script) {
	for i := 0; i < 31; i++ {
		stripOneLeadingZero(s)
	}
}

// derSignByte completes the minimal DER INTEGER encoding of the (stripped,
// non-empty) big-endian magnitude on top: if its leading byte has the high
// bit set, prepend a single 0x00 so it is not read as negative. Without
// this, a stripped magnitude like 00 FF .. would become FF .. — which the
// engine rejects as "S is negative".
//
// CRITICAL: the high-bit test is a BITWISE AND with 0x80 (a BYTE test) — NOT
// OP_BIN2NUM<0. A leading byte of exactly 0x80 has the high bit set yet is
// "negative zero" (BIN2NUM(0x80)=0, which is not < 0), so a numeric test
// would miss it and emit a sign-less 0x80.. that the engine reads as
// negative. AND-ing the byte with 0x80 catches the whole 0x80..0xff range.
func derSignByte(s *script.Script) {
	_ = s.AppendOpcodes(script.OpDUP)               // x x
	_ = s.AppendOpcodes(script.Op1, script.OpSPLIT) // x head tail
	_ = s.AppendOpcodes(script.OpDROP)              // x head
	_ = s.AppendPushData([]byte{0x80})
	_ = s.AppendOpcodes(script.OpAND) // x (head & 0x80)
	_ = s.AppendPushData([]byte{0x00})
	_ = s.AppendOpcodes(script.OpEQUAL) // x (high bit CLEAR?)
	_ = s.AppendOpcodes(script.OpNOT)   // x (high bit SET?)
	_ = s.AppendOpcodes(script.OpIF)
	_ = s.AppendPushData([]byte{0x00}) // x 0x00
	_ = s.AppendOpcodes(script.OpSWAP, script.OpCAT)
	_ = s.AppendOpcodes(script.OpENDIF)
}

// pushNumberLE pushes v (a non-negative big.Int) as a minimal little-endian
// signed-magnitude script number. script.AppendBigInt cannot be used: it
// pushes big-endian bytes, which the interpreter reads little-endian (wrong
// value). Used only for the large constants A, B, n, n/2.
func pushNumberLE(s *script.Script, v *big.Int) error {
	be := v.Bytes()
	le := make([]byte, len(be))
	for i := range be {
		le[i] = be[len(be)-1-i]
	}
	if len(le) > 0 && le[len(le)-1]&0x80 != 0 {
		le = append(le, 0x00) // keep positive
	}
	return s.AppendPushData(le)
}

// CovenantLockingScript builds the OP_PUSH_TX continuity covenant locking
// script for a token with the given identity, fixed to a successor token
// output value of `value` satoshis. The spender chooses only the new owner
// (supplied in the unlocking script); identity and value are immutable.
//
// Preconditions: tokenId 32, hPayload 32 bytes.
// Postconditions: canonical script bytes; never contains 0x6a.
//
//trace:impl CN-1
func CovenantLockingScript(tokenId, descriptor, hPayload []byte, value uint64) ([]byte, error) {
	c, err := constants()
	if err != nil {
		return nil, err
	}
	front, back, err := outputTemplateParts(tokenId, descriptor, hPayload, value)
	if err != nil {
		return nil, err
	}
	half := new(big.Int).Rsh(n, 1)

	s := &script.Script{}

	// ---- PART B: continuity ----
	_ = s.AppendPushData(front)
	_ = s.AppendOpcodes(script.OpSWAP, script.OpCAT)
	_ = s.AppendPushData(back)
	_ = s.AppendOpcodes(script.OpCAT)
	_ = s.AppendOpcodes(script.OpHASH256) // expectedHashOutputs
	_ = s.AppendOpcodes(script.OpSWAP, script.OpDUP)
	_ = s.AppendOpcodes(script.OpSIZE, script.Op8, script.OpSUB, script.OpSPLIT, script.OpDROP)
	_ = s.AppendOpcodes(script.OpSIZE)
	_ = s.AppendPushData([]byte{0x20}) // 32
	_ = s.AppendOpcodes(script.OpSUB, script.OpSPLIT, script.OpNIP)
	_ = s.AppendOpcodes(script.OpROT, script.OpEQUALVERIFY)

	// ---- PART A: preimage authentication ----
	_ = s.AppendOpcodes(script.OpHASH256)
	reverse32(s)
	_ = s.AppendPushData([]byte{0x00})
	_ = s.AppendOpcodes(script.OpCAT, script.OpBIN2NUM) // Z
	if err := pushNumberLE(s, c.A); err != nil {
		return nil, err
	}
	_ = s.AppendOpcodes(script.OpMUL)
	if err := pushNumberLE(s, c.B); err != nil {
		return nil, err
	}
	_ = s.AppendOpcodes(script.OpADD)
	if err := pushNumberLE(s, n); err != nil {
		return nil, err
	}
	_ = s.AppendOpcodes(script.OpMOD) // s0
	// low-S: if s > n/2 then s = n - s
	_ = s.AppendOpcodes(script.OpDUP)
	if err := pushNumberLE(s, half); err != nil {
		return nil, err
	}
	_ = s.AppendOpcodes(script.OpGREATERTHAN, script.OpIF)
	if err := pushNumberLE(s, n); err != nil {
		return nil, err
	}
	_ = s.AppendOpcodes(script.OpSWAP, script.OpSUB, script.OpENDIF)
	// s → minimal big-endian DER content
	_ = s.AppendPushData([]byte{0x20}) // 32
	_ = s.AppendOpcodes(script.OpNUM2BIN)
	reverse32(s)
	stripLeadingZeros(s)
	derSignByte(s)
	// 02 || slen || s
	_ = s.AppendOpcodes(script.OpSIZE, script.Op2, script.OpSWAP, script.OpCAT, script.OpSWAP, script.OpCAT)
	// prepend 02 || rlen || r  (constant)
	rpart := append([]byte{0x02, byte(len(c.RDER))}, c.RDER...)
	_ = s.AppendPushData(rpart)
	_ = s.AppendOpcodes(script.OpSWAP, script.OpCAT)
	// 30 || len || body
	_ = s.AppendOpcodes(script.OpSIZE)
	_ = s.AppendPushData([]byte{0x30})
	_ = s.AppendOpcodes(script.OpSWAP, script.OpCAT, script.OpSWAP, script.OpCAT)
	// append sighash flag, then CHECKSIG against the fixed pubkey
	_ = s.AppendPushData([]byte{SighashFlag})
	_ = s.AppendOpcodes(script.OpCAT)
	_ = s.AppendPushData(c.PubKey)
	_ = s.AppendOpcodes(script.OpCHECKSIG)

	out := *s
	if bsvscript.HasOpReturn(out) {
		return nil, fmt.Errorf("covenant: refusing locking script with OP_RETURN opcode (I-NFT-1)")
	}
	return out, nil
}

// CovenantUnlockingScript builds the unlocking script: <preimage> <ownerPKH>.
func CovenantUnlockingScript(preimage, newOwnerPKH []byte) ([]byte, error) {
	if len(newOwnerPKH) != 20 {
		return nil, fmt.Errorf("covenant: newOwnerPKH must be 20 bytes, got %d", len(newOwnerPKH))
	}
	s := &script.Script{}
	if err := s.AppendPushData(preimage); err != nil {
		return nil, err
	}
	if err := s.AppendPushData(newOwnerPKH); err != nil {
		return nil, err
	}
	return *s, nil
}

// outputTemplateParts returns the two CONSTANT byte runs the covenant
// concatenates around the spender-supplied 20-byte ownerPKH to reconstruct
// the serialized successor token output:
//
//	out0  = front || ownerPKH || back
//	front = value(8 LE) || varint(scriptLen) || <identity prefix> || 0x14
//	back  = 88 ac  (OP_EQUALVERIFY OP_CHECKSIG)
//
// It derives front/back by building a real carrier locking script (token
// package) with a dummy owner and slicing it, so the bytes are IDENTICAL to
// what the wallet will actually create — the hash must match byte-for-byte.
func outputTemplateParts(tokenId, descriptor, hPayload []byte, value uint64) (front, back []byte, err error) {
	dummy := make([]byte, 20)
	full, err := token.BuildLockingScript(tokenId, descriptor, hPayload, dummy)
	if err != nil {
		return nil, nil, err
	}
	if len(full) < 23 {
		return nil, nil, fmt.Errorf("covenant: carrier script too short")
	}
	ownerPushPos := len(full) - 23 // index of the 0x14 owner-push opcode
	if full[ownerPushPos] != 0x14 || !bytes.Equal(full[len(full)-2:], []byte{0x88, 0xac}) {
		return nil, nil, fmt.Errorf("covenant: unexpected carrier layout")
	}
	scriptPrefix := full[:ownerPushPos+1] // includes the 0x14 length byte
	back = []byte{0x88, 0xac}

	var b bytes.Buffer
	val := make([]byte, 8)
	for i := 0; i < 8; i++ {
		val[i] = byte(value >> (8 * i)) // little-endian
	}
	b.Write(val)
	writeVarInt(&b, uint64(len(full)))
	b.Write(scriptPrefix)
	return b.Bytes(), back, nil
}

// writeVarInt writes a Bitcoin CompactSize varint.
func writeVarInt(b *bytes.Buffer, v uint64) {
	switch {
	case v < 0xfd:
		b.WriteByte(byte(v))
	case v <= 0xffff:
		b.WriteByte(0xfd)
		b.WriteByte(byte(v))
		b.WriteByte(byte(v >> 8))
	case v <= 0xffffffff:
		b.WriteByte(0xfe)
		for i := 0; i < 4; i++ {
			b.WriteByte(byte(v >> (8 * i)))
		}
	default:
		b.WriteByte(0xff)
		for i := 0; i < 8; i++ {
			b.WriteByte(byte(v >> (8 * i)))
		}
	}
}
