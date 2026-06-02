// Package bsvscript holds low-level BSV script helpers shared across the
// wallet builder and the token module. Its reason to exist is one subtle,
// security-critical function: OP_RETURN detection that distinguishes the
// OPCODE 0x6a from a data byte 0x6a sitting inside a push.
//
// CLAUDE.md §2 bans OP_RETURN (opcode 0x6a). A NAIVE byte scan is WRONG:
// a perfectly legal P2PKH locking script `OP_DUP OP_HASH160 <20-byte
// hash> OP_EQUALVERIFY OP_CHECKSIG` can contain 0x6a *inside* the pubkey
// hash, and the push-drop token carrier embeds TokenId/descriptor/
// H(payload) pushes that may likewise contain 0x6a. Rejecting those would
// be a false positive (and was caught by CI). HasOpReturn walks the
// script opcode-by-opcode, stepping OVER push data, and flags 0x6a only
// when it appears as an opcode.
//
// Implements the structural side of I-NFT-1 (CLAUDE.md §2, docs/05 §5.2).
package bsvscript

// opReturn is the banned opcode.
const opReturn = 0x6a

// HasOpReturn reports whether script contains OP_RETURN as an opcode.
// Push data (0x01..0x4b direct, 0x4c PUSHDATA1, 0x4d PUSHDATA2,
// 0x4e PUSHDATA4) is skipped over, so a 0x6a *byte* inside a push is not
// a match. A malformed/truncated push terminates the walk (the script is
// invalid anyway) without a false positive.
func HasOpReturn(script []byte) bool {
	i := 0
	for i < len(script) {
		op := script[i]
		i++
		switch {
		case op >= 0x01 && op <= 0x4b: // direct push of op bytes
			i += int(op)
		case op == 0x4c: // OP_PUSHDATA1
			if i >= len(script) {
				return false
			}
			n := int(script[i])
			i += 1 + n
		case op == 0x4d: // OP_PUSHDATA2
			if i+1 >= len(script) {
				return false
			}
			n := int(script[i]) | int(script[i+1])<<8
			i += 2 + n
		case op == 0x4e: // OP_PUSHDATA4
			if i+3 >= len(script) {
				return false
			}
			n := int(script[i]) | int(script[i+1])<<8 | int(script[i+2])<<16 | int(script[i+3])<<24
			i += 4 + n
		case op == opReturn:
			return true
			// default: any other single-byte opcode — continue.
		}
	}
	return false
}
