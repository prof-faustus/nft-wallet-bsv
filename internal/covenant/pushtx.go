// Package covenant implements the Stage-2 OP_PUSH_TX continuity covenant
// (docs/02 §2.6, docs/08 §8.4; OD-3). It makes NFT token continuity
// Script-enforced rather than convention-enforced: a spend of the token
// UTXO is only valid if it reproduces a successor token output with
// BYTE-FOR-BYTE identical identity (TokenId, payloadDescriptor, H(payload))
// and the same token value, gated to the new owner. The NFT cannot be
// stripped to a plain output, nor its identity mutated, on transfer.
//
// Technique: the OP_PUSH_TX / "checkPreimage" pattern (plain BSV Script, NO
// OP_RETURN). The unlocking script PUSHES the sighash preimage; the locking
// script (a) authenticates that the pushed preimage is the genuine preimage
// of THE spending transaction, then (b) parses the preimage's hashOutputs
// and requires it to commit to the reconstructed successor output.
//
// (a) is the delicate part. We force authentication with a fixed key d and
// fixed nonce k: for message z = Hash256(preimage), a valid ECDSA signature
// under d is (r, s) with r = (k·G).x (CONSTANT) and
//
//	s = k⁻¹·(z + r·d) mod n = A·z + B mod n,   A = k⁻¹,  B = k⁻¹·r·d mod n.
//
// The script computes s from the pushed preimage, assembles the DER
// signature, and runs OP_CHECKSIG against the fixed pubkey d·G. OP_CHECKSIG
// RE-DERIVES the sighash of the ACTUAL spending transaction and verifies the
// signature against it; since r is fixed, the only z' that validates is the
// one we built s for — so the check passes iff the pushed preimage's hash
// equals the real transaction's sighash, i.e. the preimage is genuine.
//
// SECURITY NOTE (why a bug here is liveness, not theft): if the in-script s
// derivation or DER assembly were ever wrong, OP_CHECKSIG would simply FAIL
// (the spend is rejected). It can never make CHECKSIG accept a forged
// preimage, because ECDSA will not validate a wrong-message signature
// against the engine-recomputed sighash. The token-continuity guarantee is
// then enforced by the byte-exact hashOutputs comparison that runs only
// AFTER a successful CHECKSIG. A defect can reject an honest spend; it
// cannot let an attacker strip or mutate the token.
//
// This file (pushtx.go) is the PURE-MATH layer: it derives the fixed
// constants and provides a Go reference for the forced signature, so the
// arithmetic is proven independently of the Script emission (script.go).
//
// MUST NOT: emit OP_RETURN (§2, I-NFT-1); carry BTC assumptions (§1).
//
//trace:impl CN-1
package covenant

import (
	"fmt"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// n is the secp256k1 group order.
var n = ec.S256().N

// fixedD and fixedK are the covenant's PUBLIC, hard-coded private key and
// signing nonce. They are NOT secret and protect nothing: their only role
// is to make the forced signature computable in-script. Anyone may know
// them. They are small, fixed, non-zero scalars chosen for determinism.
// Whatever r they yield is a CONSTANT baked into the script, so its DER
// length needs no run-time handling.
var (
	fixedD = big.NewInt(2)
	fixedK = big.NewInt(3)
)

// PushTxConstants are the values the locking script bakes in.
type PushTxConstants struct {
	A      *big.Int // k⁻¹ mod n
	B      *big.Int // k⁻¹·r·d mod n
	R      *big.Int // (k·G).x mod n  — the constant signature r
	PubKey []byte   // compressed d·G — the fixed OP_CHECKSIG key
	RDER   []byte   // DER integer CONTENT of R (minimal, sign-correct)
}

// constants derives the PushTxConstants from fixedD/fixedK. It is computed
// once at init via mustConstants.
func constants() (PushTxConstants, error) {
	if fixedD.Sign() == 0 || fixedK.Sign() == 0 {
		return PushTxConstants{}, fmt.Errorf("covenant: fixed d and k must be non-zero")
	}
	// R = (k·G).x mod n.
	kBytes := make([]byte, 32)
	fixedK.FillBytes(kBytes)
	_, kPub := ec.PrivateKeyFromBytes(kBytes)
	r := new(big.Int).Mod(kPub.X, n)
	if r.Sign() == 0 {
		return PushTxConstants{}, fmt.Errorf("covenant: degenerate nonce (r=0)")
	}
	// A = k⁻¹ mod n.
	a := new(big.Int).ModInverse(fixedK, n)
	if a == nil {
		return PushTxConstants{}, fmt.Errorf("covenant: k not invertible mod n")
	}
	// B = k⁻¹·r·d mod n = A·r·d mod n.
	b := new(big.Int).Mul(a, r)
	b.Mul(b, fixedD)
	b.Mod(b, n)

	// PubKey = d·G compressed.
	dBytes := make([]byte, 32)
	fixedD.FillBytes(dBytes)
	_, dPub := ec.PrivateKeyFromBytes(dBytes)

	c := PushTxConstants{
		A:      a,
		B:      b,
		R:      r,
		PubKey: dPub.Compressed(),
		RDER:   derInt(r),
	}
	// r is a CONSTANT in the locking script, so its DER length (32 or 33
	// with a sign byte) is also constant and baked in; no run-time variation
	// to handle. Only s varies per-spend.
	return c, nil
}

// forcedS computes s = (A·z + B) mod n, then low-s normalizes it
// (s := n-s if s > n/2). The low-s result has top byte < 0x80 (s < n/2 <
// 2²⁵⁵), so its DER integer never needs a sign byte — see derInt.
func (c PushTxConstants) forcedS(z *big.Int) *big.Int {
	s := new(big.Int).Mul(c.A, z)
	s.Add(s, c.B)
	s.Mod(s, n)
	half := new(big.Int).Rsh(n, 1)
	if s.Cmp(half) > 0 {
		s.Sub(n, s)
	}
	return s
}

// ForcedSigDER returns the full DER signature (WITHOUT the trailing sighash
// flag byte) that the covenant forces for message z. This is the Go
// reference the Script emission must reproduce on-stack.
//
//	30 <len> 02 <rlen> <r> 02 <slen> <s>
func (c PushTxConstants) ForcedSigDER(z *big.Int) []byte {
	rDER := c.RDER
	sDER := derInt(c.forcedS(z))
	body := make([]byte, 0, 6+len(rDER)+len(sDER))
	body = append(body, 0x02, byte(len(rDER)))
	body = append(body, rDER...)
	body = append(body, 0x02, byte(len(sDER)))
	body = append(body, sDER...)
	out := make([]byte, 0, 2+len(body))
	out = append(out, 0x30, byte(len(body)))
	out = append(out, body...)
	return out
}

// derInt returns the minimal big-endian DER INTEGER content of a
// non-negative v: minimal magnitude, with a single 0x00 prepended iff the
// top byte has its high bit set (so it is not read as negative). For v=0 it
// returns a single 0x00 (DER's canonical zero).
//
// This is exactly reverse(scriptNumBytes(v)) for v>0 — the script-number
// sign rule and DER's sign rule coincide — which is why the Script emission
// can produce DER content simply by reversing the arithmetic result.
func derInt(v *big.Int) []byte {
	if v.Sign() == 0 {
		return []byte{0x00}
	}
	b := v.Bytes() // minimal big-endian, no leading zeros
	if b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	return b
}
