package covenant

import (
	"crypto/rand"
	"math/big"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// The forced signature MUST verify under real secp256k1 ECDSA against the
// fixed pubkey for the message z — this is what OP_CHECKSIG will check on
// the real spending tx's sighash. If this holds for arbitrary z, the
// in-script preimage authentication is sound (the Script emission just has
// to reproduce these exact bytes).
//
//trace:test CN-1
func TestForcedSigVerifies(t *testing.T) {
	c, err := constants()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ec.PublicKeyFromBytes(c.PubKey)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		// z is the integer of a 32-byte sighash (Hash256 output).
		zb := make([]byte, 32)
		if _, err := rand.Read(zb); err != nil {
			t.Fatal(err)
		}
		z := new(big.Int).SetBytes(zb)

		der := c.ForcedSigDER(z)
		sig, err := ec.ParseDERSignature(der)
		if err != nil {
			t.Fatalf("iter %d: forced DER does not parse: %v (der=%x)", i, err, der)
		}
		// ec.Verify takes the 32-byte digest; secp256k1 uses it big-endian.
		if !sig.Verify(zb, pub) {
			t.Fatalf("iter %d: forced signature did not verify for z=%x", i, zb)
		}
	}
}

// Targeted: include z values whose forced s is SMALL (leading-zero DER) and
// whose s top byte flirts with 0x80, to exercise the minimal-DER edges that
// random sampling hits only rarely.
//
//trace:test CN-1
func TestForcedSigDEREdges(t *testing.T) {
	c, err := constants()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ec.PublicKeyFromBytes(c.PubKey)

	// Solve A·z + B ≡ targetS (mod n) for z, so we can drive s to chosen
	// edge values: z = A⁻¹·(targetS − B) mod n.
	aInv := new(big.Int).ModInverse(c.A, n)
	half := new(big.Int).Rsh(n, 1)
	targets := []*big.Int{
		big.NewInt(1),
		big.NewInt(0xff),     // 1-byte top set
		big.NewInt(0x100),    // needs 2 bytes
		big.NewInt(0x7fffff), // top byte 0x7f, no sign byte
		big.NewInt(0x800000), // top byte 0x80, DER sign byte
		new(big.Int).Set(half),
	}
	for _, ts := range targets {
		z := new(big.Int).Sub(ts, c.B)
		z.Mul(z, aInv)
		z.Mod(z, n)
		zb := make([]byte, 32)
		z.FillBytes(zb)
		der := c.ForcedSigDER(z)
		sig, err := ec.ParseDERSignature(der)
		if err != nil {
			t.Fatalf("targetS=%x: DER parse: %v (der=%x)", ts, err, der)
		}
		if !sig.Verify(zb, pub) {
			t.Fatalf("targetS=%x: did not verify", ts)
		}
	}
}

func TestDerIntMatchesEcSerialize(t *testing.T) {
	// derInt(v) must equal the integer-content of a known-good encoder.
	for _, v := range []int64{0, 1, 0x7f, 0x80, 0xff, 0x100, 0x123456} {
		got := derInt(big.NewInt(v))
		// Reference: minimal BE with sign byte rule.
		bi := big.NewInt(v)
		var want []byte
		if v == 0 {
			want = []byte{0x00}
		} else {
			want = bi.Bytes()
			if want[0]&0x80 != 0 {
				want = append([]byte{0x00}, want...)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("v=%d: len %d != %d", v, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("v=%d: byte %d mismatch", v, i)
			}
		}
	}
}
