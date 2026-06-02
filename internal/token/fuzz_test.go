package token

import (
	"math/rand"
	"testing"

	"github.com/prof-faustus/nft-wallet-bsv/internal/bsvscript"
)

// Transaction fuzzing (docs/05 §5.6): over many randomly-mutated Tx_swap
// variants, the verifier must reject EVERY deviation from the agreed
// terms (I-NFT-2 identity preserved, I-NFT-4 exact terms), and accept the
// unmutated baseline. This is the property behind the fixed near-miss
// cases in swap_test.go, generalized.
//
//trace:test I-NFT-2 I-NFT-4
func TestSwapVerifier_FuzzNearMisses(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBEEF))
	for i := 0; i < 300; i++ {
		p, exp, _, _ := baseParams(t)
		// Baseline (no mutation) must verify.
		if err := VerifySwapTx(assembledHex(t, p), exp); err != nil {
			t.Fatalf("baseline rejected: %v", err)
		}
		// Apply exactly one random term-violating mutation; it must be rejected.
		switch rng.Intn(6) {
		case 0:
			p.TokenId = flip(p.TokenId)
		case 1:
			p.HPayload = flip(p.HPayload)
		case 2:
			p.BobOwnerPKH = flip(p.BobOwnerPKH)
		case 3:
			p.PriceSats += uint64(1 + rng.Intn(1000))
		case 4:
			p.Descriptor = append([]byte{0x01}, p.Descriptor...) // changed descriptor
		case 5:
			exp.MaxOutputs = 2 // the 3-output tx is now a "surprise output"
		}
		if err := VerifySwapTx(assembledHex(t, p), exp); err == nil {
			t.Fatalf("iter %d: a term-violating swap was accepted", i)
		}
	}
}

// I-NFT-1 property: a push-drop carrier built over ANY identity bytes
// (including ones containing 0x6a) never contains an OP_RETURN OPCODE,
// and always round-trips through ParseLockingScript byte-for-byte.
//
//trace:test I-NFT-1 I-NFT-2
func TestCarrier_NoOpReturnProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(0x6A6A))
	for i := 0; i < 500; i++ {
		tokenId := randBytes(rng, 32)
		hp := randBytes(rng, 32)
		pkh := randBytes(rng, 20)
		descLen := rng.Intn(40)
		descriptor := randBytes(rng, descLen)
		s, err := BuildLockingScript(tokenId, descriptor, hp, pkh)
		if err != nil {
			t.Fatalf("iter %d build: %v", i, err)
		}
		if bsvscript.HasOpReturn(s) {
			t.Fatalf("iter %d: carrier reported OP_RETURN opcode", i)
		}
		id, err := ParseLockingScript(s)
		if err != nil {
			t.Fatalf("iter %d parse: %v", i, err)
		}
		if string(id.TokenId) != string(tokenId) || string(id.HPayload) != string(hp) ||
			string(id.OwnerPKH) != string(pkh) || string(id.PayloadDescriptor) != string(descriptor) {
			t.Fatalf("iter %d: round-trip mismatch", i)
		}
	}
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}
