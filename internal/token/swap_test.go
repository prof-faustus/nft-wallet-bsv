package token

import (
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

const bobKeyHex = "2222222222222222222222222222222222222222222222222222222222222222"

var dummyTokenPrev = "cd" + strings.Repeat("00", 31)
var dummyPayPrev = "ef" + strings.Repeat("00", 31)

func keys(t *testing.T) (alice, bob *ec.PrivateKey) {
	t.Helper()
	a, _ := ec.PrivateKeyFromHex(aliceKeyHex)
	b, _ := ec.PrivateKeyFromHex(bobKeyHex)
	return a, b
}

// baseParams builds a correct swap params + matching expectation.
func baseParams(t *testing.T) (SwapParams, SwapExpectation, *ec.PrivateKey, *ec.PrivateKey) {
	t.Helper()
	alice, bob := keys(t)
	tid, d, hp, alicePKH := sampleIdentity(t)
	bobPKH := PubKeyHash(bob.PubKey())
	aliceCarrier, _ := LockingScriptHex(tid, d, hp, alicePKH)
	aliceAddr, _ := script.NewAddressFromPublicKey(alice.PubKey(), false)
	bobChange, _ := script.NewAddressFromPublicKey(bob.PubKey(), false)

	p := SwapParams{
		TokenPrevTxID: dummyTokenPrev, TokenPrevVout: 0, TokenLockScript: aliceCarrier, DustSats: 1,
		TokenId: tid, Descriptor: d, HPayload: hp,
		BobOwnerPKH: bobPKH,
		AliceAddr:   aliceAddr.AddressString, PriceSats: 50_000,
		Payments:      []PaymentInput{{TxID: dummyPayPrev, Vout: 0, LockingScript: p2pkhHex(t, bob), Sats: 200_000}},
		BobChangeAddr: bobChange.AddressString, ChangeSats: 149_000,
	}
	exp := SwapExpectation{
		TokenId: tid, Descriptor: d, HPayload: hp, BobOwnerPKH: bobPKH,
		AliceAddr: aliceAddr.AddressString, PriceSats: 50_000, DustSats: 1, MaxOutputs: 3,
	}
	return p, exp, alice, bob
}

func p2pkhHex(t *testing.T, k *ec.PrivateKey) string {
	t.Helper()
	a, _ := script.NewAddressFromPublicKey(k.PubKey(), false)
	ls, _ := p2pkh.Lock(a)
	return ls.String()
}

func assembledHex(t *testing.T, p SwapParams) string {
	t.Helper()
	alice, bob := keys(t)
	b, err := AssembleSwap(p, alice, bob)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	h, err := b.Hex()
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return h
}

//trace:test I-NFT-4
func TestVerifySwap_Accepts(t *testing.T) {
	p, exp, _, _ := baseParams(t)
	if err := VerifySwapTx(assembledHex(t, p), exp); err != nil {
		t.Fatalf("correct swap rejected: %v", err)
	}
}

// Every near-miss must be rejected by the verifier (docs/02 §2.5 step 2;
// I-NFT-2 identity preservation, I-NFT-4 exact terms).
//
//trace:test I-NFT-2 I-NFT-4
func TestVerifySwap_RejectsNearMisses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p *SwapParams, e *SwapExpectation)
		want   string
	}{
		{"tampered TokenId", func(p *SwapParams, _ *SwapExpectation) { p.TokenId = flip(p.TokenId) }, "TokenId changed"},
		{"tampered H(payload)", func(p *SwapParams, _ *SwapExpectation) { p.HPayload = flip(p.HPayload) }, "H(payload) changed"},
		{"token not locked to Bob", func(p *SwapParams, _ *SwapExpectation) { p.BobOwnerPKH = flip(p.BobOwnerPKH) }, "does not lock to Bob"},
		{"wrong price", func(p *SwapParams, _ *SwapExpectation) { p.PriceSats = 1 }, "price"},
		{"price not to Alice", func(p *SwapParams, _ *SwapExpectation) {
			b, _ := ec.PrivateKeyFromHex(bobKeyHex)
			other, _ := script.NewAddressFromPublicKey(b.PubKey(), false)
			p.AliceAddr = other.AddressString
		}, "does not pay Alice"},
		{"surprise extra output", func(p *SwapParams, e *SwapExpectation) { e.MaxOutputs = 2 }, "too many outputs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, exp, _, _ := baseParams(t)
			c.mutate(&p, &exp)
			err := VerifySwapTx(assembledHex(t, p), exp)
			if err == nil {
				t.Fatalf("near-miss %q was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("near-miss %q: got %q, want substring %q", c.name, err.Error(), c.want)
			}
		})
	}
}

// The verifier rejects a swap whose any output carries OP_RETURN (I-NFT-1),
// even one assembled outside our OP_RETURN-refusing builder.
//
//trace:test I-NFT-1
func TestVerifySwap_RejectsOpReturnOutput(t *testing.T) {
	p, exp, _, _ := baseParams(t)
	tx := transaction.NewTransaction()
	// out0: correct carrier; out1: price to Alice; out2: an OP_RETURN.
	carrier, _ := LockingScriptHex(p.TokenId, p.Descriptor, p.HPayload, p.BobOwnerPKH)
	cs, _ := script.NewFromHex(carrier)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: cs})
	aliceA, _ := script.NewAddressFromString(p.AliceAddr)
	als, _ := p2pkh.Lock(aliceA)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: p.PriceSats, LockingScript: als})
	if err := tx.AddOpReturnOutput([]byte("contraband")); err != nil {
		t.Fatalf("add op_return: %v", err)
	}
	exp.MaxOutputs = 3
	if err := VerifySwapTx(tx.Hex(), exp); err == nil || !strings.Contains(err.Error(), "OP_RETURN") {
		t.Fatalf("verifier did not reject OP_RETURN output: %v", err)
	}
}

func flip(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[0] ^= 0xff
	return out
}
