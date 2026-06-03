package covenant

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	hash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
)

func sha256d(b []byte) []byte { return hash.Sha256d(b) }

const tokenValue uint64 = 1000

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// spendParams configures a candidate spend of a covenant token UTXO.
type spendParams struct {
	tokenId, desc, hPayload []byte
	covValue                uint64 // value baked into the locking covenant
	out0Script              []byte // successor output 0 locking script
	out0Value               uint64 // successor output 0 value
	declaredOwner           []byte // 20-byte PKH supplied in the unlocking script
	lockTime                uint32 // varies the sighash (z)
	mutatePreimage          func([]byte) []byte
}

// run builds source+spend txs, computes the SINGLE|FORKID preimage, assembles
// the covenant unlock, and executes the script in the real BSV interpreter.
// Returns the engine error (nil = the covenant ACCEPTED the spend).
func run(t *testing.T, p spendParams) error {
	t.Helper()
	lock, err := CovenantLockingScript(p.tokenId, p.desc, p.hPayload, p.covValue)
	if err != nil {
		t.Fatalf("build covenant: %v", err)
	}
	lockScr := script.NewFromBytes(lock)

	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: tokenValue, LockingScript: lockScr})

	spend := transaction.NewTransaction()
	spend.LockTime = p.lockTime
	spend.AddInputFromTx(src, 0, nil)
	spend.AddOutput(&transaction.TransactionOutput{
		Satoshis:      p.out0Value,
		LockingScript: script.NewFromBytes(p.out0Script),
	})

	preimage, err := spend.CalcInputPreimage(0, sighash.Flag(SighashFlag))
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	if p.mutatePreimage != nil {
		preimage = p.mutatePreimage(preimage)
	}
	unlock, err := CovenantUnlockingScript(preimage, p.declaredOwner)
	if err != nil {
		t.Fatalf("build unlock: %v", err)
	}
	spend.Inputs[0].UnlockingScript = script.NewFromBytes(unlock)

	return interpreter.NewEngine().Execute(
		interpreter.WithTx(spend, 0, src.Outputs[0]),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	)
}

// faithful builds the params for a correct transfer to a fresh owner.
func faithful(t *testing.T) spendParams {
	t.Helper()
	tokenId := randBytes(32)
	desc := []byte("nftbsv/v2")
	h := randBytes(32)
	owner := randBytes(20)
	succ, err := token.BuildLockingScript(tokenId, desc, h, owner)
	if err != nil {
		t.Fatal(err)
	}
	return spendParams{
		tokenId: tokenId, desc: desc, hPayload: h, covValue: tokenValue,
		out0Script: succ, out0Value: tokenValue, declaredOwner: owner,
	}
}

// detBytes derives n deterministic bytes from a seed (reproducible tests).
func detBytes(seed string, n int) []byte {
	h := sha256.Sum256([]byte(seed))
	return h[:n]
}

// detFaithful builds a DETERMINISTIC faithful transfer from a seed, so DER
// edge cases and the liveness sweep are reproducible (no flaky randomness).
func detFaithful(t *testing.T, seed string) spendParams {
	t.Helper()
	tokenId := detBytes(seed+"|tok", 32)
	desc := []byte("nftbsv/v2")
	h := detBytes(seed+"|h", 32)
	owner := detBytes(seed+"|own", 20)
	succ, err := token.BuildLockingScript(tokenId, desc, h, owner)
	if err != nil {
		t.Fatal(err)
	}
	return spendParams{
		tokenId: tokenId, desc: desc, hPayload: h, covValue: tokenValue,
		out0Script: succ, out0Value: tokenValue, declaredOwner: owner,
	}
}

// A faithful transfer MUST be accepted (the covenant runs end-to-end in the
// real interpreter: preimage authenticated, continuity satisfied).
//
//trace:test CN-1
func TestCovenantAcceptsFaithfulTransfer(t *testing.T) {
	if err := run(t, faithful(t)); err != nil {
		t.Fatalf("faithful transfer rejected: %v", err)
	}
}

// Every way to BREAK continuity must be rejected. This is the security
// property: a hostile spender cannot strip or mutate the token.
//
//trace:test CN-1
func TestCovenantRejectsTampering(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) spendParams
	}{
		{"strip to plain P2PKH", func(t *testing.T) spendParams {
			p := faithful(t)
			// successor is a bare P2PKH (no identity prefix) — token stripped.
			var b bytes.Buffer
			b.Write([]byte{0x76, 0xa9, 0x14})
			b.Write(p.declaredOwner)
			b.Write([]byte{0x88, 0xac})
			p.out0Script = b.Bytes()
			return p
		}},
		{"mutate TokenId", func(t *testing.T) spendParams {
			p := faithful(t)
			other := randBytes(32)
			succ, _ := token.BuildLockingScript(other, p.desc, p.hPayload, p.declaredOwner)
			p.out0Script = succ // output carries a DIFFERENT identity
			return p
		}},
		{"mutate H(payload)", func(t *testing.T) spendParams {
			p := faithful(t)
			succ, _ := token.BuildLockingScript(p.tokenId, p.desc, randBytes(32), p.declaredOwner)
			p.out0Script = succ
			return p
		}},
		{"mutate descriptor", func(t *testing.T) spendParams {
			p := faithful(t)
			succ, _ := token.BuildLockingScript(p.tokenId, []byte("evil/desc"), p.hPayload, p.declaredOwner)
			p.out0Script = succ
			return p
		}},
		{"redirect to a different owner", func(t *testing.T) spendParams {
			p := faithful(t)
			// actual output goes to owner B, but unlock declares owner A.
			ownerB := randBytes(20)
			succ, _ := token.BuildLockingScript(p.tokenId, p.desc, p.hPayload, ownerB)
			p.out0Script = succ // declaredOwner stays the original A
			return p
		}},
		{"inflate the token value", func(t *testing.T) spendParams {
			p := faithful(t)
			p.out0Value = tokenValue + 1 // value is immutable; mismatch
			return p
		}},
		{"tamper one preimage byte", func(t *testing.T) spendParams {
			p := faithful(t)
			p.mutatePreimage = func(pi []byte) []byte {
				out := append([]byte(nil), pi...)
				out[len(out)/2] ^= 0xff
				return out
			}
			return p
		}},
		{"forge hashOutputs in preimage", func(t *testing.T) spendParams {
			p := faithful(t)
			// Rewrite the preimage's hashOutputs field to match a stripped
			// output, hoping PART B passes. PART A (CHECKSIG) must still
			// catch the forged preimage.
			p.mutatePreimage = func(pi []byte) []byte {
				out := append([]byte(nil), pi...)
				for i := len(out) - 40; i < len(out)-8; i++ {
					out[i] = 0x00
				}
				return out
			}
			return p
		}},
		{"wrong sighash type preimage", func(t *testing.T) spendParams {
			p := faithful(t)
			// Supply an ALL|FORKID preimage while the covenant forces 0x43.
			p.mutatePreimage = func(pi []byte) []byte {
				out := append([]byte(nil), pi...)
				out[len(out)-4] = 0x41 // flip sighash byte SINGLE->ALL
				return out
			}
			return p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := run(t, c.build(t)); err == nil {
				t.Fatalf("%s: covenant ACCEPTED a tampered spend (security failure)", c.name)
			}
		})
	}
}

// Liveness sweep: many faithful transfers with varied identity, owner, and
// lockTime (→ varied sighash z, exercising the in-script ECDSA + DER paths).
// EVERY faithful spend must be accepted.
//
//trace:test CN-1
func TestCovenantLivenessSweep(t *testing.T) {
	n := 3000
	if testing.Short() {
		n = 300
	}
	for i := 0; i < n; i++ {
		p := detFaithful(t, fmt.Sprintf("sweep-%d", i)) // deterministic → reproducible
		p.lockTime = uint32(i*7919 + 1)
		if err := run(t, p); err != nil {
			t.Fatalf("iter %d: faithful spend rejected: %v", i, err)
		}
	}
}

// Targeted DER edge: find a lockTime whose forced s is SMALL (top byte
// zero → the minimal-DER strip path must shorten the encoding) and a
// lockTime whose s has its high byte near 0x7f, and prove BOTH are accepted
// by the interpreter — the leading-zero path that random sampling rarely
// hits is exercised on the real engine.
//
//trace:test CN-1
func TestCovenantDEREdgeOnEngine(t *testing.T) {
	c, _ := constants()
	base := detFaithful(t, "der-edge") // DETERMINISTIC base → reproducible search

	findLockTime := func(pred func(s *big.Int) bool) (uint32, bool) {
		for lt := uint32(0); lt < 400000; lt++ {
			p := base
			p.lockTime = lt
			z := zForSpend(t, p)
			if pred(c.forcedS(z)) {
				return lt, true
			}
		}
		return 0, false
	}
	accept := func(name string, pred func(*big.Int) bool, required bool) {
		lt, ok := findLockTime(pred)
		if !ok {
			if required {
				t.Fatalf("could not construct the %q case in range", name)
			}
			t.Logf("no %q case found in range", name)
			return
		}
		p := base
		p.lockTime = lt
		if err := run(t, p); err != nil {
			t.Fatalf("%s spend (lockTime=%d) rejected: %v", name, lt, err)
		}
	}

	twoTo248 := new(big.Int).Lsh(big.NewInt(1), 248)
	topByte := func(s *big.Int) byte {
		b := s.Bytes()
		if len(b) == 0 {
			return 0
		}
		return b[0]
	}

	// (1) leading-zero s: s < 2^248 (the strip path shortens the encoding).
	accept("leading-zero-s", func(s *big.Int) bool { return s.Cmp(twoTo248) < 0 }, true)
	// (2) THE negative-zero trap: a stripped top magnitude byte of EXACTLY
	// 0x80 (BIN2NUM(0x80)=0). The strip must NOT eat it and the sign-byte
	// step MUST add a 0x00 prefix. This is the exact class CI caught.
	accept("top-byte-0x80", func(s *big.Int) bool { return topByte(s) == 0x80 }, true)
	// (3) high-bit-set-not-0x80: top byte in 0x81..0xff (BIN2NUM<0 path).
	accept("top-byte-high-bit", func(s *big.Int) bool { b := topByte(s); return b > 0x80 }, true)
	// (4) deep leading zeros: s < 2^240 (multiple 0x00 bytes stripped).
	accept("multi-leading-zero", func(s *big.Int) bool { return s.Cmp(new(big.Int).Lsh(big.NewInt(1), 240)) < 0 }, false)
}

// zForSpend recomputes the message integer z = int(Hash256(preimage)) for a
// spend, matching what the script derives on-stack.
func zForSpend(t *testing.T, p spendParams) *big.Int {
	t.Helper()
	lock, _ := CovenantLockingScript(p.tokenId, p.desc, p.hPayload, p.covValue)
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: tokenValue, LockingScript: script.NewFromBytes(lock)})
	spend := transaction.NewTransaction()
	spend.LockTime = p.lockTime
	spend.AddInputFromTx(src, 0, nil)
	spend.AddOutput(&transaction.TransactionOutput{Satoshis: p.out0Value, LockingScript: script.NewFromBytes(p.out0Script)})
	pre, _ := spend.CalcInputPreimage(0, sighash.Flag(SighashFlag))
	h := sha256d(pre)
	return new(big.Int).SetBytes(h)
}
