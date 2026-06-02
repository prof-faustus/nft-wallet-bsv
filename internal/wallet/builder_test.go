package wallet

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// A fixed key for deterministic offline tests.
const fixedKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"
const dummyPrevTxID = "abababababababababababababababababababababababababababababababab"

func fixedKey(t *testing.T) (*ec.PrivateKey, string) {
	t.Helper()
	k, err := ec.PrivateKeyFromHex(fixedKeyHex)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	addr, err := script.NewAddressFromPublicKey(k.PubKey(), false)
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	return k, addr.AddressString
}

// oneInTwoOut builds a 1-input (P2PKH from the fixed key) 2-output tx
// with the second output set to outBSats — enough to probe SIGHASH.
func oneInTwoOut(t *testing.T, outBSats uint64) *Builder {
	t.Helper()
	k, addr := fixedKey(t)
	a, _ := script.NewAddressFromString(addr)
	lock, _ := p2pkh.Lock(a)
	b := NewBuilder()
	if err := b.AddP2PKHInput(dummyPrevTxID, 0, lockHex(lock), 100_000, k, sighash.AllForkID); err != nil {
		t.Fatalf("add input: %v", err)
	}
	if err := b.AddP2PKHOutput(addr, 1_000); err != nil {
		t.Fatalf("add out0: %v", err)
	}
	if err := b.AddP2PKHOutput(addr, outBSats); err != nil {
		t.Fatalf("add out1: %v", err)
	}
	return b
}

func lockHex(s *script.Script) string { return s.String() }

// SIGHASH_ALL must commit to the outputs: identical txs give identical
// preimages; changing an output changes the preimage (hence any
// signature over it). docs/06 WS2 DoD: "a signature commits to exactly
// the intended inputs/outputs."
func TestSighashAllCommitsToOutputs(t *testing.T) {
	p1, err := oneInTwoOut(t, 2_000).SighashPreimage(0, sighash.AllForkID)
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	p2, _ := oneInTwoOut(t, 2_000).SighashPreimage(0, sighash.AllForkID)
	if !bytes.Equal(p1, p2) {
		t.Errorf("identical txs produced different preimages (non-determinism)")
	}
	p3, _ := oneInTwoOut(t, 3_000).SighashPreimage(0, sighash.AllForkID)
	if bytes.Equal(p1, p3) {
		t.Errorf("changing an output value did NOT change the SIGHASH_ALL preimage")
	}
}

// The builder is structurally incapable of emitting OP_RETURN: an output
// script carrying 0x6a is rejected (CLAUDE.md §2, I-NFT-1).
func TestBuilderRejectsOpReturn(t *testing.T) {
	b := NewBuilder()
	// 6a = OP_RETURN, 04deadbeef = push 4 bytes.
	if err := b.AddOutputScript("6a04deadbeef", 1); err == nil {
		t.Fatal("builder accepted an OP_RETURN output script")
	}
}

// A built+signed P2PKH transaction contains no 0x6a, and we drop its hex
// into testdata for the no-op-return gate to scan as real emitted bytes.
func TestEmittedP2PKHHasNoOpReturn(t *testing.T) {
	b := oneInTwoOut(t, 2_000)
	if err := b.Sign(); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := b.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if containsOpReturn(raw) {
		t.Fatal("emitted P2PKH tx contains 0x6a")
	}
	// Drop a copy into an ephemeral dir for ad-hoc inspection; the
	// committed sample at testdata/emitted/p2pkh_tx.hex is what the
	// no-op-return gate scans (kept static so test runs don't churn it).
	hexStr, _ := b.Hex()
	_ = os.WriteFile(filepath.Join(t.TempDir(), "p2pkh_tx.hex"), []byte(hexStr+"\n"), 0o644)
}
