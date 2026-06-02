// Offline SPV verification tests (CH-1). They run a real CMerkleBlock
// proof — captured from the SV Node regtest into testdata/spv — through
// VerifyMerkleProof with no network, proving the recompute matches the
// header's committed root and that tampering is rejected.
package chain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type spvFixture struct {
	TxID       string `json:"txid"`
	BlockHash  string `json:"block_hash"`
	MerkleRoot string `json:"merkleroot"`
	HeaderHex  string `json:"header_hex"`
	TxOutProof string `json:"txoutproof_hex"`
}

func loadSPVFixture(t *testing.T) spvFixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "spv", "proof_fixture.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f spvFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

//trace:test CH-1
func TestVerifyMerkleProof_Valid(t *testing.T) {
	f := loadSPVFixture(t)
	res, err := VerifyMerkleProof(f.TxOutProof, f.TxID)
	if err != nil {
		t.Fatalf("VerifyMerkleProof: %v", err)
	}
	if !res.RootMatchesHeader {
		t.Errorf("recomputed root does not match header root (got root %s)", res.MerkleRoot)
	}
	if !res.TxIncluded {
		t.Errorf("target txid not found among matched leaves")
	}
	if res.MerkleRoot != f.MerkleRoot {
		t.Errorf("recomputed merkleroot = %s, want %s", res.MerkleRoot, f.MerkleRoot)
	}
	if res.BlockHash != f.BlockHash {
		t.Errorf("recomputed block hash = %s, want %s", res.BlockHash, f.BlockHash)
	}
}

//trace:test CH-1
func TestVerifyMerkleProof_TamperedProofFails(t *testing.T) {
	f := loadSPVFixture(t)
	// Flip one hex nibble inside the proof's HASH section (past the
	// 80-byte/160-hex header + the u32 total + the hash-count varint).
	// Tampering a proof hash must change the recomputed Merkle root and
	// break RootMatchesHeader. (Header-byte tampering is caught instead
	// by the block-hash / header-on-chain check, not by this function.)
	b := []byte(f.TxOutProof)
	pos := 170 // first hash byte region for a small block
	if pos >= len(b) {
		t.Fatalf("fixture proof unexpectedly short (%d)", len(b))
	}
	if b[pos] == 'a' {
		b[pos] = 'b'
	} else {
		b[pos] = 'a'
	}
	res, err := VerifyMerkleProof(string(b), f.TxID)
	// Either a parse error or a root mismatch is an acceptable rejection;
	// what must NOT happen is a clean RootMatchesHeader==true.
	if err == nil && res.RootMatchesHeader {
		t.Errorf("tampered proof verified as matching the header root")
	}
}

//trace:test CH-1
func TestVerifyMerkleProof_WrongTxidNotIncluded(t *testing.T) {
	f := loadSPVFixture(t)
	wrong := "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff"
	res, err := VerifyMerkleProof(f.TxOutProof, wrong)
	if err != nil {
		t.Fatalf("VerifyMerkleProof: %v", err)
	}
	if res.TxIncluded {
		t.Errorf("a txid not in the block was reported as included")
	}
}
