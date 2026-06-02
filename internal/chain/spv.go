// SPV Merkle-proof verification (CH-1, docs/01 §1.4/§1.6).
//
// The chain adapter returns a Merkle proof as a serialized CMerkleBlock
// (the bytes SV Node's `gettxoutproof` emits). We do NOT trust the source
// of that proof: VerifyMerkleProof recomputes the Merkle root from the
// partial tree and checks it equals the root committed in the 80-byte
// block header carried in the same structure, and that the target txid is
// one of the matched leaves. A caller then checks that header against the
// chain tip (reorg awareness) — a proof is only as good as a header known
// to be on the active chain.
//
// MUST NOT: trust a node's "valid"/"invalid" verdict in place of this
// recomputation; that would defeat SPV. No BTC assumptions — the
// serialization here is the standard Bitcoin partial Merkle tree, which
// BSV inherits unchanged.
//
// Byte order: hashes inside the proof and the header are INTERNAL
// (little-endian) order; `gettxoutproof`/`getblockheader` RPC text and
// user-facing txids are DISPLAY (reversed) order. We compute in internal
// order and reverse only at the comparison boundary.
package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// sha256d is the Bitcoin double-SHA-256.
func sha256d(b []byte) [32]byte {
	h1 := sha256.Sum256(b)
	return sha256.Sum256(h1[:])
}

// reverse returns a byte-reversed copy (internal <-> display order).
func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// merkleBlock is a parsed CMerkleBlock: an 80-byte header, the total
// transaction count of the block, the proof hashes, and the traversal
// flag bits.
type merkleBlock struct {
	header []byte // 80 bytes
	total  uint32
	hashes [][32]byte // internal byte order
	flags  []byte
}

// merkleRootFromHeader extracts the Merkle root (internal order) from the
// 80-byte header: version(4) || prevHash(32) || merkleRoot(32) || ...
func (m *merkleBlock) merkleRootFromHeader() [32]byte {
	var r [32]byte
	copy(r[:], m.header[36:68])
	return r
}

// parseMerkleBlock decodes the CMerkleBlock wire format:
//
//	header[80] || nTotalTx[u32 LE] || varint(nHashes) || hashes[32]* ||
//	varint(nFlagBytes) || flags[]
func parseMerkleBlock(b []byte) (*merkleBlock, error) {
	if len(b) < 80+4 {
		return nil, fmt.Errorf("spv: proof too short (%d bytes)", len(b))
	}
	m := &merkleBlock{header: b[:80]}
	off := 80
	m.total = binary.LittleEndian.Uint32(b[off : off+4])
	off += 4
	nHashes, n, err := readVarint(b[off:])
	if err != nil {
		return nil, fmt.Errorf("spv: hash count: %w", err)
	}
	off += n
	if uint64(len(b)-off) < nHashes*32 {
		return nil, errors.New("spv: truncated hash list")
	}
	for i := uint64(0); i < nHashes; i++ {
		var h [32]byte
		copy(h[:], b[off:off+32])
		m.hashes = append(m.hashes, h)
		off += 32
	}
	nFlags, n, err := readVarint(b[off:])
	if err != nil {
		return nil, fmt.Errorf("spv: flag count: %w", err)
	}
	off += n
	if uint64(len(b)-off) < nFlags {
		return nil, errors.New("spv: truncated flag bytes")
	}
	m.flags = b[off : off+int(nFlags)]
	return m, nil
}

// partialMerkleCursor walks the partial Merkle tree consuming flag bits
// and proof hashes per the standard algorithm (CPartialMerkleTree).
type partialMerkleCursor struct {
	m        *merkleBlock
	bitsUsed uint
	hashUsed int
	matched  [][32]byte // leaves flagged as matched (internal order)
	err      error
}

func (c *partialMerkleCursor) flagBit() bool {
	i := c.bitsUsed
	c.bitsUsed++
	if i>>3 >= uint(len(c.m.flags)) {
		c.err = errors.New("spv: flag bits exhausted")
		return false
	}
	return (c.m.flags[i>>3]>>(i&7))&1 == 1
}

// treeWidth is the number of nodes at a given height (0 = leaves).
func (c *partialMerkleCursor) treeWidth(height uint) uint32 {
	return (c.m.total + (1 << height) - 1) >> height
}

func (c *partialMerkleCursor) treeHeight() uint {
	h := uint(0)
	for c.treeWidth(h) > 1 {
		h++
	}
	return h
}

// traverse returns the hash (internal order) of the subtree rooted at
// (height, pos), consuming flags/hashes as it goes.
func (c *partialMerkleCursor) traverse(height, pos uint) [32]byte {
	if c.err != nil {
		return [32]byte{}
	}
	parentOfMatch := c.flagBit()
	if height == 0 || !parentOfMatch {
		// Leaf, or an internal node whose hash is supplied directly.
		if c.hashUsed >= len(c.m.hashes) {
			c.err = errors.New("spv: hashes exhausted")
			return [32]byte{}
		}
		h := c.m.hashes[c.hashUsed]
		c.hashUsed++
		if height == 0 && parentOfMatch {
			c.matched = append(c.matched, h)
		}
		return h
	}
	left := c.traverse(height-1, pos*2)
	var right [32]byte
	if uint32(pos*2+1) < c.treeWidth(height-1) {
		right = c.traverse(height-1, pos*2+1)
		if c.err == nil && right == left {
			// Bitcoin consensus forbids duplicated right children in the
			// proof (CVE-2012-2459 hardening).
			c.err = errors.New("spv: duplicate right child in proof")
		}
	} else {
		right = left
	}
	var buf [64]byte
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	return sha256d(buf[:])
}

// MerkleProofResult is the verified outcome of a proof.
type MerkleProofResult struct {
	// RootMatchesHeader is true iff the recomputed root equals the
	// header's committed Merkle root.
	RootMatchesHeader bool
	// TxIncluded is true iff the target txid is a matched leaf.
	TxIncluded bool
	// BlockHash is the display-hex hash of the header (double-SHA-256).
	BlockHash string
	// MerkleRoot is the recomputed root in display hex.
	MerkleRoot string
}

// VerifyMerkleProof recomputes the Merkle root from a CMerkleBlock proof
// and checks (a) it equals the header's committed root and (b) the given
// txid (display hex) is one of the matched leaves.
//
// Preconditions: proofHex is a hex CMerkleBlock; txidDisplay is 64 hex.
// Postconditions: returns a result with both booleans; an error only for
// malformed input, never for a merely-failing proof (that is a false
// result the caller must handle).
// Errors: malformed hex/structure.
//
//trace:impl CH-1
func VerifyMerkleProof(proofHex, txidDisplay string) (MerkleProofResult, error) {
	raw, err := hex.DecodeString(proofHex)
	if err != nil {
		return MerkleProofResult{}, fmt.Errorf("spv: proof not hex: %w", err)
	}
	m, err := parseMerkleBlock(raw)
	if err != nil {
		return MerkleProofResult{}, err
	}
	cur := &partialMerkleCursor{m: m}
	root := cur.traverse(cur.treeHeight(), 0)
	if cur.err != nil {
		return MerkleProofResult{}, cur.err
	}
	// All flag bits (padded to a byte) and all hashes must be consumed.
	if cur.hashUsed != len(m.hashes) {
		return MerkleProofResult{}, errors.New("spv: not all proof hashes consumed")
	}
	if (cur.bitsUsed+7)/8 != uint(len(m.flags)) {
		return MerkleProofResult{}, errors.New("spv: not all flag bytes consumed")
	}

	headerRoot := m.merkleRootFromHeader()
	res := MerkleProofResult{
		RootMatchesHeader: root == headerRoot,
		MerkleRoot:        hex.EncodeToString(reverse(root[:])),
	}
	blockHash := sha256d(m.header)
	res.BlockHash = hex.EncodeToString(reverse(blockHash[:]))

	wantTxid, err := hex.DecodeString(txidDisplay)
	if err != nil || len(wantTxid) != 32 {
		return res, fmt.Errorf("spv: bad txid %q", txidDisplay)
	}
	wantInternal := reverse(wantTxid)
	for _, h := range cur.matched {
		if string(h[:]) == string(wantInternal) {
			res.TxIncluded = true
			break
		}
	}
	return res, nil
}

// readVarint reads a Bitcoin CompactSize varint, returning the value and
// the number of bytes consumed.
func readVarint(b []byte) (val uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, errors.New("spv: empty varint")
	}
	switch b[0] {
	case 0xfd:
		if len(b) < 3 {
			return 0, 0, errors.New("spv: short varint(fd)")
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3, nil
	case 0xfe:
		if len(b) < 5 {
			return 0, 0, errors.New("spv: short varint(fe)")
		}
		return uint64(binary.LittleEndian.Uint32(b[1:5])), 5, nil
	case 0xff:
		if len(b) < 9 {
			return 0, 0, errors.New("spv: short varint(ff)")
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9, nil
	default:
		return uint64(b[0]), 1, nil
	}
}
