// Package deletion implements Stage-1 local payload deletion + the
// Cooperative Deletion Attestation (CDA) — docs/04 §4.1/§4.2/§4.5.
//
// HONESTY (docs/04 §4.1/§4.7; CLAUDE.md §4): Stage 1 does NOT provide
// "verifiable deletion." A party in possession of bytes can copy them
// before any delete; software on the seller's own machine cannot prove a
// wipe to the buyer (HH-1). What this package ships is:
//   - best-effort LOCAL deletion (bounded by HH-1; NOT verifiable), and
//   - a signed cooperative ATTESTATION (a non-repudiable CLAIM bound to
//     the token + the on-chain swap), NOT evidence the bytes are gone.
//
// No symbol, comment, or error in this package says deletion is
// "verified" — that phrasing is reserved for the Stage-2/T-stage
// mechanisms (§4.5/§4.6) that actually earn it.
//
// F-16 (the load-bearing honesty test, docs/05 §5.5): settlement does NOT
// depend on the CDA. A missing CDA is recorded as a missing CLAIM
// (AttestAbsent), never as a transfer failure — Bob already owns the
// token after CONFIRMED (proven on-chain in internal/token + the engine).
//
//trace:impl HH-1 PL-1
package deletion

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// sha256d is the BSV double-SHA-256.
func sha256d(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

// cdaVersion is the canonical CDA format version. The shape is
// forward-compatible (docs/04 §4.2): Stage 2 populates KeyReference, the
// T-stage populates EnclaveAttestation; the wire shape does not change,
// only its evidentiary weight grows.
const cdaVersion uint8 = 1

// StatementDeleted is the Stage-1 CDA statement.
const StatementDeleted = "deleted"

// CDA is the cooperative deletion attestation (docs/04 §4.2):
//
//	CDA = { tokenId, tokenOutpoint, swapTxid, H(payload), timestamp,
//	        statement="deleted" }
type CDA struct {
	Version           uint8
	TokenId           []byte // 32
	TokenOutpointTxID string // display hex (32-byte)
	TokenOutpointVout uint32
	SwapTxID          string // display hex (32-byte)
	HPayload          []byte // 32
	Timestamp         int64  // unix seconds
	Statement         string // Stage 1: "deleted"
	// Forward-compatible, empty in Stage 1 (docs/04 §4.5/§4.6):
	KeyReference       []byte // Stage 2: destroyed/rotated key reference
	EnclaveAttestation []byte // T-stage: enclave attestation
}

// BuildCDA constructs a Stage-1 CDA. The forward-compat fields are left
// empty; populating them is Stage 2 / T-stage work, not Stage 1.
func BuildCDA(tokenId []byte, outpointTxID string, vout uint32, swapTxID string, hPayload []byte, timestamp int64) (CDA, error) {
	if len(tokenId) != 32 || len(hPayload) != 32 {
		return CDA{}, fmt.Errorf("deletion: tokenId and H(payload) must be 32 bytes")
	}
	return CDA{
		Version: cdaVersion, TokenId: tokenId,
		TokenOutpointTxID: outpointTxID, TokenOutpointVout: vout,
		SwapTxID: swapTxID, HPayload: hPayload, Timestamp: timestamp,
		Statement: StatementDeleted,
	}, nil
}

// canonical is the ONE deterministic serialization of a CDA, hashed for
// signing (ambiguous encoding is a defect).
func (c CDA) canonical() ([]byte, error) {
	txid, err := txidInternal(c.TokenOutpointTxID)
	if err != nil {
		return nil, fmt.Errorf("deletion: tokenOutpoint txid: %w", err)
	}
	swap, err := txidInternal(c.SwapTxID)
	if err != nil {
		return nil, fmt.Errorf("deletion: swap txid: %w", err)
	}
	var b bytes.Buffer
	b.WriteByte(c.Version)
	b.Write(c.TokenId)
	b.Write(txid)
	var v4 [4]byte
	binary.LittleEndian.PutUint32(v4[:], c.TokenOutpointVout)
	b.Write(v4[:])
	b.Write(swap)
	b.Write(c.HPayload)
	var t8 [8]byte
	binary.LittleEndian.PutUint64(t8[:], uint64(c.Timestamp))
	b.Write(t8[:])
	writeLP(&b, []byte(c.Statement))
	writeLP(&b, c.KeyReference)
	writeLP(&b, c.EnclaveAttestation)
	return b.Bytes(), nil
}

// Hash is the double-SHA-256 over the canonical bytes (the H(CDA) signed).
func (c CDA) Hash() ([]byte, error) {
	canon, err := c.canonical()
	if err != nil {
		return nil, err
	}
	return sha256d(canon), nil
}

// Sign produces sigCDA = Sign_Alice(H(CDA)) as DER bytes.
func (c CDA) Sign(key *ec.PrivateKey) ([]byte, error) {
	h, err := c.Hash()
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(h)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

// Expectation is what Bob checks a received CDA against — the token +
// swap he actually settled (docs/04 §4.2 binding).
type Expectation struct {
	TokenId           []byte
	TokenOutpointTxID string
	TokenOutpointVout uint32
	SwapTxID          string
	HPayload          []byte
}

// Verify checks a received (CDA, sigCDA): the signature must verify under
// Alice's identity key (F-15), the statement must be "deleted", and every
// bound field must match what Bob settled (F-17). A non-nil error means
// Bob does NOT store it as valid.
//
//trace:impl HH-1
func Verify(c CDA, sigCDA []byte, alicePub *ec.PublicKey, exp Expectation) error {
	h, err := c.Hash()
	if err != nil {
		return err
	}
	sig, err := ec.ParseDERSignature(sigCDA)
	if err != nil {
		return fmt.Errorf("deletion: sigCDA not parseable (F-15): %w", err)
	}
	if !sig.Verify(h, alicePub) {
		return fmt.Errorf("deletion: sigCDA does not verify under Alice's key (F-15 forged)")
	}
	if c.Statement != StatementDeleted {
		return fmt.Errorf("deletion: unexpected statement %q", c.Statement)
	}
	if !bytes.Equal(c.TokenId, exp.TokenId) || !bytes.Equal(c.HPayload, exp.HPayload) ||
		c.TokenOutpointTxID != exp.TokenOutpointTxID || c.TokenOutpointVout != exp.TokenOutpointVout ||
		c.SwapTxID != exp.SwapTxID {
		return fmt.Errorf("deletion: CDA does not match the settled token/swap (F-17)")
	}
	return nil
}

// AttestStatus is Bob's record of the deletion attestation for a swap.
type AttestStatus string

const (
	// AttestAbsent: no CDA received. This is a missing CLAIM, NOT a
	// transfer failure — Bob already owns the token (F-16, docs/04 §4.2).
	AttestAbsent AttestStatus = "absent (missing claim)"
	// AttestValid: a CDA received whose signature + bindings check out.
	AttestValid AttestStatus = "valid"
	// AttestInvalid: a CDA received that failed verification (F-15/F-17);
	// not stored as valid; ownership is unaffected (F-16).
	AttestInvalid AttestStatus = "invalid"
)

// ClassifyReceived maps a (possibly nil) received CDA to a status WITHOUT
// implying anything about settlement. A nil CDA is AttestAbsent (a missing
// claim), explicitly not a failure (F-16).
func ClassifyReceived(c *CDA, sigCDA []byte, alicePub *ec.PublicKey, exp Expectation) AttestStatus {
	if c == nil {
		return AttestAbsent
	}
	if err := Verify(*c, sigCDA, alicePub, exp); err != nil {
		return AttestInvalid
	}
	return AttestValid
}

// LocalDelete makes a BEST-EFFORT attempt to delete the seller's local
// payload copy. Per HH-1/PL-1 this is NOT verifiable and NOT a guarantee
// the bytes are gone — a copy may have been made beforehand. The honest
// claim is "attempted local deletion", never "verified deletion"
// (docs/04 §4.1/§4.7).
//
//trace:impl PL-1
func LocalDelete(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deletion: best-effort local delete failed: %w", err)
	}
	return nil
}

// helpers -----------------------------------------------------------------

func writeLP(b *bytes.Buffer, data []byte) {
	var l2 [2]byte
	binary.LittleEndian.PutUint16(l2[:], uint16(len(data)))
	b.Write(l2[:])
	b.Write(data)
}

func txidInternal(displayHex string) ([]byte, error) {
	d, err := hex.DecodeString(displayHex)
	if err != nil || len(d) != 32 {
		return nil, fmt.Errorf("bad txid %q", displayHex)
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = d[31-i]
	}
	return out, nil
}
