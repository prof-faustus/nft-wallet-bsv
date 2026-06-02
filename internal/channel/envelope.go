// Package channel implements the Stage-1 minimal two-party authenticated
// secure channel + pairing (docs/03 §3.1–§3.3) over a HOSTILE transport
// (NET-1). The transport may reorder, drop, or delay; it must not be able
// to forge or alter messages undetectably. Integrity rests on the
// sender's signature over canonical bytes + a per-session monotonic
// sequence number, NOT on trusting the relay (docs/03 §3.2).
//
// Implements: docs/03 §3.1 (identities), §3.2 (secure channel), §3.3
// (envelope + message set). NET-1.
// NG watch: NG-2 — this is STRICTLY two-party pairing; it is NOT the full
// discovery network (docs/03 §3.8). NG-1 — no third counterparty.
//
// MUST NOT: import BTC (CLAUDE.md §1); the only crypto is the BSV Go
// SDK's secp256k1 over the identity key.
package channel

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// PayloadType is the wire message type (docs/03 §3.3).
type PayloadType uint8

const (
	PtHello          PayloadType = 1
	PtHelloAck       PayloadType = 2
	PtChat           PayloadType = 3
	PtOffer          PayloadType = 4
	PtCounter        PayloadType = 5
	PtAccept         PayloadType = 6
	PtPayloadOffer   PayloadType = 7
	PtPayloadData    PayloadType = 8
	PtPayloadAck     PayloadType = 9
	PtSwapPropose    PayloadType = 10
	PtSwapPartial    PayloadType = 11
	PtSwapBroadcast  PayloadType = 12
	PtDeletionAttest PayloadType = 13
	PtAbort          PayloadType = 14
)

// Envelope is the signed wire message (docs/03 §3.3):
//
//	Envelope = { sessionId, seq, fromPubKey, payloadType, payload, sig }
//	sig = Sign_from( H(sessionId || seq || fromPubKey || payloadType || payload) )
type Envelope struct {
	SessionID   []byte      `json:"session_id"`
	Seq         uint64      `json:"seq"`
	FromPubKey  []byte      `json:"from_pubkey"` // 33-byte compressed secp256k1
	PayloadType PayloadType `json:"payload_type"`
	Payload     []byte      `json:"payload"`
	Sig         []byte      `json:"sig"` // DER ECDSA signature
}

// SigHash is the canonical preimage hash a signature commits to. The
// fixed field order is the ONE canonical encoding (ambiguity is a defect,
// docs/02 §2.2 discipline applied to the wire).
func SigHash(sessionID []byte, seq uint64, fromPub []byte, pt PayloadType, payload []byte) []byte {
	var b bytes.Buffer
	b.Write(sessionID)
	var s8 [8]byte
	binary.BigEndian.PutUint64(s8[:], seq)
	b.Write(s8[:])
	b.Write(fromPub)
	b.WriteByte(byte(pt))
	b.Write(payload)
	h := sha256.Sum256(b.Bytes())
	return h[:]
}

// sigHash for an envelope.
func (e *Envelope) sigHash() []byte {
	return SigHash(e.SessionID, e.Seq, e.FromPubKey, e.PayloadType, e.Payload)
}
