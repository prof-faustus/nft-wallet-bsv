// The authenticated session and pairing handshake (docs/03 §3.2/§3.4).
//
// Pairing: each side sends a signed HELLO carrying its identity pubkey +
// a fresh nonce; each verifies the peer's HELLO signature AGAINST THE
// PUBKEY IN THE PAYLOAD, which proves the sender holds that identity key
// (mutual authentication, NET-1). The sessionId is then derived
// deterministically from both pubkeys + both nonces, so messages cannot
// be replayed across sessions (docs/03 §3.1).
//
// Session: every message is a signed Envelope with a per-session
// monotonically increasing seq. Recv() rejects (a) a bad/absent signature
// (F-13 forged), (b) a seq <= the last accepted (F-11 replay / reorder),
// and (c) a frame that does not decode (F-12 malformed/truncated) — and
// none of these advance state.
//
//trace:impl NET-1
package channel

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

const helloVersion = 1

// helloPayload is the HELLO body (docs/03 §3.3).
type helloPayload struct {
	PubKey  []byte `json:"pubkey"` // 33-byte compressed, MUST equal Envelope.FromPubKey
	Nonce   []byte `json:"nonce"`  // 16 random bytes
	Version int    `json:"version"`
}

// Session is an established authenticated channel to one peer.
type Session struct {
	tr        Transport
	myKey     *ec.PrivateKey
	peerPub   *ec.PublicKey
	peerRaw   []byte
	sessionID []byte
	sendSeq   uint64
	recvSeq   uint64 // last accepted inbound seq (0 = none yet)
}

// PeerPubKey returns the authenticated peer identity (compressed bytes).
func (s *Session) PeerPubKey() []byte { return s.peerRaw }

// SessionID returns the bound session id.
func (s *Session) SessionID() []byte { return s.sessionID }

// Pair runs the HELLO handshake over tr and returns an authenticated
// Session. Symmetric: both sides call it; the buffered transport lets
// each send-then-receive without deadlock. nonce must be 16 fresh bytes.
//
// Preconditions: myKey set; nonce length 16.
// Postconditions: the returned Session is bound to the peer's verified
// identity key and a shared sessionId; an unverifiable peer HELLO is a
// non-nil error (no session).
func Pair(tr Transport, myKey *ec.PrivateKey, nonce []byte) (*Session, error) {
	if len(nonce) != 16 {
		return nil, fmt.Errorf("channel: nonce must be 16 bytes")
	}
	myPub := myKey.PubKey().Compressed()
	hp := helloPayload{PubKey: myPub, Nonce: nonce, Version: helloVersion}
	body, _ := json.Marshal(hp)
	// Handshake sig uses an empty sessionId (not yet derived); it binds
	// (pubkey, nonce) to the identity key.
	env := Envelope{SessionID: nil, Seq: 0, FromPubKey: myPub, PayloadType: PtHello, Payload: body}
	sig, err := myKey.Sign(env.sigHash())
	if err != nil {
		return nil, err
	}
	env.Sig = sig.Serialize()
	raw, _ := json.Marshal(env)
	if err := tr.Send(raw); err != nil {
		return nil, err
	}

	// Receive + verify the peer's HELLO.
	peerRaw, err := tr.Recv()
	if err != nil {
		return nil, err
	}
	var peerEnv Envelope
	if err := json.Unmarshal(peerRaw, &peerEnv); err != nil {
		return nil, fmt.Errorf("channel: peer HELLO malformed: %w", err)
	}
	if peerEnv.PayloadType != PtHello {
		return nil, fmt.Errorf("channel: expected HELLO, got type %d", peerEnv.PayloadType)
	}
	var peerHP helloPayload
	if err := json.Unmarshal(peerEnv.Payload, &peerHP); err != nil {
		return nil, fmt.Errorf("channel: peer HELLO body malformed: %w", err)
	}
	// The pubkey in the envelope MUST equal the one in the payload, and
	// the signature MUST verify against it (identity binding, NET-1).
	if !bytesEqual(peerEnv.FromPubKey, peerHP.PubKey) {
		return nil, fmt.Errorf("channel: peer HELLO pubkey mismatch")
	}
	peerPub, err := ec.PublicKeyFromBytes(peerEnv.FromPubKey)
	if err != nil {
		return nil, fmt.Errorf("channel: peer pubkey invalid: %w", err)
	}
	if !verifyEnvelope(&peerEnv, peerPub) {
		return nil, fmt.Errorf("channel: peer HELLO signature invalid (authentication failed)")
	}
	if len(peerHP.Nonce) != 16 {
		return nil, fmt.Errorf("channel: peer nonce wrong size")
	}

	sid := deriveSessionID(myPub, nonce, peerHP.PubKey, peerHP.Nonce)
	return &Session{tr: tr, myKey: myKey, peerPub: peerPub, peerRaw: peerEnv.FromPubKey, sessionID: sid}, nil
}

// Send signs and transmits a message under the next sequence number.
func (s *Session) Send(pt PayloadType, payload []byte) error {
	s.sendSeq++
	env := Envelope{SessionID: s.sessionID, Seq: s.sendSeq, FromPubKey: s.myKey.PubKey().Compressed(), PayloadType: pt, Payload: payload}
	sig, err := s.myKey.Sign(env.sigHash())
	if err != nil {
		return err
	}
	env.Sig = sig.Serialize()
	raw, _ := json.Marshal(env)
	return s.tr.Send(raw)
}

// Recv reads, authenticates, and anti-replay-checks the next message.
// Rejections (forged/replayed/reordered/malformed) return an error and do
// NOT advance recvSeq — the channel state is not corrupted (F-11..F-13).
func (s *Session) Recv() (PayloadType, []byte, error) {
	raw, err := s.tr.Recv()
	if err != nil {
		return 0, nil, err
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, nil, fmt.Errorf("channel: malformed frame (F-12): %w", err) // F-12
	}
	if !bytesEqual(env.SessionID, s.sessionID) {
		return 0, nil, errors.New("channel: wrong sessionId (cross-session replay)")
	}
	if !bytesEqual(env.FromPubKey, s.peerRaw) {
		return 0, nil, errors.New("channel: message not from the paired peer")
	}
	if !verifyEnvelope(&env, s.peerPub) {
		return 0, nil, errors.New("channel: signature check failed (F-13 forged)") // F-13
	}
	if env.Seq <= s.recvSeq {
		// Duplicate, replayed, or reordered-behind: reject without
		// advancing state (F-11). Strictly-increasing seq also rejects
		// out-of-order delivery.
		return 0, nil, fmt.Errorf("channel: stale seq %d <= %d (F-11 replay/reorder)", env.Seq, s.recvSeq)
	}
	s.recvSeq = env.Seq
	return env.PayloadType, env.Payload, nil
}

// verifyEnvelope checks the DER signature over the canonical sig-hash.
func verifyEnvelope(env *Envelope, pub *ec.PublicKey) bool {
	if len(env.Sig) == 0 {
		return false // absent signature (F-13)
	}
	sig, err := ec.ParseDERSignature(env.Sig)
	if err != nil {
		return false
	}
	return sig.Verify(env.sigHash(), pub)
}

// deriveSessionID = SHA256(pubLo || pubHi || nonceLo || nonceHi) with the
// pair ordered canonically by pubkey bytes, so both parties compute the
// same id regardless of role (docs/03 §3.1).
func deriveSessionID(myPub, myNonce, peerPub, peerNonce []byte) []byte {
	h := sha256.New()
	if bytesLess(myPub, peerPub) {
		h.Write(myPub)
		h.Write(peerPub)
		h.Write(myNonce)
		h.Write(peerNonce)
	} else {
		h.Write(peerPub)
		h.Write(myPub)
		h.Write(peerNonce)
		h.Write(myNonce)
	}
	return h.Sum(nil)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesLess(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
