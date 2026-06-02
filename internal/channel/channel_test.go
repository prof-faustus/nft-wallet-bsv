package channel

import (
	"encoding/json"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func mustKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	k, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pairBoth runs the handshake on both ends concurrently over a pipe.
func pairBoth(t *testing.T) (sa, sb *Session, endA, endB Transport, keyA, keyB *ec.PrivateKey) {
	t.Helper()
	endA, endB = NewPipe(16)
	keyA, keyB = mustKey(t), mustKey(t)
	type res struct {
		s   *Session
		err error
	}
	ca, cb := make(chan res, 1), make(chan res, 1)
	go func() { s, err := Pair(endA, keyA, make16("a")); ca <- res{s, err} }()
	go func() { s, err := Pair(endB, keyB, make16("b")); cb <- res{s, err} }()
	ra, rb := <-ca, <-cb
	if ra.err != nil || rb.err != nil {
		t.Fatalf("pair failed: %v / %v", ra.err, rb.err)
	}
	return ra.s, rb.s, endA, endB, keyA, keyB
}

func make16(seed string) []byte {
	b := make([]byte, 16)
	copy(b, seed)
	return b
}

func signedFrame(t *testing.T, key *ec.PrivateKey, sid []byte, seq uint64, pt PayloadType, payload []byte) []byte {
	t.Helper()
	env := Envelope{SessionID: sid, Seq: seq, FromPubKey: key.PubKey().Compressed(), PayloadType: pt, Payload: payload}
	sig, err := key.Sign(env.sigHash())
	if err != nil {
		t.Fatal(err)
	}
	env.Sig = sig.Serialize()
	raw, _ := json.Marshal(env)
	return raw
}

// inject pushes a raw frame straight onto A's outbound channel (which is
// B's inbound) — the hostile-transport seam (NET-1).
func inject(endA Transport, frame []byte) { endA.(*pipeEnd).out <- frame }

// Two instances pair (mutual auth) and exchange authenticated messages.
//
//trace:test NET-1
func TestPairAndAuthenticatedExchange(t *testing.T) {
	sa, sb, _, _, _, _ := pairBoth(t)
	if string(sa.SessionID()) != string(sb.SessionID()) {
		t.Fatal("both sides must derive the same sessionId")
	}
	if string(sa.PeerPubKey()) == "" || string(sb.PeerPubKey()) == "" {
		t.Fatal("peer identity not bound")
	}
	if err := sa.Send(PtChat, []byte("hello bob")); err != nil {
		t.Fatalf("send: %v", err)
	}
	pt, payload, err := sb.Recv()
	if err != nil || pt != PtChat || string(payload) != "hello bob" {
		t.Fatalf("recv = %d/%q err=%v", pt, payload, err)
	}
}

// F-13: a forged message (valid shape, wrong/absent signature) is
// rejected and never applied.
//
//trace:test NET-1
func TestForgedMessageRejected(t *testing.T) {
	_, sb, endA, _, keyA, _ := pairBoth(t)
	// Correct fields but a garbage signature.
	frame := signedFrame(t, keyA, sb.SessionID(), 1, PtChat, []byte("x"))
	var env Envelope
	_ = json.Unmarshal(frame, &env)
	env.Sig = []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01} // bogus DER
	bad, _ := json.Marshal(env)
	inject(endA, bad)
	if _, _, err := sb.Recv(); err == nil {
		t.Fatal("forged message accepted (F-13)")
	}
	// Absent signature too.
	env.Sig = nil
	none, _ := json.Marshal(env)
	inject(endA, none)
	if _, _, err := sb.Recv(); err == nil {
		t.Fatal("unsigned message accepted (F-13)")
	}
}

// F-11: replayed / reordered (stale seq) messages are rejected; state is
// not double-advanced.
//
//trace:test NET-1
func TestReplayAndReorderRejected(t *testing.T) {
	_, sb, endA, _, keyA, _ := pairBoth(t)
	sid := sb.SessionID()
	// seq=1 accepted.
	inject(endA, signedFrame(t, keyA, sid, 1, PtChat, []byte("one")))
	if _, _, err := sb.Recv(); err != nil {
		t.Fatalf("first message rejected: %v", err)
	}
	// replay seq=1 -> rejected.
	inject(endA, signedFrame(t, keyA, sid, 1, PtChat, []byte("one")))
	if _, _, err := sb.Recv(); err == nil {
		t.Fatal("replayed seq accepted (F-11)")
	}
	// jump to seq=5 accepted.
	inject(endA, signedFrame(t, keyA, sid, 5, PtChat, []byte("five")))
	if _, _, err := sb.Recv(); err != nil {
		t.Fatalf("seq=5 rejected: %v", err)
	}
	// reordered seq=3 (behind 5) -> rejected.
	inject(endA, signedFrame(t, keyA, sid, 3, PtChat, []byte("three")))
	if _, _, err := sb.Recv(); err == nil {
		t.Fatal("reordered/stale seq accepted (F-11)")
	}
}

// F-12: a malformed / truncated frame is rejected at parse, not a crash.
//
//trace:test NET-1
func TestMalformedFrameRejected(t *testing.T) {
	_, sb, endA, _, _, _ := pairBoth(t)
	inject(endA, []byte("this is not a json envelope"))
	if _, _, err := sb.Recv(); err == nil {
		t.Fatal("malformed frame accepted (F-12)")
	}
	// Truncated JSON.
	inject(endA, []byte(`{"session_id":`))
	if _, _, err := sb.Recv(); err == nil {
		t.Fatal("truncated frame accepted (F-12)")
	}
}

// A HELLO whose signature does not match the claimed pubkey fails pairing
// (mutual authentication).
//
//trace:test NET-1
func TestPairingRejectsBadHelloSignature(t *testing.T) {
	endA, endB := NewPipe(16)
	keyA, keyB := mustKey(t), mustKey(t)
	// A sends a HELLO signed by a DIFFERENT key than it claims.
	imposter := mustKey(t)
	hp := helloPayload{PubKey: keyA.PubKey().Compressed(), Nonce: make16("a"), Version: helloVersion}
	body, _ := json.Marshal(hp)
	env := Envelope{FromPubKey: keyA.PubKey().Compressed(), PayloadType: PtHello, Payload: body}
	sig, _ := imposter.Sign(env.sigHash()) // wrong signer
	env.Sig = sig.Serialize()
	raw, _ := json.Marshal(env)
	go func() { inject(endA, raw) }()
	if _, err := Pair(endB, keyB, make16("b")); err == nil {
		t.Fatal("pairing accepted a HELLO not signed by the claimed identity")
	}
}
