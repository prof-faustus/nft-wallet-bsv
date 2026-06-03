package relay_test

import (
	"context"
	"sync"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/prof-faustus/nft-wallet-bsv/internal/channel"
	"github.com/prof-faustus/nft-wallet-bsv/internal/relay"
)

// relayTransport implements channel.Transport over the Tier-B relay: every
// frame the secure channel sends is PoW-stamped as an Object and moved to the
// peer via the real inv → getdata → object exchange, then handed to the
// peer's channel in order. This is the "clean seam" — the Stage-1 channel
// runs UNCHANGED on top of the network (docs/03 §3.8).
type relayTransport struct {
	sendStream uint32
	ownInv     *relay.Inventory
	peerInv    *relay.Inventory
	ownInbox   chan []byte
	peerInbox  chan []byte
	bits       int
	now        int64
	mu         *sync.Mutex // shared: serialize access to the shared inventories
}

func (t *relayTransport) Send(frame []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	o, err := relay.Solve(context.Background(), relay.Object{Stream: t.sendStream, Expiry: t.now + 3600, Payload: frame}, t.bits, relay.MaxSolveAttempts)
	if err != nil {
		return err
	}
	if _, err := t.ownInv.Add(o, t.now); err != nil {
		return err
	}
	// Run the genuine relay exchange: announce inv, peer asks getdata, we
	// serve the object, peer stores it.
	h := relay.Hash32(o.Hash())
	gd, err := t.peerInv.Handle(relay.Message{Kind: relay.KindInv, Inv: []relay.Hash32{h}}, t.now)
	if err != nil {
		return err
	}
	for _, g := range gd {
		objs, err := t.ownInv.Handle(g, t.now)
		if err != nil {
			return err
		}
		for _, om := range objs {
			if _, err := t.peerInv.Handle(om, t.now); err != nil {
				return err
			}
		}
	}
	t.peerInbox <- frame // ordered hand-off to the peer's channel
	return nil
}

func (t *relayTransport) Recv() ([]byte, error) { return <-t.ownInbox, nil }

// link cross-wires two relay-backed transports on their own receive streams.
func link(bits int) (a, b *relayTransport) {
	const streamA, streamB uint32 = 1, 2
	// Both nodes serve the session's relay group (both streams).
	invA := relay.NewInventory(bits, true, streamA, streamB)
	invB := relay.NewInventory(bits, true, streamA, streamB)
	inboxA := make(chan []byte, 64)
	inboxB := make(chan []byte, 64)
	mu := &sync.Mutex{}
	a = &relayTransport{sendStream: streamB, ownInv: invA, peerInv: invB, ownInbox: inboxA, peerInbox: inboxB, bits: bits, now: 1000, mu: mu}
	b = &relayTransport{sendStream: streamA, ownInv: invB, peerInv: invA, ownInbox: inboxB, peerInbox: inboxA, bits: bits, now: 1000, mu: mu}
	return a, b
}

// A real secure channel pairs (mutual auth) and exchanges an authenticated
// message entirely over the Tier-B relay — the network seam works.
//
//trace:test NET-1
func TestChannelOverRelay(t *testing.T) {
	endA, endB := link(4) // low PoW for a fast handshake
	keyA, _ := ec.NewPrivateKey()
	keyB, _ := ec.NewPrivateKey()
	n16 := func(s string) []byte { b := make([]byte, 16); copy(b, s); return b }

	type res struct {
		s   *channel.Session
		err error
	}
	ca, cb := make(chan res, 1), make(chan res, 1)
	go func() { s, err := channel.Pair(endA, keyA, n16("a")); ca <- res{s, err} }()
	go func() { s, err := channel.Pair(endB, keyB, n16("b")); cb <- res{s, err} }()
	ra, rb := <-ca, <-cb
	if ra.err != nil || rb.err != nil {
		t.Fatalf("pair over relay failed: %v / %v", ra.err, rb.err)
	}
	if string(ra.s.SessionID()) != string(rb.s.SessionID()) {
		t.Fatal("both sides must derive the same sessionId over the relay")
	}
	// Exchange an authenticated application message over the relay.
	if err := ra.s.Send(channel.PtChat, []byte("hello over the network")); err != nil {
		t.Fatalf("send over relay: %v", err)
	}
	pt, payload, err := rb.s.Recv()
	if err != nil || pt != channel.PtChat || string(payload) != "hello over the network" {
		t.Fatalf("recv over relay: pt=%d payload=%q err=%v", pt, payload, err)
	}

	// The relay genuinely stored the objects it carried (store-and-forward
	// holds them until expiry).
	if len(endB.ownInv.ForStream(2)) == 0 {
		t.Fatal("relay did not retain the carried objects")
	}
}
