package relay_test

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/prof-faustus/nft-wallet-bsv/internal/channel"
	"github.com/prof-faustus/nft-wallet-bsv/internal/discovery"
)

// dEnvelope is one in-flight Tier-A message in the inline discovery pump.
type dEnvelope struct {
	to, from string
	msg      discovery.Message
}

func dpump(t *testing.T, nodes map[string]*discovery.Node, initial []dEnvelope) {
	t.Helper()
	q := append([]dEnvelope(nil), initial...)
	for steps := 0; len(q) > 0 && steps < 200; steps++ {
		e := q[0]
		q = q[1:]
		replies, err := nodes[e.to].Handle(e.from, e.msg)
		if err != nil {
			continue
		}
		for _, r := range replies {
			q = append(q, dEnvelope{to: e.from, from: e.to, msg: r})
		}
	}
}

func dAddr(id string) discovery.NetAddr {
	return discovery.NetAddr{ID: id, Host: id + ".local", Port: 8333, Services: discovery.ServiceRelay}
}

// FULL STACK: a node (A) DISCOVERS a peer (B) via Tier A (handshake + addr
// gossip), then the two open a real secure CHANNEL over the Tier-B object
// RELAY and complete an exchange-protocol message. This proves the three
// tiers compose into one end-to-end network flow (docs/03 §3.8): discovery
// → relay → the Stage-1 channel/exchange, all unchanged.
//
//trace:test NET-1
func TestFullStack_DiscoverThenChannelExchange(t *testing.T) {
	// ---- Tier A: A discovers B (and learns C via gossip) ----
	a := discovery.NewNode(dAddr("A"), 11)
	b := discovery.NewNode(dAddr("B"), 22)
	b.AddKnown(dAddr("C")) // B already knows C; A should learn it via getaddr
	nodes := map[string]*discovery.Node{"A": a, "B": b}

	var init []dEnvelope
	for _, m := range a.Connect(dAddr("B")) {
		init = append(init, dEnvelope{to: "B", from: "A", msg: m})
	}
	dpump(t, nodes, init)
	dpump(t, nodes, []dEnvelope{{to: "B", from: "A", msg: discovery.Message{Kind: discovery.KindGetAddr}}})

	if !a.HandshakeDone("B") || !b.HandshakeDone("A") {
		t.Fatal("Tier-A handshake did not complete both ways")
	}
	if _, ok := dBook(a)["C"]; !ok {
		t.Fatal("A did not discover C via addr gossip")
	}

	// ---- Tier B + channel: A and B exchange over the relay ----
	endA, endB := link(4) // relay-backed channel transports (low PoW)
	keyA, _ := ec.NewPrivateKey()
	keyB, _ := ec.NewPrivateKey()
	n16 := func(s string) []byte { v := make([]byte, 16); copy(v, s); return v }
	type res struct {
		s   *channel.Session
		err error
	}
	ca, cb := make(chan res, 1), make(chan res, 1)
	go func() { s, err := channel.Pair(endA, keyA, n16("a")); ca <- res{s, err} }()
	go func() { s, err := channel.Pair(endB, keyB, n16("b")); cb <- res{s, err} }()
	ra, rb := <-ca, <-cb
	if ra.err != nil || rb.err != nil {
		t.Fatalf("channel pair over relay failed: %v / %v", ra.err, rb.err)
	}
	// An exchange-protocol message (a price offer) flows over the network.
	if err := ra.s.Send(channel.PtOffer, []byte("offer: 2000000 sats")); err != nil {
		t.Fatalf("send offer over network: %v", err)
	}
	pt, payload, err := rb.s.Recv()
	if err != nil || pt != channel.PtOffer || string(payload) != "offer: 2000000 sats" {
		t.Fatalf("offer did not arrive over the network: pt=%d %q %v", pt, payload, err)
	}
}

func dBook(n *discovery.Node) map[string]discovery.NetAddr {
	out := map[string]discovery.NetAddr{}
	for _, a := range n.KnownPeers() {
		out[a.ID] = a
	}
	return out
}
