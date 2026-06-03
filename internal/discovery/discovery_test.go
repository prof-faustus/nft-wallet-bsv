package discovery

import "testing"

// envelope is one in-flight message between nodes in the test pump.
type envelope struct {
	to, from string
	msg      Message
}

// pump delivers messages between nodes (by id) until quiescent, modelling a
// transport with no sockets. Returns when the queue drains or the cap hits.
func pump(t *testing.T, nodes map[string]*Node, initial []envelope) {
	t.Helper()
	q := append([]envelope(nil), initial...)
	for steps := 0; len(q) > 0 && steps < 200; steps++ {
		e := q[0]
		q = q[1:]
		n := nodes[e.to]
		if n == nil {
			t.Fatalf("no node %q", e.to)
		}
		replies, err := n.Handle(e.from, e.msg)
		if err != nil {
			continue // a rejected message produces no replies
		}
		for _, r := range replies {
			q = append(q, envelope{to: e.from, from: e.to, msg: r})
		}
	}
}

func addr(id string) NetAddr {
	return NetAddr{ID: id, Host: id + ".local", Port: 8333, Services: ServiceRelay}
}

func TestHandshakeCompletes(t *testing.T) {
	a := NewNode(addr("A"), 1111)
	b := NewNode(addr("B"), 2222)
	nodes := map[string]*Node{"A": a, "B": b}
	// A initiates to B.
	init := []envelope{}
	for _, m := range a.Connect(addr("B")) {
		init = append(init, envelope{to: "B", from: "A", msg: m})
	}
	pump(t, nodes, init)
	if !a.HandshakeDone("B") {
		t.Fatal("A did not complete the handshake with B")
	}
	if !b.HandshakeDone("A") {
		t.Fatal("B did not complete the handshake with A")
	}
	// Each learned the other's advertised address.
	if _, ok := nodeBook(b)["A"]; !ok {
		t.Fatal("B did not learn A's address from the version")
	}
}

func TestAddrGossipPropagates(t *testing.T) {
	a := NewNode(addr("A"), 1)
	b := NewNode(addr("B"), 2)
	nodes := map[string]*Node{"A": a, "B": b}
	// A already knows C, D, E.
	for _, id := range []string{"C", "D", "E"} {
		a.AddKnown(addr(id))
	}
	// Handshake, then B asks A for addresses.
	init := []envelope{}
	for _, m := range a.Connect(addr("B")) {
		init = append(init, envelope{to: "B", from: "A", msg: m})
	}
	pump(t, nodes, init)
	pump(t, nodes, []envelope{{to: "A", from: "B", msg: Message{Kind: KindGetAddr}}})

	for _, id := range []string{"C", "D", "E"} {
		if _, ok := nodeBook(b)[id]; !ok {
			t.Fatalf("B did not learn peer %s via addr gossip", id)
		}
	}
	// getaddr must not echo the requester back to itself.
	if _, ok := nodeBook(b)["B"]; ok {
		t.Fatal("addr gossip echoed B back to itself")
	}
}

func TestPingPong(t *testing.T) {
	b := NewNode(addr("B"), 9)
	// Force handshake state so ping is allowed.
	b.peerFor("A").handshakeDone = true
	out, err := b.Handle("A", Message{Kind: KindPing, Nonce: 0xCAFE})
	if err != nil || len(out) != 1 || out[0].Kind != KindPong || out[0].Nonce != 0xCAFE {
		t.Fatalf("ping did not yield matching pong: %v %v", out, err)
	}
}

func TestRejectOldVersion(t *testing.T) {
	b := NewNode(addr("B"), 5)
	if _, err := b.Handle("A", Message{Kind: KindVersion, Version: 0, Nonce: 7, From: addr("A")}); err == nil {
		t.Fatal("accepted a below-minimum version")
	}
	if !b.Banned("A") {
		t.Fatal("an unsupported-version peer should be banned")
	}
}

func TestRejectSelfConnect(t *testing.T) {
	a := NewNode(addr("A"), 4242)
	// A receives a Version echoing its OWN nonce.
	if _, err := a.Handle("X", Message{Kind: KindVersion, Version: ProtocolVersion, Nonce: 4242, From: addr("X")}); err == nil {
		t.Fatal("accepted a self-connection nonce")
	}
	if !a.Banned("X") {
		t.Fatal("self-connection peer should be banned")
	}
}

func TestRejectMessageBeforeHandshake(t *testing.T) {
	b := NewNode(addr("B"), 5)
	if _, err := b.Handle("A", Message{Kind: KindGetAddr}); err == nil {
		t.Fatal("accepted getaddr before handshake")
	}
	if b.Score("A") == 0 {
		t.Fatal("pre-handshake message should incur a score")
	}
}

func TestOversizedAddrMisbehaves(t *testing.T) {
	b := NewNode(addr("B"), 5)
	ps := b.peerFor("A")
	ps.handshakeDone = true
	big := make([]NetAddr, MaxAddrPerMessage+1)
	if _, err := b.Handle("A", Message{Kind: KindAddr, Addrs: big}); err == nil {
		t.Fatal("accepted an oversized addr message")
	}
	if b.Score("A") < 50 {
		t.Fatal("oversized addr should incur >=50 score")
	}
}

func TestBannedPeerRejected(t *testing.T) {
	b := NewNode(addr("B"), 5)
	b.peerFor("A").handshakeDone = true
	b.Misbehave("A", DefaultBanScore)
	if !b.Banned("A") {
		t.Fatal("peer should be banned at threshold")
	}
	if _, err := b.Handle("A", Message{Kind: KindPing}); err == nil {
		t.Fatal("banned peer's message was processed")
	}
}

func TestCodecRoundTrip(t *testing.T) {
	msgs := []Message{
		{Kind: KindVersion, Version: ProtocolVersion, Nonce: 12345, From: addr("A")},
		{Kind: KindVerAck},
		{Kind: KindAddr, Addrs: []NetAddr{addr("C"), addr("D")}},
		{Kind: KindPing, Nonce: 99},
	}
	for _, m := range msgs {
		b, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		if got.Kind != m.Kind || got.Nonce != m.Nonce || len(got.Addrs) != len(m.Addrs) {
			t.Fatalf("round-trip mismatch: %+v vs %+v", got, m)
		}
	}
}

// nodeBook is a test accessor for the address book as a map.
func nodeBook(n *Node) map[string]NetAddr {
	out := map[string]NetAddr{}
	for _, a := range n.KnownPeers() {
		out[a.ID] = a
	}
	return out
}
