package netstack

import (
	"context"
	"testing"

	"github.com/prof-faustus/nft-wallet-bsv/internal/discovery"
)

type env struct {
	to, from string
	e        Envelope
}

// pump drives composed envelopes between two routers (by id) until quiescent.
func pump(t *testing.T, nodes map[string]*Router, initial []env) {
	t.Helper()
	q := append([]env(nil), initial...)
	for steps := 0; len(q) > 0 && steps < 300; steps++ {
		cur := q[0]
		q = q[1:]
		replies, err := nodes[cur.to].Route(cur.from, cur.e)
		if err != nil {
			continue
		}
		for _, r := range replies {
			q = append(q, env{to: cur.from, from: cur.to, e: r})
		}
	}
}

func naddr(id string) discovery.NetAddr {
	return discovery.NetAddr{ID: id, Host: id + ".local", Port: 8333, Services: discovery.ServiceRelay}
}

// The composed router does BOTH tiers: A and B complete the discovery
// handshake, then an object A publishes is relayed to B (and B can retrieve
// it) — all over the single Envelope wire.
func TestRouterComposesDiscoveryAndRelay(t *testing.T) {
	const stream uint32 = 42
	a := New(naddr("A"), 1, 4, 3600, stream)
	b := New(naddr("B"), 2, 4, 3600, stream)
	nodes := map[string]*Router{"A": a, "B": b}

	// Tier A handshake.
	var init []env
	for _, e := range a.Hello(naddr("B")) {
		init = append(init, env{to: "B", from: "A", e: e})
	}
	pump(t, nodes, init)
	if !a.HandshakeDone("B") || !b.HandshakeDone("A") {
		t.Fatal("composed handshake did not complete")
	}

	// Tier B: A publishes an object; announce flows to B; B fetches + stores.
	_, announce, err := a.Publish(context.Background(), stream, []byte("a channel frame"))
	if err != nil {
		t.Fatal(err)
	}
	deliver := make([]env, 0, len(announce))
	for _, e := range announce {
		deliver = append(deliver, env{to: "B", from: "A", e: e})
	}
	pump(t, nodes, deliver)

	got := b.Received(stream)
	if len(got) != 1 || string(got[0].Payload) != "a channel frame" {
		t.Fatalf("object did not relay to B over the composed stack: %v", got)
	}
}

func TestEnvelopeCodecRoundTrip(t *testing.T) {
	a := New(naddr("A"), 1, 4, 3600, 1)
	for _, e := range a.Hello(naddr("B")) {
		raw, err := Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got.Tier != e.Tier || got.A == nil {
			t.Fatalf("round-trip lost the Tier-A message: %+v", got)
		}
	}
}
