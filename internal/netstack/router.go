// Package netstack composes the two network tiers (internal/discovery Tier A
// + internal/relay Tier B) into a single node "router": one object that does
// the peer handshake/gossip AND the object relay, behind a unified Envelope.
// It is the pure, transport-agnostic core that cmd/netnode wraps in TCP — so
// the routing logic is tested with no sockets (Route returns the replies to
// send), exactly like the tiers it composes.
//
// The secure channel (internal/channel) rides on top as Tier-B object
// payloads — the clean seam (docs/03 §3.8). netstack neither reads nor needs
// the plaintext.
//
// MUST NOT: import BTC; touch chain/scripts.
//
//trace:impl NET-1
package netstack

import (
	"encoding/json"
	"time"

	"github.com/prof-faustus/nft-wallet-bsv/internal/discovery"
	"github.com/prof-faustus/nft-wallet-bsv/internal/relay"
)

// Tier selects which protocol an Envelope carries.
type Tier string

const (
	TierA Tier = "A" // discovery
	TierB Tier = "B" // relay
)

// Envelope is the single wire unit: exactly one of A/B is set.
type Envelope struct {
	Tier Tier               `json:"tier"`
	A    *discovery.Message `json:"a,omitempty"`
	B    *relay.Message     `json:"b,omitempty"`
}

// Encode/Decode are the wire codec the TCP transport uses.
func Encode(e Envelope) ([]byte, error) { return json.Marshal(e) }
func Decode(b []byte) (Envelope, error) {
	var e Envelope
	err := json.Unmarshal(b, &e)
	return e, err
}

// Router is a composed network node.
type Router struct {
	disc *discovery.Node
	inv  *relay.Inventory
	now  func() int64
	ttl  int64
}

// New builds a router for a node identity, with a self-connection nonce, the
// relay PoW difficulty, an object TTL (seconds), and the streams it relays.
func New(self discovery.NetAddr, nonce uint64, powBits int, ttlSeconds int64, streams ...uint32) *Router {
	return &Router{
		disc: discovery.NewNode(self, nonce),
		inv:  relay.NewInventory(powBits, true, streams...),
		now:  func() int64 { return time.Now().Unix() },
		ttl:  ttlSeconds,
	}
}

// Hello initiates the Tier-A handshake to a peer; returns envelopes to send.
func (r *Router) Hello(peer discovery.NetAddr) []Envelope {
	return wrapA(r.disc.Connect(peer))
}

// GetAddr asks a peer for more peers (Tier A).
func (r *Router) GetAddr() Envelope {
	m := discovery.Message{Kind: discovery.KindGetAddr}
	return Envelope{Tier: TierA, A: &m}
}

// Route dispatches an inbound envelope to the right tier and returns replies.
//
//trace:impl NET-1
func (r *Router) Route(from string, e Envelope) ([]Envelope, error) {
	switch e.Tier {
	case TierA:
		if e.A == nil {
			return nil, nil
		}
		out, err := r.disc.Handle(from, *e.A)
		return wrapA(out), err
	case TierB:
		if e.B == nil {
			return nil, nil
		}
		out, err := r.inv.Handle(*e.B, r.now())
		return wrapB(out), err
	default:
		return nil, nil
	}
}

// Publish PoW-stamps payload as an object on a stream, stores it locally, and
// returns the inv announcement envelopes to broadcast.
//
//trace:impl NET-1
func (r *Router) Publish(stream uint32, payload []byte) (relay.Object, []Envelope, error) {
	o := relay.Solve(relay.Object{Stream: stream, Expiry: r.now() + r.ttl, Payload: payload}, r.inv.PoW())
	if _, err := r.inv.Add(o, r.now()); err != nil {
		return o, nil, err
	}
	h := relay.Hash32(o.Hash())
	m := relay.Message{Kind: relay.KindInv, Inv: []relay.Hash32{h}}
	return o, []Envelope{{Tier: TierB, B: &m}}, nil
}

// Received returns the objects this node holds for a stream (store-and-forward).
func (r *Router) Received(stream uint32) []relay.Object { return r.inv.ForStream(stream) }

// HandshakeDone reports whether the Tier-A handshake with id completed.
func (r *Router) HandshakeDone(id string) bool { return r.disc.HandshakeDone(id) }

// KnownPeers returns the discovered address book.
func (r *Router) KnownPeers() []discovery.NetAddr { return r.disc.KnownPeers() }

func wrapA(ms []discovery.Message) []Envelope {
	out := make([]Envelope, 0, len(ms))
	for i := range ms {
		m := ms[i]
		out = append(out, Envelope{Tier: TierA, A: &m})
	}
	return out
}
func wrapB(ms []relay.Message) []Envelope {
	out := make([]Envelope, 0, len(ms))
	for i := range ms {
		m := ms[i]
		out = append(out, Envelope{Tier: TierB, B: &m})
	}
	return out
}
