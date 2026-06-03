// Package relay is the Tier-B, Bitmessage-style object relay of the full
// network (docs/03 §3.8, formal-architecture §7.8). Peers gossip opaque,
// proof-of-work-stamped, expiring OBJECTS by hash (inv / getdata / object)
// within a STREAM (the table-/session-scoped relay group). A recipient
// retrieves objects addressed to its stream even if it was offline when they
// were sent (store-and-forward) — the inventory holds them until expiry.
//
// The object payload is opaque to the relay: it is the Stage-1 secure-channel
// frame (internal/channel). The relay neither reads nor needs the plaintext;
// only the holder of the channel key decrypts. The secure channel therefore
// rides UNCHANGED on top of either minimal pairing (Stage 1) or this network
// (the "clean seam") — see relayseam_test for a channel running over it.
//
// Transport-agnostic and side-effect-free: Inventory.Handle(msg) returns the
// replies to send. Proof-of-work (leading-zero bits of the object hash) is
// the anti-spam gate; expiry bounds storage; a stream allowlist scopes relay.
//
// MUST NOT: import BTC; touch chain/scripts (no OP_RETURN surface).
//
//trace:impl NET-1
package relay

import (
	"encoding/binary"

	hash "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// Limits (named, not magic).
const (
	MaxPayloadBytes = 256 * 1024 // an object payload larger than this is rejected
)

// Object is a relayed, opaque, expiring, PoW-stamped blob.
type Object struct {
	Stream  uint32 `json:"stream"`  // the relay group (session/table scope)
	Expiry  int64  `json:"expiry"`  // unix seconds; relays drop after this
	Nonce   uint64 `json:"nonce"`   // proof-of-work nonce (set by Solve)
	Payload []byte `json:"payload"` // opaque (a secure-channel frame)
}

// serialize is the canonical byte layout the object hash covers (includes the
// PoW nonce, so the hash is both the identity AND the PoW proof).
func (o Object) serialize() []byte {
	b := make([]byte, 0, 4+8+8+len(o.Payload))
	var n4 [4]byte
	binary.LittleEndian.PutUint32(n4[:], o.Stream)
	b = append(b, n4[:]...)
	var n8 [8]byte
	binary.LittleEndian.PutUint64(n8[:], uint64(o.Expiry))
	b = append(b, n8[:]...)
	binary.LittleEndian.PutUint64(n8[:], o.Nonce)
	b = append(b, n8[:]...)
	b = append(b, o.Payload...)
	return b
}

// Hash is the object identity (sha256d of serialize). Leading-zero bits of
// this hash are the proof-of-work.
func (o Object) Hash() [32]byte {
	var h [32]byte
	copy(h[:], hash.Sha256d(o.serialize()))
	return h
}

// leadingZeroBits counts the leading zero bits of h.
func leadingZeroBits(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if b&mask != 0 {
				return n
			}
			n++
		}
		break
	}
	return n
}

// PoWBits returns the object's achieved proof-of-work (leading zero bits).
func (o Object) PoWBits() int { return leadingZeroBits(o.Hash()) }

// Solve grinds Nonce until the object hash has >= targetBits leading zero
// bits. Deterministic given the object content; returns the solved object.
func Solve(o Object, targetBits int) Object {
	for {
		if leadingZeroBits(o.Hash()) >= targetBits {
			return o
		}
		o.Nonce++
	}
}

// Kind tags a Tier-B message.
type Kind string

const (
	KindInv     Kind = "inv"     // announce object hashes held
	KindGetData Kind = "getdata" // request objects by hash
	KindObject  Kind = "object"  // deliver one object
)

// Hash32 is a JSON-friendly 32-byte hash.
type Hash32 [32]byte

// Message is one Tier-B wire message.
type Message struct {
	Kind   Kind     `json:"kind"`
	Inv    []Hash32 `json:"inv,omitempty"`
	Get    []Hash32 `json:"get,omitempty"`
	Object *Object  `json:"object,omitempty"`
}

// Inventory is a node's object store for the streams it relays.
type Inventory struct {
	targetBits int
	streams    map[uint32]bool
	objs       map[Hash32]Object
	relay      bool // when true, re-announce newly accepted objects (gossip)
}

// NewInventory builds an inventory requiring targetBits PoW, relaying the
// given streams.
func NewInventory(targetBits int, relay bool, streams ...uint32) *Inventory {
	inv := &Inventory{targetBits: targetBits, streams: map[uint32]bool{}, objs: map[Hash32]Object{}, relay: relay}
	for _, s := range streams {
		inv.streams[s] = true
	}
	return inv
}

// Subscribe adds a stream to relay/store.
func (inv *Inventory) Subscribe(stream uint32) { inv.streams[stream] = true }

// Add validates and stores an object: sufficient PoW, not expired (at now),
// a subscribed stream, and a bounded payload. Returns (added, error).
//
//trace:impl NET-1
func (inv *Inventory) Add(o Object, now int64) (bool, error) {
	if len(o.Payload) > MaxPayloadBytes {
		return false, errStr("relay: object payload too large")
	}
	if o.Expiry <= now {
		return false, errStr("relay: object expired")
	}
	if !inv.streams[o.Stream] {
		return false, errStr("relay: stream not subscribed")
	}
	if leadingZeroBits(o.Hash()) < inv.targetBits {
		return false, errStr("relay: insufficient proof-of-work")
	}
	h := Hash32(o.Hash())
	if _, ok := inv.objs[h]; ok {
		return false, nil // already have it (not an error)
	}
	inv.objs[h] = o
	return true, nil
}

// Have reports whether the inventory holds object h.
func (inv *Inventory) Have(h Hash32) bool { _, ok := inv.objs[h]; return ok }

// Get returns object h.
func (inv *Inventory) Get(h Hash32) (Object, bool) { o, ok := inv.objs[h]; return o, ok }

// InvList returns the hashes the inventory holds (to announce).
func (inv *Inventory) InvList() []Hash32 {
	out := make([]Hash32, 0, len(inv.objs))
	for h := range inv.objs {
		out = append(out, h)
	}
	return out
}

// ForStream returns the objects held for a stream (a recipient scans these
// and decrypts the one addressed to it — store-and-forward retrieval).
func (inv *Inventory) ForStream(stream uint32) []Object {
	out := []Object{}
	for _, o := range inv.objs {
		if o.Stream == stream {
			out = append(out, o)
		}
	}
	return out
}

// Expire drops objects whose expiry has passed.
func (inv *Inventory) Expire(now int64) {
	for h, o := range inv.objs {
		if o.Expiry <= now {
			delete(inv.objs, h)
		}
	}
}

// Handle processes an inbound Tier-B message at time now and returns replies.
//
//trace:impl NET-1
func (inv *Inventory) Handle(m Message, now int64) ([]Message, error) {
	switch m.Kind {
	case KindInv:
		var want []Hash32
		for _, h := range m.Inv {
			if !inv.Have(h) {
				want = append(want, h)
			}
		}
		if len(want) == 0 {
			return nil, nil
		}
		return []Message{{Kind: KindGetData, Get: want}}, nil
	case KindGetData:
		var out []Message
		for _, h := range m.Get {
			if o, ok := inv.Get(h); ok {
				oc := o
				out = append(out, Message{Kind: KindObject, Object: &oc})
			}
		}
		return out, nil
	case KindObject:
		if m.Object == nil {
			return nil, errStr("relay: object message with no object")
		}
		added, err := inv.Add(*m.Object, now)
		if err != nil {
			return nil, err
		}
		if added && inv.relay {
			h := Hash32(m.Object.Hash())
			return []Message{{Kind: KindInv, Inv: []Hash32{h}}}, nil // gossip
		}
		return nil, nil
	default:
		return nil, errStr("relay: unknown message kind")
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }
