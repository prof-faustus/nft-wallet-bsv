// Package discovery is the Tier-A, Bitcoin-style peer-discovery layer of the
// full network (docs/03 §3.8, formal-architecture §7.8). It replaces the
// Stage-1 minimal two-party pairing's assumption of an out-of-band rendezvous
// with a real discovery protocol: a version/verack handshake, getaddr/addr
// peer exchange, ping/pong liveness, and peer scoring + banning.
//
// It is TRANSPORT-AGNOSTIC and side-effect-free: Node.Handle(from, msg)
// returns the messages to send in reply, so the whole protocol is driven and
// tested without sockets or goroutines (the Stage-1 "hostile transport"
// model — the secure channel rides on top unchanged). A real transport just
// pipes Message bytes (Encode/Decode) between nodes.
//
// MUST NOT: import BTC libraries or carry BTC chain assumptions. This is a
// peer-gossip protocol modelled on Bitcoin's, implemented from scratch; it
// touches no chain and no scripts (so no OP_RETURN surface).
//
//trace:impl NET-1
package discovery

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ProtocolVersion is this node's wire version; MinPeerVersion is the lowest
// peer version we will complete a handshake with.
const (
	ProtocolVersion = 1
	MinPeerVersion  = 1
)

// Limits (named, not magic — docs/06 §6 doc standard).
const (
	MaxAddrPerMessage = 1000 // an Addr carrying more is misbehaviour
	GetAddrSample     = 23   // peers returned per getaddr (Bitcoin-ish)
	DefaultBanScore   = 100  // score at/above which a peer is banned
)

// Services is a bitfield of advertised capabilities.
type Services uint64

const (
	// ServiceRelay: the peer relays Tier-B objects (see internal/relay).
	ServiceRelay Services = 1 << iota
)

// NetAddr identifies a peer.
type NetAddr struct {
	ID       string   `json:"id"` // stable peer id (e.g. pubkey hash / node id)
	Host     string   `json:"host"`
	Port     uint16   `json:"port"`
	Services Services `json:"services"`
	LastSeen int64    `json:"last_seen"`
}

// Kind tags a wire message.
type Kind string

const (
	KindVersion Kind = "version"
	KindVerAck  Kind = "verack"
	KindGetAddr Kind = "getaddr"
	KindAddr    Kind = "addr"
	KindPing    Kind = "ping"
	KindPong    Kind = "pong"
)

// Message is a single tagged wire message (one optional payload per Kind).
type Message struct {
	Kind    Kind      `json:"kind"`
	Version int       `json:"version,omitempty"`
	Nonce   uint64    `json:"nonce,omitempty"`
	From    NetAddr   `json:"from,omitempty"`
	Addrs   []NetAddr `json:"addrs,omitempty"`
}

// Encode/Decode are the wire codec a real transport uses.
func Encode(m Message) ([]byte, error) { return json.Marshal(m) }
func Decode(b []byte) (Message, error) {
	var m Message
	err := json.Unmarshal(b, &m)
	return m, err
}

type peerState struct {
	addr          NetAddr
	theirVersion  int
	sentVersion   bool
	gotVersion    bool
	handshakeDone bool
	score         int
	banned        bool
}

// Node is a local discovery node. Not safe for concurrent use; a transport
// serializes calls per peer (or guards with its own lock).
type Node struct {
	self         NetAddr
	nonce        uint64 // self-connection detector
	banThreshold int
	book         map[string]NetAddr // known peers by id
	peers        map[string]*peerState
}

// NewNode builds a node with a self-connection nonce. The nonce should be
// random in production; tests pass a fixed value.
func NewNode(self NetAddr, nonce uint64) *Node {
	return &Node{
		self:         self,
		nonce:        nonce,
		banThreshold: DefaultBanScore,
		book:         map[string]NetAddr{},
		peers:        map[string]*peerState{},
	}
}

// Connect initiates a handshake to addr: returns the Version to send.
func (n *Node) Connect(addr NetAddr) []Message {
	ps := n.peerFor(addr.ID)
	ps.addr = addr
	ps.sentVersion = true
	return []Message{n.versionMsg()}
}

func (n *Node) versionMsg() Message {
	return Message{Kind: KindVersion, Version: ProtocolVersion, Nonce: n.nonce, From: n.self}
}

func (n *Node) peerFor(id string) *peerState {
	ps, ok := n.peers[id]
	if !ok {
		ps = &peerState{addr: NetAddr{ID: id}}
		n.peers[id] = ps
	}
	return ps
}

// Handle processes an inbound message from peer `from` and returns the
// replies to send. A banned peer yields an error and no replies.
//
//trace:impl NET-1
func (n *Node) Handle(from string, m Message) ([]Message, error) {
	ps := n.peerFor(from)
	if ps.banned {
		return nil, fmt.Errorf("discovery: peer %s is banned", from)
	}
	// Only Version is allowed before the handshake completes.
	if !ps.handshakeDone && m.Kind != KindVersion && m.Kind != KindVerAck {
		n.misbehave(ps, 20)
		return nil, fmt.Errorf("discovery: %q before handshake from %s", m.Kind, from)
	}

	switch m.Kind {
	case KindVersion:
		return n.onVersion(ps, m)
	case KindVerAck:
		ps.handshakeDone = ps.gotVersion && ps.sentVersion
		return nil, nil
	case KindGetAddr:
		return []Message{{Kind: KindAddr, Addrs: n.sampleAddrs(from)}}, nil
	case KindAddr:
		return n.onAddr(ps, m)
	case KindPing:
		return []Message{{Kind: KindPong, Nonce: m.Nonce}}, nil
	case KindPong:
		return nil, nil
	default:
		n.misbehave(ps, 10)
		return nil, fmt.Errorf("discovery: unknown message kind %q", m.Kind)
	}
}

func (n *Node) onVersion(ps *peerState, m Message) ([]Message, error) {
	// Self-connection: the peer echoed our own nonce.
	if m.Nonce == n.nonce {
		n.misbehave(ps, n.banThreshold) // ban a loopback/forgery
		return nil, fmt.Errorf("discovery: self-connection nonce")
	}
	if m.Version < MinPeerVersion {
		n.misbehave(ps, n.banThreshold)
		return nil, fmt.Errorf("discovery: peer version %d < min %d", m.Version, MinPeerVersion)
	}
	ps.theirVersion = m.Version
	ps.gotVersion = true
	if m.From.ID != "" {
		ps.addr = m.From
		n.AddKnown(m.From)
	}
	var out []Message
	// If we haven't sent our Version yet (we are the responder), send it now.
	if !ps.sentVersion {
		ps.sentVersion = true
		out = append(out, n.versionMsg())
	}
	out = append(out, Message{Kind: KindVerAck})
	// Completing the handshake may need the peer's VerAck too; mark partial.
	if ps.gotVersion && ps.sentVersion {
		// handshake completes when VerAck is received (KindVerAck above).
	}
	return out, nil
}

func (n *Node) onAddr(ps *peerState, m Message) ([]Message, error) {
	if len(m.Addrs) > MaxAddrPerMessage {
		n.misbehave(ps, 50)
		return nil, fmt.Errorf("discovery: addr too large (%d > %d)", len(m.Addrs), MaxAddrPerMessage)
	}
	for _, a := range m.Addrs {
		if a.ID != "" && a.ID != n.self.ID {
			n.AddKnown(a)
		}
	}
	return nil, nil
}

// AddKnown records a peer address in the address book.
func (n *Node) AddKnown(a NetAddr) {
	if a.ID == "" || a.ID == n.self.ID {
		return
	}
	n.book[a.ID] = a
}

// sampleAddrs returns up to GetAddrSample known peers, excluding the
// requester (deterministic order for testability).
func (n *Node) sampleAddrs(exclude string) []NetAddr {
	ids := make([]string, 0, len(n.book))
	for id := range n.book {
		if id != exclude {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > GetAddrSample {
		ids = ids[:GetAddrSample]
	}
	out := make([]NetAddr, 0, len(ids))
	for _, id := range ids {
		out = append(out, n.book[id])
	}
	return out
}

// KnownPeers returns the address book (sorted by id).
func (n *Node) KnownPeers() []NetAddr {
	ids := make([]string, 0, len(n.book))
	for id := range n.book {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]NetAddr, 0, len(ids))
	for _, id := range ids {
		out = append(out, n.book[id])
	}
	return out
}

// HandshakeDone reports whether the handshake with peer id completed.
func (n *Node) HandshakeDone(id string) bool {
	ps, ok := n.peers[id]
	return ok && ps.handshakeDone
}

// Misbehave adds score to a peer; at/above the ban threshold it is banned.
//
//trace:impl NET-1
func (n *Node) Misbehave(id string, points int) { n.misbehave(n.peerFor(id), points) }

func (n *Node) misbehave(ps *peerState, points int) {
	ps.score += points
	if ps.score >= n.banThreshold {
		ps.banned = true
	}
}

// Banned reports whether peer id is banned.
func (n *Node) Banned(id string) bool {
	ps, ok := n.peers[id]
	return ok && ps.banned
}

// Score returns a peer's current misbehaviour score.
func (n *Node) Score(id string) int {
	ps, ok := n.peers[id]
	if !ok {
		return 0
	}
	return ps.score
}
