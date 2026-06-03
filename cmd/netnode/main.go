// Command netnode is a runnable full-network node (docs/03 §3.8): it wraps
// internal/netstack (Tier-A discovery + Tier-B object relay) in a TCP
// transport. Two instances discover each other and relay objects (the
// secure-channel frames ride as opaque object payloads — the clean seam).
//
// Demo (two terminals):
//
//	netnode --id A --addr 127.0.0.1:9701 --stream 42
//	netnode --id B --addr 127.0.0.1:9702 --peer 127.0.0.1:9701 --stream 42 --send "hello over the network"
//
// A prints the object B relays to it. The routing core is tested hermetically
// (internal/netstack, internal/discovery, internal/relay); this binary is the
// thin TCP plumbing.
//
// MUST NOT expose keys (it carries only opaque relay payloads) or import BTC.
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/prof-faustus/nft-wallet-bsv/internal/discovery"
	"github.com/prof-faustus/nft-wallet-bsv/internal/netstack"
)

func main() {
	id := flag.String("id", "node", "this node's id")
	addr := flag.String("addr", "127.0.0.1:9701", "TCP listen address")
	peer := flag.String("peer", "", "peer TCP address to dial (optional)")
	stream := flag.Uint("stream", 42, "relay stream (session-scoped group)")
	pow := flag.Int("pow", 8, "relay proof-of-work difficulty (leading zero bits)")
	ttl := flag.Int64("ttl", 3600, "object TTL seconds")
	send := flag.String("send", "", "if set (and --peer given), publish this payload after the handshake")
	flag.Parse()

	self := discovery.NetAddr{ID: *id, Host: hostOf(*addr), Port: portOf(*addr), Services: discovery.ServiceRelay}
	r := netstack.New(self, uint64(time.Now().UnixNano()), *pow, *ttl, uint32(*stream))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("netnode: listen %s: %v", *addr, err)
	}
	log.Printf("netnode %s: listening on %s (stream=%d, pow=%d)", *id, *addr, *stream, *pow)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(r, c, uint32(*stream), "", false)
		}
	}()

	if *peer != "" {
		c, err := net.Dial("tcp", *peer)
		if err != nil {
			log.Fatalf("netnode: dial %s: %v", *peer, err)
		}
		log.Printf("netnode %s: dialed peer %s", *id, *peer)
		go serve(r, c, uint32(*stream), *send, true)
	}

	select {} // run until killed
}

// serve handles one connection: frames envelopes, routes them, and (for the
// initiator) drives the handshake then optionally publishes a payload.
func serve(r *netstack.Router, c net.Conn, stream uint32, send string, initiator bool) {
	defer c.Close()
	from := c.RemoteAddr().String()
	var wmu sync.Mutex
	write := func(es []netstack.Envelope) {
		wmu.Lock()
		defer wmu.Unlock()
		for _, e := range es {
			b, err := netstack.Encode(e)
			if err != nil {
				continue
			}
			var l [4]byte
			binary.LittleEndian.PutUint32(l[:], uint32(len(b)))
			if _, err := c.Write(l[:]); err != nil {
				return
			}
			_, _ = c.Write(b)
		}
	}

	if initiator {
		write(r.Hello(discovery.NetAddr{ID: from, Host: hostOf(from), Port: portOf(from)}))
	}

	published := false
	seen := 0
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		n := binary.LittleEndian.Uint32(hdr)
		if n == 0 || n > 8<<20 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		e, err := netstack.Decode(buf)
		if err != nil {
			continue
		}
		replies, err := r.Route(from, e)
		if err != nil {
			log.Printf("netnode: route error from %s: %v", from, err)
			continue
		}
		write(replies)

		// Once the handshake completes, the initiator asks for peers and
		// (optionally) publishes its payload exactly once.
		if initiator && r.HandshakeDone(from) {
			if !published {
				write([]netstack.Envelope{r.GetAddr()})
				if send != "" {
					_, ann, perr := r.Publish(stream, []byte(send))
					if perr == nil {
						write(ann)
						log.Printf("netnode: published %q on stream %d", send, stream)
					}
				}
				published = true
			}
		}

		// Print any newly relayed objects.
		if objs := r.Received(stream); len(objs) > seen {
			for _, o := range objs[seen:] {
				log.Printf("netnode: RECEIVED object on stream %d: %q", stream, string(o.Payload))
			}
			seen = len(objs)
		}
	}
}

func hostOf(a string) string {
	h, _, err := net.SplitHostPort(a)
	if err != nil {
		return a
	}
	return h
}

func portOf(a string) uint16 {
	_, p, err := net.SplitHostPort(a)
	if err != nil {
		return 0
	}
	n, _ := net.LookupPort("tcp", p)
	return uint16(n)
}
