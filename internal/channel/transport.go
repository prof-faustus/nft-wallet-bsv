// Transport is the pluggable, UNTRUSTED carrier beneath the secure
// channel (docs/03 §3.2; OD-8 relay/WebSocket/WebRTC). The channel logic
// is transport-agnostic so the §5.6 fault interposer can sit on it.
//
// This file provides the interface, an in-memory pipe (for tests and the
// in-harness default), and a fault-injecting interposer that can drop,
// duplicate, reorder, truncate, or forge frames — the adversary the
// channel must withstand (NET-1; F-11..F-13).
package channel

// Transport moves opaque frames. It guarantees nothing about order,
// delivery, or integrity — that is the channel's job above it.
type Transport interface {
	Send(frame []byte) error
	Recv() ([]byte, error)
}

// Pipe is an in-memory, buffered, bidirectional transport pair for tests
// and the in-harness default. Buffered so a HELLO send never deadlocks
// against a peer that also sends-then-receives.
type pipeEnd struct {
	out chan []byte
	in  chan []byte
}

func (p *pipeEnd) Send(frame []byte) error {
	cp := make([]byte, len(frame))
	copy(cp, frame)
	p.out <- cp
	return nil
}

func (p *pipeEnd) Recv() ([]byte, error) {
	f, ok := <-p.in
	if !ok {
		return nil, errClosed
	}
	return f, nil
}

// NewPipe returns the two ends of an in-memory transport.
func NewPipe(buffer int) (Transport, Transport) {
	a2b := make(chan []byte, buffer)
	b2a := make(chan []byte, buffer)
	return &pipeEnd{out: a2b, in: b2a}, &pipeEnd{out: b2a, in: a2b}
}

var errClosed = errString("channel: transport closed")

type errString string

func (e errString) Error() string { return string(e) }
