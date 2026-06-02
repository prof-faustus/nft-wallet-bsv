package channel

import "testing"

// Message fuzzing (docs/05 §5.6): arbitrary bytes delivered by the
// hostile transport must NEVER crash the channel and must NEVER be
// accepted as a valid message (no advance on an unsigned/forged/malformed
// frame). Run as `go test` (seed corpus) or `go test -fuzz=FuzzRecv`.
//
//trace:test NET-1
func FuzzRecv(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("not json at all"))
	f.Add([]byte(`{"session_id":null,"seq":1,"payload_type":3}`))
	f.Add([]byte(`{"session_id":"AA==","seq":9999999999,"from_pubkey":"AA==","payload_type":3,"payload":"AA==","sig":"AA=="}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, sb, endA, _, _, _ := pairBoth(t)
		inject(endA, data)
		// The sole invariants: no panic, and recvSeq is not corrupted by a
		// rejected frame. A random blob cannot carry a valid signature for
		// the paired peer, so it must be rejected (err != nil); if it
		// somehow parsed, it must not have advanced state.
		before := sb.recvSeq
		_, _, err := sb.Recv()
		if err == nil {
			t.Fatalf("arbitrary frame accepted: %q", data)
		}
		if sb.recvSeq != before {
			t.Fatalf("rejected frame advanced recvSeq %d -> %d", before, sb.recvSeq)
		}
	})
}
