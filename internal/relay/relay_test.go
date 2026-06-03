package relay

import "testing"

const testBits = 8 // low PoW so tests are fast

func obj(stream uint32, expiry int64, payload string) Object {
	return Solve(Object{Stream: stream, Expiry: expiry, Payload: []byte(payload)}, testBits)
}

func TestPoWSolveAndVerify(t *testing.T) {
	o := obj(1, 1_000_000, "hello")
	if o.PoWBits() < testBits {
		t.Fatalf("Solve did not meet target: %d < %d", o.PoWBits(), testBits)
	}
	// An object with a reset nonce almost surely fails the target.
	bad := o
	bad.Nonce = 0
	inv := NewInventory(testBits, false, 1)
	if bad.PoWBits() >= testBits {
		t.Skip("nonce 0 happened to satisfy PoW; rare")
	}
	if _, err := inv.Add(bad, 1); err == nil {
		t.Fatal("accepted an object with insufficient PoW")
	}
}

func TestAddValidation(t *testing.T) {
	inv := NewInventory(testBits, false, 1)
	// not subscribed
	if _, err := inv.Add(obj(2, 1_000_000, "x"), 1); err == nil {
		t.Fatal("accepted an object for an unsubscribed stream")
	}
	// expired
	if _, err := inv.Add(obj(1, 100, "x"), 200); err == nil {
		t.Fatal("accepted an expired object")
	}
	// good
	added, err := inv.Add(obj(1, 1_000_000, "x"), 1)
	if err != nil || !added {
		t.Fatalf("rejected a valid object: %v", err)
	}
}

// inv → getdata → object delivers an object from a sender holding it to a
// receiver that lacks it (the core relay exchange).
func TestInvGetdataObjectExchange(t *testing.T) {
	now := int64(1)
	sender := NewInventory(testBits, true, 7)
	receiver := NewInventory(testBits, true, 7)
	o := obj(7, 1_000_000, "the secret frame")
	if _, err := sender.Add(o, now); err != nil {
		t.Fatal(err)
	}
	h := Hash32(o.Hash())

	// sender announces inv → receiver asks getdata.
	out, err := receiver.Handle(Message{Kind: KindInv, Inv: []Hash32{h}}, now)
	if err != nil || len(out) != 1 || out[0].Kind != KindGetData {
		t.Fatalf("inv did not yield getdata: %v %v", out, err)
	}
	// sender serves getdata → object.
	out, err = sender.Handle(out[0], now)
	if err != nil || len(out) != 1 || out[0].Kind != KindObject {
		t.Fatalf("getdata did not yield object: %v %v", out, err)
	}
	// receiver accepts the object (and gossips an inv).
	out, err = receiver.Handle(out[0], now)
	if err != nil {
		t.Fatal(err)
	}
	if !receiver.Have(h) {
		t.Fatal("receiver did not store the delivered object")
	}
	if len(out) != 1 || out[0].Kind != KindInv {
		t.Fatal("relaying receiver should re-announce (gossip) the new object")
	}
}

// Store-and-forward: the recipient is "offline" when the object is sent; the
// relay holds it; the recipient retrieves it later by scanning its stream.
func TestStoreAndForward(t *testing.T) {
	now := int64(1)
	relayNode := NewInventory(testBits, true, 5)
	o := obj(5, 1_000_000, "deliver later")
	if _, err := relayNode.Add(o, now); err != nil {
		t.Fatal(err)
	}
	// Recipient comes online, subscribed to stream 5, and pulls what the
	// relay holds for it.
	recipient := NewInventory(testBits, false, 5)
	for _, held := range relayNode.ForStream(5) {
		if _, err := recipient.Add(held, now); err != nil {
			t.Fatalf("recipient could not accept stored object: %v", err)
		}
	}
	got := recipient.ForStream(5)
	if len(got) != 1 || string(got[0].Payload) != "deliver later" {
		t.Fatalf("store-and-forward did not deliver: %v", got)
	}
}

func TestExpireDrops(t *testing.T) {
	inv := NewInventory(testBits, false, 1)
	o := obj(1, 500, "ephemeral")
	if _, err := inv.Add(o, 100); err != nil {
		t.Fatal(err)
	}
	inv.Expire(600) // past expiry
	if len(inv.InvList()) != 0 {
		t.Fatal("expired object was not dropped")
	}
}

func TestDuplicateAddIsNoop(t *testing.T) {
	inv := NewInventory(testBits, false, 1)
	o := obj(1, 1_000_000, "dup")
	added1, _ := inv.Add(o, 1)
	added2, err := inv.Add(o, 1)
	if !added1 || added2 || err != nil {
		t.Fatalf("duplicate add not handled: %v %v %v", added1, added2, err)
	}
}

func TestOversizedPayloadRejected(t *testing.T) {
	inv := NewInventory(0, false, 1) // zero PoW so only size gates
	o := Object{Stream: 1, Expiry: 1_000_000, Payload: make([]byte, MaxPayloadBytes+1)}
	if _, err := inv.Add(o, 1); err == nil {
		t.Fatal("accepted an oversized payload")
	}
}
