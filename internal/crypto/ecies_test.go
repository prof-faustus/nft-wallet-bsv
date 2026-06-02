package crypto

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestAEADRoundTripAndTamper(t *testing.T) {
	k, _ := NewContentKey()
	pt := []byte("the unique NFT payload")
	blob, err := AEADSeal(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AEADOpen(k, blob)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round-trip: %v / %q", err, got)
	}
	// Tamper a ciphertext byte → auth fails.
	blob[len(blob)-1] ^= 0xff
	if _, err := AEADOpen(k, blob); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	// Wrong key → fails.
	k2, _ := NewContentKey()
	blob2, _ := AEADSeal(k, pt)
	if _, err := AEADOpen(k2, blob2); err == nil {
		t.Fatal("wrong key opened")
	}
}

func TestECDHSymmetric(t *testing.T) {
	a, _ := ec.NewPrivateKey()
	b, _ := ec.NewPrivateKey()
	ka, err := ECDHKey(a, b.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ECDHKey(b, a.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatal("ECDH not symmetric")
	}
	if len(ka) != KeyLen {
		t.Fatalf("derived key len %d", len(ka))
	}
	// A different counterparty yields a different key.
	c, _ := ec.NewPrivateKey()
	kc, _ := ECDHKey(a, c.PubKey())
	if bytes.Equal(ka, kc) {
		t.Fatal("ECDH key collision across counterparties")
	}
}
