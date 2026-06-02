package threshold

import (
	"testing"
)

func TestSplitReconstruct(t *testing.T) {
	secret, _ := randScalar()
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	// Any 3 distinct shares reconstruct the secret …
	if got, _ := Reconstruct(shares[:3]); got.Cmp(secret) != 0 {
		t.Fatalf("3-of-5 reconstruct mismatch")
	}
	if got, _ := Reconstruct([]Share{shares[0], shares[2], shares[4]}); got.Cmp(secret) != 0 {
		t.Fatalf("a different 3-of-5 set must reconstruct the same secret")
	}
	// … but fewer than t does NOT (threshold property).
	if got, _ := Reconstruct(shares[:2]); got.Cmp(secret) == 0 {
		t.Fatalf("2 shares reconstructed the secret — threshold broken")
	}
}

// Dealerless: no single party's sub-secret equals the group secret; any t
// combined shares reconstruct it.
func TestDealerlessGenerate(t *testing.T) {
	group, shares, err := DealerlessGenerate(3, 5, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Reconstruct([]Share{shares[1], shares[3], shares[4]}); got.Cmp(group) != 0 {
		t.Fatalf("dealerless 3-of-5 reconstruct mismatch")
	}
	if got, _ := Reconstruct(shares[:2]); got.Cmp(group) == 0 {
		t.Fatalf("2 shares reconstructed the dealerless group secret")
	}
}

// The reconstructed secret IS a working secp256k1 ECDSA key — i.e. this
// is dealerless THRESHOLD ECDSA key generation (reconstruct-to-sign).
func TestThresholdKeyIsUsableECDSA(t *testing.T) {
	group, shares, err := DealerlessGenerate(2, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	recon, _ := Reconstruct(shares[:2])
	if recon.Cmp(group) != 0 {
		t.Fatal("reconstruct != group")
	}
	priv, pub, err := ScalarToECDSA(recon)
	if err != nil {
		t.Fatal(err)
	}
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	sig, err := priv.Sign(hash)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.Verify(hash, pub) {
		t.Fatal("signature from threshold-reconstructed key did not verify")
	}
	// Sanity: the group secret yields the same key.
	priv2, _, _ := ScalarToECDSA(group)
	if priv2.Hex() != priv.Hex() {
		t.Fatal("reconstructed key differs from group-secret key")
	}
}
