package wallet

import (
	"path/filepath"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

//trace:test SC-1
func TestFileKeystore_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ks.json")
	ks, err := OpenFileKeystore(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	k, _ := ec.NewPrivateKey()
	if err := ks.Put("alice", k); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Reopen with the right passphrase and recover the same key.
	ks2, err := OpenFileKeystore(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := ks2.Get("alice")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Hex() != k.Hex() {
		t.Errorf("recovered key differs")
	}
}

//trace:test SC-1
func TestFileKeystore_WrongPassphraseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ks.json")
	ks, _ := OpenFileKeystore(path, "right-pass")
	k, _ := ec.NewPrivateKey()
	_ = ks.Put("k", k)
	if _, err := OpenFileKeystore(path, "wrong-pass"); err == nil {
		t.Fatal("wrong passphrase unlocked the store (AES-GCM auth must fail)")
	}
}
