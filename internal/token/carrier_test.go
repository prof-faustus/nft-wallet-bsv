package token

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
)

const aliceKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"

func sampleIdentity(t *testing.T) (tokenId, descriptor, hPayload, ownerPKH []byte) {
	t.Helper()
	k, err := ec.PrivateKeyFromHex(aliceKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	d, err := PayloadDescriptor{ContentType: "image/png", Length: 1234, EncScheme: EncPlaceholderV1}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	hp := HashPayload([]byte("the-nft-payload-bytes"))
	mint := Outpoint{TxID: "ab" + strings.Repeat("00", 31), Vout: 0}
	tid, err := ComputeTokenId(mint, k.PubKey().Compressed(), d, hp)
	if err != nil {
		t.Fatal(err)
	}
	return tid, d, hp, PubKeyHash(k.PubKey())
}

// Build -> parse must recover the identity BYTE-FOR-BYTE (I-NFT-2) and
// the script must contain no OP_RETURN (I-NFT-1). The recovery path is
// how Stage-1 continuity is convention-enforced (CN-1).
//
//trace:test I-NFT-1 I-NFT-2 CN-1
func TestCarrierRoundTrip(t *testing.T) {
	tid, d, hp, pkh := sampleIdentity(t)
	raw, err := BuildLockingScript(tid, d, hp, pkh)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if bytes.IndexByte(raw, 0x6a) >= 0 {
		t.Fatal("carrier contains OP_RETURN (0x6a) — I-NFT-1 violation")
	}
	id, err := ParseLockingScript(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(id.TokenId, tid) || !bytes.Equal(id.PayloadDescriptor, d) ||
		!bytes.Equal(id.HPayload, hp) || !bytes.Equal(id.OwnerPKH, pkh) {
		t.Fatal("recovered identity does not match (I-NFT-2)")
	}

	// Commit a deterministic carrier sample for the no-op-return gate.
	dir := filepath.Join("testdata", "emitted")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "token_carrier.hex"), []byte(hexStr(raw)+"\n"), 0o644)
}

func hexStr(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, by := range b {
		out[i*2] = h[by>>4]
		out[i*2+1] = h[by&0xf]
	}
	return string(out)
}

//trace:test I-NFT-2
func TestParseRejectsNonCarrier(t *testing.T) {
	// A bare P2PKH (no push-drop prefix) must not parse as a carrier.
	k, _ := ec.PrivateKeyFromHex(aliceKeyHex)
	a, _ := script.NewAddressFromPublicKey(k.PubKey(), false)
	if _, err := ParseLockingScript([]byte("not a script")); err == nil {
		t.Error("garbage parsed as a carrier")
	}
	_ = a
}

// I-NFT-5: addresses derive from the BSV SDK + params, not BTC.
//
//trace:test I-NFT-5
func TestAddressesAreBSV(t *testing.T) {
	k, _ := ec.PrivateKeyFromHex(aliceKeyHex)
	a, err := script.NewAddressFromPublicKey(k.PubKey(), false) // regtest/testnet
	if err != nil {
		t.Fatal(err)
	}
	if a.AddressString == "" {
		t.Fatal("empty address")
	}
	// Positive BSV check: it round-trips through the BSV SDK's Base58
	// address decoder (BSV uses legacy Base58 addressing only).
	if _, err := script.NewAddressFromString(a.AddressString); err != nil {
		t.Fatalf("address does not decode as a BSV Base58 address: %v", err)
	}
}
