package sidecar

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	bsvparams "github.com/prof-faustus/nft-wallet-bsv/internal/params"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

func newTestServer(t *testing.T, eng *engine.Engine) (*Server, *wallet.Wallet) {
	t.Helper()
	ks, err := wallet.OpenFileKeystore(filepath.Join(t.TempDir(), "ks.json"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(ks, bsvparams.Regtest)
	return New(w, eng, 1), w
}

func TestStatusHonest(t *testing.T) {
	eng := engine.New(engine.Buyer)
	s, _ := newTestServer(t, eng)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// Drive to BROADCAST.
	for _, ev := range []engine.EventType{engine.EvStartPairing, engine.EvHelloAckValid, engine.EvOffer, engine.EvAcceptMatches, engine.EvPayloadDeliveredOK, engine.EvSwapAssembled, engine.EvTermsVerifyOK, engine.EvPeerPartialReceived, engine.EvOwnSigned, engine.EvBroadcastAccepted} {
		eng.Apply(engine.Event{Type: ev})
	}
	var st statusResp
	getJSON(t, ts.URL+"/status", &st)
	if st.Success || !st.Pending || !strings.Contains(st.Label, "Pending") {
		t.Fatalf("BROADCAST status not honest pending: %+v", st)
	}
	if strings.Contains(strings.ToLower(st.DeletionLabel), "verified") {
		t.Fatalf("deletion label claims verified: %q", st.DeletionLabel)
	}
	// Confirm.
	eng.Apply(engine.Event{Type: engine.EvConfirmedAtDepth})
	getJSON(t, ts.URL+"/status", &st)
	if !st.Success {
		t.Fatalf("CONFIRMED not success: %+v", st)
	}
}

// The renderer is non-custodial: /address returns an address and NEVER
// the private key (WS7 DoD).
func TestAddressNeverLeaksKey(t *testing.T) {
	s, w := newTestServer(t, engine.New(engine.Seller))
	if _, err := w.NewKey("alice"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	priv, _ := w.Key("alice")
	keyHex := priv.Hex()

	resp, err := http.Get(ts.URL + "/address?label=alice")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "address") {
		t.Fatalf("no address in response: %s", body)
	}
	if strings.Contains(string(body), keyHex) {
		t.Fatal("PRIVATE KEY LEAKED in /address response")
	}
}

// /swap/review returns the exact terms for a correct swap and rejects a
// tampered expectation (the signing prompt is truthful — docs/02 §2.5).
func TestSwapReviewExactTerms(t *testing.T) {
	s, _ := newTestServer(t, engine.New(engine.Seller))
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	alice, _ := ec.NewPrivateKey()
	bob, _ := ec.NewPrivateKey()
	tokenId := bytes32(0xAB)
	hp := bytes32(0xCD)
	descr, _ := token.PayloadDescriptor{ContentType: "x", Length: 1, EncScheme: token.EncPlaceholderV1}.Bytes()
	alicePKH := token.PubKeyHash(alice.PubKey())
	bobPKH := token.PubKeyHash(bob.PubKey())
	aliceAddr, _ := script.NewAddressFromPublicKey(alice.PubKey(), false)
	bobAddr, _ := script.NewAddressFromPublicKey(bob.PubKey(), false)
	carrier, _ := token.LockingScriptHex(tokenId, descr, hp, alicePKH)
	bls, _ := p2pkh.Lock(bobAddr)
	bobLockScript := bls.String()

	const price = 50_000
	sp := token.SwapParams{
		TokenPrevTxID: strings.Repeat("aa", 32), TokenPrevVout: 0, TokenLockScript: carrier, DustSats: 1,
		TokenId: tokenId, Descriptor: descr, HPayload: hp, BobOwnerPKH: bobPKH,
		AliceAddr: aliceAddr.AddressString, PriceSats: price,
		Payments:      []token.PaymentInput{{TxID: strings.Repeat("bb", 32), Vout: 0, LockingScript: bobLockScript, Sats: 200_000}},
		BobChangeAddr: bobAddr.AddressString, ChangeSats: 149_000,
	}
	b, err := token.AssembleSwap(sp, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	txHex, _ := b.Hex()

	req := swapReviewReq{
		TxHex: txHex, TokenIdHex: hex.EncodeToString(tokenId), DescrHex: hex.EncodeToString(descr),
		HPayloadHex: hex.EncodeToString(hp), BobPKHHex: hex.EncodeToString(bobPKH),
		AliceAddr: aliceAddr.AddressString, PriceSats: price, DustSats: 1, MaxOutputs: 3,
	}
	var resp swapReviewResp
	postJSON(t, ts.URL+"/swap/review", req, &resp)
	if !resp.OK || resp.Terms == nil || resp.Terms.PriceToAliceSats != price {
		t.Fatalf("valid swap not reviewed OK with exact terms: %+v", resp)
	}

	// Tampered expectation (wrong price) → rejected, no terms.
	req.PriceSats = 1
	var bad swapReviewResp
	postJSON(t, ts.URL+"/swap/review", req, &bad)
	if bad.OK {
		t.Fatal("tampered-price review accepted")
	}
}

// helpers ------------------------------------------------------------------

func bytes32(b byte) []byte { out := make([]byte, 32); out[0] = b; return out }

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func postJSON(t *testing.T, url string, in, out any) {
	t.Helper()
	body, _ := json.Marshal(in)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}
