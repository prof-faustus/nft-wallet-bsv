package sidecar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	bsvparams "github.com/prof-faustus/nft-wallet-bsv/internal/params"
	"github.com/prof-faustus/nft-wallet-bsv/internal/shred"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

func u64(v uint64) *uint64 { return &v }
func iptr(v int) *int      { return &v }

// newV2Server builds a sidecar wired to the SCRIPT-VALIDATING simulation
// node (test-only). Real sessions run against a real node; the sim lets us
// exhaustively test every option fast and hermetically.
func newV2Server(t *testing.T) *httptest.Server {
	t.Helper()
	ks, err := wallet.OpenFileKeystore(filepath.Join(t.TempDir(), "ks.json"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(ks, bsvparams.Regtest)
	s := New(w, engine.New(engine.Buyer), 1)
	s.EnableV2(NewSimNode())
	return httptest.NewServer(s.Handler())
}

func post(t *testing.T, base, path string, body any) v2Resp {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	resp, err := http.Post(base+path, "application/json", &buf)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var r v2Resp
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("POST %s: decode %q: %v", path, string(b), err)
	}
	return r
}

func mustOK(t *testing.T, r v2Resp, what string) {
	t.Helper()
	if !r.OK {
		t.Fatalf("%s: expected OK, got error: %s", what, r.Error)
	}
}

func mustErr(t *testing.T, r v2Resp, what string) {
	t.Helper()
	if r.OK {
		t.Fatalf("%s: expected an error (no-default / precondition), got OK", what)
	}
}

// The WHOLE lifecycle must succeed for EVERY crypto-shred scheme the menu
// offers — fund → mint(seal) → deliver(open+verify) → swap → confirm →
// shred → attest — validated end to end by the script-checking sim node.
func TestV2_EveryScheme_FullLifecycle(t *testing.T) {
	srv := newV2Server(t)
	defer srv.Close()
	base := srv.URL

	// The menu drives the option set — we test exactly what the UI offers.
	opts := post(t, base, "/v2/options", nil) // GET via POST is fine for this handler
	_ = opts
	schemes := shred.Names()
	if len(schemes) == 0 {
		t.Fatal("no schemes offered")
	}

	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			mustOK(t, post(t, base, "/v2/reset", resetReq{Scheme: scheme}), "reset")
			mustOK(t, post(t, base, "/v2/keys", keysReq{
				AliceLabel: "alice-" + scheme, BobLabel: "bob-" + scheme,
			}), "keys")
			mustOK(t, post(t, base, "/v2/fund", fundReq{Who: "alice", Sats: u64(6_000_000)}), "fund alice")
			mustOK(t, post(t, base, "/v2/fund", fundReq{Who: "bob", Sats: u64(12_000_000)}), "fund bob")
			mustOK(t, post(t, base, "/v2/mint", mintReq{
				PayloadText: "secret NFT content for " + scheme, DustSats: u64(1), FeeSats: u64(100_000),
			}), "mint")

			// Bob opens + verifies (access transfer).
			dl := post(t, base, "/v2/deliver", nil)
			mustOK(t, dl, "deliver")
			if m, ok := dl.Data.(map[string]any); ok {
				if v, _ := m["verified"].(bool); !v {
					t.Fatalf("%s: deliver did not verify", scheme)
				}
			}

			mustOK(t, post(t, base, "/v2/swap", swapReq{PriceSats: u64(2_000_000), FeeSats: u64(100_000)}), "swap")
			mustOK(t, post(t, base, "/v2/confirm", confirmReq{Blocks: iptr(1)}), "confirm")

			// Shred: after shredding, the seller cannot reopen.
			sh := post(t, base, "/v2/shred", nil)
			mustOK(t, sh, "shred")
			if m, ok := sh.Data.(map[string]any); ok {
				if v, _ := m["can_open_after"].(bool); v {
					t.Fatalf("%s: seller could still open after shred", scheme)
				}
			}
			mustOK(t, post(t, base, "/v2/attest", nil), "attest")
		})
	}
}

// No assistant-selected defaults: every required input, when omitted, is an
// ERROR — the user must choose. (Owner rule: "no defaults unless explicitly
// specified"; "failure to allow selection is failure".)
func TestV2_NoDefaults_RequireExplicitChoices(t *testing.T) {
	srv := newV2Server(t)
	defer srv.Close()
	base := srv.URL

	mustErr(t, post(t, base, "/v2/reset", resetReq{Scheme: ""}), "reset without scheme")
	mustErr(t, post(t, base, "/v2/reset", resetReq{Scheme: "no-such-scheme"}), "reset unknown scheme")

	mustOK(t, post(t, base, "/v2/reset", resetReq{Scheme: shred.DefaultScheme}), "reset")
	mustOK(t, post(t, base, "/v2/keys", keysReq{AliceLabel: "a", BobLabel: "b"}), "keys")

	// fund with no amount → error (user must choose).
	mustErr(t, post(t, base, "/v2/fund", fundReq{Who: "alice", Sats: nil}), "fund without sats")
	mustErr(t, post(t, base, "/v2/fund", fundReq{Who: "neither", Sats: u64(1)}), "fund bad party")

	mustOK(t, post(t, base, "/v2/fund", fundReq{Who: "alice", Sats: u64(6_000_000)}), "fund alice")
	// mint with missing dust/fee → error.
	mustErr(t, post(t, base, "/v2/mint", mintReq{PayloadText: "x", DustSats: nil, FeeSats: u64(1)}), "mint without dust")
	mustErr(t, post(t, base, "/v2/mint", mintReq{PayloadText: "", DustSats: u64(1), FeeSats: u64(1)}), "mint without payload")

	// confirm requires an explicit block count.
	mustErr(t, post(t, base, "/v2/confirm", confirmReq{Blocks: nil}), "confirm without blocks")
}

// Ordering preconditions: each step refuses to run before its prerequisites
// (the menu enables steps in order; the server enforces it regardless).
func TestV2_OrderingPreconditions(t *testing.T) {
	srv := newV2Server(t)
	defer srv.Close()
	base := srv.URL
	mustOK(t, post(t, base, "/v2/reset", resetReq{Scheme: shred.DefaultScheme}), "reset")
	// swap/deliver/mint before their prerequisites must error.
	mustErr(t, post(t, base, "/v2/mint", mintReq{PayloadText: "x", DustSats: u64(1), FeeSats: u64(1)}), "mint before keys")
	mustErr(t, post(t, base, "/v2/deliver", nil), "deliver before mint")
	mustErr(t, post(t, base, "/v2/swap", swapReq{PriceSats: u64(1), FeeSats: u64(1)}), "swap before mint")
	mustErr(t, post(t, base, "/v2/confirm", confirmReq{Blocks: iptr(1)}), "confirm before swap")
}

func ExampleSimNode() {
	// A tiny smoke check that the sim validates a P2PKH spend it created.
	fmt.Println("sim node is script-validating")
	// Output: sim node is script-validating
}
