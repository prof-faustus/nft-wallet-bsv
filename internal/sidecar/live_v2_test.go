// Live test of the /v2 menu API against the REAL SV Node — the exact
// path the native app drives (shell → sidecar → node). The hermetic
// TestV2_* tests run this orchestration against the script-validating
// SimNode; this proves the SAME sidecar code on real node consensus, for
// both continuity modes (convention-enforced and the OP_PUSH_TX covenant).
//
// Gated by NFTBSV_RUN_LIVE; CI's chain-integration job runs it.
package sidecar

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prof-faustus/nft-wallet-bsv/internal/chain/svnode"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	bsvparams "github.com/prof-faustus/nft-wallet-bsv/internal/params"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

func liveEnvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// newV2LiveServer wires the sidecar to the REAL node adapter and matures
// coinbase into the node wallet so /v2/fund (sendtoaddress) has spendable
// funds (the user supplies real coins in production).
func newV2LiveServer(t *testing.T) string {
	t.Helper()
	ad := svnode.New(svnode.Config{
		URL:  liveEnvOr("NFTBSV_RPC_URL", "http://127.0.0.1:18332/"),
		User: liveEnvOr("NFTBSV_RPC_USER", "nftbsv"),
		Pass: liveEnvOr("NFTBSV_RPC_PASS", "nftbsv-dev-rpc-password"),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := ad.MineBlocks(ctx, 101); err != nil {
		t.Fatalf("mature coinbase: %v", err)
	}
	ks, err := wallet.OpenFileKeystore(filepath.Join(t.TempDir(), "ks.json"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(ks, bsvparams.Regtest)
	s := New(w, engine.New(engine.Buyer), 1)
	s.EnableV2(ad)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestLiveV2_FullExchange_BothContinuityModes runs the full menu flow
// (fund → mint → deliver → swap → confirm → shred → attest) through the
// sidecar on the REAL node, for covenant OFF and covenant ON.
func TestLiveV2_FullExchange_BothContinuityModes(t *testing.T) {
	if os.Getenv("NFTBSV_RUN_LIVE") != "1" {
		t.Skip("set NFTBSV_RUN_LIVE=1 (regtest node up) to run the live /v2 test")
	}
	base := newV2LiveServer(t)
	bptr := func(b bool) *bool { return &b }

	cases := []struct {
		scheme string
		cov    bool
	}{
		{"ecdh-singleuse", false}, // carrier swap path on the node
		{"threshold", true},       // OP_PUSH_TX covenant swap path on the node
	}
	for _, c := range cases {
		name := c.scheme
		if c.cov {
			name += "+covenant"
		}
		t.Run(name, func(t *testing.T) {
			mustOK(t, post(t, base, "/v2/reset", resetReq{Scheme: c.scheme, UseCovenant: bptr(c.cov)}), "reset")
			mustOK(t, post(t, base, "/v2/keys", keysReq{AliceLabel: "seller-" + name, BobLabel: "buyer-" + name}), "keys")
			mustOK(t, post(t, base, "/v2/fund", fundReq{Who: "alice", Sats: u64(6_000_000)}), "fund seller")
			mustOK(t, post(t, base, "/v2/fund", fundReq{Who: "bob", Sats: u64(12_000_000)}), "fund buyer")
			mustOK(t, post(t, base, "/v2/mint", mintReq{PayloadText: "live secret " + name, DustSats: u64(1), FeeSats: u64(100_000)}), "mint")
			mustOK(t, post(t, base, "/v2/deliver", nil), "deliver")
			mustOK(t, post(t, base, "/v2/swap", swapReq{PriceSats: u64(2_000_000), FeeSats: u64(100_000)}), "swap")
			mustOK(t, post(t, base, "/v2/confirm", confirmReq{Blocks: iptr(1)}), "confirm")
			mustOK(t, post(t, base, "/v2/shred", nil), "shred")
			mustOK(t, post(t, base, "/v2/attest", nil), "attest")
		})
	}
}
