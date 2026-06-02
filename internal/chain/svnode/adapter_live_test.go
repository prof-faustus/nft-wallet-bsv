// Live integration test for the SV Node adapter — the WS1 Definition of
// Done (docs/06 WS1): against a LIVE regtest node, broadcast a funded
// P2PKH tx, mine it, observe it reach a chosen confirmation depth, verify
// its SPV Merkle proof, and detect a conflicting spend — all through the
// adapter, never the raw node API (the conflict is built with harness
// RPCs, but every assertion goes through chain.Adapter).
//
// Gated by NFTBSV_RUN_LIVE=1 (+ NFTBSV_RPC_URL/USER/PASS); skipped
// otherwise so the unit suite stays hermetic. CI runs it in the
// chain-integration job against deploy/regtest.
//
// White-box (package svnode) so it may use the unexported RPC client for
// harness-only methods (createrawtransaction/signrawtransaction/
// listunspent) while exercising the adapter's PUBLIC methods for the
// actual DoD assertions.
package svnode

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/prof-faustus/nft-wallet-bsv/internal/chain"
)

func liveAdapter(t *testing.T) *Adapter {
	t.Helper()
	if os.Getenv("NFTBSV_RUN_LIVE") != "1" {
		t.Skip("set NFTBSV_RUN_LIVE=1 (with a regtest node from deploy/regtest) to run the live WS1 DoD test")
	}
	cfg := Config{
		URL:  envOr("NFTBSV_RPC_URL", "http://127.0.0.1:18332/"),
		User: envOr("NFTBSV_RPC_USER", "nftbsv"),
		Pass: envOr("NFTBSV_RPC_PASS", "nftbsv-dev-rpc-password"),
	}
	return New(cfg)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// TestWS1_DoD covers broadcast + confirm-to-depth + SPV-proof in one flow.
//
//trace:test CH-1
func TestWS1_DoD(t *testing.T) {
	a := liveAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Mature a spendable balance, then fund a fresh P2PKH address.
	if _, err := a.MineBlocks(ctx, 101); err != nil {
		t.Fatalf("mine maturing blocks: %v", err)
	}
	addr, err := a.NewAddress(ctx)
	if err != nil {
		t.Fatalf("new address: %v", err)
	}
	const fundSats = 2_500_000
	txid, err := a.FundAddress(ctx, addr, fundSats)
	if err != nil {
		t.Fatalf("fund (broadcast P2PKH): %v", err)
	}

	// Unconfirmed in the mempool.
	if st, err := a.TxStatus(ctx, txid); err != nil || st.State != chain.TxMempool {
		t.Fatalf("pre-mine TxStatus = %+v, err=%v; want mempool", st, err)
	}

	// Mine to a chosen depth and observe it climb.
	if _, err := a.MineBlocks(ctx, 3); err != nil {
		t.Fatalf("mine: %v", err)
	}
	st, err := a.TxStatus(ctx, txid)
	if err != nil {
		t.Fatalf("post-mine TxStatus: %v", err)
	}
	if st.State != chain.TxConfirmed || st.Depth < 3 {
		t.Fatalf("TxStatus = %+v; want confirmed depth>=3", st)
	}

	// SPV: fetch the Merkle proof via the adapter and VERIFY it (CH-1) —
	// the proof must recompute to the header's committed root and include
	// our txid; reject trusting the node's say-so.
	proof, err := a.MerkleProof(ctx, txid)
	if err != nil {
		t.Fatalf("MerkleProof: %v", err)
	}
	res, err := chain.VerifyMerkleProof(proof, txid)
	if err != nil {
		t.Fatalf("VerifyMerkleProof: %v", err)
	}
	if !res.RootMatchesHeader || !res.TxIncluded {
		t.Fatalf("SPV verify: rootMatches=%v included=%v", res.RootMatchesHeader, res.TxIncluded)
	}

	// Tip sanity (reorg-awareness basis).
	if tip, err := a.Tip(ctx); err != nil || tip.Height == 0 {
		t.Fatalf("Tip = %+v err=%v", tip, err)
	}
}

// TestWS1_ConflictDetection proves the adapter detects a conflicting
// spend: two txs spend the same funded outpoint; after one confirms, the
// shared output reads spent and the competing broadcast is rejected.
//
//trace:test CH-1
func TestWS1_ConflictDetection(t *testing.T) {
	a := liveAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := a.MineBlocks(ctx, 101); err != nil {
		t.Fatalf("mine: %v", err)
	}
	// Fund a dedicated address with a known integer-sat amount.
	srcAddr, err := a.NewAddress(ctx)
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	const srcSats = 5_000_000
	const feeSats = 100_000
	fundTxid, err := a.FundAddress(ctx, srcAddr, srcSats)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}
	if _, err := a.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine fund: %v", err)
	}

	// Locate the funding outpoint (vout) via a harness RPC.
	vout := findVout(ctx, t, a, fundTxid, srcAddr)
	op := chain.Outpoint{TxID: fundTxid, Vout: vout}
	if st, _ := a.OutputStatus(ctx, op); st.State != chain.OutUnspent {
		t.Fatalf("funded output should be unspent, got %s", st.State)
	}

	// Build two conflicting txs spending that same outpoint to two
	// different addresses (different txids, same input).
	a1, _ := a.NewAddress(ctx)
	a2, _ := a.NewAddress(ctx)
	txA := buildSignedSpend(ctx, t, a, fundTxid, vout, a1, srcSats-feeSats)
	txB := buildSignedSpend(ctx, t, a, fundTxid, vout, a2, srcSats-feeSats)

	// Broadcast + confirm txA via the adapter.
	txidA, err := a.Broadcast(ctx, txA)
	if err != nil {
		t.Fatalf("broadcast txA: %v", err)
	}
	if _, err := a.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine txA: %v", err)
	}

	// Conflict signals via the adapter: shared output now spent ...
	if st, err := a.OutputStatus(ctx, op); err != nil || st.State != chain.OutSpent {
		t.Fatalf("after txA confirmed, OutputStatus = %+v err=%v; want spent", st, err)
	}
	if st, _ := a.TxStatus(ctx, txidA); st.State != chain.TxConfirmed {
		t.Fatalf("txA should be confirmed, got %s", st.State)
	}
	// ... and the conflicting txB is rejected (its input is gone).
	if _, err := a.Broadcast(ctx, txB); err == nil {
		t.Fatalf("conflicting txB was accepted; want rejection")
	}
}

// findVout returns the output index of fundTxid paying addr.
func findVout(ctx context.Context, t *testing.T, a *Adapter, fundTxid, addr string) uint32 {
	t.Helper()
	res, err := a.rpc.call(ctx, "listunspent", 1, 9999999, []string{addr})
	if err != nil {
		t.Fatalf("listunspent: %v", err)
	}
	var utxos []struct {
		TxID string `json:"txid"`
		Vout uint32 `json:"vout"`
	}
	if err := json.Unmarshal(res, &utxos); err != nil {
		t.Fatalf("listunspent decode: %v", err)
	}
	for _, u := range utxos {
		if u.TxID == fundTxid {
			return u.Vout
		}
	}
	t.Fatalf("funding outpoint not found for %s", addr)
	return 0
}

// buildSignedSpend creates + signs a raw tx spending (txid,vout) to addr
// for valueSats, using harness RPCs. Money stays integer satoshis until
// the RPC boundary (satsToBSV).
func buildSignedSpend(ctx context.Context, t *testing.T, a *Adapter, txid string, vout uint32, addr string, valueSats uint64) string {
	t.Helper()
	inputs := []map[string]any{{"txid": txid, "vout": vout}}
	outputs := map[string]string{addr: satsToBSV(valueSats)}
	rawRes, err := a.rpc.call(ctx, "createrawtransaction", inputs, outputs)
	if err != nil {
		t.Fatalf("createrawtransaction: %v", err)
	}
	var rawHex string
	_ = json.Unmarshal(rawRes, &rawHex)
	signRes, err := a.rpc.call(ctx, "signrawtransaction", rawHex)
	if err != nil {
		t.Fatalf("signrawtransaction: %v", err)
	}
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if err := json.Unmarshal(signRes, &signed); err != nil || !signed.Complete {
		t.Fatalf("sign incomplete: %v (%s)", err, string(signRes))
	}
	return signed.Hex
}
