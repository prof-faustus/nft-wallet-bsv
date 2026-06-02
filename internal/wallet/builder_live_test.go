// Live WS2 Definition-of-Done test (docs/06 WS2): against a regtest node,
// build/sign/broadcast a standard P2PKH transaction AND a transaction
// co-signed by two independently-held keys via partial signing (the
// atomic-swap co-signing flow). Gated by NFTBSV_RUN_LIVE; CI runs it in
// the chain-integration job. The actual broadcast/confirm goes through
// the chain.Adapter (WS1); the wallet builds and signs.
package wallet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain/svnode"
	"github.com/prof-faustus/nft-wallet-bsv/internal/params"
)

func liveSetup(t *testing.T) (*svnode.Adapter, *Wallet, context.Context) {
	t.Helper()
	if os.Getenv("NFTBSV_RUN_LIVE") != "1" {
		t.Skip("set NFTBSV_RUN_LIVE=1 (regtest node up) to run the live WS2 DoD test")
	}
	ad := svnode.New(svnode.Config{
		URL:  envOr("NFTBSV_RPC_URL", "http://127.0.0.1:18332/"),
		User: envOr("NFTBSV_RPC_USER", "nftbsv"),
		Pass: envOr("NFTBSV_RPC_PASS", "nftbsv-dev-rpc-password"),
	})
	ks, err := OpenFileKeystore(filepath.Join(t.TempDir(), "ks.json"), "test-pass")
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	w := New(ks, params.Regtest)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ad, w, ctx
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func lockScriptHex(t *testing.T, addr string) string {
	t.Helper()
	a, err := script.NewAddressFromString(addr)
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	ls, err := p2pkh.Lock(a)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	return ls.String()
}

// Standard P2PKH: fund a wallet key, spend it, broadcast, confirm.
func TestWS2_P2PKHBuildSignBroadcast(t *testing.T) {
	ad, w, ctx := liveSetup(t)
	if _, err := ad.MineBlocks(ctx, 101); err != nil {
		t.Fatalf("mine: %v", err)
	}
	const fund = 3_000_000
	const fee = 100_000
	addr, err := w.NewKey("alice")
	if err != nil {
		t.Fatalf("newkey: %v", err)
	}
	fundTxid, err := ad.FundAddress(ctx, addr, fund)
	if err != nil {
		t.Fatalf("fund: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine fund: %v", err)
	}
	vout, err := ad.FindVout(ctx, fundTxid, lockScriptHex(t, addr))
	if err != nil {
		t.Fatalf("findvout: %v", err)
	}

	dest, _ := w.NewKey("dest")
	aliceKey, _ := w.Key("alice")
	b := NewBuilder()
	if err := b.AddP2PKHInput(fundTxid, vout, lockScriptHex(t, addr), fund, aliceKey, sighash.AllForkID); err != nil {
		t.Fatalf("add input: %v", err)
	}
	if err := b.AddP2PKHOutput(dest, fund-fee); err != nil {
		t.Fatalf("add output: %v", err)
	}
	if err := b.Sign(); err != nil {
		t.Fatalf("sign: %v", err)
	}
	rawHex, _ := b.Hex()
	txid, err := ad.Broadcast(ctx, rawHex)
	if err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine spend: %v", err)
	}
	if st, err := ad.TxStatus(ctx, txid); err != nil || st.State.String() != "confirmed" {
		t.Fatalf("TxStatus = %+v err=%v; want confirmed", st, err)
	}
}

// Two-key co-sign via partial signing: two inputs, each owned by an
// independent key; each key signs only its own input. (The atomic-swap
// pattern, docs/02 §2.5 / docs/03 §3.3.)
func TestWS2_TwoKeyCoSignPartial(t *testing.T) {
	ad, w, ctx := liveSetup(t)
	if _, err := ad.MineBlocks(ctx, 101); err != nil {
		t.Fatalf("mine: %v", err)
	}
	const fund = 2_000_000
	const fee = 100_000
	addr0, _ := w.NewKey("k0")
	addr1, _ := w.NewKey("k1")
	tx0, err := ad.FundAddress(ctx, addr0, fund)
	if err != nil {
		t.Fatalf("fund0: %v", err)
	}
	tx1, err := ad.FundAddress(ctx, addr1, fund)
	if err != nil {
		t.Fatalf("fund1: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine: %v", err)
	}
	v0, err := ad.FindVout(ctx, tx0, lockScriptHex(t, addr0))
	if err != nil {
		t.Fatalf("vout0: %v", err)
	}
	v1, err := ad.FindVout(ctx, tx1, lockScriptHex(t, addr1))
	if err != nil {
		t.Fatalf("vout1: %v", err)
	}

	k0, _ := w.Key("k0")
	k1, _ := w.Key("k1")
	dest, _ := w.NewKey("dest2")

	b := NewBuilder()
	// Input 0 carries k0's template now; input 1 is added WITHOUT a
	// template (the counterparty signs it later).
	if err := b.AddP2PKHInput(tx0, v0, lockScriptHex(t, addr0), fund, k0, sighash.AllForkID); err != nil {
		t.Fatalf("in0: %v", err)
	}
	if err := b.AddP2PKHInput(tx1, v1, lockScriptHex(t, addr1), fund, nil, sighash.AllForkID); err != nil {
		t.Fatalf("in1: %v", err)
	}
	if err := b.AddP2PKHOutput(dest, fund*2-fee); err != nil {
		t.Fatalf("out: %v", err)
	}
	// Party A signs its input only (input 1 stays unsigned).
	if err := b.Sign(); err != nil {
		t.Fatalf("partial sign A: %v", err)
	}
	// Party B (independent key) now signs its own input.
	if err := b.SetInputSigner(1, k1, sighash.AllForkID); err != nil {
		t.Fatalf("set signer B: %v", err)
	}
	if err := b.Sign(); err != nil {
		t.Fatalf("partial sign B: %v", err)
	}
	rawHex, _ := b.Hex()
	txid, err := ad.Broadcast(ctx, rawHex)
	if err != nil {
		t.Fatalf("broadcast co-signed: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine: %v", err)
	}
	if st, err := ad.TxStatus(ctx, txid); err != nil || st.State.String() != "confirmed" {
		t.Fatalf("co-signed TxStatus = %+v err=%v; want confirmed", st, err)
	}
}
