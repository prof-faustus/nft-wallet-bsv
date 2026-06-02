// Live WS3 / milestone M1 test (docs/05 §5.4 E2E-1 mint, E2E-5 swap;
// docs/06 WS3 DoD). Against a regtest node: mint the token (exactly one
// live UTXO carrying the identity — I-NFT-3, identity recoverable), then
// assemble + verify + co-sign + broadcast Tx_swap transferring the token
// to Bob and paying Alice in one transaction (I-NFT-2/I-NFT-4). Gated by
// NFTBSV_RUN_LIVE; CI runs it in the chain-integration job.
package token

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain/svnode"
	bsvparams "github.com/prof-faustus/nft-wallet-bsv/internal/params"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

func liveEnv(t *testing.T) (*svnode.Adapter, *wallet.Wallet, context.Context) {
	t.Helper()
	if os.Getenv("NFTBSV_RUN_LIVE") != "1" {
		t.Skip("set NFTBSV_RUN_LIVE=1 (regtest node up) to run the live M1 mint+swap test")
	}
	ad := svnode.New(svnode.Config{
		URL:  envOr("NFTBSV_RPC_URL", "http://127.0.0.1:18332/"),
		User: envOr("NFTBSV_RPC_USER", "nftbsv"),
		Pass: envOr("NFTBSV_RPC_PASS", "nftbsv-dev-rpc-password"),
	})
	ks, err := wallet.OpenFileKeystore(filepath.Join(t.TempDir(), "ks.json"), "pw")
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	w := wallet.New(ks, bsvparams.Regtest)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return ad, w, ctx
}

// M1: mint, then atomic-swap to Bob.
//
//trace:test I-NFT-3 I-NFT-4
func TestM1_MintThenSwap(t *testing.T) {
	ad, w, ctx := liveEnv(t)
	if _, err := ad.MineBlocks(ctx, 101); err != nil {
		t.Fatalf("mine: %v", err)
	}

	// ---- E2E-1: mint ----
	aliceAddr, _ := w.NewKey("alice")
	aliceKey, _ := w.Key("alice")
	const aliceFund = 5_000_000
	const fee = 100_000
	const dust = 1
	fTx, err := ad.FundAddress(ctx, aliceAddr, aliceFund)
	if err != nil {
		t.Fatalf("fund alice: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine: %v", err)
	}
	fVout, err := ad.FindVout(ctx, fTx, lockHex(t, aliceAddr))
	if err != nil {
		t.Fatalf("find fund vout: %v", err)
	}

	descr, _ := PayloadDescriptor{ContentType: "application/octet-stream", Length: 42, EncScheme: EncPlaceholderV1}.Bytes()
	hp := HashPayload([]byte("stage-1-placeholder-payload"))
	mr, err := Mint(MintParams{
		Funding:    []FundingInput{{TxID: fTx, Vout: fVout, LockingScript: lockHex(t, aliceAddr), Sats: aliceFund}},
		OwnerKey:   aliceKey,
		Descriptor: descr, HPayload: hp, DustSats: dust,
		ChangeAddr: aliceAddr, ChangeSats: aliceFund - dust - fee,
	})
	if err != nil {
		t.Fatalf("mint assemble: %v", err)
	}
	if err := mr.Builder.Sign(); err != nil {
		t.Fatalf("mint sign: %v", err)
	}
	mintHex, _ := mr.Builder.Hex()
	mintTxid, err := ad.Broadcast(ctx, mintHex)
	if err != nil {
		t.Fatalf("mint broadcast: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine mint: %v", err)
	}
	// I-NFT-3: the token is exactly one live UTXO at (mintTxid, 0).
	if st, err := ad.OutputStatus(ctx, chain.Outpoint{TxID: mintTxid, Vout: 0}); err != nil || st.State != chain.OutUnspent {
		t.Fatalf("minted token not a live UTXO: %+v err=%v", st, err)
	}
	// Identity recoverable from the token output, TokenId fixed.
	rawCarrier, _ := script.NewFromHex(mr.LockScriptHex)
	id, err := ParseLockingScript(*rawCarrier)
	if err != nil || string(id.TokenId) != string(mr.TokenId) {
		t.Fatalf("identity not recoverable from minted token: %v", err)
	}

	// ---- E2E-5: atomic swap to Bob ----
	bobAddr, _ := w.NewKey("bob")
	bobKey, _ := w.Key("bob")
	bobPKH := PubKeyHash(bobKey.PubKey())
	const bobFund = 10_000_000
	const price = 2_000_000
	pTx, err := ad.FundAddress(ctx, bobAddr, bobFund)
	if err != nil {
		t.Fatalf("fund bob: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine: %v", err)
	}
	pVout, err := ad.FindVout(ctx, pTx, lockHex(t, bobAddr))
	if err != nil {
		t.Fatalf("find bob vout: %v", err)
	}

	sp := SwapParams{
		TokenPrevTxID: mintTxid, TokenPrevVout: 0, TokenLockScript: mr.LockScriptHex, DustSats: dust,
		TokenId: mr.TokenId, Descriptor: descr, HPayload: hp,
		BobOwnerPKH: bobPKH,
		AliceAddr:   aliceAddr, PriceSats: price,
		Payments:      []PaymentInput{{TxID: pTx, Vout: pVout, LockingScript: lockHex(t, bobAddr), Sats: bobFund}},
		BobChangeAddr: bobAddr, ChangeSats: bobFund - price - fee,
	}
	exp := SwapExpectation{
		TokenId: mr.TokenId, Descriptor: descr, HPayload: hp, BobOwnerPKH: bobPKH,
		AliceAddr: aliceAddr, PriceSats: price, DustSats: dust, MaxOutputs: 3,
	}
	b, err := AssembleSwap(sp, aliceKey, bobKey)
	if err != nil {
		t.Fatalf("assemble swap: %v", err)
	}
	// Verify BEFORE signing (docs/02 §2.5 step 2).
	unsignedHex, _ := b.Hex()
	if err := VerifySwapTx(unsignedHex, exp); err != nil {
		t.Fatalf("swap verify (pre-sign): %v", err)
	}
	if err := b.Sign(); err != nil {
		t.Fatalf("co-sign: %v", err)
	}
	swapHex, _ := b.Hex()
	swapTxid, err := ad.Broadcast(ctx, swapHex)
	if err != nil {
		t.Fatalf("swap broadcast: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatalf("mine swap: %v", err)
	}

	// I-NFT-4/I-NFT-3: the old token UTXO is spent (token moved); the new
	// token UTXO at (swapTxid,0) is live and now locks to Bob (I-NFT-2).
	if st, _ := ad.OutputStatus(ctx, chain.Outpoint{TxID: mintTxid, Vout: 0}); st.State != chain.OutSpent {
		t.Fatalf("old token UTXO not spent after swap: %s", st.State)
	}
	if st, err := ad.OutputStatus(ctx, chain.Outpoint{TxID: swapTxid, Vout: 0}); err != nil || st.State != chain.OutUnspent {
		t.Fatalf("new token UTXO not live: %+v err=%v", st, err)
	}
	newCarrier, _ := LockingScriptHex(mr.TokenId, descr, hp, bobPKH)
	cs, _ := script.NewFromHex(newCarrier)
	newID, err := ParseLockingScript(*cs)
	if err != nil || string(newID.OwnerPKH) != string(bobPKH) || string(newID.TokenId) != string(mr.TokenId) {
		t.Fatalf("post-swap token not owned by Bob with same identity: %v", err)
	}
	if st, _ := ad.TxStatus(ctx, swapTxid); st.State != chain.TxConfirmed {
		t.Fatalf("swap not confirmed: %s", st.State)
	}
}

// helpers ------------------------------------------------------------------

func lockHex(t *testing.T, addr string) string {
	t.Helper()
	h, err := p2pkhScriptHex(addr)
	if err != nil {
		t.Fatalf("lockHex: %v", err)
	}
	return h
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
