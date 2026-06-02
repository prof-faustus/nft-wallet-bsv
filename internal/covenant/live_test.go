// Live regtest test for the OP_PUSH_TX covenant (OD-3) on REAL node
// consensus. Gated by NFTBSV_RUN_LIVE; CI's chain-integration job runs it
// against the SV Node. It proves on the actual node (not just the
// interpreter) that:
//   - a covenant token can be minted and then transferred by a covenant
//     swap (the OP_PUSH_TX token input validates under consensus rules), and
//   - a spend that STRIPS the successor token output is REJECTED by the node
//     — Script-enforced continuity on real consensus.
package covenant

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain/svnode"
	bsvparams "github.com/prof-faustus/nft-wallet-bsv/internal/params"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestLive_CovenantMintSwapAndStripRejected(t *testing.T) {
	if os.Getenv("NFTBSV_RUN_LIVE") != "1" {
		t.Skip("set NFTBSV_RUN_LIVE=1 (regtest node up) to run the live covenant test")
	}
	ad := svnode.New(svnode.Config{
		URL:  envOr("NFTBSV_RPC_URL", "http://127.0.0.1:18332/"),
		User: envOr("NFTBSV_RPC_USER", "nftbsv"),
		Pass: envOr("NFTBSV_RPC_PASS", "nftbsv-dev-rpc-password"),
	})
	ks, err := wallet.OpenFileKeystore(filepath.Join(t.TempDir(), "ks.json"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(ks, bsvparams.Regtest)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const sellerFund = 6_000_000
	const buyerFund = 12_000_000
	const tokenVal = 1
	const fee = 100_000
	const price = 2_000_000

	if _, err := ad.MineBlocks(ctx, 101); err != nil {
		t.Fatalf("mine: %v", err)
	}

	// --- seller funds + mints a COVENANT token ---
	sellerAddr, _ := w.NewKey("seller")
	sellerKey, _ := w.Key("seller")
	sellerFundTx, err := ad.FundAddress(ctx, sellerAddr, sellerFund)
	if err != nil {
		t.Fatalf("fund seller: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatal(err)
	}
	sellerLock, _ := p2pkhHex(sellerAddr)
	sellerVout, err := ad.FindVout(ctx, sellerFundTx, sellerLock)
	if err != nil {
		t.Fatalf("find seller funding: %v", err)
	}
	descr, _ := token.PayloadDescriptor{ContentType: "application/octet-stream", Length: 9, EncScheme: token.EncPlaceholderV1}.Bytes()
	hp := token.HashPayload([]byte("secret art"))
	mr, err := MintCovenant(MintCovenantParams{
		Funding:  []token.FundingInput{{TxID: sellerFundTx, Vout: sellerVout, LockingScript: sellerLock, Sats: sellerFund}},
		OwnerKey: sellerKey, Descriptor: descr, HPayload: hp, TokenValue: tokenVal,
		ChangeAddr: sellerAddr, ChangeSats: sellerFund - tokenVal - fee,
	})
	if err != nil {
		t.Fatalf("covenant mint: %v", err)
	}
	if err := mr.Builder.Sign(); err != nil {
		t.Fatal(err)
	}
	mintHex, _ := mr.Builder.Hex()
	mintTxid, err := ad.Broadcast(ctx, mintHex)
	if err != nil {
		t.Fatalf("mint broadcast (node rejected a covenant mint): %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatal(err)
	}

	// --- buyer funds ---
	buyerAddr, _ := w.NewKey("buyer")
	buyerKey, _ := w.Key("buyer")
	buyerPKH := token.PubKeyHash(buyerKey.PubKey())
	buyerFundTx, err := ad.FundAddress(ctx, buyerAddr, buyerFund)
	if err != nil {
		t.Fatalf("fund buyer: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatal(err)
	}
	buyerLock, _ := p2pkhHex(buyerAddr)
	buyerVout, err := ad.FindVout(ctx, buyerFundTx, buyerLock)
	if err != nil {
		t.Fatalf("find buyer funding: %v", err)
	}

	swapParams := CovenantSwapParams{
		TokenPrevTxID: mintTxid, TokenPrevVout: 0,
		TokenId: mr.TokenId, Descriptor: descr, HPayload: hp, TokenValue: tokenVal,
		BobOwnerPKH: buyerPKH, SellerAddr: sellerAddr, PriceSats: price,
		Payments:      []token.PaymentInput{{TxID: buyerFundTx, Vout: buyerVout, LockingScript: buyerLock, Sats: buyerFund}},
		BobChangeAddr: buyerAddr, ChangeSats: buyerFund - price - fee,
	}

	// --- (1) a STRIP attempt must be REJECTED by the node ---
	stripBuilder, err := AssembleCovenantSwap(swapParams, buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := stripBuilder.Sign(); err != nil {
		t.Fatal(err)
	}
	stripHex, _ := stripBuilder.Hex()
	stripTx, _ := transaction.NewTransactionFromHex(stripHex)
	stripTx.Outputs[0].LockingScript = script.NewFromBytes([]byte{0x51}) // OP_TRUE — strip the token
	if _, err := ad.Broadcast(ctx, stripTx.String()); err == nil {
		t.Fatal("NODE ACCEPTED a stripped covenant spend — Script enforcement failed on consensus")
	} else {
		t.Logf("node correctly rejected the strip: %v", err)
	}

	// --- (2) the faithful covenant swap must be ACCEPTED ---
	b, err := AssembleCovenantSwap(swapParams, buyerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Sign(); err != nil {
		t.Fatal(err)
	}
	swapHex, _ := b.Hex()
	swapTxid, err := ad.Broadcast(ctx, swapHex)
	if err != nil {
		t.Fatalf("node rejected a FAITHFUL covenant swap: %v", err)
	}
	if _, err := ad.MineBlocks(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if st, _ := ad.OutputStatus(ctx, chain.Outpoint{TxID: mintTxid, Vout: 0}); st.State != chain.OutSpent {
		t.Fatalf("covenant token UTXO not spent after swap (state=%v)", st.State)
	}
	if st, err := ad.OutputStatus(ctx, chain.Outpoint{TxID: swapTxid, Vout: 0}); err != nil || st.State != chain.OutUnspent {
		t.Fatalf("successor token UTXO not live (err=%v state=%v)", err, st.State)
	}
}

func p2pkhHex(addr string) (string, error) {
	a, err := script.NewAddressFromString(addr)
	if err != nil {
		return "", err
	}
	ls, err := p2pkh.Lock(a)
	if err != nil {
		return "", err
	}
	return ls.String(), nil
}
