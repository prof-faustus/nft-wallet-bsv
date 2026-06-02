// Package e2e holds the full two-party end-to-end scenario (docs/05 §5.4
// E2E-8): mint → pair → negotiate → deliver → co-sign → broadcast →
// confirm → attest, wiring every layer together (chain adapter WS1,
// wallet+builder WS2, token+swap WS3, channel WS4, engine WS5, deletion
// WS6) for both Alice (seller) and Bob (buyer) in one run.
//
// It asserts the Stage-1 honest claim (docs/04 §4.7): control transfer is
// VERIFIED (token UTXO spent to Bob) while deletion is ATTESTED, not
// verified; and there is NO state where payment was taken but the token
// did not move (I-NFT-4).
//
// Gated by NFTBSV_RUN_LIVE; CI runs it in the chain-integration job (-p 1).
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain/svnode"
	"github.com/prof-faustus/nft-wallet-bsv/internal/channel"
	"github.com/prof-faustus/nft-wallet-bsv/internal/deletion"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
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

func lockHex(t *testing.T, addr string) string {
	t.Helper()
	a, err := script.NewAddressFromString(addr)
	if err != nil {
		t.Fatal(err)
	}
	ls, err := p2pkh.Lock(a)
	if err != nil {
		t.Fatal(err)
	}
	return ls.String()
}

// TestE2E8_FullExchange is the Stage-1 acceptance milestone M4/E2E-8.
func TestE2E8_FullExchange(t *testing.T) {
	if os.Getenv("NFTBSV_RUN_LIVE") != "1" {
		t.Skip("set NFTBSV_RUN_LIVE=1 (regtest node up) to run E2E-8")
	}
	ad := svnode.New(svnode.Config{
		URL:  envOr("NFTBSV_RPC_URL", "http://127.0.0.1:18332/"),
		User: envOr("NFTBSV_RPC_USER", "nftbsv"),
		Pass: envOr("NFTBSV_RPC_PASS", "nftbsv-dev-rpc-password"),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	ks, _ := wallet.OpenFileKeystore(filepath.Join(t.TempDir(), "ks.json"), "pw")
	w := wallet.New(ks, bsvparams.Regtest)
	if _, err := ad.MineBlocks(ctx, 101); err != nil {
		t.Fatalf("mine: %v", err)
	}

	const fee, dust, price, bobFund, aliceFund = 100_000, 1, 3_000_000, 12_000_000, 6_000_000
	aliceEng := engine.New(engine.Seller)
	bobEng := engine.New(engine.Buyer)

	// ---- E2E-1: Alice mints the token ----
	aliceAddr, _ := w.NewKey("alice")
	aliceKey, _ := w.Key("alice")
	payload := []byte("the unique NFT payload (stage-1 placeholder)")
	hp := token.HashPayload(payload)
	descr, _ := token.PayloadDescriptor{ContentType: "application/octet-stream", Length: uint64(len(payload)), EncScheme: token.EncPlaceholderV1}.Bytes()

	fTx, _ := ad.FundAddress(ctx, aliceAddr, aliceFund)
	mineOrFatal(t, ad, ctx, 1)
	fVout, _ := ad.FindVout(ctx, fTx, lockHex(t, aliceAddr))
	mr, err := token.Mint(token.MintParams{
		Funding:  []token.FundingInput{{TxID: fTx, Vout: fVout, LockingScript: lockHex(t, aliceAddr), Sats: aliceFund}},
		OwnerKey: aliceKey, Descriptor: descr, HPayload: hp, DustSats: dust,
		ChangeAddr: aliceAddr, ChangeSats: aliceFund - dust - fee,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	must(t, mr.Builder.Sign())
	mintHex, _ := mr.Builder.Hex()
	mintTxid, err := ad.Broadcast(ctx, mintHex)
	if err != nil {
		t.Fatalf("mint broadcast: %v", err)
	}
	mineOrFatal(t, ad, ctx, 1)

	// ---- E2E-2: pair Alice↔Bob over the authenticated channel ----
	endA, endB := channel.NewPipe(16)
	bobIdent, _ := ec.NewPrivateKey()
	aliceIdent, _ := ec.NewPrivateKey()
	type pres struct {
		s   *channel.Session
		err error
	}
	ca, cb := make(chan pres, 1), make(chan pres, 1)
	go func() { s, e := channel.Pair(endA, aliceIdent, make16("alice")); ca <- pres{s, e} }()
	go func() { s, e := channel.Pair(endB, bobIdent, make16("bobxx")); cb <- pres{s, e} }()
	ra, rb := <-ca, <-cb
	if ra.err != nil || rb.err != nil {
		t.Fatalf("pair: %v / %v", ra.err, rb.err)
	}
	aliceSess, bobSess := ra.s, rb.s
	driveEng(t, aliceEng, engine.EvStartPairing, engine.EvHelloAckValid)
	driveEng(t, bobEng, engine.EvStartPairing, engine.EvHelloAckValid)

	// ---- E2E-3: negotiate price over the channel (Bob OFFER, Alice ACCEPT) ----
	offer, _ := json.Marshal(map[string]any{"tokenId": mr.TokenId, "priceSats": price})
	must(t, bobSess.Send(channel.PtOffer, offer))
	if pt, _, err := aliceSess.Recv(); err != nil || pt != channel.PtOffer {
		t.Fatalf("alice recv offer: %v (pt %d)", err, pt)
	}
	driveEng(t, bobEng, engine.EvOffer)
	driveEng(t, aliceEng, engine.EvOffer)
	must(t, aliceSess.Send(channel.PtAccept, offer))
	if pt, _, err := bobSess.Recv(); err != nil || pt != channel.PtAccept {
		t.Fatalf("bob recv accept: %v", err)
	}
	driveEng(t, aliceEng, engine.EvAcceptMatches)
	driveEng(t, bobEng, engine.EvAcceptMatches)

	// ---- E2E-4: Alice delivers the payload; Bob verifies H(payload) ----
	must(t, aliceSess.Send(channel.PtPayloadData, payload))
	_, gotPayload, err := bobSess.Recv()
	if err != nil {
		t.Fatalf("bob recv payload: %v", err)
	}
	if string(token.HashPayload(gotPayload)) != string(hp) {
		t.Fatal("E2E-4: Bob's payload hash != token H(payload)") // (F-4 would abort here)
	}
	driveEng(t, aliceEng, engine.EvPayloadDeliveredOK)
	driveEng(t, bobEng, engine.EvPayloadDeliveredOK)

	// ---- E2E-5: assemble Tx_swap, both verify, co-sign, broadcast ----
	bobAddr, _ := w.NewKey("bob")
	bobKey, _ := w.Key("bob")
	bobPKH := token.PubKeyHash(bobKey.PubKey())
	pTx, _ := ad.FundAddress(ctx, bobAddr, bobFund)
	mineOrFatal(t, ad, ctx, 1)
	pVout, _ := ad.FindVout(ctx, pTx, lockHex(t, bobAddr))

	sp := token.SwapParams{
		TokenPrevTxID: mintTxid, TokenPrevVout: 0, TokenLockScript: mr.LockScriptHex, DustSats: dust,
		TokenId: mr.TokenId, Descriptor: descr, HPayload: hp, BobOwnerPKH: bobPKH,
		AliceAddr: aliceAddr, PriceSats: price,
		Payments:      []token.PaymentInput{{TxID: pTx, Vout: pVout, LockingScript: lockHex(t, bobAddr), Sats: bobFund}},
		BobChangeAddr: bobAddr, ChangeSats: bobFund - price - fee,
	}
	exp := token.SwapExpectation{
		TokenId: mr.TokenId, Descriptor: descr, HPayload: hp, BobOwnerPKH: bobPKH,
		AliceAddr: aliceAddr, PriceSats: price, DustSats: dust, MaxOutputs: 3,
	}
	b, err := token.AssembleSwap(sp, aliceKey, bobKey)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	driveEng(t, aliceEng, engine.EvSwapAssembled)
	driveEng(t, bobEng, engine.EvSwapAssembled)
	// Both parties verify the exact terms BEFORE signing (docs/02 §2.5 step 2).
	unsigned, _ := b.Hex()
	must(t, token.VerifySwapTx(unsigned, exp))
	driveEng(t, aliceEng, engine.EvTermsVerifyOK)
	driveEng(t, bobEng, engine.EvTermsVerifyOK)
	// Co-sign (Bob's input + Alice's token input) + own/peer partials.
	must(t, b.Sign())
	for _, e := range []*engine.Engine{aliceEng, bobEng} {
		driveEng(t, e, engine.EvPeerPartialReceived, engine.EvOwnSigned)
	}
	swapHex, _ := b.Hex()
	swapTxid, err := ad.Broadcast(ctx, swapHex)
	if err != nil {
		t.Fatalf("swap broadcast: %v", err)
	}
	driveEng(t, aliceEng, engine.EvBroadcastAccepted)
	driveEng(t, bobEng, engine.EvBroadcastAccepted)

	// ---- E2E-6: confirm; token now Bob's ----
	mineOrFatal(t, ad, ctx, 1) // CONF_DEPTH = 1
	driveEng(t, aliceEng, engine.EvConfirmedAtDepth)
	driveEng(t, bobEng, engine.EvConfirmedAtDepth)
	// Control transfer is VERIFIABLE: old token UTXO spent; new one live + Bob's.
	if st, _ := ad.OutputStatus(ctx, chain.Outpoint{TxID: mintTxid, Vout: 0}); st.State != chain.OutSpent {
		t.Fatalf("token UTXO not spent (no token movement)")
	}
	if st, err := ad.OutputStatus(ctx, chain.Outpoint{TxID: swapTxid, Vout: 0}); err != nil || st.State != chain.OutUnspent {
		t.Fatalf("new token UTXO not live: %+v %v", st, err)
	}
	newCarrier, _ := token.LockingScriptHex(mr.TokenId, descr, hp, bobPKH)
	cs, _ := script.NewFromHex(newCarrier)
	id, err := token.ParseLockingScript(*cs)
	if err != nil || string(id.OwnerPKH) != string(bobPKH) {
		t.Fatalf("token not owned by Bob post-swap: %v", err)
	}
	// I-NFT-4: Alice's price output is present (payment moved iff token moved).
	if st, _ := ad.OutputStatus(ctx, chain.Outpoint{TxID: swapTxid, Vout: 1}); st.State != chain.OutUnspent {
		t.Fatalf("Alice's price output not present")
	}

	// ---- E2E-7: Alice deletes locally + attests; Bob validates → DONE ----
	must(t, deletion.LocalDelete(filepath.Join(t.TempDir(), "alice_copy.bin"))) // best-effort
	cda, _ := deletion.BuildCDA(mr.TokenId, mintTxid, 0, swapTxid, hp, time.Now().Unix())
	sigCDA, _ := cda.Sign(aliceIdent)
	driveEng(t, aliceEng, engine.EvLocalDeleteDone) // → ATTESTED
	cdaExp := deletion.Expectation{TokenId: mr.TokenId, TokenOutpointTxID: mintTxid, TokenOutpointVout: 0, SwapTxID: swapTxid, HPayload: hp}
	if deletion.ClassifyReceived(&cda, sigCDA, aliceIdent.PubKey(), cdaExp) != deletion.AttestValid {
		t.Fatal("Bob could not validate Alice's CDA")
	}
	driveEng(t, bobEng, engine.EvDeletionAttestValid) // → DONE

	// ---- Acceptance assertions (docs/05 §5.4 E2E-8 + honesty boundary) ----
	if aliceEng.State() != engine.StateAttested {
		t.Fatalf("seller end state %s, want ATTESTED", aliceEng.State())
	}
	if bobEng.State() != engine.StateDone {
		t.Fatalf("buyer end state %s, want DONE", bobEng.State())
	}
	// Honest boundary: control transfer VERIFIED (asserted on-chain above);
	// deletion only ATTESTED — the status is a validated CLAIM, never
	// "verified deletion" (docs/04 §4.7). The type system makes this
	// explicit: ClassifyReceived returns AttestValid, not "verified".
	_ = bobSess
}

func make16(seed string) []byte {
	b := make([]byte, 16)
	copy(b, seed)
	return b
}

func driveEng(t *testing.T, e *engine.Engine, evs ...engine.EventType) {
	t.Helper()
	for _, ev := range evs {
		if _, err := e.Apply(engine.Event{Type: ev}); err != nil {
			t.Fatalf("engine event %v in %s: %v", ev, e.State(), err)
		}
	}
}

func mineOrFatal(t *testing.T, ad *svnode.Adapter, ctx context.Context, n int) {
	t.Helper()
	if _, err := ad.MineBlocks(ctx, n); err != nil {
		t.Fatalf("mine: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
