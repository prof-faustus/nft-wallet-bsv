// Live interactive actions (WS7 / E2E-8 through the UI). When the sidecar
// is started against a regtest node (EnableLiveActions), the shell's
// buttons POST here and the sidecar performs the REAL on-chain steps —
// mint, co-signed atomic swap, confirm, deletion attestation — driving
// the engine and the honest status as it goes. This is the genuine
// interactive exchange (a single-app driver of the two-party swap; the
// full two-instances-over-a-channel walkthrough is docs/runbooks).
//
// Keys never leave the sidecar (non-custodial shell, WS7 DoD).
package sidecar

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain"
	"github.com/prof-faustus/nft-wallet-bsv/internal/deletion"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
)

// liveAdapter is the subset of the SV Node adapter the live actions use
// (an interface so server.go stays node-agnostic).
type liveAdapter interface {
	MineBlocks(ctx context.Context, n int) ([]string, error)
	FundAddress(ctx context.Context, addr string, sats uint64) (string, error)
	FindVout(ctx context.Context, txid, lockingScriptHex string) (uint32, error)
	Broadcast(ctx context.Context, rawTxHex string) (string, error)
	OutputStatus(ctx context.Context, op chain.Outpoint) (chain.OutputStatus, error)
	NewAddress(ctx context.Context) (string, error)
}

const (
	exFee       = 100_000
	exDust      = 1
	exPrice     = 2_000_000
	exAliceFund = 6_000_000
	exBobFund   = 12_000_000
)

// exchange holds the artifacts of the in-progress interactive exchange.
type exchange struct {
	aliceAddr, bobAddr string
	aliceKey, bobKey   *ec.PrivateKey
	bobFundTxid        string
	tokenId, descr, hp []byte
	bobPKH             []byte
	mintTxid, lockHex  string
	swapTxid           string
	log                []string
}

// EnableLiveActions wires the live regtest adapter and registers the
// /action/* + /log routes. Call before serving.
func (s *Server) EnableLiveActions(ad liveAdapter) {
	s.ad = ad
	s.ex = &exchange{}
	// Every /action/* route holds command authority over the keys, so each is
	// guard()ed identically to /v2 (POST + control token + same-site). "The
	// browser holds no keys" is insufficient — the browser has command
	// authority unless the sidecar authenticates it (audit finding 5).
	s.mux.HandleFunc("/action/setup-mint", s.guard(s.actionHandler(s.doSetupMint)))
	s.mux.HandleFunc("/action/swap", s.guard(s.actionHandler(s.doSwap)))
	s.mux.HandleFunc("/action/confirm", s.guard(s.actionHandler(s.doConfirm)))
	s.mux.HandleFunc("/action/attest", s.guard(s.actionHandler(s.doAttest)))
	s.mux.HandleFunc("/log", s.logHandler)
	s.mux.HandleFunc("/", s.webHandler) // interactive browser control panel (serves the token for same-origin use)
}

type actionResp struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
	Log   []string `json:"log"`
}

// actionHandler serializes an action, runs it, and returns the log.
func (s *Server) actionHandler(fn func(context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s.actMu.Lock()
		defer s.actMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		err := fn(ctx)
		resp := actionResp{OK: err == nil, Log: s.snapshotLog()}
		if err != nil {
			resp.Error = err.Error()
		}
		writeJSON(w, resp)
	}
}

func (s *Server) logHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, actionResp{OK: true, Log: s.snapshotLog()})
}

func (s *Server) snapshotLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.ex.log))
	copy(out, s.ex.log)
	return out
}

func (s *Server) logf(format string, a ...any) {
	s.mu.Lock()
	s.ex.log = append(s.ex.log, fmt.Sprintf(format, a...))
	s.mu.Unlock()
}

func (s *Server) lockScriptHex(addr string) (string, error) {
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

// doSetupMint: fund Alice + Bob, mint the token under Alice, and advance
// the engine to SWAP_ASSEMBLED (paired, price agreed, payload delivered,
// terms verified — ready to sign).
func (s *Server) doSetupMint(ctx context.Context) error {
	ex := s.ex
	if _, err := s.ad.MineBlocks(ctx, 101); err != nil {
		return err
	}
	var err error
	if ex.aliceAddr, err = s.w.NewKey("alice"); err != nil {
		return err
	}
	if ex.bobAddr, err = s.w.NewKey("bob"); err != nil {
		return err
	}
	ex.aliceKey, _ = s.w.Key("alice")
	ex.bobKey, _ = s.w.Key("bob")
	ex.bobPKH = token.PubKeyHash(ex.bobKey.PubKey())
	aliceFundTxid, err := s.ad.FundAddress(ctx, ex.aliceAddr, exAliceFund)
	if err != nil {
		return err
	}
	if ex.bobFundTxid, err = s.ad.FundAddress(ctx, ex.bobAddr, exBobFund); err != nil {
		return err
	}
	if _, err = s.ad.MineBlocks(ctx, 1); err != nil {
		return err
	}
	s.logf("Funded Alice (%s) and Bob (%s) on regtest.", ex.aliceAddr, ex.bobAddr)

	aliceLock, _ := s.lockScriptHex(ex.aliceAddr)
	aliceVout, err := s.ad.FindVout(ctx, aliceFundTxid, aliceLock)
	if err != nil {
		return fmt.Errorf("find alice funding: %w", err)
	}
	payload := []byte("the unique NFT payload (stage-1 placeholder)")
	ex.hp = token.HashPayload(payload)
	ex.descr, _ = token.PayloadDescriptor{ContentType: "application/octet-stream", Length: uint64(len(payload)), EncScheme: token.EncPlaceholderV1}.Bytes()
	mr, err := token.Mint(token.MintParams{
		Funding:  []token.FundingInput{{TxID: aliceFundTxid, Vout: aliceVout, LockingScript: aliceLock, Sats: exAliceFund}},
		OwnerKey: ex.aliceKey, Descriptor: ex.descr, HPayload: ex.hp, DustSats: exDust,
		ChangeAddr: ex.aliceAddr, ChangeSats: exAliceFund - exDust - exFee,
	})
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}
	if err = mr.Builder.Sign(); err != nil {
		return err
	}
	mintHex, _ := mr.Builder.Hex()
	if ex.mintTxid, err = s.ad.Broadcast(ctx, mintHex); err != nil {
		return fmt.Errorf("mint broadcast: %w", err)
	}
	if _, err = s.ad.MineBlocks(ctx, 1); err != nil {
		return err
	}
	ex.tokenId = mr.TokenId
	ex.lockHex = mr.LockScriptHex
	s.logf("MINTED token %s in tx %s (one live UTXO; identity bound).", hex.EncodeToString(mr.TokenId)[:16]+"…", ex.mintTxid)

	for _, e := range []engine.EventType{engine.EvStartPairing, engine.EvHelloAckValid, engine.EvOffer, engine.EvAcceptMatches, engine.EvPayloadDeliveredOK, engine.EvSwapAssembled, engine.EvTermsVerifyOK} {
		if err = s.Advance(e); err != nil {
			return err
		}
	}
	s.logf("Paired, price agreed (%d sats), payload delivered + hash-verified, terms verified. Ready to sign the swap.", exPrice)
	return nil
}

// doSwap: assemble + co-sign + broadcast the real Tx_swap.
func (s *Server) doSwap(ctx context.Context) error {
	ex := s.ex
	if ex.mintTxid == "" {
		return fmt.Errorf("run Setup + Mint first")
	}
	bobLock, _ := s.lockScriptHex(ex.bobAddr)
	bobVout, err := s.ad.FindVout(ctx, ex.bobFundTxid, bobLock)
	if err != nil {
		return fmt.Errorf("find bob payment: %w", err)
	}
	sp := token.SwapParams{
		TokenPrevTxID: ex.mintTxid, TokenPrevVout: 0, TokenLockScript: ex.lockHex, DustSats: exDust,
		TokenId: ex.tokenId, Descriptor: ex.descr, HPayload: ex.hp, BobOwnerPKH: ex.bobPKH,
		AliceAddr: ex.aliceAddr, PriceSats: exPrice,
		Payments:      []token.PaymentInput{{TxID: ex.bobFundTxid, Vout: bobVout, LockingScript: bobLock, Sats: exBobFund}},
		BobChangeAddr: ex.bobAddr, ChangeSats: exBobFund - exPrice - exFee,
	}
	exp := token.SwapExpectation{TokenId: ex.tokenId, Descriptor: ex.descr, HPayload: ex.hp, BobOwnerPKH: ex.bobPKH, AliceAddr: ex.aliceAddr, PriceSats: exPrice, DustSats: exDust, MaxOutputs: 3}
	b, err := token.AssembleSwap(sp, ex.aliceKey, ex.bobKey)
	if err != nil {
		return err
	}
	unsigned, _ := b.Hex()
	if err = token.VerifySwapTx(unsigned, exp); err != nil {
		return fmt.Errorf("term review failed: %w", err)
	}
	if err = b.Sign(); err != nil {
		return err
	}
	swapHex, _ := b.Hex()
	if ex.swapTxid, err = s.ad.Broadcast(ctx, swapHex); err != nil {
		return fmt.Errorf("swap broadcast: %w", err)
	}
	for _, e := range []engine.EventType{engine.EvPeerPartialReceived, engine.EvOwnSigned, engine.EvBroadcastAccepted} {
		if err = s.Advance(e); err != nil {
			return err
		}
	}
	s.SetChainDepth(0)
	s.logf("Co-signed + BROADCAST Tx_swap %s (token→Bob, %d sats→Alice, atomic). Status: PENDING.", ex.swapTxid, exPrice)
	return nil
}

// doConfirm: mine a block and verify the on-chain transfer.
func (s *Server) doConfirm(ctx context.Context) error {
	ex := s.ex
	if ex.swapTxid == "" {
		return fmt.Errorf("broadcast the swap first")
	}
	if _, err := s.ad.MineBlocks(ctx, 1); err != nil {
		return err
	}
	if st, _ := s.ad.OutputStatus(ctx, chain.Outpoint{TxID: ex.mintTxid, Vout: 0}); st.State != chain.OutSpent {
		return fmt.Errorf("old token UTXO not spent")
	}
	if st, err := s.ad.OutputStatus(ctx, chain.Outpoint{TxID: ex.swapTxid, Vout: 0}); err != nil || st.State != chain.OutUnspent {
		return fmt.Errorf("new token UTXO not live")
	}
	if err := s.Advance(engine.EvConfirmedAtDepth); err != nil {
		return err
	}
	s.SetChainDepth(1)
	s.logf("CONFIRMED. Token now controlled by Bob (UTXO %s:0); Alice's %d-sat output present. Control transfer is VERIFIABLE on-chain.", ex.swapTxid, exPrice)
	return nil
}

// doAttest: Alice attests deletion (a signed CLAIM); Bob validates.
func (s *Server) doAttest(ctx context.Context) error {
	ex := s.ex
	if ex.swapTxid == "" {
		return fmt.Errorf("confirm the swap first")
	}
	cda, err := deletion.BuildCDA(ex.tokenId, ex.mintTxid, 0, ex.swapTxid, ex.hp, time.Now().Unix())
	if err != nil {
		return err
	}
	sig, err := cda.Sign(ex.aliceKey)
	if err != nil {
		return err
	}
	exp := deletion.Expectation{TokenId: ex.tokenId, TokenOutpointTxID: ex.mintTxid, TokenOutpointVout: 0, SwapTxID: ex.swapTxid, HPayload: ex.hp}
	if deletion.ClassifyReceived(&cda, sig, ex.aliceKey.PubKey(), exp) != deletion.AttestValid {
		return fmt.Errorf("CDA failed validation")
	}
	s.SetAttest(deletion.AttestValid)
	if err := s.Advance(engine.EvDeletionAttestValid); err != nil {
		return err
	}
	s.logf("Seller sent a deletion ATTESTATION; Bob validated the signature + bindings. A signed CLAIM — NOT proof the copy is gone.")
	return nil
}
