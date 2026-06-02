// actions_v2.go — the PARAMETER-DRIVEN, menu-driven exchange API.
//
// Design rules (owner-mandated):
//   - No assistant-selected choices, no server-side defaults. Every value
//     (scheme, funding amounts, price, fee, dust, payload, labels) is
//     supplied by the caller; a missing required field is an ERROR, never a
//     silent default.
//   - Every action is a discrete, user-initiated step. Funding and
//     defunding are user-controlled.
//   - GET /v2/options serves the menus (the crypto-shred scheme list comes
//     from shred.Names()), so the UI never hard-codes choices.
//   - Bots/simulation are TEST-ONLY; a real session runs against a real
//     node. This layer is identical whether the adapter is the live node or
//     the script-validating SimNode.
//
// Keys never leave the sidecar (WS7). The crypto-shred scheme really
// encrypts the payload (docs/08): Alice seals it to Bob, Bob opens it after
// the swap and verifies H(plaintext), and Alice can shred her key material.
package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/prof-faustus/nft-wallet-bsv/internal/chain"
	"github.com/prof-faustus/nft-wallet-bsv/internal/covenant"
	"github.com/prof-faustus/nft-wallet-bsv/internal/deletion"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	"github.com/prof-faustus/nft-wallet-bsv/internal/shred"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

// v2Session holds one user-driven exchange. Every field is populated by an
// explicit user action; nothing is pre-set.
type v2Session struct {
	scheme      string // chosen crypto-shred scheme (required)
	useCovenant bool   // user choice: Script-enforce continuity via OP_PUSH_TX

	aliceLabel, bobLabel string
	aliceKey, bobKey     *ec.PrivateKey
	aliceAddr, bobAddr   string
	bobPKH               []byte

	aliceFundTxid string
	aliceFundSats uint64
	bobFundTxid   string
	bobFundSats   uint64

	payload      []byte
	sealed       *shred.Sealed
	sellerSecret *shred.SellerSecret
	bobOpened    bool

	tokenId, descr, hp []byte
	dustSats           uint64
	mintTxid, lockHex  string

	swapTxid  string
	priceSats uint64

	log []string
}

// EnableV2 wires the parameter-driven exchange API against an adapter (the
// live node, or — for tests only — the SimNode). Call before serving.
func (s *Server) EnableV2(ad liveAdapter) {
	s.ad = ad
	s.v2 = &v2Session{}
	s.mux.HandleFunc("/v2/options", s.v2Options)
	s.mux.HandleFunc("/v2/reset", s.v2JSON(s.v2Reset))
	s.mux.HandleFunc("/v2/keys", s.v2JSON(s.v2Keys))
	s.mux.HandleFunc("/v2/fund", s.v2JSON(s.v2Fund))
	s.mux.HandleFunc("/v2/mint", s.v2JSON(s.v2Mint))
	s.mux.HandleFunc("/v2/deliver", s.v2JSON(s.v2Deliver))
	s.mux.HandleFunc("/v2/swap", s.v2JSON(s.v2Swap))
	s.mux.HandleFunc("/v2/confirm", s.v2JSON(s.v2Confirm))
	s.mux.HandleFunc("/v2/shred", s.v2JSON(s.v2Shred))
	s.mux.HandleFunc("/v2/attest", s.v2JSON(s.v2Attest))
}

type v2Resp struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
	Log   []string `json:"log"`
	Data  any      `json:"data,omitempty"`
}

// v2JSON adapts a (ctx, json.RawMessage) -> (data, error) handler into an
// HTTP handler that serializes actions and returns the running log.
func (s *Server) v2JSON(fn func(context.Context, json.RawMessage) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := readAll(r)
		s.actMu.Lock()
		defer s.actMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		data, err := fn(ctx, body)
		resp := v2Resp{OK: err == nil, Log: s.v2log(), Data: data}
		if err != nil {
			resp.Error = err.Error()
		}
		writeJSON(w, resp)
	}
}

// v2Options serves the menus so the UI never hard-codes choices.
func (s *Server) v2Options(w http.ResponseWriter, _ *http.Request) {
	type opt struct {
		Schemes            []string `json:"schemes"`
		DefaultScheme      string   `json:"default_scheme_note"`
		CovenantSelectable bool     `json:"covenant_selectable"`
		CovenantNote       string   `json:"covenant_note"`
	}
	writeJSON(w, v2Resp{OK: true, Data: opt{
		Schemes:            shred.Names(),
		DefaultScheme:      "none — the user must choose a scheme explicitly",
		CovenantSelectable: true,
		CovenantNote:       "off = convention-enforced continuity; on = OP_PUSH_TX covenant (Script-enforced, cannot be stripped). The user chooses.",
	}})
}

func (s *Server) v2logf(format string, a ...any) {
	s.mu.Lock()
	s.v2.log = append(s.v2.log, fmt.Sprintf(format, a...))
	s.mu.Unlock()
}

func (s *Server) v2log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v2 == nil {
		return nil
	}
	out := make([]string, len(s.v2.log))
	copy(out, s.v2.log)
	return out
}

// ---- requests (pointers/strings so "absent" is detectable) ---------------

type resetReq struct {
	Scheme      string `json:"scheme"`
	UseCovenant *bool  `json:"use_covenant"` // required: the user must choose on/off
}

func (s *Server) v2Reset(_ context.Context, body json.RawMessage) (any, error) {
	var req resetReq
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("bad request")
	}
	if req.Scheme == "" {
		return nil, fmt.Errorf("scheme is required — choose one of %v (no default)", shred.Names())
	}
	if _, err := shred.ForName(req.Scheme); err != nil {
		return nil, fmt.Errorf("unknown scheme %q; choose one of %v", req.Scheme, shred.Names())
	}
	if req.UseCovenant == nil {
		return nil, fmt.Errorf("use_covenant is required — choose true (Script-enforced) or false (no default)")
	}
	s.mu.Lock()
	s.v2 = &v2Session{scheme: req.Scheme, useCovenant: *req.UseCovenant}
	s.eng = engine.New(s.eng.Role())
	s.curDepth = 0
	s.attest = deletion.AttestAbsent
	s.mu.Unlock()
	s.v2logf("Session reset. Scheme = %q; continuity = %s (both chosen by the user).", req.Scheme, covLabel(*req.UseCovenant))
	return map[string]any{"scheme": req.Scheme, "use_covenant": *req.UseCovenant}, nil
}

func covLabel(on bool) string {
	if on {
		return "OP_PUSH_TX covenant (Script-enforced)"
	}
	return "convention-enforced"
}

type keysReq struct {
	AliceLabel string `json:"alice_label"`
	BobLabel   string `json:"bob_label"`
}

func (s *Server) v2Keys(_ context.Context, body json.RawMessage) (any, error) {
	var req keysReq
	_ = json.Unmarshal(body, &req)
	if req.AliceLabel == "" || req.BobLabel == "" {
		return nil, fmt.Errorf("alice_label and bob_label are both required")
	}
	ex := s.v2
	var err error
	if ex.aliceAddr, err = s.w.NewKey(req.AliceLabel); err != nil {
		return nil, err
	}
	if ex.bobAddr, err = s.w.NewKey(req.BobLabel); err != nil {
		return nil, err
	}
	ex.aliceLabel, ex.bobLabel = req.AliceLabel, req.BobLabel
	ex.aliceKey, _ = s.w.Key(req.AliceLabel)
	ex.bobKey, _ = s.w.Key(req.BobLabel)
	ex.bobPKH = token.PubKeyHash(ex.bobKey.PubKey())
	s.v2logf("Created keys: seller %q=%s, buyer %q=%s (the browser/shell never sees the keys).", req.AliceLabel, ex.aliceAddr, req.BobLabel, ex.bobAddr)
	return map[string]string{"alice_addr": ex.aliceAddr, "bob_addr": ex.bobAddr}, nil
}

type fundReq struct {
	Who  string  `json:"who"`  // "alice" | "bob"
	Sats *uint64 `json:"sats"` // required; user-chosen amount
}

func (s *Server) v2Fund(ctx context.Context, body json.RawMessage) (any, error) {
	var req fundReq
	_ = json.Unmarshal(body, &req)
	if req.Sats == nil {
		return nil, fmt.Errorf("sats is required — the user chooses the funding amount (no default)")
	}
	ex := s.v2
	var addr string
	switch req.Who {
	case "alice":
		addr = ex.aliceAddr
	case "bob":
		addr = ex.bobAddr
	default:
		return nil, fmt.Errorf("who must be \"alice\" or \"bob\"")
	}
	if addr == "" {
		return nil, fmt.Errorf("create keys first (/v2/keys)")
	}
	txid, err := s.ad.FundAddress(ctx, addr, *req.Sats)
	if err != nil {
		return nil, err
	}
	if _, err := s.ad.MineBlocks(ctx, 1); err != nil {
		return nil, err
	}
	if req.Who == "alice" {
		ex.aliceFundTxid, ex.aliceFundSats = txid, *req.Sats
	} else {
		ex.bobFundTxid, ex.bobFundSats = txid, *req.Sats
	}
	s.v2logf("Funded %s with %d sats (user-chosen) in %s.", req.Who, *req.Sats, txid)
	return map[string]any{"txid": txid, "sats": *req.Sats}, nil
}

type mintReq struct {
	PayloadText string  `json:"payload_text"`
	DustSats    *uint64 `json:"dust_sats"`
	FeeSats     *uint64 `json:"fee_sats"`
}

func (s *Server) v2Mint(ctx context.Context, body json.RawMessage) (any, error) {
	var req mintReq
	_ = json.Unmarshal(body, &req)
	ex := s.v2
	if ex.scheme == "" {
		return nil, fmt.Errorf("reset with a chosen scheme first (/v2/reset)")
	}
	if ex.aliceKey == nil {
		return nil, fmt.Errorf("create keys first (/v2/keys)")
	}
	if ex.aliceFundTxid == "" {
		return nil, fmt.Errorf("fund alice first (/v2/fund)")
	}
	if req.PayloadText == "" {
		return nil, fmt.Errorf("payload_text is required (the NFT's secret content)")
	}
	if req.DustSats == nil || req.FeeSats == nil {
		return nil, fmt.Errorf("dust_sats and fee_sats are required (user-chosen; no default)")
	}
	if ex.aliceFundSats <= *req.DustSats+*req.FeeSats {
		return nil, fmt.Errorf("alice funding %d too small for dust %d + fee %d", ex.aliceFundSats, *req.DustSats, *req.FeeSats)
	}
	ex.payload = []byte(req.PayloadText)
	ex.hp = token.HashPayload(ex.payload)

	// REAL crypto-shred: seal the payload to Bob with the chosen scheme.
	sc, err := shred.ForName(ex.scheme)
	if err != nil {
		return nil, err
	}
	sealed, secret, err := sc.Seal(ex.payload, ex.bobKey.PubKey())
	if err != nil {
		return nil, fmt.Errorf("seal payload (%s): %w", ex.scheme, err)
	}
	ex.sealed, ex.sellerSecret = sealed, secret
	ex.bobOpened = false
	s.v2logf("Sealed the payload with scheme %q (strength=%s). Alice holds the ciphertext; Bob gets access on swap.", ex.scheme, sc.Strength())

	ex.descr, err = token.PayloadDescriptor{ContentType: "application/octet-stream", Length: uint64(len(ex.payload)), EncScheme: token.EncPlaceholderV1}.Bytes()
	if err != nil {
		return nil, err
	}
	aliceLock, _ := s.lockScriptHex(ex.aliceAddr)
	aliceVout, err := s.ad.FindVout(ctx, ex.aliceFundTxid, aliceLock)
	if err != nil {
		return nil, fmt.Errorf("find alice funding: %w", err)
	}
	funding := []token.FundingInput{{TxID: ex.aliceFundTxid, Vout: aliceVout, LockingScript: aliceLock, Sats: ex.aliceFundSats}}
	change := ex.aliceFundSats - *req.DustSats - *req.FeeSats
	var mintBuilder *wallet.Builder
	if ex.useCovenant {
		mr, err := covenant.MintCovenant(covenant.MintCovenantParams{
			Funding: funding, OwnerKey: ex.aliceKey, Descriptor: ex.descr, HPayload: ex.hp,
			TokenValue: *req.DustSats, ChangeAddr: ex.aliceAddr, ChangeSats: change,
		})
		if err != nil {
			return nil, fmt.Errorf("covenant mint: %w", err)
		}
		mintBuilder, ex.tokenId, ex.lockHex = mr.Builder, mr.TokenId, mr.LockScriptHex
	} else {
		mr, err := token.Mint(token.MintParams{
			Funding: funding, OwnerKey: ex.aliceKey, Descriptor: ex.descr, HPayload: ex.hp,
			DustSats: *req.DustSats, ChangeAddr: ex.aliceAddr, ChangeSats: change,
		})
		if err != nil {
			return nil, fmt.Errorf("mint: %w", err)
		}
		mintBuilder, ex.tokenId, ex.lockHex = mr.Builder, mr.TokenId, mr.LockScriptHex
	}
	ex.dustSats = *req.DustSats
	if err := mintBuilder.Sign(); err != nil {
		return nil, err
	}
	mintHex, _ := mintBuilder.Hex()
	if ex.mintTxid, err = s.ad.Broadcast(ctx, mintHex); err != nil {
		return nil, fmt.Errorf("mint broadcast: %w", err)
	}
	if _, err = s.ad.MineBlocks(ctx, 1); err != nil {
		return nil, err
	}
	for _, e := range []engine.EventType{engine.EvStartPairing, engine.EvHelloAckValid, engine.EvOffer, engine.EvAcceptMatches, engine.EvPayloadDeliveredOK, engine.EvSwapAssembled, engine.EvTermsVerifyOK} {
		if err = s.Advance(e); err != nil {
			return nil, err
		}
	}
	s.v2logf("MINTED token %s… in %s (one live UTXO; continuity=%s). Ready to sign the swap.", hex.EncodeToString(ex.tokenId)[:16], ex.mintTxid, covLabel(ex.useCovenant))
	return map[string]any{"token_id": hex.EncodeToString(ex.tokenId), "mint_txid": ex.mintTxid}, nil
}

// v2Deliver: Bob opens the sealed payload with HIS key and verifies the hash
// the token commits to — the access transfer (I-CS-2).
func (s *Server) v2Deliver(_ context.Context, _ json.RawMessage) (any, error) {
	ex := s.v2
	if ex.sealed == nil {
		return nil, fmt.Errorf("mint first (/v2/mint)")
	}
	sc, _ := shred.ForName(ex.scheme)
	plain, err := sc.Open(ex.sealed, ex.bobKey)
	if err != nil {
		return nil, fmt.Errorf("bob open (%s): %w", ex.scheme, err)
	}
	if hex.EncodeToString(token.HashPayload(plain)) != hex.EncodeToString(ex.hp) {
		return nil, fmt.Errorf("decrypted payload hash mismatch — would abort (F-4)")
	}
	ex.bobOpened = true
	s.v2logf("Buyer decrypted the payload with scheme %q and verified H(plaintext) matches the token. Access transferred.", ex.scheme)
	return map[string]any{"verified": true, "bytes": len(plain)}, nil
}

type swapReq struct {
	PriceSats *uint64 `json:"price_sats"`
	FeeSats   *uint64 `json:"fee_sats"`
}

func (s *Server) v2Swap(ctx context.Context, body json.RawMessage) (any, error) {
	var req swapReq
	_ = json.Unmarshal(body, &req)
	ex := s.v2
	if ex.mintTxid == "" {
		return nil, fmt.Errorf("mint first (/v2/mint)")
	}
	if ex.bobFundTxid == "" {
		return nil, fmt.Errorf("fund bob first (/v2/fund)")
	}
	if req.PriceSats == nil || req.FeeSats == nil {
		return nil, fmt.Errorf("price_sats and fee_sats are required (user-chosen; no default)")
	}
	if ex.bobFundSats <= *req.PriceSats+*req.FeeSats {
		return nil, fmt.Errorf("bob funding %d too small for price %d + fee %d", ex.bobFundSats, *req.PriceSats, *req.FeeSats)
	}
	bobLock, _ := s.lockScriptHex(ex.bobAddr)
	bobVout, err := s.ad.FindVout(ctx, ex.bobFundTxid, bobLock)
	if err != nil {
		return nil, fmt.Errorf("find bob payment: %w", err)
	}
	payments := []token.PaymentInput{{TxID: ex.bobFundTxid, Vout: bobVout, LockingScript: bobLock, Sats: ex.bobFundSats}}
	change := ex.bobFundSats - *req.PriceSats - *req.FeeSats
	exp := token.SwapExpectation{TokenId: ex.tokenId, Descriptor: ex.descr, HPayload: ex.hp, BobOwnerPKH: ex.bobPKH, AliceAddr: ex.aliceAddr, PriceSats: *req.PriceSats, DustSats: ex.dustSats, MaxOutputs: 3}
	var b *wallet.Builder
	if ex.useCovenant {
		// The token input is the covenant UTXO, spent via OP_PUSH_TX; the
		// successor token output is Script-FORCED to preserve identity/value.
		b, err = covenant.AssembleCovenantSwap(covenant.CovenantSwapParams{
			TokenPrevTxID: ex.mintTxid, TokenPrevVout: 0,
			TokenId: ex.tokenId, Descriptor: ex.descr, HPayload: ex.hp, TokenValue: ex.dustSats,
			BobOwnerPKH: ex.bobPKH, SellerAddr: ex.aliceAddr, PriceSats: *req.PriceSats,
			Payments: payments, BobChangeAddr: ex.bobAddr, ChangeSats: change,
		}, ex.bobKey)
	} else {
		b, err = token.AssembleSwap(token.SwapParams{
			TokenPrevTxID: ex.mintTxid, TokenPrevVout: 0, TokenLockScript: ex.lockHex, DustSats: ex.dustSats,
			TokenId: ex.tokenId, Descriptor: ex.descr, HPayload: ex.hp, BobOwnerPKH: ex.bobPKH,
			AliceAddr: ex.aliceAddr, PriceSats: *req.PriceSats,
			Payments: payments, BobChangeAddr: ex.bobAddr, ChangeSats: change,
		}, ex.aliceKey, ex.bobKey)
	}
	if err != nil {
		return nil, err
	}
	unsigned, _ := b.Hex()
	if err = token.VerifySwapTx(unsigned, exp); err != nil {
		return nil, fmt.Errorf("term review failed: %w", err)
	}
	if err = b.Sign(); err != nil {
		return nil, err
	}
	swapHex, _ := b.Hex()
	if ex.swapTxid, err = s.ad.Broadcast(ctx, swapHex); err != nil {
		return nil, fmt.Errorf("swap broadcast: %w", err)
	}
	ex.priceSats = *req.PriceSats
	for _, e := range []engine.EventType{engine.EvPeerPartialReceived, engine.EvOwnSigned, engine.EvBroadcastAccepted} {
		if err = s.Advance(e); err != nil {
			return nil, err
		}
	}
	s.SetChainDepth(0)
	s.v2logf("Co-signed + BROADCAST swap %s (token→buyer, %d sats→seller, atomic). PENDING.", ex.swapTxid, *req.PriceSats)
	return map[string]any{"swap_txid": ex.swapTxid}, nil
}

type confirmReq struct {
	Blocks *int `json:"blocks"`
}

func (s *Server) v2Confirm(ctx context.Context, body json.RawMessage) (any, error) {
	var req confirmReq
	_ = json.Unmarshal(body, &req)
	ex := s.v2
	if ex.swapTxid == "" {
		return nil, fmt.Errorf("broadcast the swap first (/v2/swap)")
	}
	if req.Blocks == nil || *req.Blocks < 1 {
		return nil, fmt.Errorf("blocks is required and must be >= 1 (user-chosen)")
	}
	if _, err := s.ad.MineBlocks(ctx, *req.Blocks); err != nil {
		return nil, err
	}
	if st, _ := s.ad.OutputStatus(ctx, chain.Outpoint{TxID: ex.mintTxid, Vout: 0}); st.State != chain.OutSpent {
		return nil, fmt.Errorf("old token UTXO not spent")
	}
	if st, err := s.ad.OutputStatus(ctx, chain.Outpoint{TxID: ex.swapTxid, Vout: 0}); err != nil || st.State != chain.OutUnspent {
		return nil, fmt.Errorf("new token UTXO not live")
	}
	if err := s.Advance(engine.EvConfirmedAtDepth); err != nil {
		return nil, err
	}
	s.SetChainDepth(s.confDepth)
	s.v2logf("CONFIRMED. Token controlled by buyer (%s:0); seller paid %d. Control transfer VERIFIABLE on-chain.", ex.swapTxid, ex.priceSats)
	return map[string]any{"confirmed": true}, nil
}

// v2Shred: Alice destroys her key material; afterwards she CANNOT reopen the
// ciphertext (crypto-shred). The enforced (tee) scheme never let her open.
func (s *Server) v2Shred(_ context.Context, _ json.RawMessage) (any, error) {
	ex := s.v2
	if ex.sellerSecret == nil {
		return nil, fmt.Errorf("nothing sealed yet (mint first)")
	}
	beforeErr := func() error { _, e := ex.sellerSecret.TryOpen(ex.sealed); return e }()
	ex.sellerSecret.Shred()
	afterErr := func() error { _, e := ex.sellerSecret.TryOpen(ex.sealed); return e }()
	if afterErr == nil {
		return nil, fmt.Errorf("crypto-shred FAILED: seller can still open after shred")
	}
	s.v2logf("Seller SHREDDED key material (scheme %q). Could-open-before=%v; can-open-after=false. (Cooperative shred is a CLAIM, not proof of deletion.)", ex.scheme, beforeErr == nil)
	return map[string]any{"could_open_before": beforeErr == nil, "can_open_after": false}, nil
}

func (s *Server) v2Attest(_ context.Context, _ json.RawMessage) (any, error) {
	ex := s.v2
	if ex.swapTxid == "" {
		return nil, fmt.Errorf("confirm the swap first")
	}
	cda, err := deletion.BuildCDA(ex.tokenId, ex.mintTxid, 0, ex.swapTxid, ex.hp, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	sig, err := cda.Sign(ex.aliceKey)
	if err != nil {
		return nil, err
	}
	exp := deletion.Expectation{TokenId: ex.tokenId, TokenOutpointTxID: ex.mintTxid, TokenOutpointVout: 0, SwapTxID: ex.swapTxid, HPayload: ex.hp}
	if deletion.ClassifyReceived(&cda, sig, ex.aliceKey.PubKey(), exp) != deletion.AttestValid {
		return nil, fmt.Errorf("CDA failed validation")
	}
	s.SetAttest(deletion.AttestValid)
	if err := s.Advance(engine.EvDeletionAttestValid); err != nil {
		return nil, err
	}
	s.v2logf("Seller sent a deletion ATTESTATION; buyer validated signature + bindings. A signed CLAIM — NOT proof the copy is gone.")
	return map[string]any{"attested": true}, nil
}

// readAll reads the request body (bounded) for JSON decoding.
func readAll(r *http.Request) (json.RawMessage, error) {
	if r == nil || r.Body == nil {
		return json.RawMessage("{}"), nil
	}
	defer r.Body.Close()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		nr, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:nr]...)
		if err != nil || len(buf) > 1<<20 {
			break
		}
	}
	if len(buf) == 0 {
		return json.RawMessage("{}"), nil
	}
	return json.RawMessage(buf), nil
}

var _ = script.NewFromBytes // keep script import available to this package
