// Package sidecar is the Go services layer the native .NET/C# shell talks
// to over localhost HTTP (OD-2, docs/01 §1.1/§1.2; docs/06 WS7). It is
// where keys live and where all BSV/script/engine work happens; the
// renderer (the C# shell) holds NO keys and only renders what the sidecar
// reports.
//
// Two WS7 guarantees are enforced HERE (in testable Go), not in GUI code:
//   - The renderer never receives private key material — /address returns
//     an address only.
//   - Status is the honest uistate (pending vs confirmed; deletion a
//     CLAIM, never "verified"), and /swap/review returns the EXACT terms
//     the user is about to sign (docs/02 §2.5 step 2) before any signature.
//
// Implements: docs/06 WS7. MUST NOT expose keys or import BTC.
package sidecar

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/prof-faustus/nft-wallet-bsv/internal/deletion"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
	"github.com/prof-faustus/nft-wallet-bsv/internal/uistate"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

// Server holds the wallet (keys), the engine, and the observable chain
// depth / attestation status the UI polls.
type Server struct {
	mu        sync.Mutex
	w         *wallet.Wallet
	eng       *engine.Engine
	confDepth uint32
	curDepth  uint32
	attest    deletion.AttestStatus
	mux       *http.ServeMux
}

// New builds a sidecar over a wallet + engine.
func New(w *wallet.Wallet, eng *engine.Engine, confDepth uint32) *Server {
	s := &Server{w: w, eng: eng, confDepth: confDepth, attest: deletion.AttestAbsent, mux: http.NewServeMux()}
	s.mux.HandleFunc("/healthz", s.healthz)
	s.mux.HandleFunc("/status", s.status)
	s.mux.HandleFunc("/address", s.address)
	s.mux.HandleFunc("/swap/review", s.swapReview)
	return s
}

// Handler exposes the routes (for httptest and the cmd/sidecar listener).
func (s *Server) Handler() http.Handler { return s.mux }

// SetChainDepth / SetAttest let the chain/deletion adapters feed the UI
// state (the engine drives state; these annotate it honestly).
func (s *Server) SetChainDepth(d uint32)            { s.mu.Lock(); s.curDepth = d; s.mu.Unlock() }
func (s *Server) SetAttest(a deletion.AttestStatus) { s.mu.Lock(); s.attest = a; s.mu.Unlock() }

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }

type statusResp struct {
	EngineState   string `json:"engine_state"`
	Label         string `json:"label"`
	Success       bool   `json:"success"`
	Pending       bool   `json:"pending"`
	Failed        bool   `json:"failed"`
	DeletionLabel string `json:"deletion_label"`
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	d := uistate.ForExchange(s.eng.State(), s.eng.Reason(), s.curDepth, s.confDepth)
	dl := uistate.DeletionLabel(s.attest)
	s.mu.Unlock()
	writeJSON(w, statusResp{d.EngineState, d.Label, d.Success, d.Pending, d.Failed, dl})
}

type addressResp struct {
	Label   string `json:"label"`
	Address string `json:"address"`
}

// address returns ONLY a public address for a label. It never returns key
// material — the renderer is non-custodial (WS7 DoD).
func (s *Server) address(w http.ResponseWriter, r *http.Request) {
	label := r.URL.Query().Get("label")
	addr, err := s.w.AddressFor(label)
	if err != nil {
		http.Error(w, "no such key label", http.StatusNotFound)
		return
	}
	writeJSON(w, addressResp{Label: label, Address: addr})
}

// swapReviewReq is what the shell posts to review a swap before signing.
type swapReviewReq struct {
	TxHex       string `json:"tx_hex"`
	TokenIdHex  string `json:"token_id_hex"`
	DescrHex    string `json:"descriptor_hex"`
	HPayloadHex string `json:"h_payload_hex"`
	BobPKHHex   string `json:"bob_pkh_hex"`
	AliceAddr   string `json:"alice_addr"`
	PriceSats   uint64 `json:"price_sats"`
	DustSats    uint64 `json:"dust_sats"`
	MaxOutputs  int    `json:"max_outputs"`
}

type swapReviewResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Terms echoed for the human to confirm BEFORE signing.
	Terms *struct {
		PriceToAliceSats uint64 `json:"price_to_alice_sats"`
		AliceAddr        string `json:"alice_addr"`
		TokenIdHex       string `json:"token_id_hex"`
		HPayloadHex      string `json:"h_payload_hex"`
		BobOwnerPKHHex   string `json:"bob_owner_pkh_hex"`
	} `json:"terms,omitempty"`
}

// swapReview verifies the assembled tx encodes EXACTLY the expected terms
// (token identity preserved + locked to Bob, price to Alice, no surprise
// outputs, no OP_RETURN) and echoes those terms for the signing prompt.
// A failed review returns ok=false with the reason — the shell must show
// the reason and NOT offer to sign (docs/02 §2.5 step 2).
func (s *Server) swapReview(w http.ResponseWriter, r *http.Request) {
	var req swapReviewReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, swapReviewResp{OK: false, Error: "bad request"})
		return
	}
	tokenId, _ := hex.DecodeString(req.TokenIdHex)
	descr, _ := hex.DecodeString(req.DescrHex)
	hp, _ := hex.DecodeString(req.HPayloadHex)
	pkh, _ := hex.DecodeString(req.BobPKHHex)
	exp := token.SwapExpectation{
		TokenId: tokenId, Descriptor: descr, HPayload: hp, BobOwnerPKH: pkh,
		AliceAddr: req.AliceAddr, PriceSats: req.PriceSats, DustSats: req.DustSats, MaxOutputs: req.MaxOutputs,
	}
	if err := token.VerifySwapTx(req.TxHex, exp); err != nil {
		writeJSON(w, swapReviewResp{OK: false, Error: err.Error()})
		return
	}
	resp := swapReviewResp{OK: true}
	resp.Terms = &struct {
		PriceToAliceSats uint64 `json:"price_to_alice_sats"`
		AliceAddr        string `json:"alice_addr"`
		TokenIdHex       string `json:"token_id_hex"`
		HPayloadHex      string `json:"h_payload_hex"`
		BobOwnerPKHHex   string `json:"bob_owner_pkh_hex"`
	}{req.PriceSats, req.AliceAddr, req.TokenIdHex, req.HPayloadHex, req.BobPKHHex}
	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
