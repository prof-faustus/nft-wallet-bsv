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
	"fmt"
	"net/http"
	"sync"

	"github.com/prof-faustus/nft-wallet-bsv/internal/deletion"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	"github.com/prof-faustus/nft-wallet-bsv/internal/token"
	"github.com/prof-faustus/nft-wallet-bsv/internal/uistate"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

// Server holds the wallet (keys), the engine, and the observable chain
// depth / attestation status the UI polls. When live actions are enabled
// (EnableLiveActions) it also drives a REAL exchange on regtest.
type Server struct {
	mu        sync.Mutex
	w         *wallet.Wallet
	eng       *engine.Engine
	confDepth uint32
	curDepth  uint32
	attest    deletion.AttestStatus
	delLabel  string // T-stage override for the deletion label (when set)
	mux       *http.ServeMux
	token     string // per-process control token (auth.go) — required on mutating routes

	actMu sync.Mutex // serializes live actions (one button at a time)
	ad    liveAdapter
	ex    *exchange
	v2    *v2Session // parameter-driven exchange (EnableV2)
}

// New builds a sidecar over a wallet + engine. It mints a fresh per-process
// control token (auth.go); every MUTATING route is wrapped with guard() so a
// stray local process or a cross-origin webpage cannot drive money-moving
// actions. Read-only routes (/healthz, /status, /address) stay open. The
// launcher prints the token and hands it to the shell; SetControlToken can
// pin a shared value.
func New(w *wallet.Wallet, eng *engine.Engine, confDepth uint32) *Server {
	s := &Server{w: w, eng: eng, confDepth: confDepth, attest: deletion.AttestAbsent, mux: http.NewServeMux(), token: newControlToken()}
	s.mux.HandleFunc("/healthz", s.healthz)
	s.mux.HandleFunc("/status", s.status)
	s.mux.HandleFunc("/address", s.address)
	s.mux.HandleFunc("/swap/review", s.guard(s.swapReview)) // takes a body + drives a signing decision → guarded
	return s
}

// Handler exposes the routes (for httptest and the cmd/sidecar listener).
func (s *Server) Handler() http.Handler { return s.mux }

// SetChainDepth / SetAttest let the chain/deletion adapters feed the UI
// state (the engine drives state; these annotate it honestly).
func (s *Server) SetChainDepth(d uint32)            { s.mu.Lock(); s.curDepth = d; s.mu.Unlock() }
func (s *Server) SetAttest(a deletion.AttestStatus) { s.mu.Lock(); s.attest = a; s.mu.Unlock() }

// Advance applies an engine event under the server lock (safe against
// concurrent /status reads). Used by the chain/deletion adapters and the
// --demo driver.
func (s *Server) Advance(ev engine.EventType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.eng.Apply(engine.Event{Type: ev})
	return err
}

// engState returns the engine's current state under the server lock (safe
// against concurrent /status reads and Advance).
func (s *Server) engState() engine.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eng.State()
}

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
	if s.delLabel != "" {
		dl = s.delLabel // T-stage attested-wipe override (docs/04 §4.6)
	}
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

// Exact decoded lengths the swap-review fields MUST have (named, not magic):
// a token id and a payload hash are SHA-256 (32 bytes); an owner PKH is
// HASH160 (20 bytes). A descriptor must be present and bounded.
const (
	tokenIDLen       = 32
	payloadHashLen   = 32
	ownerPKHLen      = 20
	maxDescriptorLen = 4096
)

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
	// UseCovenant tells the review which continuity model the tx uses, so the
	// echoed terms label it unambiguously (docs/02 §6; CLAUDE.md §4).
	UseCovenant bool `json:"use_covenant"`
}

type swapTerms struct {
	PriceToAliceSats uint64 `json:"price_to_alice_sats"`
	AliceAddr        string `json:"alice_addr"`
	TokenIdHex       string `json:"token_id_hex"`
	HPayloadHex      string `json:"h_payload_hex"`
	BobOwnerPKHHex   string `json:"bob_owner_pkh_hex"`
	// Continuity is the EXACT enforcement model the user is signing under —
	// never silently implied. Convention mode is labelled "wallet/indexer
	// enforced only" so it is never mistaken for a Script-enforced token.
	Continuity string `json:"continuity"`
}

type swapReviewResp struct {
	OK    bool       `json:"ok"`
	Error string     `json:"error,omitempty"`
	Terms *swapTerms `json:"terms,omitempty"` // echoed for the human to confirm BEFORE signing
}

// continuityLabel renders the user-facing continuity model for a signing
// review. Convention mode MUST be presented as wallet/indexer-enforced only
// (not Script-enforced) so the distinction is unavoidable (audit finding 10;
// CLAUDE.md §4).
func continuityLabel(covenant bool) string {
	if covenant {
		return "Script-enforced (OP_PUSH_TX covenant — token identity/value cannot be stripped)"
	}
	return "wallet/indexer enforced only (convention mode — NOT Script-enforced; an indexer/wallet that ignores the convention is not stopped by Script)"
}

// decodeFixed hex-decodes s and requires exactly n bytes. It returns a named
// error so a malformed field fails the review immediately and clearly rather
// than producing a misleading downstream verifier failure (audit finding 7).
func decodeFixed(field, s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid hex", field)
	}
	if len(b) != n {
		return nil, fmt.Errorf("%s: must be %d bytes, got %d", field, n, len(b))
	}
	return b, nil
}

// swapReview verifies the assembled tx encodes EXACTLY the expected terms
// (token identity preserved + locked to Bob, price to Alice, no surprise
// outputs, no OP_RETURN) and echoes those terms for the signing prompt.
// A failed review returns ok=false with the reason — the shell must show
// the reason and NOT offer to sign (docs/02 §2.5 step 2). Malformed hex or
// wrong-length fields are rejected up front (audit findings 5, 7).
func (s *Server) swapReview(w http.ResponseWriter, r *http.Request) {
	var req swapReviewReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, swapReviewResp{OK: false, Error: "bad request"})
		return
	}
	tokenId, err := decodeFixed("token_id", req.TokenIdHex, tokenIDLen)
	if err != nil {
		writeJSON(w, swapReviewResp{OK: false, Error: err.Error()})
		return
	}
	hp, err := decodeFixed("h_payload", req.HPayloadHex, payloadHashLen)
	if err != nil {
		writeJSON(w, swapReviewResp{OK: false, Error: err.Error()})
		return
	}
	pkh, err := decodeFixed("bob_pkh", req.BobPKHHex, ownerPKHLen)
	if err != nil {
		writeJSON(w, swapReviewResp{OK: false, Error: err.Error()})
		return
	}
	descr, err := hex.DecodeString(req.DescrHex)
	if err != nil {
		writeJSON(w, swapReviewResp{OK: false, Error: "descriptor: invalid hex"})
		return
	}
	if len(descr) == 0 || len(descr) > maxDescriptorLen {
		writeJSON(w, swapReviewResp{OK: false, Error: fmt.Sprintf("descriptor: must be 1..%d bytes", maxDescriptorLen)})
		return
	}
	exp := token.SwapExpectation{
		TokenId: tokenId, Descriptor: descr, HPayload: hp, BobOwnerPKH: pkh,
		AliceAddr: req.AliceAddr, PriceSats: req.PriceSats, DustSats: req.DustSats, MaxOutputs: req.MaxOutputs,
	}
	if err := token.VerifySwapTx(req.TxHex, exp); err != nil {
		writeJSON(w, swapReviewResp{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, swapReviewResp{OK: true, Terms: &swapTerms{
		PriceToAliceSats: req.PriceSats, AliceAddr: req.AliceAddr,
		TokenIdHex: req.TokenIdHex, HPayloadHex: req.HPayloadHex, BobOwnerPKHHex: req.BobPKHHex,
		Continuity: continuityLabel(req.UseCovenant),
	}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
