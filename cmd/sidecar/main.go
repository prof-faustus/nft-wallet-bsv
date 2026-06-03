// Command sidecar is the local Go services process the native .NET/C#
// shell (WS7, OD-2) talks to over localhost HTTP. Keys live here; the
// shell holds none. It binds 127.0.0.1 only — it is a local IPC surface,
// never a network service.
//
// MUST NOT expose key material over the wire (see internal/sidecar).
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/prof-faustus/nft-wallet-bsv/internal/chain/svnode"
	"github.com/prof-faustus/nft-wallet-bsv/internal/deletion"
	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	bsvparams "github.com/prof-faustus/nft-wallet-bsv/internal/params"
	"github.com/prof-faustus/nft-wallet-bsv/internal/sidecar"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

// runDemo walks the engine through the canonical happy path on a timer so
// the shell visibly shows the HONEST progression (in-progress → amber
// PENDING → green CONFIRMED → deletion CLAIM). This is a DEMO of the UI's
// honesty surface only — it scripts engine events; it is not a real
// on-chain exchange.
func runDemo(s *sidecar.Server) {
	steps := []struct {
		ev    engine.EventType
		depth uint32
		pause time.Duration
	}{
		{engine.EvStartPairing, 0, 2 * time.Second},
		{engine.EvHelloAckValid, 0, 2 * time.Second},
		{engine.EvOffer, 0, 2 * time.Second},
		{engine.EvAcceptMatches, 0, 2 * time.Second},
		{engine.EvPayloadDeliveredOK, 0, 2 * time.Second},
		{engine.EvSwapAssembled, 0, 1 * time.Second},
		{engine.EvTermsVerifyOK, 0, 1 * time.Second},
		{engine.EvPeerPartialReceived, 0, 1 * time.Second},
		{engine.EvOwnSigned, 0, 1 * time.Second},
		{engine.EvBroadcastAccepted, 0, 4 * time.Second}, // amber PENDING
		{engine.EvConfirmedAtDepth, 1, 3 * time.Second},  // green CONFIRMED
		{engine.EvDeletionAttestValid, 1, 0},             // buyer DONE (CDA claim)
	}
	for _, st := range steps {
		time.Sleep(st.pause)
		s.SetChainDepth(st.depth)
		if st.ev == engine.EvDeletionAttestValid {
			s.SetAttest(deletion.AttestValid)
		}
		if err := s.Advance(st.ev); err != nil {
			log.Printf("demo: %v", err)
		}
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "localhost bind address (IPC only)")
	ksPath := flag.String("keystore", "nftbsv-keystore.json", "encrypted keystore path")
	pass := flag.String("passphrase", "", "keystore passphrase (required)")
	role := flag.String("role", "buyer", "seller|buyer")
	demo := flag.Bool("demo", false, "drive the engine through the happy path on a timer (UI honesty demo; not a real exchange)")
	simulate := flag.Bool("simulate", false, "TEST/DEMO ONLY: drive the menu API against an in-memory script-validating simulation node (NOT a real chain; never the default). Use --rpc-url for a real exchange.")
	rpcURL := flag.String("rpc-url", "", "regtest node JSON-RPC URL; if set, enables LIVE on-chain actions")
	rpcUser := flag.String("rpc-user", "nftbsv", "node RPC user")
	rpcPass := flag.String("rpc-pass", "nftbsv-dev-rpc-password", "node RPC password")
	unsafeListen := flag.Bool("unsafe-listen", false, "permit a NON-loopback bind address (DANGEROUS: the sidecar holds keys and is a local IPC surface; only set this if you understand the exposure)")
	flag.Parse()

	if *pass == "" {
		log.Fatal("sidecar: --passphrase is required (keys are encrypted at rest, SC-1)")
	}
	// The sidecar is a local IPC surface that holds keys. Refuse to bind a
	// non-loopback address unless explicitly forced (audit finding 1).
	if !isLoopbackBind(*addr) && !*unsafeListen {
		log.Fatalf("sidecar: refusing to bind non-loopback address %q (keys live here). Pass --unsafe-listen to override.", *addr)
	}
	ks, err := wallet.OpenFileKeystore(*ksPath, *pass)
	if err != nil {
		log.Fatalf("sidecar: keystore: %v", err)
	}
	w := wallet.New(ks, bsvparams.Regtest)
	r := engine.Buyer
	if *role == "seller" {
		r = engine.Seller
	}
	s := sidecar.New(w, engine.New(r), 1)
	if *rpcURL != "" {
		ad := svnode.New(svnode.Config{URL: *rpcURL, User: *rpcUser, Pass: *rpcPass})
		s.EnableLiveActions(ad) // v1 fixed-flow panel (kept for the legacy /action/* path)
		s.EnableV2(ad)          // v2 menu-driven API the native shell uses — REAL node
		log.Printf("sidecar: LIVE on-chain actions enabled against %s (menu API at /v2)", *rpcURL)
	} else if *simulate {
		s.EnableV2(sidecar.NewSimNode())
		log.Printf("sidecar: SIMULATION mode (--simulate): /v2 menu API against an in-memory script-validating node. NOT a real chain; for trying the UI only.")
	}
	if *demo {
		log.Printf("sidecar: --demo driving the engine through the happy path (UI honesty demo)")
		go runDemo(s)
	}

	// Print the per-process control token: the launcher hands it to the shell,
	// which must send it in the X-NFTBSV-Control-Token header on every mutating
	// request. Without it, a stray local process or a webpage cannot drive the
	// money-moving routes (audit finding 1).
	log.Printf("sidecar: control token = %s (set %s on every mutating request)", s.ControlToken(), sidecar.ControlTokenHeader)

	log.Printf("sidecar: listening on %s (role=%s) — localhost IPC for the .NET shell", *addr, *role)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second, // slow-loris guard
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      150 * time.Second, // > the 120s action context
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// isLoopbackBind reports whether addr binds a loopback host. An empty/":port"
// host binds all interfaces (NOT loopback). A bare hostname that is not
// "localhost" is treated as non-loopback (fail-safe).
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":8090" binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
