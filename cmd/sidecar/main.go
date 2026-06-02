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
	"net/http"

	"github.com/prof-faustus/nft-wallet-bsv/internal/engine"
	bsvparams "github.com/prof-faustus/nft-wallet-bsv/internal/params"
	"github.com/prof-faustus/nft-wallet-bsv/internal/sidecar"
	"github.com/prof-faustus/nft-wallet-bsv/internal/wallet"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "localhost bind address (IPC only)")
	ksPath := flag.String("keystore", "nftbsv-keystore.json", "encrypted keystore path")
	pass := flag.String("passphrase", "", "keystore passphrase (required)")
	role := flag.String("role", "buyer", "seller|buyer")
	flag.Parse()

	if *pass == "" {
		log.Fatal("sidecar: --passphrase is required (keys are encrypted at rest, SC-1)")
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

	log.Printf("sidecar: listening on %s (role=%s) — localhost IPC for the .NET shell", *addr, *role)
	srv := &http.Server{Addr: *addr, Handler: s.Handler()}
	log.Fatal(srv.ListenAndServe())
}
