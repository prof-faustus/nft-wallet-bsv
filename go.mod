// Module nft-wallet-bsv — the Go sidecar/services layer (BSV Go SDK).
//
// Per CLAUDE.md §1 this project is BSV-only; per docs/07 OD-2 the Go
// sidecar performs all key custody and BSV/script/chain operations while
// the native .NET/C# shell (WS7) is UI only. No BTC dependency may ever
// appear in this graph — the `bsv-only` gate (docs/05 §5.2) enforces it.
module github.com/prof-faustus/nft-wallet-bsv

go 1.23
