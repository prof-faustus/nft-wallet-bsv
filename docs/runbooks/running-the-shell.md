# Runbook — running the Windows shell (WS7) and the E2E-8-through-UI acceptance (M4)

The Stage-1 architecture (OD-2, `docs/07`) is a **native .NET/C# shell**
over a **Go sidecar**. The sidecar holds the keys and does all BSV/script/
engine work; the shell holds **no keys** and only renders what the sidecar
reports. This split is why the renderer can never leak key material and
why the honest "pending vs confirmed" / "attested vs not-proof" state is
authoritative in Go (`internal/uistate`, `internal/sidecar`), not in GUI
strings.

> Milestone **M4** (`docs/05` §5.4 E2E-8 through the UI) is a **human**
> acceptance: a person runs two instances and completes the exchange in
> the GUI. The GUI cannot be auto-asserted the way the rest of the suite
> is; CI only *compile-verifies* the shell (`dotnet-shell` job). The
> honest-state logic the GUI displays **is** unit-tested in Go
> (`internal/uistate`, `internal/sidecar`).

## Prerequisites

- A BSV regtest node (`deploy/regtest`, see `docs/runbooks/live-chain-e2e`-style bring-up).
- Go toolchain (sidecar) and the **.NET 8 SDK** (shell).

## 1. Start two sidecars (Alice = seller, Bob = buyer)

Keys are encrypted at rest (SC-1); each sidecar needs a passphrase.

```powershell
go run ./cmd/sidecar --addr 127.0.0.1:8090 --role seller --keystore alice.json --passphrase <alice-pass>
go run ./cmd/sidecar --addr 127.0.0.1:8091 --role buyer  --keystore bob.json   --passphrase <bob-pass>
```

## 2. Start two shells, one per sidecar

```powershell
$env:NFTBSV_SIDECAR = "http://127.0.0.1:8090"; dotnet run --project apps/shell   # Alice
$env:NFTBSV_SIDECAR = "http://127.0.0.1:8091"; dotnet run --project apps/shell   # Bob
```

## 3. Drive E2E-8 through the UI and check the honesty boundary

Walk the exchange (mint → pair → negotiate → deliver → review+sign swap →
confirm → attest). While doing so, verify by eye:

- The status banner shows **PENDING** (amber) after broadcast and only
  flips to **CONFIRMED** (green) once the node has mined to `CONF_DEPTH`.
  It must **never** show a success/complete state before then.
- The **swap-review** panel shows the *exact* terms (price to Alice,
  token id + `H(payload)`, owner = Bob) and the **Sign & Confirm** button
  is only enabled after the sidecar's `/swap/review` returns `ok`.
- The **Deletion** line reads as a *claim* ("a signed CLAIM, not proof") —
  it must **never** say "verified".

A run that shows "complete" before `CONFIRMED`, or "verified" for
deletion, is a **defect** (`docs/04` §4.7), not a pass.

## What CI verifies vs what you verify

| Check | Where |
|---|---|
| Sidecar honest-state logic (pending/confirmed; never "verified"; no key leak; exact-terms review) | CI — `internal/uistate`, `internal/sidecar` tests |
| Shell compiles | CI — `dotnet-shell` job (windows runner) |
| The full GUI walk-through (E2E-8 / M4) | **You**, by this runbook |
