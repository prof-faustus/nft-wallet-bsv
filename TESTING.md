# TESTING.md — what was tested, by whom, and how you verify it

This is the sign-off manifest. It enumerates exactly what has been tested so
you verify a finished thing rather than hunt for defects. Everything below is
run by `go test ./...` (hermetic) plus the live regtest job in CI; the native
app is the real Windows window you launch yourself.

Attribution: implemented and tested by Claude (Opus 4.8) under the owner's
rules — no assistant-selected choices, no defaults, menu-driven, every option
exercised, bots are test-only.

---

## 0. How to run everything yourself (the real product)

**All automated tests (hermetic — no node needed):**

```
cd D:\claude\SPVNFT
go test ./...                 # full suite (covenant sweep runs 3000 iters)
go test -short ./...          # faster (covenant sweep 300 iters)
```

**The four CI gates:**

```
go run ./tools/gates/spectrace
go run ./tools/gates/noopreturn
go run ./tools/gates/bsvonly
gofmt -l internal tools cmd    # empty output = clean
```

**The REAL native Windows app (you launch it — a person runs the real thing):**

1. Build + start the sidecar in simulation mode (try the UI with no node):
   ```
   go build -o sidecar.exe ./cmd/sidecar
   .\sidecar.exe --addr 127.0.0.1:8090 --keystore ks.json --passphrase pw --simulate
   ```
   `--simulate` is TEST/DEMO ONLY (an in-memory, script-validating node — not a
   real chain, never the default). For a REAL on-chain exchange use
   `--rpc-url http://127.0.0.1:18332/` against the regtest node
   (`deploy/regtest/docker-compose.yml`) instead of `--simulate`.

2. In another terminal, launch the native window (user-scoped .NET 8 SDK):
   ```
   & "$env:LOCALAPPDATA\Microsoft\dotnet\dotnet.exe" run --project apps\shell\shell.csproj
   ```
   The window opens on YOUR desktop. Choose a scheme from the dropdown (nothing
   is preselected), type every amount, and click each step in turn.

> GUI boundary (honest): the agent cannot render a window on your interactive
> desktop (a Windows session-isolation rule), so **you** launch the app. What
> the agent verified for you: the app compiles clean (0 warnings), and the
> sidecar it talks to drives the entire menu flow end-to-end over HTTP (§4).

---

## 1. Crypto-shred — all five schemes, every one exercised

`internal/shred`, `internal/crypto` (AES-256-GCM + secp256k1 ECDH).

- **TestAllSchemes_BobOpens** — for EVERY scheme (ecdh-singleuse, key-surrender,
  reencrypt, tee-attested, threshold): Bob opens post-swap; a tampered
  ciphertext fails authentication.
- **TestSellerShred** — for EVERY scheme: the cooperative seller can open BEFORE
  shredding and CANNOT after; the enforced (tee) scheme never lets her open.
- **TestWrongKeyCannotOpen / TestAttestationOnlyEnforced** — wrong recipient
  cannot open the ECDH schemes; only the enforced scheme carries a verifiable
  attestation; cooperative schemes carry none.
- **TestThresholdSchemeSharing** — the dealerless t-of-n scheme: Bob reconstructs
  from exactly the t shares the swap delivers; fewer than t cannot decrypt.

## 2. Dealerless threshold ECDSA

`internal/threshold` (Shamir over the secp256k1 order N).

- **TestSplitReconstruct / TestDealerlessGenerate** — any t shares reconstruct;
  any t-1 reveal nothing; dealerless group secret reconstructs.
- **TestThresholdKeyIsUsableECDSA** — the reconstructed scalar is a real
  secp256k1 key that signs and verifies (reconstruct-to-use). Honest scope: key
  GENERATION/SHARING, not hand-rolled interactive threshold signing.

## 3. OP_PUSH_TX continuity covenant (OD-3) — executed in the real interpreter

`internal/covenant`. Run in the genuine BSV script interpreter.

- **TestForcedSigVerifies** — the in-script forced ECDSA signature verifies under
  real secp256k1 for 2000 random messages.
- **TestForcedSigDEREdges / TestDerIntMatchesEcSerialize** — minimal-DER edge
  cases (leading zero, high-bit sign byte) are correct.
- **TestCovenantAcceptsFaithfulTransfer** — a faithful transfer is ACCEPTED.
- **TestCovenantRejectsTampering** — ALL of these are REJECTED: strip-to-P2PKH,
  TokenId mutation, H(payload) mutation, descriptor mutation, owner redirect,
  value inflation, preimage tamper, hashOutputs forgery, wrong sighash type.
- **TestCovenantLivenessSweep** — 3000 faithful transfers over varied
  identity/owner/sighash all accepted.
- **TestCovenantDEREdgeOnEngine** — the leading-zero and high-bit-after-strip
  `s` cases (one of which a sweep originally caught as a real bug, since fixed)
  are accepted on the engine.

Security note: a defect in the in-script arithmetic can only make CHECKSIG
*fail* (reject a spend) — never accept a forged preimage. The strip/mutate
guarantee is the byte-exact hashOutputs check after a successful CHECKSIG.

## 4. The menu-driven exchange — every scheme, no defaults, real binary

`internal/sidecar` against the SCRIPT-VALIDATING simulation node (every
broadcast is validated through the real interpreter, so bad sigs / covenant
violations are rejected exactly as a node would).

- **TestV2_EveryScheme_FullLifecycle** — for EVERY scheme, the whole flow runs
  end to end: reset → keys → fund seller → fund buyer → mint(seal) →
  deliver(buyer opens + verifies H(plaintext)) → swap → confirm → shred → attest.
- **TestV2_NoDefaults_RequireExplicitChoices** — every omitted required input is
  an ERROR (no scheme, no funding amount, no dust/fee, no payload, no blocks).
- **TestV2_OrderingPreconditions** — each step refuses to run before its
  prerequisites.
- **Running-binary check** (manual, reproducible): `--simulate` sidecar drives
  the full menu flow over HTTP to DONE, and `fund` with no amount returns
  "sats is required". (See §0 to reproduce.)

## 5. Stage-1 foundations (still green)

Chain adapter + SPV, wallet + full-Script builder, push-drop token carrier (NO
OP_RETURN), atomic swap, authenticated channel, deterministic engine (happy +
every abort/fault row), deletion CDA, and the live regtest M1 mint+swap — all
covered by their existing tests and the CI live job.

---

## 6. Boundaries stated honestly (no overclaiming)

- Cooperative shred (4 of 5 schemes) is a **CLAIM**: "the retained ciphertext is
  useless IF the seller destroyed the single-use key" — never "verified deletion".
- The enforced (tee-attested) scheme is a **software stand-in** for a real TEE.
- Deletion attestation is a signed CLAIM, never proof the copy is gone.
- The covenant is verified in the BSV script interpreter (the consensus
  script-validation engine); a real-node consensus run is the live regtest job.
