# RUN_PLAN — Stage 1 Build & Execution Plan (`nft-wallet-bsv`)

This is the executable plan to build and verify Stage 1 end to end. It orchestrates the
**entire document set, `docs/00`–`docs/07`** (mapped in §A), and the **`docs/00` §0.5
non-goals are incorporated as hard scope guardrails** (§B), re-checked at every phase.

It introduces **no new requirements**. Everything here derives from `docs/00`–`docs/07`,
`README.md`, and `CLAUDE.md`. Where an exact command, node RPC, or constant is not verified,
it is marked `TODO(verify)` — not invented.

**How to use this plan.** Read `CLAUDE.md` (the gates) and `docs/00` (scope) first. Resolve
the blocking decision in §C. Run Pre-flight (§D), then the phases in §E **in order**. Do not
start a phase before its **entry** criteria hold; do not mark a phase done before its **exit
(DoD)** criteria and required **gates** are green. **If any step would implement a §B
non-goal, halt and surface it** (`CLAUDE.md` §8). Build and verify on **regtest** throughout;
promotion to testnet/mainnet is via the single network-params module (`docs/01` §1.4) with the
same gates.

---

## A. Document set — all of `docs/00`–`docs/07` are in scope and used here

| Document | Governs | Used in |
|---|---|---|
| `README.md` | Orientation, scope boundary, prohibitions, provenance | All phases |
| `CLAUDE.md` | Operating rules and the four gates; build order; stop-and-ask | All phases; gates continuous (§F) |
| `docs/00` | Scope, normative stage boundary, definitions, **§0.5 non-goals** | §B guardrails; framing for all phases |
| `docs/01` | Architecture, components, process model, stack, persistence, chain connectivity | Pre-flight, WS0–WS2, WS7 |
| `docs/02` | Token-as-UTXO, push-drop carrier, mint, atomic swap, optional covenant, constants, invariants `I-NFT-1..5` | WS2, WS3 |
| `docs/03` | Pairing, secure channel, message set, state machine, timeouts, aborts | WS4, WS5 |
| `docs/04` | Deletion analysis, CDA, trust register, threat model, Stage-2/T hooks | WS6; trust framing |
| `docs/05` | Regtest harness, scenario matrix (`E2E-*`, `F-*`), property tests, fault injection, **the four CI gates** | Pre-flight, WS8, §F gates, §G milestones |
| `docs/06` | Ordered workstreams WS0–WS8 with Definition of Done; documentation/comment standard | §E phases |
| `docs/07` | Assumptions (classified), open decisions OD-1..8, `TODO(verify)` register, non-guarantees | §C decisions, §I non-deliverables |

---

## B. Scope guardrails — Stage 1 non-goals (`docs/00` §0.5), INCORPORATED

These are **hard out-of-scope** items. The run must not drift into any of them. If a task
begins implementing one, **halt and surface it** — this is an explicit `CLAUDE.md` §8
stop-and-ask trigger, the same severity as a BTC or `OP_RETURN` contamination.

| # | Non-goal (verbatim from `docs/00` §0.5) | What it means for the run | Phases that must actively avoid it |
|---|---|---|---|
| NG-1 | Multi-party (>2) exchange, order books, or a marketplace. One seller, one buyer, one NFT. | No matching engine, no book, no third counterparty. Exactly Alice↔Bob, one token. | WS4, WS5 |
| NG-2 | The full discovery network (two-tier Bitcoin-style + Bitmessage-style). | Stage 1 uses **minimal two-party pairing only**; the full network is a defined later slot (`docs/03` §3.8). | WS4 |
| NG-3 | Payment channels / streaming micropayments. | Settlement is **one on-chain swap transaction**. No channels, no streaming. | WS1, WS2, WS5 |
| NG-4 | Card-game logic. | Shares mechanisms with the In-Between work but ships **none** of the game. | All |
| NG-5 | Regulatory framing. | Out of scope unless the owner requests it. Not added to code, UI, or docs. | All |

Each phase in §E carries a **"NG watch"** line restating which of these it must not cross.

---

## C. Decisions to resolve (`docs/07` OD-1..8), with the phase each gates

| OD | Decision | Default | Resolve by | Blocks the run? |
|---|---|---|---|---|
| **OD-4** | SV Node vs Teranode | choose one | **Pre-flight** | **YES** — no node, no Pre-flight/WS1 |
| OD-2 | Electron+Go sidecar vs native .NET/C# | Electron+Go (`docs/01`) | before WS0 skeleton; hard by WS7 | Partial — shapes skeleton + UI; set early to avoid rework |
| OD-5 | Carrier Construction A vs B | A | before WS3 | No (default A) |
| OD-8 | Transport relay / WebSocket / WebRTC | pluggable | before WS4 | No (default pluggable) |
| OD-3 | Continuity covenant in Stage 1, or defer | defer | before WS3, only if pulling in | No |
| OD-6 | Anti-grief signing variant | off | before WS5, only if adopting | No |
| OD-7 | Escrow template variant | off | n/a unless adopted | No |
| OD-1 | "T" = TEE vs TTP | TEE (open) | confirm anytime | **NO** — Stage 1 runs on the HH-1 baseline regardless; OD-1 shapes Stage 2+/the T-stage, not this build |

**Only OD-4 strictly blocks the start.** OD-2 should be fixed before WS0 to avoid skeleton
rework. The rest have working defaults and can be confirmed at their phase.

---

## D. Pre-flight (Phase P) — environment, node, gates live

**Goal:** a reachable BSV **regtest** chain and a repo whose gates already bite, before any
feature code. (This is the environment WS0–WS1 assume. It is **not** a "WS0.5" — "0.5" in
the brief refers to `docs/00` §0.5, handled in §B.)

- **P1.** Resolve **OD-4** (node) and **OD-2** (app shape).
- **P2.** Stand up a BSV regtest node — SV Node in regtest mode, or Teranode via
  `teranode-quickstart` (`TODO(verify)`: exact compose target). Confirm block-on-demand and
  funding at the node level. (`TODO(verify)`: exact RPC/admin method names per node version —
  do not assume SV Node ↔ Teranode parity.) This is a daemon, not repo code.
- **P3.** Initialise the repo and CI; wire the four gates so CI is **red until they pass**.
  This is **WS0** (§E) — the **first committed code**, so the gates bite from commit 1.
- **P4.** Build the **regtest control interface** — `mineBlocks`, `fundAddress`,
  `invalidateToHeight` — behind **one** node adapter, as the **only** node-specific surface
  (`docs/05` §5.3). First gated code on top of WS0; WS1–WS8 and the harness call this, never
  the raw node API.

**Exit (DoD):** a reachable regtest node; two funded wallet keypairs (amounts from the single
fixtures source); blocks mined on command; all behind the control interface and green under
`bsv-only`; CI pipeline running.
**NG watch:** NG-3 — the node settles single swap transactions only; no channels.

---

## E. Execution phases (WS0–WS8 from `docs/06`)

Each phase: **Docs · Entry · Do · Exit (DoD) · Gates · NG watch.**

### WS0 — Repository, CI gates, params skeleton (FIRST)
- **Docs:** `docs/06` WS0; `CLAUDE.md` §1–§2; `docs/01` (params); `docs/02` §2.8 (constants).
- **Entry:** Pre-flight P1–P2 done.
- **Do:** repo skeleton; the four gates; the single **BSV params module**; the single
  **fixtures/params source** (`DUST_SATS`, `FEE_RATE` — `TODO(verify)`; funding amounts);
  the traceability-annotation mechanism.
- **Exit (DoD):** a planted `OP_RETURN` fails `no-op-return`; a planted BTC dependency fails
  `bsv-only`; an orphan normative ID fails `spec-traceability`; CI is red until the plants
  are removed (the gates are proven to bite, then reverted).
- **Gates:** all four wired and demonstrated.
- **NG watch:** —

### WS1 — Network parameters + chain adapter
- **Docs:** `docs/06` WS1; `docs/01` §1.4; `docs/05` §5.3.
- **Entry:** WS0 DoD holds.
- **Do:** chain adapter (broadcast, tx/output status, confirmation depth, conflict
  detection); SPV path (CH-1); the regtest control interface bound to the chosen node.
- **Exit (DoD):** against a live regtest node — broadcast a funded P2PKH tx, mine it, observe
  it reach a chosen depth, and detect a conflicting spend, **all via the adapter**; node
  RPC/ARC method names pinned in the adapter (`TODO(verify)`).
- **Gates:** `bsv-only` green; no BTC params in the adapter or its tests.
- **NG watch:** NG-3 — single-transaction settlement only; no channels.

### WS2 — Wallet core + general Script-capable transaction builder
- **Docs:** `docs/06` WS2; `docs/02` §2.5 (SIGHASH for the swap); `docs/04` SC-1.
- **Entry:** WS1 DoD holds.
- **Do:** key generation + software custody (OS keystore / DPAPI, SC-1); UTXO tracking + coin
  selection; a **general full-Script tx builder** with explicit `SIGHASH` control and
  partial-signing support; fees from the single fee module.
- **Exit (DoD):** build/sign/broadcast standard **and** custom-script txs on regtest,
  including a tx co-signed by two independently-held keys; `SIGHASH` behaviour unit-tested;
  no `OP_RETURN` reachable from any builder path.
- **Gates:** `no-op-return` green over emitted bytes; `bsv-only` green.
- **NG watch:** NG-3.

### WS3 — NFT / token module (non-`OP_RETURN`)
- **Docs:** `docs/06` WS3; `docs/02` §2.3 (carrier), §2.4 (mint), §2.5 (swap), §2.6 (optional
  covenant); invariants `I-NFT-1..5`.
- **Entry:** WS2 DoD holds.
- **Do:** push-drop locking template (Construction A; OD-5) over a P2PKH gate; mint; the
  atomic-swap assembler + verifier; token-status queries. **Optional (OD-3):** the
  `OP_PUSH_TX` continuity covenant (§2.6) — plain Script, no `OP_RETURN` (BSVM/Rúnar allowed,
  not required) — only if OD-3 is pulled into Stage 1.
- **Exit (DoD):** mint = exactly one live UTXO (`I-NFT-3`), identity bytes recoverable;
  assemble + co-sign + broadcast a `Tx_swap` that transfers the token and pays the seller in
  one transaction; `I-NFT-1..4` asserted by property tests; every near-miss swap variant
  rejected.
- **Gates:** all four.
- **NG watch:** NG-1 — one NFT, no marketplace.

### WS4 — Secure channel + pairing
- **Docs:** `docs/06` WS4; `docs/03` §3.1–§3.2; NET-1.
- **Entry:** WS2 DoD holds (parallelizable with WS3).
- **Do:** two-party pairing (HELLO) + identity binding; an authenticated **secure channel
  over a hostile transport**; transport per OD-8 (behind an interface so the §5.6 interposer
  can sit on it).
- **Exit (DoD):** two instances pair and exchange authenticated messages; forged, replayed,
  reordered, and truncated messages are rejected (`F-11`…`F-13`).
- **Gates:** all four.
- **NG watch:** **NG-2** — strictly two-party pairing; **do not** build the full discovery
  network (`docs/03` §3.8). **NG-1** — no third counterparty.

### WS5 — Exchange protocol engine
- **Docs:** `docs/06` WS5; `docs/03` §3.3 (messages), §3.5 (state machine), §3.6 (timeouts).
- **Entry:** WS3 **and** WS4 DoDs hold.
- **Do:** the deterministic state machine; the full message set; co-signing order (Bob
  `SWAP_PARTIAL` first, Alice countersigns and broadcasts) unless OD-6 relaxes it; timeouts
  `T_pair`/`T_deliver`/`T_sign`/`T_confirm`/`CONF_DEPTH`; **no silent success** and **reorg
  awareness** (`docs/03` §3.5).
- **Exit (DoD):** `E2E-2`…`E2E-6` pass on regtest; engine fault rows `F-1`…`F-14` produce the
  **specified** terminal state and reason with no fund loss and no false success; every
  state-machine edge exercised.
- **Gates:** all four.
- **NG watch:** NG-1, NG-3 — two-party single swap; no order book; no channels.

### WS6 — Deletion + attestation module
- **Docs:** `docs/06` WS6; `docs/04` §4.1 (deletion limits), §4.2 (CDA), §4.5 (Stage-2 hook).
- **Entry:** WS5 DoD holds.
- **Do:** best-effort local payload deletion (HH-1; honestly **not** verifiable); CDA
  construct / sign / transmit / validate / store; the forward-compatible CDA shape
  (`docs/04` §4.2, §4.5).
- **Exit (DoD):** `E2E-7`; `F-15`…`F-17` (forged / missing / mismatched CDA handled
  correctly). `F-16` proves settlement does **not** depend on the CDA. **No** code path or
  test asserts Stage 1 deletion is "verified" (`docs/04` §4.7).
- **Gates:** all four.
- **NG watch:** —

### WS7 — Windows application shell + UI
- **Docs:** `docs/06` WS7; `docs/01`; OD-2.
- **Entry:** WS5 DoD holds (and WS6 for the attestation surface).
- **Do:** the Windows app hosting wallet, NFT vault, chat + negotiation, swap review/confirm,
  and the deletion/attestation surface; honest state distinctions — **"pending" vs
  "confirmed"** and **"deletion attested" vs "deletion verified."**
- **Exit (DoD):** a human runs two instances and completes `E2E-8` through the UI; the UI
  never shows success before `CONFIRMED` and never shows "deletion verified"; renderer holds
  no keys if the sidecar shape (OD-2) is used; OD-2 recorded.
- **Gates:** all four.
- **NG watch:** NG-4 — no card-game UI.

### WS8 — Test harness + full scenario suite (spans all; finalised here)
- **Docs:** `docs/06` WS8; `docs/05` §5.3–§5.7.
- **Entry:** built incrementally from WS0; finalised after WS7.
- **Do:** regtest harness + two-instance fixture; **every** `E2E-*` (§5.4) and **every**
  `F-*` (§5.5); the fault interposer, message fuzzing, transaction fuzzing, and invariant
  property tests (§5.6).
- **Exit (DoD):** every `E2E-*` and `F-*` row has a passing automated test; all four gates
  green on a clean checkout; coverage ≥ the pinned threshold (`TODO(verify)`) as a **floor**,
  with scenario completeness as the actual bar.
- **Gates:** all four.
- **NG watch:** —

**Dependency order:**

```
WS0 → WS1 → WS2 → { WS3  ∥  WS4 } → WS5 → WS6 → WS7
                                                     WS8 spans all
```

WS3 and WS4 are parallelizable once WS2 holds. WS8 is not a final bolt-on; its tests are
written as each phase's DoD demands.

---

## F. Continuous gates (every commit) — `docs/05` §5.2

`no-op-return` · `bsv-only` · `lint/format` · `spec-traceability`. All four green = a commit
is mergeable. They enforce, respectively: no `OP_RETURN` anywhere (`I-NFT-1`); BSV-only with
no BTC dependency or parameter; the formatting/comment standard; and that **every** normative
ID across `docs/00`–`docs/07` is implemented **and** tested (no orphan in either direction).

---

## G. Acceptance milestones (verification) — `docs/05` §5.4–§5.5

| Milestone | After | Must pass |
|---|---|---|
| M1 | WS3 | `E2E-1`, `E2E-5`; `I-NFT-1..4` hold |
| M2 | WS5 | `E2E-2`…`E2E-6`; engine fault rows `F-1`…`F-14` |
| M3 | WS6 | `E2E-7`; `F-15`…`F-17` (incl. `F-16` settlement-independent-of-CDA) |
| M4 | WS7 | `E2E-8` through the UI |
| M5 | WS8 | full `E2E-*` + `F-*` matrix passing; four gates green; coverage floor met |

**Honesty-boundary acceptance (in `E2E-8`):** the system reports **control transfer as
verified** (token UTXO spent to Bob) and **deletion as attested, not verified** (`docs/04`
§4.7). A test that asserts "deletion verified" in Stage 1 is itself a defect.

---

## H. Stage 1 — overall Definition of Done

Stage 1 is done when: all WS0–WS8 DoDs hold; M1–M5 pass; the four gates are green on a clean
checkout; **every** `docs/00`–`docs/07` normative ID is traceable to implementation **and**
test (`spec-traceability`); and **no §B non-goal has been implemented**. The honest Stage-1
claim (`docs/07` §7.5) holds, and nothing in code, UI, logs, or docs overclaims it.

---

## I. What this run does NOT deliver (stated — `docs/00` §0.5 and `docs/07` §7.5)

- **None of the §B non-goals** (NG-1 multi-party/marketplace, NG-2 full discovery network,
  NG-3 payment channels/streaming, NG-4 card-game logic, NG-5 regulatory framing).
- **Not payload confidentiality / exclusivity** (PL-1) — Stage 2 (crypto-shred).
- **Not verifiable deletion** — only the CDA, a signed *claim*, and explicitly not required
  for settlement. Stage 2 (crypto-shred) and the T-stage earn "verifiable."
- **Not protection against a malicious host leaking its own keys** (HH-1) — the T-stage
  (OD-1).
- **Not Script-enforced continuity** unless OD-3's covenant is built (CN-1).
- **Not reorg-proof** — a deep reorg can regress a confirmed swap; it is surfaced, never
  hidden (CH-1).
