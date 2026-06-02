# 06 — Implementation Workstreams

The ordered build plan for Claude Code. It is sequenced so the project's hard rules are
mechanically enforced from the first commit, and so each layer rests only on layers already
built and tested. Each workstream has a **Definition of Done (DoD)**; a workstream is not
complete until its DoD holds and the CI gates (`docs/05` §5.2) are green.

This document plans work. It contains no application code. The comment and documentation
standard that the code must meet is §6 below — it is itself a gate (`spec-traceability`).

**Sequencing principle:** gates and skeleton first, then the chain, then the wallet, then the
token, then the channel, then the protocol, then deletion, then the UI, with the test harness
growing alongside from WS0. Do not build a later workstream before its predecessors' DoD
holds. Building the protocol engine on an untested tx-builder is how hidden defects enter.

---

## Pre-flight (Phase P) — environment, node, and foundation (do this first)

**Why this phase exists.** Every workstream below, and the entire `docs/05` regtest harness,
assumes a reachable BSV regtest chain to run against — WS1's DoD ("against a live regtest
node") and WS2–WS8's tests all depend on it. This phase **builds** that chain and the
foundation, so the assumption is satisfied by a tracked step with its own DoD rather than left
implicit. It is **not** a "WS0.5"; it is the environment-and-foundation bring-up. (`RUN_PLAN.md`
§D is the same phase, with the same DoD.)

Ordered steps:
- **P1 — Decisions.** Resolve **OD-4** (SV Node vs Teranode) and **OD-2** (app shape). OD-4
  blocks everything below; OD-2 is fixed now to avoid skeleton rework.
- **P2 — Node up (infra).** Stand up a BSV regtest node — SV Node in regtest mode, or Teranode
  via `teranode-quickstart` (`TODO(verify)`: exact compose target). Confirm block-on-demand and
  funding at the node level. (`TODO(verify)`: exact RPC/admin method names per node version —
  do not assume SV Node ↔ Teranode parity.) This is a daemon, not committed code.
- **P3 — Foundation (= WS0).** Initialise the repo and wire the four gates plus the single
  params/fixtures modules — this is **WS0** (below), the **first committed code**, so the gates
  bite from commit 1.
- **P4 — Regtest control interface.** Build `mineBlocks` / `fundAddress` / `invalidateToHeight`
  behind **one** node adapter (`docs/05` §5.3) — the only node-specific surface. First gated
  code on top of WS0; WS1–WS8 and the harness call this interface, never the raw node API.

**DoD (environment + foundation ready):** a reachable regtest node; two funded wallet keypairs
(amounts from the single fixtures source); blocks mined on command; all behind the control
interface and green under `bsv-only`.

**NG watch:** NG-3 — the node settles single swap transactions only; no payment channels.

---

## WS0 — Repository, CI gates, params skeleton (FIRST)

**Why first:** §1–§2 of `CLAUDE.md` (BSV-only, no `OP_RETURN`) must be enforced from commit 1.
If the gates arrive later, nothing stops a prohibited construction from entering early and
becoming load-bearing. (Pre-flight P1–P2 — decisions and standing up the node daemon — precede
it, but they are not committed code; WS0 is the first committed code.)

Produces:
- Repository skeleton, formatter/linter config, CI pipeline.
- The four CI gates wired and running on every commit: `no-op-return`, `bsv-only`,
  `lint/format`, `spec-traceability` (`docs/05` §5.2).
- The single **BSV params module** (network magic, address version, default ports, all
  sourced once) — the only place network constants live.
- The single **fixtures/params source** for `DUST_SATS`, `FEE_RATE`, funding amounts
  (`docs/02` §2.8).
- The traceability-annotation mechanism the `spec-traceability` gate reads (§6.5).

**DoD:**
- A deliberately-planted `OP_RETURN` in a throwaway test fixture makes `no-op-return` fail
  (the gate is proven to bite, not just present).
- A deliberately-added BTC dependency makes `bsv-only` fail.
- A normative ID with no implementing/test reference makes `spec-traceability` fail.
- CI is red until those plants are removed — gates demonstrated, then reverted.

---

## WS1 — Network parameters + chain adapter

Depends on Pre-flight (Phase P) and WS0.

Produces:
- The **chain adapter** (`docs/01`): broadcast a raw tx, query tx/output status, query
  confirmation depth, subscribe to confirmations, detect a conflicting confirmed spend.
- (The **regtest control interface** — `mineBlocks` / `fundAddress` / `invalidateToHeight`,
  one node adapter, OD-4 — is built in **Pre-flight (Phase P)**; WS1 consumes it, it is not
  rebuilt here.)
- SPV verification path (`docs/01`, CH-1).

`TODO(verify)` at implementation time: exact node RPC / broadcaster (ARC) method names and
signatures for the pinned node version; pin them in the adapter and nowhere else. An assumed
method name is a defect — verify against the running node.

**DoD:**
- Against a live regtest node: broadcast a funded P2PKH tx, mine it, observe it reach a chosen
  confirmation depth, and detect a conflicting spend. All via the adapter, not raw node calls.
- `bsv-only` green; no BTC params anywhere in the adapter or its tests.

---

## WS2 — Wallet core: keys, UTXOs, general Script-capable transaction builder

Depends on WS1.

Produces:
- Key generation and **software key custody** via the OS keystore / DPAPI (SC-1, `docs/04`).
- UTXO tracking and coin selection.
- A **general, full-Script-capable transaction builder**: arbitrary inputs/outputs, arbitrary
  locking/unlocking scripts, explicit and correct **SIGHASH** control (the swap depends on
  `SIGHASH_ALL`, `docs/02` §2.5). The builder must support the partial-signing flow used by
  the atomic swap.
- Fee handling sourced from the single fee-policy module (`FEE_RATE`).

**DoD:**
- Build, sign, and broadcast standard and non-standard (custom-script) BSV transactions on
  regtest, including a transaction co-signed by two independently-held keys.
- SIGHASH behaviour unit-tested: a signature is shown to commit to exactly the intended
  inputs/outputs.
- No `OP_RETURN` reachable from any builder path (`no-op-return` green over emitted bytes).

---

## WS3 — NFT / token module (non-`OP_RETURN`)

Depends on WS2.

Produces:
- The **push-drop locking-script template** carrying `TokenId` / `payloadDescriptor` /
  `H(payload)` via Construction A (push-data-with-drop prefix) over a P2PKH ownership gate
  (`docs/02` §2.3). Construction B is the OD-5 alternative.
- **Mint** (`docs/02` §2.4): create the single token UTXO binding identity + payload hash.
- The **atomic-swap assembler and verifier** (`docs/02` §2.5): assemble the single
  `Tx_swap`; verify that out 0 reproduces the identity byte-for-byte (I-NFT-2) and that the
  agreed value/owner terms hold (I-NFT-4).
- Token-status queries (live/spent, current owner) over the chain adapter.
- OPTIONAL (OD-3): the `OP_PUSH_TX` continuity covenant (`docs/02` §2.6) — plain Script, no
  `OP_RETURN` (BSVM and Rúnar are allowed but not required for it). Build only if OD-3 is pulled into Stage 1.

**DoD:**
- Mint on regtest; the token is exactly one live UTXO (I-NFT-3); identity bytes recoverable
  from the output.
- Assemble + co-sign + broadcast a `Tx_swap` that transfers the token to a second key and
  pays the seller in one transaction; I-NFT-1..4 asserted by property tests (`docs/05` §5.6).
- Negative tests: every near-miss swap variant is rejected by the verifier.

---

## WS4 — Secure channel + pairing

Depends on WS2 (identity keys). Independent of WS3.

Produces:
- **Pairing** (HELLO handshake) and identity binding (`docs/03` §3.1–§3.2).
- A **secure channel over a hostile transport** (NET-1): per-message authentication and
  integrity such that forgery/replay/reorder cannot corrupt state; transport itself untrusted.
- The transport binding selected by OD-8 (relay / WebSocket / WebRTC), behind an interface so
  the channel logic is transport-agnostic and the §5.6 interposer can sit on it.

**DoD:**
- Two instances pair and exchange authenticated messages over a real channel.
- Forged, replayed, reordered, and truncated messages are rejected (F-11…F-13) — the channel
  passes its slice of the fault matrix before any protocol rides on it.

---

## WS5 — Exchange protocol engine

Depends on WS3 and WS4.

Produces:
- The **deterministic state machine** of `docs/03` §3.5: `IDLE → PAIRING → CONNECTED →
  NEGOTIATING → PRICE_AGREED → PAYLOAD_DELIVERED → SWAP_ASSEMBLED → SWAP_SIGNED → BROADCAST →
  CONFIRMED → (seller) ATTESTED → DONE`, with `ABORTED`/`FAILED` terminals.
- The full **message set** (`docs/03` §3.3): HELLO, CHAT, OFFER/COUNTER/ACCEPT,
  PAYLOAD_OFFER/PAYLOAD_DATA/PAYLOAD_ACK, SWAP_PROPOSE/SWAP_PARTIAL/SWAP_BROADCAST,
  DELETION_ATTEST, ABORT.
- **Co-signing orchestration** in the required order (Bob `SWAP_PARTIAL` first, Alice
  countersigns and broadcasts — `docs/03` §3.3), unless OD-6 relaxes it.
- **Timeout/abort handling**: `T_pair`, `T_deliver`, `T_sign` (= Δ), `T_confirm`,
  `CONF_DEPTH` (`docs/03` §3.6). **No silent success** and **reorg awareness** (`docs/03`
  §3.5) enforced here.

**DoD:**
- E2E-2 … E2E-6 (`docs/05` §5.4) pass on regtest.
- The full fault/abort matrix rows that touch the engine (F-1…F-14) pass: every edge produces
  the **specified** terminal state and reason code, with no fund loss and no false success.
- Every state-machine edge in `docs/03` §3.5 is exercised by at least one test
  (`spec-traceability`).

---

## WS6 — Deletion + attestation module

Depends on WS5.

Produces:
- Local payload deletion (Stage 1: best-effort local destruction of the held payload by the
  cooperating host — bounded by HH-1; honestly **not** verifiable, `docs/04` §4.1).
- The **Cooperative Deletion Attestation (CDA)**: construct, sign (`sigCDA`), transmit
  (`DELETION_ATTEST`), receive, validate, store (`docs/04` §4.2).
- The **forward-compatible CDA shape** so Stage 2 can add the destroyed/rotated-key reference
  without a format break (`docs/04` §4.2, §4.5).

**DoD:**
- E2E-7 passes; F-15…F-17 pass (forged / missing / mismatched CDA handled correctly).
- F-16 specifically proves settlement does **not** depend on the CDA: Bob owns the token after
  `CONFIRMED` regardless of whether a valid CDA ever arrives, and a missing CDA is recorded as
  a missing **claim**, not a transfer failure.
- No code path or test asserts Stage 1 deletion is "verified" (that would encode an overclaim,
  `docs/04` §4.7).

---

## WS7 — Windows application shell + UI

Depends on WS5 (and WS6 for the attestation surface). Shape decided by OD-2.

Produces:
- The **Windows desktop application** that hosts the wallet, the NFT vault view, the chat +
  negotiation UI, the swap review/confirm UI, and the deletion/attestation surface
  (`docs/01`).
- A UI that makes the honest state distinctions visible: **"pending" vs "confirmed"** (never
  conflated, `docs/03` §3.5) and **"deletion attested" vs "deletion verified"** (the latter is
  not claimed in Stage 1, `docs/04`).
- Swap review screen that shows the exact terms a user is about to sign (value, owner, the
  token identity) before any signature.

**DoD:**
- A human operator can run two instances and complete E2E-8 entirely through the UI.
- The UI never displays "complete"/"success" before `CONFIRMED`, and never displays
  "deletion verified."
- OD-2 chosen and recorded; if Electron+Go sidecar (the `docs/01` recommendation), the IPC
  boundary is documented and the renderer holds no keys.

---

## WS8 — Test harness + full scenario suite (grows from WS0, completed here)

Depends on all prior workstreams; built incrementally alongside them, finalized here.

Produces:
- The regtest harness and two-instance fixture (`docs/05` §5.3).
- The complete scenario matrix: every E2E row (§5.4) and every fault/abort row (§5.5).
- The fault-injection interposer, message fuzzing, transaction fuzzing, and invariant property
  tests (§5.6).

**DoD:**
- Every row of `docs/05` §5.4 and §5.5 has a passing automated test.
- All four CI gates green on a clean checkout.
- Coverage at or above the pinned threshold (`docs/05` §5.7) — as a floor, with scenario
  completeness as the actual bar.

---

## Dependency graph (summary)

```
Pre-flight P  (OD-4/OD-2 · node up · WS0 gates · regtest control interface)
   │
   └─> WS1 ─> WS2 ─┬─> WS3 ─┐
                   │        ├─> WS5 ─> WS6 ─> WS7
                   └─> WS4 ─┘
   WS8 spans all (its harness builds on the Pre-flight control interface)
```

Pre-flight P (which includes WS0's gates) precedes all feature work. WS3 and WS4 are
parallelizable once WS2 holds. WS8 is not a final phase bolted on; its tests are written as
each workstream's DoD demands them.

---

## 6. Documentation and comment standard (a gate, not a preference)

The brief is explicit: documentation and commenting must read as **over-engineered** to a
mission-critical reviewer. The following is mandatory and is checked by `spec-traceability`
plus review. Comments explain **why**, and explain Script and transaction structure at the
byte/opcode level; they never restate the obvious.

### 6.1 Module headers

Every module begins with: its purpose; which `docs/` section(s) it implements; the
assumptions it relies on (by trust-register ID — HH-1, SC-1, PL-1, CN-1, NET-1, CH-1); and the
invariants it must preserve (by ID — I-NFT-1..5).

### 6.2 Function contracts

Every non-trivial function documents: preconditions, postconditions, error/abort modes, and
the SIGHASH / signing implications where it touches transactions. For state-machine handlers,
the source and target states and the guard condition (`docs/03` §3.5) are named.

### 6.3 Opcode-by-opcode script annotation

Every locking and unlocking script template is annotated **opcode by opcode**: what each
opcode does, what it consumes and leaves on the stack, and why it is present. The push-drop
identity prefix and the P2PKH ownership gate (`docs/02` §2.3), and the optional `OP_PUSH_TX`
covenant (§2.6) if built, each carry a full opcode walk-through. A reviewer must be able to
read the comment and reconstruct the script's stack behaviour without running it. The comment
must make explicit that **no `0x6a`/`OP_RETURN`** appears and why the data carriage uses
push-drop instead (I-NFT-1).

### 6.4 Transaction-builder layout comments

Every transaction the system builds is documented input-by-input and output-by-output: what
each input spends, what each output locks to, the value, and the SIGHASH flag on each
signature. `Tx_swap` carries the full layout from `docs/02` §2.5 and the atomicity argument in
a comment, including why the construction admits no taken-payment-without-token state
(I-NFT-4).

### 6.5 Spec traceability

Every implementing unit and every test carries a traceability annotation naming the normative
ID(s) it implements or tests (`I-NFT-*`, state-machine edges, message types, trust-register
IDs). The `spec-traceability` gate (`docs/05` §5.2) fails the build if any normative ID has
zero implementing references or zero test references. This is the mechanism that makes "the
docs say it, the code does it, a test proves it" enforceable rather than aspirational.

### 6.6 No magic numbers

No inline numeric constant for `DUST_SATS`, `FEE_RATE`, timeouts (`T_*`), `CONF_DEPTH`, or
funding amounts. All resolve to the single params/fixtures source (`docs/02` §2.8). A magic
number fails `lint/format` + review.

### 6.7 Honest comments

Comments state limitations where they are real. The deletion module comments say plainly that
Stage 1 local deletion is best-effort and **not verifiable** (HH-1, PL-1). The continuity code
comments say plainly whether continuity is convention-enforced or Script-enforced (CN-1 /
OD-3). A comment that claims a guarantee the code does not provide is a defect equal to a
wrong assertion.
