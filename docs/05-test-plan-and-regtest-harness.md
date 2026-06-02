# 05 — Test Plan and RegTest Harness

This document defines the verification layer. It is the part of the project that justifies
the phrase "tested beyond belief": every normative requirement in `docs/00`–`docs/04` has a
named test here, every abort and fault edge has a scenario, and the four CI gates are
specified as automated checks that run on every commit.

This is a **test plan and harness design**, not test code. Claude Code implements the tests
against this plan. Where an exact node RPC name or signature is not verified, it is marked
`TODO(verify)` rather than guessed — an unverified method name is a defect, not a detail.

**Hard rule restated:** the harness and all fixtures are BSV-only. No BTC node, no BTC
library, no BTC network parameter appears anywhere in the test tree. A fixture that pulls a
BTC artifact is a failed build, not a flaky test (`bsv-only` gate, §5.2).

---

## 5.1 Test taxonomy

Five layers. A workstream (`docs/06`) is not "done" until its layer-appropriate tests exist
and pass, and the relevant CI gates are green.

| Layer | Question it answers | Runs against |
|---|---|---|
| Unit | Does this function honour its contract in isolation? | mocked dependencies |
| Property / invariant | Do the system invariants `I-NFT-1..5` hold over many generated inputs? | pure functions + generated transactions |
| Integration | Do two real wallet instances complete the protocol over a real channel? | local relay/channel, no chain |
| End-to-end (regtest) | Does the full transfer settle, confirm, and attest on a real BSV chain? | local regtest node (§5.3) |
| Fault / adversarial | Does every abort and attack edge produce the **specified** terminal state with no fund loss and no false success? | regtest + fault-injection harness (§5.6) |

Coverage is necessary but not the bar. The bar is **scenario completeness**: every row of
§5.4 and §5.5 has an automated test, and every state-machine edge in `docs/03` §3.5 is
exercised by at least one test. A green coverage number with a missing abort scenario is a
failed test plan.

---

## 5.2 The four CI gates (automated, every commit)

These gates are defined normatively in `CLAUDE.md`. Here they are specified as concrete
checks the CI implements. All four must pass for a commit to be mergeable.

### Gate `no-op-return` (enforces I-NFT-1)

- A script-scanner walks **every** locking and unlocking script the codebase can construct —
  by static template inspection and by scanning serialized transactions produced in the test
  suite — and fails if opcode byte `0x6a` (`OP_RETURN`) appears in any of them.
- The scanner also fails on a bare/false-return data-output shape even if produced by a
  helper that does not literally name `OP_RETURN`.
- The gate runs over both source templates and the actual bytes emitted by every E2E test,
  so a regression that introduces `OP_RETURN` at runtime is caught even if the source looks
  clean.
- `TODO(verify)`: confirm the chosen BSV SDK exposes the fully serialized script bytes for
  inspection at the point the scanner runs; if it does not, the scanner parses the raw tx
  hex instead.

### Gate `bsv-only`

- **Dependency allowlist.** The build fails if any dependency outside an explicit BSV/runtime
  allowlist is present. BTC chain libraries are not on the list; their presence fails the
  build.
- **Network-parameter grep.** A grep gate fails on hard-coded BTC magic bytes, BTC bech32
  human-readable parts, BTC default ports, or any address-version byte not sourced from the
  single BSV params module.
- **Single params source.** Address encoding, network magic, and default ports must resolve
  to the one BSV params module. A second, divergent source of network constants fails the
  gate.

### Gate `lint/format`

- Formatter and linter run in check mode (no write). Any diff fails the gate. This keeps the
  "commented beyond belief" standard (`docs/06` §6) from rotting into noise.

### Gate `spec-traceability`

- Every normative requirement ID in `docs/` (`I-NFT-*`, the state-machine edges, the message
  set, the trust register IDs) must be referenced by at least one implementing unit and at
  least one test, via a traceability annotation (`docs/06` §6).
- The gate fails if any normative ID has **zero** implementing references or **zero** test
  references. This is what mechanically prevents "spec says X, code never did X."

---

## 5.3 RegTest harness — topology

RegTest is the primary Stage 1 proving ground: it gives deterministic block production,
instant funding, and the ability to force reorgs. Test and main networks are also valid
targets (`docs/00`), but the deterministic fault matrix (§5.5) is run on regtest.

```
                +-------------------------------+
                |   BSV node (regtest mode)     |
                |   SV Node  OR  Teranode       |   <- OD-4 (docs/07)
                |   - generate blocks on demand |
                |   - local, ephemeral chain    |
                +---------------+---------------+
                                | RPC / broadcast (chain adapter, docs/01)
                +---------------+---------------+
                |                               |
        +-------+--------+             +--------+-------+
        | Wallet A (Alice)|<-- channel ->| Wallet B (Bob) |
        | holds the NFT   |  (relay /    | holds funds    |
        |                 |  WS / WebRTC |                |
        |                 |   — OD-8)    |                |
        +-----------------+             +----------------+
```

- **Two wallet instances**, separate data directories, separate keystores. They are the same
  binary run twice; the harness must never let them share state except over the channel and
  the chain. Shared in-process state would invalidate every integration and E2E result.
- **One regtest node.** Both wallets point their chain adapter at it.
- **The channel** is the transport selected by OD-8. For deterministic CI the default is a
  local relay or in-harness WebSocket; the fault harness (§5.6) interposes on this channel.

### Node choice (OD-4)

| | SV Node (C++) | Teranode (Go) |
|---|---|---|
| RegTest | supported | supported (`teranode-quickstart` Docker) `TODO(verify)` exact compose target name |
| Forced reorg primitive | `invalidateblock` / `reconsiderblock` `TODO(verify)` exact method availability on the pinned version | `TODO(verify)` — Teranode admin interface differs from SV Node RPC; do not assume parity |
| Block-on-demand | `generatetoaddress` `TODO(verify)` | `TODO(verify)` |

The harness must abstract these behind a small **regtest control interface** (e.g.
`mineBlocks(n)`, `fundAddress(addr, sats)`, `invalidateToHeight(h)`), with one adapter per
node. The scenario tests call the interface, never the raw node API, so the scenario suite is
identical across the OD-4 choice. `TODO(verify)` the exact RPC/admin method names per node
version and pin them in the adapter — these are the only place node-specific names live.

### Deterministic funding

- The harness mines an initial run of blocks to mature a coinbase spendable balance, then
  funds Alice's NFT-minting key and Bob's payment key with named amounts from a fixtures file.
- Funding amounts, `DUST_SATS`, and `FEE_RATE` come from the single fixtures/params source
  (`docs/02` §2.8). No amount is written inline in a test. A magic number in a test is a
  `lint/format` + review failure.

---

## 5.4 Happy-path E2E scenarios

Each is a single automated E2E test on regtest. Each asserts the full post-condition set, not
just "no exception."

| ID | Scenario | Key assertions |
|---|---|---|
| E2E-1 | Mint NFT in Alice's wallet | one live UTXO carries `TokenId`/`payloadDescriptor`/`H(payload)`; I-NFT-1 (no `OP_RETURN`); I-NFT-3 (single token) |
| E2E-2 | Pair Alice↔Bob, exchange HELLO, open secure channel | both reach `CONNECTED`; channel keys agreed; per-message signatures verify |
| E2E-3 | Chat + negotiate to a price (OFFER/COUNTER/ACCEPT) | both reach `PRICE_AGREED` with identical agreed terms |
| E2E-4 | Deliver payload, Bob verifies `H(payload)` | both reach `PAYLOAD_DELIVERED`; Bob's computed hash equals token's `H(payload)` |
| E2E-5 | Assemble `Tx_swap`, co-sign (Bob first, Alice second), broadcast | I-NFT-2 (out 0 reproduces identity byte-for-byte); I-NFT-4 (no taken-payment-without-token state); single tx atomic |
| E2E-6 | Confirm at `CONF_DEPTH`; token now Bob's | both reach `CONFIRMED`; token UTXO owner = Bob; Alice's payment output present and spendable |
| E2E-7 | Alice deletes locally, sends `DELETION_ATTEST` (CDA) | Alice → `ATTESTED`; Bob validates `sigCDA`, stores it, → `DONE` |
| E2E-8 | Full chain E2E-1 → E2E-7 in one run | end state `DONE`/`ATTESTED`; full transcript persisted; **no** state where payment was taken but token did not move |

**E2E-8 also asserts the honest-claim boundary:** the test verifies that the system reports
control transfer as verified (token UTXO spent to Bob) and reports deletion as **attested,
not verified** (`docs/04` §4.7). A test that asserts "deletion verified" in Stage 1 is itself
a defect — it encodes an overclaim.

---

## 5.5 Fault and abort matrix (adversarial E2E)

Every row is an automated test. The invariant across the entire matrix: **no fund loss, no
false success, deterministic specified terminal state.** "It errored somehow" is not a pass;
the test asserts the exact terminal state and reason code from `docs/03` §3.5.

### Counterparty refusal / misbehaviour

| ID | Injected fault | Required outcome |
|---|---|---|
| F-1 | Bob never sends `SWAP_PARTIAL` | `T_sign` elapses → `ABORTED`; no tx broadcast; Alice's token untouched; no payment moved |
| F-2 | Alice never countersigns after Bob's `SWAP_PARTIAL` | `T_sign` elapses → `ABORTED`; Bob's funds untouched (his signature alone cannot move them) |
| F-3 | Bob sends `SWAP_PARTIAL` with a signature over a **different** tx | terms/signature verify FAIL → `ABORTED` reason `TERMS_MISMATCH`; nothing broadcast |
| F-4 | Alice sends a payload whose bytes hash ≠ token `H(payload)` | Bob → `ABORTED` reason `HASH_MISMATCH` before any signing |
| F-5 | Either party sends `ABORT` mid-flow | clean teardown → `ABORTED`; no partial on-chain effect |

### Chain-level faults

| ID | Injected fault | Required outcome |
|---|---|---|
| F-6 | Alice double-spends her token UTXO (broadcasts a conflicting tx) before/at swap | network confirms exactly one; if the conflict wins, swap → `FAILED` reason `DOUBLE_SPENT`; **Bob's payment is not taken** (I-NFT-4) |
| F-7 | Node **rejects** the broadcast (fee too low / missing input) | `SWAP_SIGNED` → `FAILED` with the node's reason surfaced; no silent retry that loses funds |
| F-8 | Reorg: confirmed `swapTxid` invalidated below `CONF_DEPTH` (`invalidateToHeight`) | system regresses `CONFIRMED`→`BROADCAST`, surfaces "pending again," never reports success during the regression (`docs/03` §3.5) |
| F-9 | Long no-confirmation period (mine no blocks past `T_confirm`) | stays `BROADCAST`, surfaces "pending," **never** auto-advances to `CONFIRMED` |

### Channel / message faults (transport is hostile — NET-1)

| ID | Injected fault | Required outcome |
|---|---|---|
| F-10 | Message reordering | engine tolerates or rejects per the state machine; no out-of-order message advances state illegally |
| F-11 | Message replay (resend a captured signed message) | replay detected and ignored; no double application; no state corruption |
| F-12 | Malformed / truncated message | rejected at parse/verify; connection-level error, not a crash; recoverable |
| F-13 | Forged message (valid shape, wrong/absent signature) | signature check fails → rejected; never applied (integrity rests on signatures, not the relay) |
| F-14 | Channel drop + reconnect mid-flow | session resumes to the correct state from persisted transcript, or aborts cleanly; no inconsistent half-state |

### Deletion / attestation faults

| ID | Injected fault | Required outcome |
|---|---|---|
| F-15 | Alice sends a **forged** CDA (bad `sigCDA`) | Bob rejects it; stays out of `DONE`; the forged attestation is not stored as valid |
| F-16 | Alice never sends a CDA after `CONFIRMED` | Bob already **owns** the token (settlement is independent of the CDA); test asserts ownership holds and the missing attestation is recorded as such — **not** as a transfer failure |
| F-17 | CDA references the wrong `swapTxid`/`tokenOutpoint` | Bob rejects as non-matching; not stored as valid |

F-16 is the load-bearing honesty test: it proves on-chain ownership does not depend on
Alice's cooperation in the deletion step, and that a missing CDA is reported as a missing
**claim**, consistent with `docs/04`.

---

## 5.6 Fault injection and fuzzing

- **Channel interposer.** A test double sits on the OD-8 channel and can drop, delay,
  duplicate, reorder, truncate, and bit-flip messages on command. Scenarios F-10…F-14 drive
  it. It is the single mechanism for all transport adversarial tests.
- **Message fuzzing.** Structure-aware fuzzing over each wire message type (`docs/03` §3.3):
  random/boundary field values, oversized fields, missing required fields, wrong types. The
  invariant: the engine never crashes, never advances state on an invalid message, never
  applies an unsigned/forged message.
- **Transaction fuzzing.** Generate near-miss `Tx_swap` variants (wrong output value, wrong
  `ownerPKH`, altered identity bytes, extra/missing output) and assert the verifier rejects
  every variant that violates the agreed terms (drives I-NFT-2/I-NFT-4 negatively).
- **Property tests for invariants.** I-NFT-1..5 are encoded as properties checked over many
  generated transactions, not just the fixed E2E flows. `no-OP_RETURN` and `BSV-not-BTC` are
  asserted as properties **and** as CI gates (§5.2) — defence in depth.

---

## 5.7 Coverage, comments, and the documentation standard in tests

- **Coverage** is reported but is a floor, not the bar (§5.1). Target the high coverage a
  mission-critical build expects; pin the exact threshold in CI config (`TODO(verify)`: set
  the number when the language/runtime is fixed by OD-2).
- **Every test is a specification.** Each test names the requirement ID it covers
  (`spec-traceability`, §5.2) and reads as prose: given/when/then, with the asserted
  post-condition stated explicitly. A test with an opaque assertion and no requirement
  reference fails review.
- **Adversarial tests state the threat.** Each F-row test header names the trust-register
  item or attack it exercises (`docs/04` §4.3), so the test tree is a readable map from
  threat → mitigation → proof.

---

## 5.8 What the test suite does NOT prove (stated, not hidden)

- It does **not** prove payload confidentiality or that Alice cannot retain a usable copy
  (PL-1). No Stage 1 test asserts this; a test claiming it would be false.
- It does **not** prove deletion as a verified fact (`docs/04`). It proves the CDA is
  well-formed, correctly signed, correctly rejected when forged, and **not** required for
  settlement. The meaningful-deletion proof arrives with Stage 2 crypto-shred and the T-stage
  (`docs/04` §4.5–§4.6) and will add its own tests then.
- It does **not** prove Script-enforced continuity unless OD-3's covenant is built; until
  then the continuity tests assert convention-level (wallet/indexer) detection, not
  Script-level prevention (CN-1).

These boundaries are the same ones stated in `docs/00`, `docs/02`, and `docs/04`. The test
plan does not quietly claim more than the architecture guarantees.
