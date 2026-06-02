# 07 — Assumptions and Open Decisions

This document exists so nothing is assumed silently. Every assumption Stage 1 relies on is
listed and classified here. Every decision left to the project owner is listed as an open
decision (OD) with its default and its consequence. Every fact that is **not yet verified** —
and must be pinned against the running system before it is trusted — is listed in §7.4 as a
`TODO(verify)` item, not presented as known.

The standard applied: a hidden assumption is a serious defect; a stated, classified
assumption with its limits is the correct way to ship a staged design. An unverified fact
presented as verified would be fabrication. Neither is permitted here.

---

## 7.1 Classification key

| Class | Meaning |
|---|---|
| **VERIFIED** | Established by a source or by direct construction; safe to rely on. |
| **DEFERRED** | A property deliberately **not** provided in Stage 1; out of scope by design, removed/added in a named later stage. Not a safety assumption — a stated non-provision. |
| **LOAD-BEARING** | A Stage 1 assumption that, if false, breaks a Stage 1 guarantee. Called out so it is impossible to overlook. |
| **OPEN** | Awaiting a project-owner decision (an OD). Has a stated default so work can proceed, but the owner should confirm. |
| **UNVERIFIED** | Not yet checked against the running system. Must be pinned at implementation (`TODO(verify)`). Not relied upon until then. |

---

## 7.2 Assumptions, classified

These mirror the trust register (`docs/04` §4.3); here each carries its classification and
what removes it.

| ID | Assumption / posture | Class | If false / not provided | Removed or resolved by |
|---|---|---|---|---|
| HH-1 | Each instance runs the protocol as specified and does not exfiltrate **its own** keys (honest host). The explicit Stage 1 stand-in for the TEE. | **LOAD-BEARING** | A malicious host can leak its own keys and retain the payload; the "seller loses access" property fails. | T-stage (TEE attestation), OD-1 |
| PL-1 | Payload confidentiality is **not** assured; placeholder encryption only. Alice can technically retain a usable copy. | **DEFERRED** (Stage 2) | Nothing — this is stated, not assumed-safe. Stage 1 makes no confidentiality claim. | Stage 2 (real encryption + crypto-shred), `docs/04` §4.5 |
| SC-1 | Software key custody (OS keystore / DPAPI) protects keys at rest. | DEFERRED (hardening) | Key theft if the host is compromised. | T-stage (enclave custody) |
| CN-1 | Token continuity is convention-enforced (wallet/indexer), not Script-enforced. | **OPEN** (OD-3) | A hostile spender could strip the token; this is **detected**, not **prevented**, in the default. | OD-3 covenant (`docs/02` §2.6) |
| NET-1 | Transport is hostile; integrity rests on per-message signatures, not the relay. | VERIFIED (by construction) | n/a — this is the design posture; DoS/delay possible, forgery is not. | already minimal |
| CH-1 | The BSV network is the settlement authority; SPV verifies inclusion; proof-of-work orders. | VERIFIED | A deep reorg can regress a confirmed swap; this is **surfaced**, not hidden (`docs/03` §3.5). | higher `CONF_DEPTH` reduces probability; not eliminable |

**The two that matter most:** HH-1 and PL-1. Together they are the entire gap between Stage 1
and a true "sell, and the seller can no longer use the asset" guarantee. PL-1 is closed by
Stage 2 (crypto-shredding). HH-1 is closed by the T-stage (TEE). This is stated plainly in
`docs/00`, `docs/04`, and the README; it is the central honesty boundary of the project.

---

## 7.3 Open-decisions register

Each OD has a default so WS0–WS8 can proceed without blocking. The owner should confirm OD-1,
OD-2, and OD-4 early because they shape structure; the rest can be confirmed as their
workstream is reached.

| OD | Decision | Default (current design assumes) | Consequence of the choice |
|---|---|---|---|
| **OD-1** | What does **"T"** mean? | **TEE** (Trusted Execution Environment). | TEE → T-stage is attested execution + attested wipe; removes HH-1 and SC-1. **TTP instead** → the trusted element becomes a dispute arbiter, the CDA is augmented by arbiter adjudication, and HH-1 is **not** removed the same way (`docs/04` §4.6). This changes the entire T-stage design. **Owner confirmation requested.** |
| **OD-2** | Windows app shape. | Electron (TypeScript/React/Vite) renderer + **Go sidecar** for chain/protocol, recommended in `docs/01`. | Sidecar → reuses the BSV TS + Go SDKs cleanly; renderer holds no keys. **Native .NET/C#** → single stack, but a different BSV library story to verify. |
| **OD-3** | Script-enforced token continuity (`OP_PUSH_TX` covenant) in Stage 1, or defer? | **Defer**; Stage 1 continuity is convention-enforced (CN-1). | Pull in → continuity is **Script-enforced** (prevented, not just detected), plain Script, still no `OP_RETURN` (BSVM/Rúnar allowed, not required); adds covenant complexity and per-tx overhead. Defer → simpler Stage 1, continuity is a detected-not-prevented property. (`docs/02` §2.6) |
| **OD-4** | RegTest/settlement node. | Choose one: **SV Node (C++)** or **Teranode (Go)**; both support regtest/testnet/mainnet. | Affects only the node adapter behind the regtest control interface (`docs/05` §5.3); the scenario suite is identical either way. Forced-reorg and block-on-demand method names differ and are `TODO(verify)` per node. |
| **OD-5** | Identity carrier construction. | **Construction A** (push-data-with-drop prefix in the locking script; self-describing output). | A → simpler indexing. **Construction B** (push in unlocking script) → smaller locking script, identity bound by spend logic. (`docs/02` §2.3) |
| **OD-6** | Anti-grief signing variant. | **Off**; ordered co-signing (Bob first, Alice second), griefing bounded by `T_sign` = Δ. | On (a SIGHASH-partial construction) → relaxes signing order and strengthens the anti-grief property; must be shown non-exploitable before adoption. (`docs/02` §2.5, `docs/03` §3.3) |
| **OD-7** | Two-step escrow template variant. | **Off**; the single atomic `Tx_swap` is the Stage 1 default. | On → a 2-of-2 funding + pre-signed settlement template (Fair-Play-style); adds an on-chain step and is not required for Stage 1 atomicity. (`docs/02` §2.7) |
| **OD-8** | Channel transport. | Pluggable behind the channel interface; pick the Stage 1 default (relay / direct WebSocket / WebRTC). | Affects only the transport binding (WS4); the secure-channel logic and the fault interposer (`docs/05` §5.6) are transport-agnostic. (`docs/03` §3.2) |

---

## 7.4 Unverified items to pin at implementation (`TODO(verify)`)

These are **not** assumed. They are flagged everywhere they appear in the docs and must be
checked against the running system, then pinned in the one place each belongs. Trusting any
of them before verification would be a defect.

| Item | Where it lives once verified | Source to verify against |
|---|---|---|
| BSV dust threshold / minimum relayable output → `DUST_SATS` | the single params/fixtures source (`docs/02` §2.8) | the pinned BSV node's policy — **not** any BTC value |
| Fee rate (sat/byte) → `FEE_RATE` | the single fee-policy module | BSV node/broadcaster fee policy at build time |
| Node RPC / broadcaster (ARC) method names + signatures (broadcast, status, depth, conflict detection) | the chain adapter, WS1 (`docs/01`, `docs/05` §5.3) | the running node / ARC for the pinned version |
| Block-on-demand + forced-reorg method names (`mineBlocks`, `invalidateToHeight`) per node | the per-node regtest adapter | SV Node RPC **or** Teranode admin interface — do not assume parity (OD-4) |
| Whether the chosen BSV SDK exposes fully serialized script bytes for the `no-op-return` scanner | the gate implementation (`docs/05` §5.2) | the SDK at build time; fall back to raw-tx-hex scan if not |
| Coverage threshold number | CI config (`docs/05` §5.7) | set once OD-2 fixes the language/runtime |
| Teranode `teranode-quickstart` exact compose target | the Teranode regtest adapter | the Teranode quickstart for the pinned version |
| Whether patent GB2616862 has granted to a "B" form | n/a to Stage 1 build; record only | not confirmable from the documents on hand |

---

## 7.5 What Stage 1 does NOT guarantee (consolidated)

Stated once more, in one place, so it cannot be lost across documents:

- **Not payload confidentiality, not exclusivity.** Alice can technically retain a usable copy
  of the payload in Stage 1 (PL-1). Stage 2 (crypto-shred) addresses this.
- **Not verifiable deletion.** Stage 1 ships a Cooperative Deletion **Attestation** — a signed
  *claim*, correctly formed and correctly rejected when forged, and explicitly **not** required
  for settlement. It is not proof the payload was destroyed. Meaningful deletion needs Stage 2
  (crypto-shred) and the T-stage (attested wipe). (`docs/04`)
- **Not protection against a malicious host leaking its own keys** (HH-1). The T-stage (TEE)
  addresses this; pending OD-1.
- **Not Script-enforced continuity** unless OD-3's covenant is built; the default detects, it
  does not prevent (CN-1).
- **Not reorg-proof.** A deep reorg can regress a confirmed swap; it is surfaced, never hidden
  (CH-1, `docs/03` §3.5).

**What Stage 1 does guarantee** (the other side, so this is not only caveats): a complete,
exhaustively tested, BSV-only, `OP_RETURN`-free pipeline that mints a token-as-UTXO, negotiates
over a hostile channel with authenticated messages, and transfers control of the token against
payment in a **single atomic transaction** with no taken-payment-without-token state (I-NFT-1
..5), with on-chain control transfer that **is** verifiable, and with deterministic,
specified behaviour on every abort, fault, double-spend, and reorg edge in the matrix
(`docs/05` §5.5). That is the Stage 1 claim, and it is the whole of it.

---

## Resolution log (RUN_PLAN §C)

Decisions made by the project owner to start the run. Recorded here per
`CLAUDE.md` §4 (no hidden assumptions / decisions live in `docs/07`).

| OD | Resolution | Date | Notes |
|---|---|---|---|
| **OD-4** | **SV Node (regtest)** | 2026-06-02 | bitcoind-style regtest (`bitcoinsv/bitcoin-sv` image). `generatetoaddress` for block-on-demand; `invalidateblock`/`reconsiderblock` for forced reorg — exact methods pinned in the node adapter as `TODO(verify)` against the running version (Pre-flight P2/P4). |
| **OD-2** | **Native .NET/C# shell + Go sidecar** | 2026-06-02 | Owner chose "native .NET/C#" over Electron+Go. Reconciled with `CLAUDE.md` §1 (which mandates the **BSV Go SDK for services**): the .NET/C# layer is the **UI shell only**; a **Go sidecar using the BSV Go SDK** holds all keys and performs all BSV/script/chain operations (renderer holds no keys — WS7 DoD). The BSV TypeScript SDK client named in §1/`docs/01` is **superseded** by the .NET shell. If the owner intends *pure* .NET (no Go sidecar), that requires a `CLAUDE.md` §1 amendment — flagged, not assumed. |

OD-5 (carrier A), OD-8 (transport pluggable), OD-3 (covenant deferred), OD-6/OD-7 (off),
OD-1 (HH-1 baseline) remain at their RUN_PLAN §C defaults until their gating phase.
