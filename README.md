# nft-wallet-bsv — Stage 1 Architecture (Encrypted-NFT Transfer Wallet, BSV)

**Status:** Architecture specification only. This repository contains **no application
source code**. It is the design that an implementer (Claude Code) builds from.

**Chain:** Bitcoin SV (**BSV**) only. Never BTC. See `CLAUDE.md` §1.

**Hard prohibitions (absolute, CI-enforced):**

- **No BTC.** No BTC libraries, network parameters, address formats, or assumptions.
  BSV and BTC share no codebase here. Any BTC dependency is a build failure.
- **No `OP_RETURN`.** Anywhere. In any locking or unlocking script. Data is carried
  by push-drop in a locking script or by a push in an unlocking script — never
  `OP_RETURN`. A static scanner rejects any script containing opcode `0x6a`.
- **BSVM and Rúnar are available.** They are usable primitives in this project, not
  excluded. The only hard exclusion is `OP_RETURN` (above). The project's academic papers
  use BSVM and Rúnar; their constructions may be drawn on, minus any `OP_RETURN` path.
- **TEE is an open decision, not a prohibition.** The current design does not *require* a
  device TEE — its baseline is honest-host execution plus software key custody, labelled as
  such. Whether/when a TEE is adopted, and whether "T" means TEE, is an open decision
  (`docs/07`, OD-1).

---

## 1. What this system is

A **Windows desktop application** that is a non-custodial, full-Script-capable **BSV
wallet** which additionally holds and transfers a **tokenised object** ("the NFT").

Two instances of the same application interact:

- **Alice** holds the NFT.
- **Bob** wants it. Bob connects to Alice, they **chat**, they agree a price, and the
  NFT is exchanged for BSV in a **single atomic transaction**.

The application can run against **regtest** (local, primary for the prototype and the
test suite), **testnet**, or **mainnet**. All three are supported; the prototype is
demonstrated and exercised on regtest.

## 2. What Stage 1 delivers (and what it deliberately does not)

Stage 1 is the **transport and settlement plumbing**, end to end and exhaustively tested:

- Pairing and an authenticated peer-to-peer channel between two app instances.
- Chat, and price negotiation carried as signed structured messages.
- Off-chain delivery of the NFT payload file, hash-bound to the on-chain token.
- An **atomic swap**: NFT-for-BSV in one transaction, co-signed, all-or-nothing.
- On-chain **transfer of control** (the token UTXO moves from Alice's key to Bob's).
- A **cooperative deletion attestation** from Alice after settlement.

Stage 1 **does not** provide, and **does not claim**:

- **Real payload confidentiality / crypto-shredding.** Encryption is a placeholder in
  Stage 1 and is the subject of Stage 2. Alice can technically retain a usable copy of
  the payload in Stage 1. This is stated, not hidden. See `docs/04`.
- **Verified deletion of Alice's local copy.** Only a signed *claim* of deletion. See
  `docs/04` for why true verifiable deletion needs Stage 2 (crypto-shred) or the
  T-element (TEE).
- **Script-enforced token continuity.** Stage 1 enforces token identity by wallet +
  indexer convention. The `OP_PUSH_TX` covenant that makes continuity Script-enforced
  (no `OP_RETURN`) is specified as a hardening — see `docs/02`
  §6 — and is an open decision for whether to pull into Stage 1.

## 2.5 What Stage 2 adds — BUILT (see `docs/08`, `TESTING.md`)

Stage 2 is implemented, exhaustively tested, and CI-green (incl. a live SV Node job):

- **Real payload encryption + crypto-shredding**, six selectable schemes
  (`internal/shred`): `ecdh-singleuse`, `key-surrender`, `reencrypt`, `tee-attested`
  (a simple software stand-in), `threshold` — a **dealerless threshold ECDSA** key
  generation/sharing (`internal/threshold`, Shamir over secp256k1 N, reconstruct-to-use) —
  and **`tee-enclave`**, the **T-element**: an attested secure-enclave release using the
  project's `tee-sim` wire format (`internal/tee`), fail-closed verifier, interop-proven
  against the real `tee-sim` binary. Cooperative shred is a CLAIM, never "verified deletion";
  the enclave path is a SIMULATION (self-generated root), not hardware.
- **Script-enforced token continuity — the `OP_PUSH_TX` covenant (OD-3), built**
  (`internal/covenant`). A spend must reproduce a successor token output with identical
  identity + value; stripping/mutating is impossible in Script. No `OP_RETURN`. Proven
  in the BSV interpreter (3000-iteration sweep + every tampering vector) **and on a real
  SV Node** (faithful mint+swap accepted, strip rejected).
- **A menu-driven exchange** (`internal/sidecar` `/v2`, native WPF shell in `apps/shell`):
  the user chooses every option (scheme, continuity, all amounts) — no assistant-selected
  defaults; a missing required value is an error. Bots/simulation are test-only.

## 3. Deferred to later stages (slots are defined now)

| Item | Stage | Status / Defined in |
|---|---|---|
| Real payload encryption + crypto-shredding | 2 | ✅ **built** — `internal/shred`, `docs/08` |
| Dealerless threshold ECDSA custody | 2 | ✅ **built** — `internal/threshold`, `docs/08` |
| Script-enforced token continuity (`OP_PUSH_TX` covenant) | 2 (OD-3) | ✅ **built** — `internal/covenant`, `docs/08` §8.4 |
| The **T**-element (read as **TEE**; see `docs/07`) — attested execution + attested wipe | 2 (sim) / 2+ (hardware) | ✅ **attested enclave built** — `tee-enclave` scheme via `internal/tee`, wire-compatible with `Property/tee-sim` (KAT-proven); a SIMULATION (self-generated root). Genuine hardware TEE (verified vendor root) drops into the same verifier — `docs/04` §6, `docs/07` |
| Full two-tier discovery network (Bitcoin-style + Bitmessage-style) | later | `docs/03` §8 |

## 4. Document map

Read in order. Each document is self-contained for its scope.

| File | Contents |
|---|---|
| `CLAUDE.md` | Operating rules for the implementer. The non-negotiable gates. Read first. |
| `docs/00-scope-and-stages.md` | Precise scope, the Stage 1/2/T boundary, definitions. |
| `docs/01-system-architecture.md` | Components, process model, technology stack, persistence, the Windows-app shape. |
| `docs/02-nft-and-transaction-model.md` | The non-`OP_RETURN` token; push-drop construction; locking/unlocking templates; payload binding; the atomic-swap transaction; the optional continuity covenant. |
| `docs/03-exchange-protocol.md` | Pairing, secure channel, chat, negotiation, delivery, co-signing, broadcast, attestation. Wire messages, state machine, timeouts, aborts. |
| `docs/04-deletion-and-trust-model.md` | The honest deletion analysis. Trust register. The T (TEE) slot. The crypto-shred hook. Threats. |
| `docs/05-test-plan-and-regtest-harness.md` | The regtest harness, the scenario matrix (happy path + every abort/fault), property tests, fault injection, the CI gates. |
| `docs/06-implementation-workstreams.md` | The ordered build plan, each with a Definition of Done, plus the documentation/comment standard. |
| `docs/07-assumptions-and-open-decisions.md` | Every assumption, classified. Every open decision awaiting the project owner. What is NOT guaranteed. |

## 5. Provenance of the design

Grounded in this project's own documents:

- Non-`OP_RETURN` data carriers (push-drop prefix; unlocking-script push) — from the
  project's *BSVM Online Appendix 2, "Script-Embedded DA."* The data-carrier technique is
  plain Script; BSVM and Rúnar remain available where they would strengthen it.
- Funding → 2-of-2 multisig with a pre-signed settlement template; timeout redirection
  (Path T); fair-play locking scripts as the no-TTP enforcement; TTP arbitration as a
  composable add-on — from *Fair_Play_Transactions*.
- Conjunctive settlement predicate using only `OP_CHECKSIG`; pre-signed recovery
  transactions rather than script-level time-locks where applicable — from
  *strict_provable_fairness*.
- Technology stack, two-tier networking, wallet-as-protocol-agent, API surface, and the
  workstream structure — from `formal-architecture-v1.docx` (the In-Between deliverable).

BSV infrastructure facts used here were verified against current BSV documentation
(SV Node and Teranode; regtest/testnet/mainnet; ARC broadcaster; BSV SDKs), not assumed
from BTC tooling.
