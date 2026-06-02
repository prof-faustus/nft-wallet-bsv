# 01 — System Architecture

## 1.1 Shape of the application

A single **Windows desktop application**, one binary per user, run independently by Alice
and by Bob. It is non-custodial: each instance holds its own keys and signs its own
transactions. There is no shared server holding funds or the NFT.

The application is composed of three local tiers inside one process boundary, plus
optional out-of-process helpers:

```
┌───────────────────────────────────────────────────────────────────┐
│  Windows application instance (Alice or Bob)                        │
│                                                                     │
│  ┌──────────────┐   ┌───────────────────────┐   ┌───────────────┐  │
│  │ UI / shell    │◄─►│ Protocol engine        │◄─►│ Wallet core   │  │
│  │ (renderer)    │   │ (exchange state machine│   │ keys, UTXOs,  │  │
│  │ React/TS/Vite │   │  chat, negotiation,    │   │ tx builder,   │  │
│  │               │   │  delivery, attestation)│   │ SIGHASH ctrl) │  │
│  └──────────────┘   └───────────────────────┘   └───────┬───────┘  │
│         ▲                     ▲                          │           │
│         │                     │                          ▼           │
│  ┌──────┴──────┐      ┌───────┴────────┐         ┌───────────────┐   │
│  │ NFT vault    │      │ Secure channel │         │ Chain adapter │   │
│  │ (token recs, │      │ (authenticated │         │ (regtest RPC, │   │
│  │  payloads)   │      │  peer session) │         │  ARC, SPV)    │   │
│  └──────────────┘      └───────┬────────┘         └───────┬───────┘   │
└────────────────────────────────┼────────────────────────┼───────────┘
                                  │                         │
                          peer (Bob/Alice)          BSV node / ARC / indexer
```

### Recommended packaging (open decision OD-2, `docs/07`)

- **Renderer / UI:** TypeScript + React + Vite, packaged with **Electron** for Windows.
  Rationale: matches the established project stack (`formal-architecture-v1.docx` §7.2),
  the **BSV TypeScript SDK** runs in the renderer for tx building and SPV, and Web Crypto
  / IndexedDB are available. Electron gives a genuine Windows app with the existing stack.
- **Services / sidecar:** **Go**, using the **BSV Go SDK**, for the secure-channel relay
  client, the chain adapter, transcript verification, and any long-running concurrency.
  Rationale: matches the project's Go relay/SPV/indexer choice.
- **Alternative considered:** a native .NET/C# Windows app. Rejected as the default
  because it would not reuse the BSV TS/Go SDKs and the existing stack; recorded as OD-2
  for the owner to overrule.

The split is a recommendation. The architecture below is framework-agnostic; only OD-2
fixes the framing.

## 1.2 Components (responsibilities and boundaries)

1. **Wallet core.** Key management (identity key, payment key tree, derivation); UTXO
   tracking and coin selection; a **general** Script-capable transaction builder that can
   construct and spend arbitrary locking scripts (not only P2PKH) and set SIGHASH flags
   per input; signing. It must support: P2PKH, the push-drop token template (`docs/02`),
   2-of-2 multisig, pre-signed templates, and (if OD-3 chosen) `OP_PUSH_TX` introspection.
   The builder **has no `OP_RETURN` primitive** (`CLAUDE.md` §2).
2. **NFT vault.** Stores token records and payload files. A token record holds: token id,
   the push-drop payload (identity + `H(payload)`), the current outpoint, the owner key
   reference, status (`Owned | Offered | Transferring | Transferred | Deleted`), and the
   linked payload file reference. See §3 persistence.
3. **Protocol engine.** Drives the exchange state machine (`docs/03`): pairing, chat,
   negotiation, payload delivery + hash verification, swap-tx assembly + co-signing,
   broadcast, confirmation tracking, deletion attestation. Owns timeouts and aborts.
4. **Secure channel.** An authenticated, ordered, integrity-protected session to the
   peer (`docs/03` §2). Carries chat, negotiation, delivery, and partially signed
   transactions. Untrusted transport underneath.
5. **Chain adapter.** The only component that talks to BSV. Broadcasts transactions,
   queries UTXO/transaction status, fetches Merkle proofs for SPV, watches for confirms
   and conflicting spends. Abstracts over network mode (§4).
6. **UI / shell.** Pairing screen, chat, NFT vault view, the offer/sign prompts, status
   and confirmation display, and an audit/replay view of the transcript. The UI must
   "conceal complexity without concealing consequences" (`formal-architecture-v1.docx`):
   a signing prompt must show exactly what is being signed (price to Alice, token+hash to
   Bob, fee).

## 1.3 Process and concurrency model

- The protocol engine is a **deterministic state machine** driven by typed events
  (peer message received, chain event observed, user action, timer fired). State
  transitions are pure functions of (current state, event); side effects (sign,
  broadcast, send) are issued as commands the adapters execute. This makes the engine
  unit-testable without a network and **replayable** from a transcript (`docs/05`).
- All money values are integer satoshis. No floating-point arithmetic anywhere in value
  handling, fee computation, or display conversion.
- Long-running work (broadcast, confirmation polling, large payload transfer) runs off the
  UI thread; the UI observes engine state, it does not own it.

## 1.4 Chain connectivity (BSV-specific; verified facts)

Two BSV node implementations exist and both support the needed network modes:

- **SV Node** (C++, BSV Association). Supports `regtest`, `STN`, `testnet`, `mainnet`.
- **Teranode** (Go microservices, next generation). `teranode-quickstart` provides a
  Docker setup for `mainnet`, `testnet`, `teratestnet`, and `regtest`.

The chain adapter targets a **network-params module** with three profiles:

- **regtest (primary):** a local node (SV Node or Teranode via quickstart, OD-4). The
  adapter:
  - broadcasts via the node's raw-transaction submit RPC;
  - generates blocks on demand for tests via the node's block-generation RPC;
  - reads UTXO/tx status and Merkle proofs from the local node.
  - `TODO(verify): exact RPC method names and arguments against the installed node
    version (e.g. submit-raw-transaction, generate-to-address). Do not hard-code an
    unverified signature; confirm against the node's RPC docs at implementation time.`
- **testnet / mainnet:** broadcast via **ARC** (the multi-node broadcaster, which submits
  across nodes rather than relying on one); UTXO/tx status and Merkle proofs via an
  indexer/overlay/SPV service. SPV (Merkle-proof verification, BUMP-style) via the BSV SDK.
  - `TODO(verify): the ARC endpoint, auth, and response schema, and the indexer chosen
    (e.g. a public testnet explorer API) against current docs at implementation time.`

The adapter exposes a stable internal interface so the engine is independent of node
choice and network mode:

| Operation | Meaning |
|---|---|
| `broadcast(tx) -> txid \| reject(reason)` | submit a fully signed transaction |
| `txStatus(txid) -> {unknown, mempool, confirmed(depth), conflicted}` | track a transaction |
| `outputStatus(outpoint) -> {unspent, spentBy(txid), unknown}` | detect spends / double-spends |
| `merkleProof(txid) -> proof` | SPV proof for confirmation |
| `tip() -> {height, hash}` | chain tip, for reorg awareness |
| `generate(n, addr)` *(regtest only)* | mine n blocks (tests) |

The adapter **must not** import BTC libraries or BTC params (`CLAUDE.md` §1). Address
encoding, params, and SDK are BSV.

## 1.5 Persistence model (local, per instance)

All state is local to the instance. Recommended store: an embedded database (the renderer
side may use IndexedDB per the established stack; the Go sidecar may use an embedded
key-value/SQL store). Stores:

1. **Key store.** Identity key, payment key tree (derivation path documented), session
   keys. Encrypted at rest using the OS keystore / **DPAPI** on Windows. This software
   custody is the explicit Stage 1 stand-in for the TEE (`docs/04` §6); label it so.
   The store never logs private keys; a log gate forbids key material in logs.
2. **NFT vault.** Token records and payload files (see §1.2). Payload files are stored as
   opaque blobs plus metadata; in Stage 1 they are placeholder-encrypted, see `docs/04`.
3. **Transcript store.** Append-only, ordered log of every protocol message (chat,
   negotiation, delivery notices, partial signatures, attestations) with each party's
   signature. This is the audit and replay source (`docs/05`). Entries are immutable once
   written; corrections are new entries.
4. **Chain cache.** Observed UTXOs relevant to this wallet, transaction statuses, and
   Merkle proofs. Treated as a cache of chain truth, never as authority over it; on
   conflict, chain observation wins (`docs/03` double-spend handling).

### Invariants on persistence

- A token record's `status` advances monotonically through the lifecycle and never
  silently regresses; a regression (e.g. `Transferred -> Owned` because of a reorg) is an
  explicit, logged, user-visible event, not a quiet overwrite.
- Local "optimistic" state (e.g. "swap sent") is always distinguishable in storage and UI
  from enforceable committed state (e.g. "swap confirmed at depth N"). The architecture
  must not allow silent ambiguity between the two (`formal-architecture-v1.docx` §6.3).

## 1.6 Security architecture (Stage 1 posture)

- **Keys** stay within the wallet core; the UI and protocol engine request *signatures*,
  never raw keys. Signing prompts are explicit (`docs/03`).
- **Channel** is authenticated to the peer's identity key; messages are signed; transport
  is assumed hostile (`docs/03` §2).
- **Chain** is the settlement authority; the adapter verifies via SPV rather than trusting
  a single source where possible.
- **The honest-host assumption (HH-1)** is the load-bearing Stage 1 assumption and is
  stated in `docs/04` §6 and `docs/07`. The whole confidentiality/exclusivity story that
  HH-1 papers over is the explicit subject of Stage 2 and the T-stage.
