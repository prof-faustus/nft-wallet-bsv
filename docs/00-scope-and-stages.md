# 00 — Scope, Stages, and Definitions

## 0.1 Purpose of Stage 1

Demonstrate, end to end and under exhaustive test, that two instances of a BSV
full-Script wallet can:

1. find and authenticate each other (two-party pairing),
2. communicate (chat + structured negotiation),
3. deliver a payload file from seller to buyer, bound by hash to an on-chain token,
4. exchange that token for BSV **atomically** in a single transaction,
5. record a cooperative deletion attestation from the seller.

Stage 1 is **plumbing correctness**, not confidentiality and not exclusivity. The value
proposition of a *unique* sellable NFT (the seller can no longer use or resell it) is only
fully realised once Stage 2 (encryption + crypto-shredding) and, if chosen, the `docs/02`
§6 continuity covenant are in place. Stage 1 builds the rails those depend on.

## 0.2 Stage boundary — normative

| Capability | Stage 1 | Stage 2 | T-stage (TEE) |
|---|---|---|---|
| Pairing + authenticated channel | ✅ build | harden | enclave-attested channel |
| Chat + signed negotiation | ✅ build | — | — |
| Payload delivery (hash-bound) | ✅ build (placeholder encryption) | **real encryption** | enclave-sealed payload |
| Atomic NFT-for-BSV swap | ✅ build | — | — |
| On-chain transfer of control | ✅ build (verifiable) | — | — |
| Token continuity | convention-enforced; covenant optional (`docs/02` §6) | covenant default | — |
| Payload confidentiality | ❌ not provided | ✅ crypto-shred | enclave seal |
| "Deletion" | cooperative **attestation** only | **crypto-shred** (retained ciphertext useless) | **attested wipe** of plaintext |
| Key custody | OS keystore (software) | OS keystore + KDF hardening | enclave (sk never leaves) |
| Honest-host assumption | **assumed** (stand-in for T) | reduced | removed via attestation |

A capability marked ❌ in Stage 1 must be described as absent everywhere — code, UI, logs,
docs. See `CLAUDE.md` §4.

## 0.3 Definitions

- **NFT / token.** A single tokenised object represented on-chain by one **1-satoshi
  (dust) UTXO** whose locking script (a) carries the token's identity and a hash of its
  payload via a push-drop prefix (no `OP_RETURN`), and (b) gates spending by an ownership
  condition. Defined fully in `docs/02`.
- **Payload.** The off-chain file the token represents (the "encrypted NFT" contents). In
  Stage 1 the payload is delivered with **placeholder** encryption; real encryption is
  Stage 2. The on-chain token commits to `H(payload)`.
- **Atomic swap.** One BSV transaction spending Alice's token UTXO and Bob's payment
  UTXO, producing the token under Bob's key and the price under Alice's key. Valid only
  with both signatures; all-or-nothing. Defined in `docs/02` §5.
- **Cooperative deletion attestation (DA).** A message signed by the seller asserting it
  has deleted its payload copy, bound to the swap txid and `H(payload)`. A verifiable
  *claim*, not a verified *fact*. Defined in `docs/04`.
- **The T-element ("T").** Read as **Trusted Execution Environment (TEE)**. Stage 1 does
  not use it and instead **assumes honest host execution** as its equivalent. The owner
  must confirm this reading (alternative: TTP). See `docs/07` open decision OD-1.
- **Honest-host assumption (HH-1).** The Stage 1 trust assumption standing in for the TEE:
  each instance executes the protocol as specified and does not exfiltrate its own keys.
  Classified and bounded in `docs/04` §6 and `docs/07`.
- **Network modes.** `regtest` (local private chain; primary for prototype and tests),
  `testnet` (public test chain), `mainnet` (live BSV). Selected by a single network-params
  module. See `docs/01` §4.

## 0.4 Actors and trust posture (Stage 1)

- **Alice (seller)** and **Bob (buyer)** are mutually distrusting counterparties.
- There is **no trusted third party** in Stage 1 (no escrow operator, no arbiter). The
  atomicity that protects both parties comes from the single-transaction swap, not from a
  trusted intermediary.
- A **relay** may carry messages and may be untrusted: it can drop or delay but must not be
  able to forge signed messages or alter transactions undetectably (`docs/03` §2).
- The **BSV network** is the settlement authority. First valid spend of the token UTXO
  wins; conflicting spends are resolved by the network, observed via SPV (`docs/01` §4).

## 0.5 Explicit non-goals for Stage 1

- Multi-party (>2) exchange, order books, or a marketplace. One seller, one buyer, one NFT.
- The full discovery network. Stage 1 uses minimal two-party pairing; the two-tier
  Bitcoin-style + Bitmessage-style network is a defined later slot (`docs/03` §8).
- Payment channels / streaming micropayments. The swap is a single on-chain transaction.
- Card-game logic. This wallet shares mechanisms with the In-Between work but Stage 1
  ships none of the game.
- Regulatory framing. Out of scope unless the owner requests it.
