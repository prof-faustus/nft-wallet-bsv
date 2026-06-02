# 03 — Exchange Protocol

Defines how two instances meet, talk, and complete the swap. All messages are **signed**
by the sender's identity key and carried over the secure channel (§2). The protocol engine
is a deterministic state machine (§4) driven by typed events; this makes it replayable and
testable without a live peer.

## 3.1 Identities

- Each instance has a long-lived **identity key** (secp256k1; BSV). Its public key (or a
  paymail-style handle bound to it) is the instance's identity.
- A **session** is bound to both identity public keys and a fresh session nonce, so
  messages cannot be replayed across sessions.

## 3.2 Secure channel (over hostile transport)

Stage 1 uses a **minimal two-party authenticated channel**. The transport beneath (a relay,
a direct WebSocket, or a WebRTC data channel — OD-8) is **untrusted**: it may reorder, drop,
or delay, but must not be able to forge or alter messages undetectably.

Channel requirements:

- **Mutual authentication** to each party's identity key (a signed handshake binding both
  public keys and the session nonce).
- **Message integrity and origin:** every message carries the sender's signature over its
  canonical bytes, the session id, and a per-session monotonically increasing sequence
  number. Out-of-order or duplicate sequence numbers are rejected (anti-replay).
- **Confidentiality of chat/negotiation** over the wire is desirable but is **not** the
  Stage 1 confidentiality guarantee for the payload (that is Stage 2). Channel encryption,
  if used, protects transport only.
- **Liveness is not assumed.** Every state that waits on the peer has a timeout (§5).

`TODO(verify): the exact handshake/auth construction (e.g. a signed Diffie-Hellman over
secp256k1, or a paymail-based mutual auth) — choose and pin one, with test vectors. Do not
leave the handshake under-specified.`

## 3.3 Message set (wire protocol)

All messages share an envelope:

```
Envelope = { sessionId, seq, fromPubKey, payloadType, payload, sig }
sig       = Sign_from( H(sessionId || seq || fromPubKey || payloadType || payload) )
```

| `payloadType` | Direction | Purpose / key fields |
|---|---|---|
| `HELLO` | both | handshake: identity pubkey, session nonce, supported versions |
| `HELLO_ACK` | both | accept handshake, bind session |
| `CHAT` | both | free-text chat (UTF-8); for human conversation |
| `OFFER` | Bob→Alice | propose price: `{ tokenId, priceSats, expiry }` |
| `COUNTER` | Alice→Bob | counter-propose: `{ tokenId, priceSats, expiry }` |
| `ACCEPT` | either | accept the standing price: `{ tokenId, priceSats }` |
| `PAYLOAD_OFFER` | Alice→Bob | announce payload: `{ tokenId, payloadDescriptor, H(payload), size }` |
| `PAYLOAD_DATA` | Alice→Bob | the payload bytes (chunked); each chunk indexed and hashed |
| `PAYLOAD_ACK` | Bob→Alice | Bob confirms `H(received payload) == H(payload)` |
| `SWAP_PROPOSE` | proposer | the assembled unsigned `Tx_swap` (canonical) for review |
| `SWAP_PARTIAL` | each | the sender's signature(s) for its own input(s) of `Tx_swap` |
| `SWAP_BROADCAST` | broadcaster | the fully signed `Tx_swap` + the resulting txid |
| `DELETION_ATTEST` | Alice→Bob | signed deletion attestation (`docs/04`) |
| `ABORT` | either | abort with a reason code; ends the exchange cleanly |

Negotiation (`OFFER`/`COUNTER`/`ACCEPT`) is the structured layer on top of human `CHAT`.
A price is agreed only when one side sends `ACCEPT` matching the other's standing
`OFFER`/`COUNTER` with consistent `tokenId` and `priceSats`. Ambiguity (e.g. crossed
offers) resolves by the **last** signed `OFFER`/`COUNTER` that an `ACCEPT` references; the
engine rejects an `ACCEPT` that does not reference a current standing price.

## 3.4 Happy-path sequence

```
Alice (seller, holds token)                         Bob (buyer)
  |                                                   |
  |<----------------- HELLO / HELLO_ACK ------------->|   pair + authenticate
  |<======================= CHAT =====================>|   converse
  |                                                   |
  |                          OFFER (price)            |   Bob offers
  |<--------------------------------------------------|
  | COUNTER (price)                                   |   (optional) Alice counters
  |-------------------------------------------------->|
  |                          ACCEPT (price)           |   agreement reached
  |<--------------------------------------------------|
  |                                                   |
  | PAYLOAD_OFFER (descriptor, H(payload))            |   Alice announces payload
  |-------------------------------------------------->|
  | PAYLOAD_DATA (chunks)                             |   Alice sends payload
  |-------------------------------------------------->|
  |                          PAYLOAD_ACK              |   Bob verifies H(payload) matches
  |<--------------------------------------------------|
  |                                                   |
  | SWAP_PROPOSE (unsigned Tx_swap)                   |   engine assembles exact swap
  |-------------------------------------------------->|
  |  (both verify terms per docs/02 §2.5 step 2)      |
  |                          SWAP_PARTIAL (sigB)      |   Bob signs his input
  |<--------------------------------------------------|
  | SWAP_PARTIAL (sigA)                               |   Alice signs her token input
  |-------------------------------------------------->|
  | SWAP_BROADCAST (full tx, txid)                    |   broadcaster submits
  |-------------------------------------------------->|
  |  ... both watch chain for confirmation ...        |
  | DELETION_ATTEST (signed)                          |   after confirm: Alice attests delete
  |-------------------------------------------------->|
```

Who broadcasts and who signs first is fixed to remove ambiguity: **Bob sends
`SWAP_PARTIAL` first; Alice signs second and broadcasts.** Rationale: Alice controls the
unique scarce input (the token) and has the least incentive to grief after agreement; Bob's
early signature is on a transaction that pays Alice and gives Bob the token, so it is not
unilaterally exploitable. (If OD-6 SIGHASH-partial is adopted, ordering relaxes.)

## 3.5 State machine (normative)

States (per exchange, per instance):

`IDLE → PAIRING → CONNECTED → NEGOTIATING → PRICE_AGREED → PAYLOAD_DELIVERED →
SWAP_ASSEMBLED → SWAP_SIGNED → BROADCAST → CONFIRMED → (seller) ATTESTED → DONE`

with terminal `ABORTED` and `FAILED` reachable from many states.

| From | Event | To | Action |
|---|---|---|---|
| IDLE | user starts pairing | PAIRING | send/await HELLO |
| PAIRING | HELLO_ACK valid | CONNECTED | open chat |
| PAIRING | timeout `T_pair` | ABORTED | — |
| CONNECTED | ACCEPT matches standing price | PRICE_AGREED | record agreed price |
| CONNECTED | ABORT | ABORTED | — |
| PRICE_AGREED | (seller) payload sent; (buyer) PAYLOAD_ACK with matching hash | PAYLOAD_DELIVERED | — |
| PRICE_AGREED | buyer hash mismatch | ABORTED | buyer refuses; reason `HASH_MISMATCH` |
| PRICE_AGREED | timeout `T_deliver` | ABORTED | — |
| PAYLOAD_DELIVERED | engine assembles Tx_swap | SWAP_ASSEMBLED | SWAP_PROPOSE |
| SWAP_ASSEMBLED | terms verify OK + own signature produced + peer SWAP_PARTIAL received | SWAP_SIGNED | combine signatures |
| SWAP_ASSEMBLED | terms verify FAIL | ABORTED | reason `TERMS_MISMATCH` |
| SWAP_ASSEMBLED | timeout `T_sign` | ABORTED | — |
| SWAP_SIGNED | broadcast accepted | BROADCAST | watch chain |
| SWAP_SIGNED | broadcast rejected | FAILED | reason from node (fee/input) |
| BROADCAST | swapTxid confirmed at depth ≥ `CONF_DEPTH` | CONFIRMED | update vault status |
| BROADCAST | conflicting spend of token UTXO confirmed | FAILED | reason `DOUBLE_SPENT`; no attestation expected |
| BROADCAST | timeout `T_confirm` with no confirm and no conflict | (stay) BROADCAST | keep watching; surface "pending" to user; never silently succeed |
| CONFIRMED | (seller) local delete done | ATTESTED | send DELETION_ATTEST |
| CONFIRMED | (buyer) DELETION_ATTEST received + valid | DONE | store attestation |
| any waiting | ABORT received | ABORTED | clean teardown |

Rules:

- **No silent success.** The engine never reports the swap complete before `CONFIRMED`.
  Between `BROADCAST` and `CONFIRMED` the UI shows "pending," distinct from "confirmed."
- **Idempotent transitions.** Replayed or duplicated peer messages do not double-advance
  state (anti-replay via `seq`).
- **Reorg awareness.** If a confirmed `swapTxid` is later reorged out below `CONF_DEPTH`,
  the engine regresses status with a logged, user-visible event (`docs/01` §1.5), not a
  quiet overwrite.

## 3.6 Timeouts and abort (named constants — no magic numbers)

| Constant | Meaning | Default note |
|---|---|---|
| `T_pair` | handshake timeout | seconds; choose and document |
| `T_deliver` | payload delivery + ack timeout | scales with payload size |
| `T_sign` | co-signing window (the abandon window Δ) | minutes; bounds griefing (`docs/02` §2.5) |
| `T_confirm` | how long before "pending" is surfaced (not a failure) | minutes |
| `CONF_DEPTH` | confirmations before `CONFIRMED` | blocks; document choice; tunable per network mode |

Aborts are explicit (`ABORT` with a reason code) and always leave both parties in a clean
terminal state with the transcript intact. An abort before `BROADCAST` costs nothing
on-chain. An abort/failure after `BROADCAST` is governed by the chain outcome (§3.5).

## 3.7 What the protocol does and does not guarantee (stated)

- **Guaranteed:** atomic exchange of on-chain token control for payment (`docs/02` §2.5);
  buyer never pays without first verifying the payload hash; no fund loss from a stalling
  counterparty; a clean, signed transcript of the whole exchange.
- **Not guaranteed in Stage 1:** that the seller cannot retain a usable payload copy
  (Stage 2 crypto-shred); that deletion physically occurred (cooperative attestation only,
  `docs/04`); that the token cannot be Script-stripped by a hostile spender unless the
  OD-3 covenant is implemented (`docs/02` §2.6).

## 3.8 Deferred — full discovery network

The minimal two-party pairing (§3.2) is Stage 1. The full network from
`formal-architecture-v1.docx` §7.8 — **Tier A** Bitcoin-style discovery
(`version`/`verack`, `getaddr`/`addr`, peer scoring) and **Tier B** Bitmessage-style
inventory/object relay (`inv`/`getdata`/`object`, streams), with a table-/session-scoped
relay group — is a later slot. Stage 1 leaves a clean seam: the secure channel and message
set above sit unchanged on top of either minimal pairing or the full network.
