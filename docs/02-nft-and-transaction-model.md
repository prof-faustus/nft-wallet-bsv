# 02 — NFT Object and Transaction Model

This document specifies on-chain objects. Everything here is **protocol design** — the
structure of scripts and transactions — not application source code. Implement it through
the BSV SDK. The one hard exclusion is `OP_RETURN`. BSVM and Rúnar are available primitives
and may be used where they improve a construction.

## 2.1 The token as a UTXO

The NFT is **one 1-satoshi (dust) UTXO**. Its existence, identity, and owner are read from
the chain. Ownership transfers by spending it to a new output. The satoshi value is a
carrier; the value of the NFT is its identity and bound payload, not the dust amount.

`TODO(verify): the current BSV dust threshold / minimum relayable output value for the
chosen node version, and set the named constant DUST_SATS from it. Do not assume BTC's
546. Confirm against BSV node policy at implementation time.`

## 2.2 Token identity and payload binding

The token's **identity record** is fixed at mint and preserved across every transfer:

```
TokenId        = H( mintOutpoint || ownerPubKey_at_mint || payloadDescriptor || H(payload) )
payloadDescriptor = canonical bytes: { version, contentType, length, encScheme }
H(payload)     = double-SHA256 of the (Stage 1: placeholder-encrypted) payload bytes
```

- `H(payload)` binds the on-chain token to the off-chain file. A buyer who has the payload
  can verify it matches the token before paying (`docs/03`).
- `encScheme` in Stage 1 records the **placeholder** scheme; in Stage 2 it records the real
  encryption scheme. The binding mechanism does not change between stages; only the bytes
  being hashed do. This is why Stage 1 can build the binding rail without the real crypto.
- Canonical serialisation of `payloadDescriptor` and of all on-chain pushes is mandatory;
  define it once and cover it with test vectors (`docs/05`). Ambiguous encoding is a defect.

## 2.3 Carrying the identity on-chain WITHOUT `OP_RETURN`

The token output carries its identity data using the project's documented **push-drop**
data-carrier (Construction A from *BSVM Online Appendix 2, "Script-Embedded DA"*). The
technique is plain BSV Script; it carries identity without `OP_RETURN`. BSVM and Rúnar
remain available if a richer carrier or covenant is wanted (see §2.6 and OD-5).

**Token output locking script template** (annotate opcode-by-opcode in code):

```
<TokenId>  <payloadDescriptor>  <H(payload)>     ; push the identity data
OP_DROP  OP_DROP  OP_DROP                          ; drop it (data-carry, consumed on spend)
OP_DUP  OP_HASH160  <ownerPKH>  OP_EQUALVERIFY  OP_CHECKSIG   ; P2PKH-style ownership gate
```

- The identity data lives in the output's **own** locking script as a push-drop prefix.
  When the output is spent, the pushes are dropped before the ownership check runs.
- Ownership is a standard public-key-hash + signature gate (`OP_CHECKSIG`), consistent with
  the project's preference for conjunctive `OP_CHECKSIG` predicates
  (*strict_provable_fairness*).
- **No `OP_RETURN`.** Recovery of historical identity data is via block/transaction history
  (the appendix notes this is equivalent to `OP_RETURN`'s archival recovery, without the
  `OP_RETURN` path).

**Alternative carrier (Construction B, unlocking-script push).** If keeping the locking
script minimal is preferred, the identity data can instead be supplied in the **unlocking**
script of the spend and bound by the spend logic. Stage 1 default is Construction A
(self-describing output, simpler indexing). The choice is recorded as OD-5 (`docs/07`).

## 2.4 Mint (Stage 1: local provisioning of the token)

Minting creates the first token UTXO under Alice's key:

- **Inputs:** one or more of Alice's funding UTXOs.
- **Output 0:** the token output (1 sat), locking script per §2.3 with `ownerPKH = Alice`.
- **Output 1:** Alice's change.
- Alice signs (SIGHASH_ALL) and broadcasts. `TokenId` is now fixed and on-chain.

Stage 1 mint is a provisioning step for the demo; it is not a public sale mechanism.

## 2.5 The atomic swap (the core transfer)

Transfer of the NFT to Bob in exchange for BSV is a **single transaction** `Tx_swap`,
co-signed by both parties, valid only with both signatures — therefore atomic.

**`Tx_swap` layout:**

| Index | Input | Provided by | Unlocking script |
|---|---|---|---|
| in 0 | Alice's token UTXO (§2.3) | Alice | `<sigA> <pubKeyA>` (satisfies ownership gate) |
| in 1 | Bob's payment UTXO(s) | Bob | `<sigB> <pubKeyB>` |

| Index | Output | Value | Locking script |
|---|---|---|---|
| out 0 | token, now Bob's | DUST_SATS | §2.3 template with `ownerPKH = Bob`, **same** `TokenId`/`payloadDescriptor`/`H(payload)` |
| out 1 | price to Alice | agreed price | P2PKH to Alice |
| out 2 | Bob's change | remainder − fee | P2PKH to Bob |

**Atomicity argument.** `Tx_swap` is valid only if **both** `sigA` (spending the token) and
`sigB` (spending Bob's payment) are present and the transaction is accepted by the network.
There is no partial outcome: either the whole transaction confirms (Bob gets the token,
Alice gets the price) or nothing changes on-chain. No trusted third party is involved.

**Co-signing sequence (default — SIGHASH_ALL):**

1. The protocol engine assembles the exact `Tx_swap` from the agreed terms.
2. **Both parties independently verify** the assembled transaction encodes precisely the
   agreed terms before signing:
   - out 1 pays the agreed price to Alice's address;
   - out 0 reproduces `TokenId`, `payloadDescriptor`, and `H(payload)` **unchanged** and
     locks to Bob;
   - the fee is within the agreed bound; no extra outputs.
   Bob additionally requires that he has already received the payload off-chain and that
   `H(received payload) == H(payload)` in out 0 (`docs/03`). If any check fails, the party
   does **not** sign.
3. Each party signs its own input(s) with **SIGHASH_ALL** (commits to all inputs and
   outputs — neither party can alter the transaction after signing without invalidating
   the other's signature).
4. Either party broadcasts (`docs/03` assigns the broadcaster). On accept, the swap is
   atomic.

**Honest griefing note (stated, not hidden).** A party who has seen the counterparty's
signature can simply stall and never broadcast. With SIGHASH_ALL co-signing this causes
**no loss of funds** — a half-signed transaction is unbroadcastable and a fully signed one
already protects both sides — the only harm is a failed trade. The protocol bounds stalling
with an **abandon timer** Δ (`docs/03`): if the swap is not confirmed within Δ, both sides
abandon and may rebuild. A SIGHASH-partial exchange variant (each signature individually
non-exploitable) is recorded as OD-6 if a stronger anti-grief property is wanted; it is not
required for atomicity or safety.

**Double-spend / equivocation by Alice.** After co-signing, Alice could attempt to spend
her token UTXO in a *different* transaction (e.g. sell it to a third party). Both spends
conflict on the same input; the **network confirms at most one**. The protocol engine
watches `outputStatus(tokenOutpoint)` and `txStatus(swapTxid)`; if a conflicting spend
confirms, the swap is treated as **failed**, Bob's payment was never taken (it was an input
to the losing transaction), and no deletion attestation is expected. This is handled
explicitly in the state machine (`docs/03`), not assumed away.

## 2.6 Optional hardening — Script-enforced token continuity (`OP_PUSH_TX` covenant)

**Problem.** The §2.3 template does **not**, by itself, force a spender to reproduce the
identity data in the next output. In Stage 1, continuity (that `Tx_swap` out 0 really
carries the same `TokenId`/payload hash) is **verified by the wallet and an indexer reading
the chain** — convention-enforced, not Script-enforced. A non-cooperating spender could, in
principle, spend the token UTXO to a plain output and "strip" the token. Stage 1 detects
this (the token simply ceases to exist as a valid token in the vault's view) but does not
**prevent** it in Script.

**Hardening.** Make continuity Script-enforced with an **`OP_PUSH_TX` covenant** — a plain
BSV Script technique (sighash-preimage introspection via `OP_CHECKSIG` against a chosen
key), used by this project's `Fair_Play_Transactions` / `strict_provable_fairness` /
shuffle constructions. It requires no `OP_RETURN`; BSVM and Rúnar are **expressly allowed**
but are not required for this particular covenant. The token's
locking script additionally:

```
; (sketch — full opcode annotation required in code)
; 1. Push the sighash preimage in the unlocking script (OP_PUSH_TX pattern).
; 2. Verify the preimage corresponds to the spending transaction (OP_CHECKSIG technique).
; 3. Reconstruct the expected next token output script: the same push-drop identity prefix
;    (TokenId, payloadDescriptor, H(payload)) followed by a P2PKH gate to the new owner.
; 4. Verify the spending transaction's hashOutputs commits to that reconstructed output,
;    i.e. out 0 of the spend MUST be a token output with identical identity data.
;    Abort otherwise.
```

This binds every spend to producing a valid successor token output with **unchanged**
identity — the NFT cannot be stripped or have its identity mutated on transfer.

**Decision (OD-3, `docs/07`).** Stage 1 default: **convention-enforced** continuity
(simpler, meets the Stage 1 plumbing goal) with this covenant **specified and ready**.
Recommendation: pull the covenant into Stage 1 only if the owner wants the prototype to be
robust against a hostile spender at the Script level; otherwise it lands with the Stage 2
hardening. Either way it is plain Script and `OP_RETURN`-free.

## 2.7 Optional escrow-template variant (for richer negotiation)

The single `Tx_swap` is the minimal atomic path and the Stage 1 default. For workflows
where the parties want collateralised commitment during negotiation, the project's
`Fair_Play_Transactions` pattern composes here: fund a **2-of-2 multisig** of (Alice, Bob)
with a **pre-signed settlement template** and a **timeout-redirection path (Path T)** after
Δ blocks. This is recorded as OD-7. It is **not** required for Stage 1 and adds an on-chain
funding step; the single co-signed `Tx_swap` already gives atomicity without locking funds
up front.

## 2.8 Fees and dust — named constants (no magic numbers)

- `DUST_SATS` — the token output value. Source: BSV node policy (`TODO(verify)` §2.1).
- `FEE_RATE` — sat/byte for BSV. Source: a single fee-policy module; `TODO(verify)` against
  current BSV fee expectations at implementation time. BSV fee economics differ from BTC;
  do not import a BTC fee assumption.
- Fee is computed from the actual serialised transaction size, not estimated by a fixed
  constant, and is shown in the signing prompt.

## 2.9 Invariants (test these — `docs/05`)

- **I-NFT-1 (no `OP_RETURN`).** No script in any constructed transaction contains `0x6a`.
- **I-NFT-2 (identity preserved).** For any accepted transfer, out 0 reproduces `TokenId`,
  `payloadDescriptor`, and `H(payload)` byte-for-byte. (Script-enforced if OD-3 covenant is
  in; otherwise verified by the vault/indexer and asserted in tests.)
- **I-NFT-3 (single token).** Exactly one live UTXO carries a given `TokenId` at any tip;
  any conflicting spend resolves to one survivor (`docs/03`).
- **I-NFT-4 (atomic value).** No accepted-state exists where Bob's payment was taken but
  the token did not move to Bob, or vice versa. (Holds by single-transaction construction.)
- **I-NFT-5 (BSV-only).** Address encoding, params, and SDK calls are BSV; CI gate
  `bsv-only` passes.
