# 04 — Deletion and Trust Model

This document is deliberately blunt about what can and cannot be guaranteed. The owner's
standard is that overclaiming is a defect. Nothing here is softened.

## 4.1 The deletion problem, stated plainly

The goal is: after Bob buys the NFT, **Alice should no longer have it**. "Have it" splits
into two distinct things:

1. **On-chain control of the token.** After `Tx_swap` confirms, the token UTXO is spent;
   Bob's key controls the successor output. Alice cannot spend it again. **This is
   verifiable** — anyone can check `outputStatus(tokenOutpoint) == spentBy(swapTxid)` and
   that out 0 is now under Bob's key. The transfer of control is real and provable.

2. **Possession of the payload.** Alice held the payload file. After the sale she should
   not be able to use it. **This cannot be remotely verified or enforced in Stage 1.** A
   party in physical possession of bytes can copy them before any "delete." No software
   running on Alice's own machine can prove to Bob that Alice wiped her copy, because Alice
   controls that machine. This is a fundamental limitation, not an implementation gap.

**Therefore Stage 1 does not provide "verifiable deletion."** It provides:

- verifiable **transfer of control** (point 1), plus
- a **cooperative deletion attestation** (point 2) — defined next.

Do not let any code comment, UI string, log, or doc describe Stage 1 as offering
"verifiable deletion." That phrasing is reserved for the Stage 2 / T-stage mechanisms in
§4.5–§4.6, which actually earn it.

## 4.2 Cooperative Deletion Attestation (CDA) — what Stage 1 ships

After `CONFIRMED`, Alice deletes her local payload copy and emits:

```
CDA = { tokenId, tokenOutpoint, swapTxid, H(payload), timestamp, statement="deleted" }
sigCDA = Sign_Alice( H(CDA) )
```

- Bob stores `(CDA, sigCDA)` in his transcript.
- **What it is:** a cryptographically signed, non-repudiable **claim** by Alice that she
  deleted her copy, bound to the specific token and the specific on-chain swap.
- **What it is not:** evidence that the bytes are gone. Alice can sign this and keep a copy.
  The CDA binds Alice's **reputation and identity** to the statement; it does not bind her
  disk.
- **Useful properties anyway:** it creates an auditable record; in a repeated-interaction
  or reputation context (cf. `Fair_Play_Transactions` repeated-game discussion), a false
  attestation is detectable and attributable if a retained copy ever surfaces.

The CDA structure is **forward-compatible**: in Stage 2 the same message additionally
references the destroyed/rotated key (§4.5); in the T-stage it additionally carries the
enclave attestation (§4.6). The wire/format does not change shape, only its evidentiary
weight grows.

## 4.3 Trust register (Stage 1)

| ID | Assumption / trust | Who must be trusted | Consequence if violated | Removed by |
|---|---|---|---|---|
| HH-1 | **Honest host execution** — each instance runs the protocol as specified and does not exfiltrate its own keys. This is the explicit Stage 1 stand-in for the TEE. | the local host of each party (for its own behaviour) | a malicious host can leak its own keys / retain payload | T-stage (TEE attestation) |
| SC-1 | Software key custody (OS keystore / DPAPI) protects keys at rest | the OS keystore | key theft if host compromised | T-stage (enclave custody) |
| PL-1 | Payload confidentiality is **not** assured (placeholder encryption) | nobody — explicitly not provided | seller retains usable payload | Stage 2 (real encryption + crypto-shred) |
| CN-1 | Token continuity is convention-enforced unless OD-3 covenant is built | the wallet/indexer view | hostile spender could strip the token (detected, not prevented) | OD-3 covenant (`docs/02` §2.6) |
| NET-1 | Transport may be hostile; integrity rests on per-message signatures, not the relay | nobody (relay untrusted) | DoS/delay possible; no forgery | — (already minimal) |
| CH-1 | BSV network is the settlement authority; SPV used to verify | BSV proof-of-work / SPV proofs | a deep reorg can regress a confirmed swap (surfaced, not hidden) | higher `CONF_DEPTH` |

HH-1 is the **load-bearing** Stage 1 assumption. Everything that makes Stage 1 fall short
of a true "sell-and-the-seller-loses-access" guarantee traces back to HH-1 + PL-1. They are
removed, in order, by Stage 2 (PL-1) and the T-stage (HH-1).

## 4.4 Threat model (Stage 1, with honest outcomes)

| Threat | Stage 1 outcome |
|---|---|
| Buyer pays, seller never delivers payload | Buyer verifies `H(payload)` **before** signing; if no valid payload, buyer does not sign; no payment occurs. **Safe.** |
| Seller delivers wrong file | Hash mismatch → `ABORTED(HASH_MISMATCH)`; no payment. **Safe.** |
| Seller co-signs then double-spends the token elsewhere | Network confirms at most one; swap → `FAILED(DOUBLE_SPENT)`; buyer's payment was an input to the losing tx, never taken. **Safe (no loss).** |
| Buyer co-signs then stalls / seller stalls | No fund loss (SIGHASH_ALL); trade fails after Δ. **Safe (liveness only).** |
| Relay drops/reorders/replays messages | Signatures + `seq` reject forgery/replay; timeouts handle drops. **Safe (DoS possible).** |
| **Seller retains a usable payload copy** | **Not prevented in Stage 1.** PL-1. Mitigated only by CDA (a claim). **Stated limitation.** |
| Hostile spender strips token identity on a non-swap spend | Detected (token leaves the vault's valid set); **prevented only with OD-3 covenant.** |
| Malicious host leaks its own keys | Out of Stage 1 scope; HH-1. Addressed by T-stage. |

## 4.5 Stage 2 hook — crypto-shredding (makes deletion meaningful)

In Stage 2 the payload is encrypted under a key `K_payload`, and the on-chain
`payloadDescriptor.encScheme` records the real scheme. "Deletion" then becomes
**crypto-shredding**: destroy or rotate `K_payload` so that any ciphertext Alice retains is
**useless**. The mechanism slots into the existing rails:

- Bind `K_payload` (or the means to derive it) to the transfer so that, post-swap, **Bob**
  can decrypt and **Alice** can no longer obtain `K_payload`. Candidate constructions to
  evaluate in Stage 2 (do not pick one here): a single-use ECDH-derived content key tied to
  the swap (cf. the project's single-use ECDH reveal-token mechanism), key surrender bound
  to the swap signature, or re-encryption to Bob's key as part of delivery.
- The CDA (§4.2) then additionally references the destroyed/rotated key, and the claim
  "deleted" upgrades to "the seller can no longer access the plaintext," which **is**
  verifiable to the extent the key-control transfer is on-chain-evidenced.

This is why Stage 1 builds the binding (`H(payload)` in the token) and the CDA shape now:
Stage 2 strengthens them without redesign.

## 4.6 T-stage hook — the TEE ("T") slot

"T" is read as a **Trusted Execution Environment** (Secure Enclave / TrustZone), matching
this project's papers, which root the player layer in device TEEs. In the T-stage:

- Keys are generated and held **inside the enclave**; `sk` never leaves it. SC-1 and the
  key-exfiltration part of HH-1 are removed.
- The enclave can **attest** that it zeroized the plaintext payload after the sale —
  turning point 2 (§4.1) into a **hardware-attested wipe**. The CDA then carries the
  attestation, and "verifiable deletion" becomes defensible **at last**.
- UI hardening (e.g. OS-level screen-capture prevention, as in the project's
  `FLAG_SECURE`/`UIScreen.isCaptured` usage) complements the enclave.

**Open decision OD-1 (`docs/07`):** confirm that "T" means TEE. If the owner instead means
a **TTP** (the Option-A 2-of-3 arbitration in `Fair_Play_Transactions`), then this section
is replaced: the trusted element becomes a dispute arbiter engaged only on dispute, the CDA
is replaced/augmented by arbiter adjudication on retained-copy disputes, and HH-1's removal
path changes accordingly. The Stage 1 build is unaffected either way because Stage 1 only
*assumes the equivalent property* and defines the slot.

## 4.7 Summary — the one-paragraph honest claim

Stage 1 provides a **verifiable, atomic transfer of on-chain token control** in exchange
for BSV, with the payload **hash-bound** to the token so the buyer cannot be made to pay
for the wrong thing, plus a **signed cooperative deletion attestation** from the seller.
Stage 1 **does not** provide payload confidentiality, does not prevent the seller from
retaining a copy, and does not verify physical deletion; those require Stage 2
(crypto-shredding) and the T-stage (TEE-attested wipe), whose integration points are
defined here.
