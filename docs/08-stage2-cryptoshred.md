# 08 — Stage 2: real encryption + crypto-shredding + Script-enforced continuity

Stage 1 built the rails (`docs/00`–`docs/07`): a verifiable atomic transfer of token
control, payload hash-bound to the token, and a cooperative deletion **attestation**. Stage 1
deliberately did **not** provide payload confidentiality (PL-1) or Script-enforced continuity
(CN-1). Stage 2 delivers both, on the existing rails, without redesign (`docs/04` §4.5,
`docs/02` §6). The owner's honesty standard from `CLAUDE.md` §4 applies unchanged: this
document is blunt about exactly which guarantee each option does and does not provide.

## 8.1 Scope

- **Real payload encryption.** The payload is encrypted under a content key `K`
  (AES-256-GCM). `payloadDescriptor.encScheme` records the real scheme; `H(payload)` binds
  the **ciphertext**. The binding mechanism is unchanged from Stage 1 — only the bytes hashed
  change (`docs/02` §2.2).
- **Crypto-shredding as a pluggable, selectable CHOICE.** "Deletion" becomes destroying or
  rotating `K` so that a retained ciphertext is useless. *How* `K` is bound to the swap is a
  per-exchange choice among several schemes (§8.3) — the owner asked for all of them as
  options, plus a TEE option, secure and robust.
- **Script-enforced token continuity** via the `OP_PUSH_TX` covenant (OD-3, `docs/02` §6):
  a spend MUST reproduce the token identity in out 0, so the NFT cannot be stripped.

## 8.2 Real encryption (the encScheme upgrade)

`Enc(K, payload) -> ciphertext` is AES-256-GCM with a random 96-bit nonce. `K` is a fresh
256-bit content key per token. The token commits to `H(ciphertext)`. Bob, once he holds `K`
(via the chosen scheme, §8.3), decrypts and verifies `H` before settlement — exactly the
Stage-1 buyer check, now over real ciphertext.

## 8.3 Crypto-shred schemes (pluggable; OD-S2-1)

A **Scheme** governs how `K` reaches Bob and how Alice loses it. All schemes below are
implemented and **selectable** per exchange. Each declares its **shred strength** honestly:

- **COOPERATIVE** — the retained ciphertext is useless *iff* Alice actually destroys her key
  material. Software on Alice's own host cannot force that (HH-1); the scheme makes key
  release **single-use and on-chain-evidenced**, so a later-surfacing retained key is
  detectable and attributable, but destruction is not enforced.
- **ENFORCED** — a Trusted Execution Environment attests that it released `K` to Bob and
  zeroized Alice's access. This removes the payload part of HH-1. It requires a real
  enclave; the software implementation here is a clearly-labelled **stand-in/mock** pending
  the T-stage (`docs/04` §4.6).

| Scheme | id | How K is conveyed / shredded | Strength |
|---|---|---|---|
| Single-use ECDH (**default**) | `ecdh-singleuse` | Alice generates a single-use ephemeral keypair `eph`; `KEK = KDF(ECDH(eph_priv, bobPub))`; `K` is wrapped under `KEK`. The binding material published with the swap is `eph_pub`. Bob recovers `KEK = KDF(ECDH(bobPriv, eph_pub))` and unwraps `K`. Alice shreds `eph_priv`, `K`, and the plaintext — she then holds only ciphertext + `eph_pub`, from which `K` is **not** recoverable (needs `eph_priv` or `bobPriv`). | COOPERATIVE |
| Key-surrender bound to the swap | `key-surrender` | `K` is wrapped under a secret `s` that is revealed/committed by the swap (Bob learns `s` from settlement). Ties release tightly to the on-chain event. | COOPERATIVE |
| Re-encryption to Bob | `reencrypt` | Alice re-encrypts the payload to Bob's key on delivery. Simplest; weakest "Alice can no longer access" property (she re-encrypted, so she held plaintext). | COOPERATIVE |
| TEE-attested ("cloud TEE") | `tee-attested` | `K` is generated/held inside a TEE/cloud-TEE that, on swap settlement, releases `K` to Bob and **zeroizes** Alice's access, emitting an attestation. The only scheme that **enforces** Alice's loss. | ENFORCED (real enclave) / stand-in here |
| Dealerless threshold custody | `threshold` | `K` is the 32-byte big-endian encoding of a **dealerless** `t`-of-`n` threshold secret over the secp256k1 order `N` (Shamir shares summed across independent contributors — no single party, not even Alice, holds `K` alone at generation). The swap delivers `t` shares to Bob, who **reconstructs** `K` (reconstruct-to-use) and decrypts. Alice shreds her shares + `K`. The reconstructed scalar is a *usable* secp256k1 key — this is dealerless threshold **key generation/sharing**, NOT interactive threshold ECDSA **signing** (a GG/FROST-class MtA protocol, deliberately not hand-rolled). | COOPERATIVE |

The default is `ecdh-singleuse` (the project's single-use ECDH reveal-token mechanism,
`docs/04` §4.5). The TEE scheme is the bridge to the T-stage (OD-1). The `threshold`
scheme distributes custody so that `t` honest custodians must collude to recover `K`
early — a higher bar, but still **cooperative**: it does not *prove* Alice destroyed her
copy.

## 8.4 Script-enforced continuity — the `OP_PUSH_TX` covenant (OD-3) — IMPLEMENTED

Per `docs/02` §6: the token locking script additionally introspects the spending
transaction (push the sighash preimage in the unlocking script; verify it commits to the
spend via the `OP_CHECKSIG` technique; reconstruct the expected next token output — same
push-drop identity prefix + a P2PKH gate to the new owner — and require the spend's
`hashOutputs` to commit to it). Plain BSV Script, **no `OP_RETURN`**. This makes continuity
Script-enforced: the NFT cannot be stripped or have its identity mutated on transfer (CN-1
upgrades from convention-enforced to Script-enforced).

**Status: built** (`internal/covenant`, OD-3 pulled into Stage 2). Construction details:

- **Preimage authentication (OP_PUSH_TX).** A fixed, public key `d` and nonce `k` make the
  forced signature computable in-script: for `z = Hash256(preimage)`, a valid signature
  under `d` is `(r, s)` with `r = (k·G).x` (constant) and `s = A·z + B mod n`,
  `A = k⁻¹`, `B = k⁻¹·r·d mod n`. The script computes `s`, assembles the DER signature
  with low-S normalisation and minimal-encoding (sign-byte) handling, appends the sighash
  flag, and runs `OP_CHECKSIG` against `d·G`. The engine re-derives the **actual** spend's
  sighash, so the check passes iff the pushed preimage is genuine.
- **Sighash binding.** `SIGHASH_SINGLE|FORKID` (0x43): `hashOutputs` commits to exactly the
  output at the token input's index (index 0), so the covenant constrains its own successor
  output and leaves payment/change outputs free.
- **Continuity check.** The spender supplies only the new owner's 20-byte PKH; the covenant
  reconstructs `out0 = value || varint(len) || <fixed identity prefix> || PKH || OP_EQUALVERIFY OP_CHECKSIG`
  (identity and value immutable), hashes it, and requires equality with the preimage's
  `hashOutputs`. The reconstructed prefix bytes are taken from the real carrier builder so
  the hash matches byte-for-byte.
- **Failure mode is liveness, not theft.** A defect in the in-script arithmetic can only make
  `OP_CHECKSIG` *fail* (reject a spend); it can never make it accept a forged preimage,
  because ECDSA will not validate a wrong-message signature against the engine-recomputed
  sighash. The strip/mutate guarantee is the byte-exact `hashOutputs` equality that runs
  only after a successful `OP_CHECKSIG`.
- **Verification.** Executed in the real BSV script interpreter: a faithful transfer is
  accepted; strip-to-P2PKH, TokenId/H(payload)/descriptor mutation, owner redirection,
  value inflation, preimage tampering, `hashOutputs` forgery, and wrong-sighash-type are all
  rejected; a 3000-iteration liveness sweep over varied identity/owner/sighash and the
  minimal-DER edge cases (leading-zero `s`, high-bit-after-strip `s`) all pass.

## 8.5 Invariants (test these)

- **I-CS-1 (ciphertext useless without K).** Decrypting the payload requires `K`; `K` is not
  recoverable from `(ciphertext, on-chain binding material)` alone — recovery needs Bob's
  key (post-swap) or Alice's pre-shred secret. After a cooperative shred that destroys
  Alice's secret, Alice cannot recover `K`.
- **I-CS-2 (access transfers).** Post-swap, Bob can always derive `K` and decrypt (liveness
  of the access transfer).
- **I-CS-3 (enforced shred is attested, not assumed).** The `tee-attested` scheme yields an
  attestation of zeroization; the cooperative schemes do **not** — and must never be
  described as if they do.
- **I-CS-4 (dealerless threshold sharing).** Under the `threshold` scheme, `K` is split
  into `n` dealerless shares such that any `t` reconstruct it and any `t-1` reveal nothing;
  Bob recovers `K` from exactly the `t` shares the swap delivers (no recipient key needed),
  and fewer than `t` shares cannot decrypt the payload.

## 8.6 Honest claim (the Stage-2 upgrade, bounded)

Under the **enforced** (`tee-attested`) scheme, the Stage-1 "deletion attested" claim
upgrades to **"the seller can no longer access the plaintext,"** attested by the enclave.
Under the **cooperative** schemes it upgrades only to **"the retained ciphertext is useless
*if* the seller destroyed the single-use key"** — auditable, single-use, but not enforced.
No artifact may describe a cooperative scheme as enforced deletion (`CLAUDE.md` §4).
