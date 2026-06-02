# CLAUDE.md — Operating Rules for the Implementer

You are implementing the system specified in `docs/`. Read this file before writing any
code. These rules are gates, not guidance. A violation of any §1–§4 rule is a defect that
must stop the build, not a stylistic preference.

This repository's specification contains **no application source code**. You write it.
Script templates and transaction layouts in `docs/` are **protocol design artifacts**
(the architecture of the on-chain objects), not application source; you implement them
through the BSV SDK.

---

## 1. BSV only. Never BTC.

- Target chain is **Bitcoin SV**. BSV and BTC do not share a codebase in this project.
- Use **BSV** network parameters, **BSV** address/encoding rules, the **BSV TypeScript
  SDK** (client) and **BSV Go SDK** (services). Do not import, vendor, or copy any BTC
  library (no `bitcoinjs-lib`, no `btcd`, no `rust-bitcoin`, etc.).
- Do not carry over BTC assumptions: not the 1 MB / Taproot / SegWit model, not BTC
  fee markets, not BTC standardness rules, not BTC's RBF, not BTC's `OP_RETURN`
  unspendability semantics.
- **CI gate `bsv-only`:** dependency allowlist. Build fails if any non-BSV chain library
  is present in the dependency graph. Network-parameter constants must come from a single
  BSV params module; a grep gate fails on hard-coded BTC magic bytes, BTC bech32 HRP
  (`bc`), or BTC default ports.

If a `docs/` instruction and a BTC habit ever conflict, the habit is wrong. If a `docs/`
instruction is itself BTC-contaminated, **stop and raise it** — do not implement it.

## 2. `OP_RETURN` is banned. Absolutely.

- No `OP_RETURN` (`0x6a`) in any locking script or any unlocking script, in any
  transaction this software constructs, signs, or broadcasts. There is no "limited use."
- Carry data only by: **(A)** push-data-with-drop prefix inside a locking script
  (`<data> OP_DROP <conditions>`), or **(B)** a push inside an unlocking script that the
  script consumes. See `docs/02` §3. These are plain BSV Script techniques.
- **CI gate `no-op-return`:** a script scanner parses every locking and unlocking script
  the codebase can emit (templates and any dynamically assembled scripts in tests) and
  fails if opcode `0x6a` appears anywhere. The transaction builder must be structurally
  incapable of appending `OP_RETURN`; the builder API must not expose an `OP_RETURN`
  primitive at all.

## 3. BSVM and Rúnar are available primitives. The only hard exclusion is `OP_RETURN`.

- **BSVM and Rúnar are available and MAY be used** anywhere in this project where they
  improve the design. They are **not** excluded. (This corrects a prior version of this
  file that wrongly prohibited them.)
- The academic papers in this project (`bsvpoker_*`, `bsvm_*`) use BSVM and Rúnar-compiled
  covenants; their constructions are fair game to draw on — **with one exception**: any
  `OP_RETURN`-based data-carriage or commitment is banned (§2) and must be replaced with a
  non-`OP_RETURN` construction. The exclusion is `OP_RETURN`, not BSVM or Rúnar.
- **TEE / the "T"-element is an open decision, not a prohibition.** The Stage 1 design as
  written does not *require* a device TEE: its working baseline is honest-host execution
  (HH-1) plus software key custody (OS keystore / DPAPI), and those stand-ins are labelled
  as such everywhere they appear (`docs/04` §4.6). Whether and when a TEE is introduced —
  and whether "T" even means TEE — is **OD-1** (`docs/07`). Do not assume TEE in or out;
  build to the HH-1 baseline and treat TEE as the open decision it is.

## 4. No hidden assumptions. No overclaiming.

- Every assumption lives in `docs/07` and is classified. If you introduce one while
  implementing, add it to `docs/07` in the same change. An undocumented assumption is a
  defect.
- Do not let any artifact (code comment, UI string, log line, README) claim a property
  the system does not structurally provide. In particular:
  - Stage 1 deletion is a **cooperative attestation**, never "verifiable deletion."
  - Stage 1 token continuity is **convention-enforced** unless the `docs/02` §6 covenant
    is implemented; do not describe it as tamper-proof when it is not.
  - The swap is atomic with respect to **on-chain control + payload copy delivery**, not
    with respect to payload *exclusivity* (Alice may retain a copy in Stage 1).
- Prefer "I don't know / needs verification" markers (`TODO(verify): …`) over plausible
  invention. A `TODO(verify)` must name what to check and against which source.

## 5. Test-first, and the gates run on every commit.

- Implement against `docs/05`. The happy path and **every** abort/fault scenario in the
  scenario matrix must have an automated test before a workstream is "done."
- The four CI gates — `no-op-return`, `bsv-only`, `lint/format`, `spec-traceability` —
  run on every commit and block merge on failure.
- Determinism: anything that must be reproducible (serialisation, hashing, key
  derivation, fee computation) is covered by test vectors. No floating point in money
  arithmetic; satoshis are integers.

## 6. Documentation standard (the "commented beyond belief" requirement).

This project's owner requires documentation a mission-critical reviewer would call
over-engineered. Apply all of the following. CI gate `spec-traceability` checks the
header and reference rules mechanically; the rest is enforced in review.

- **Every module** opens with a header block: purpose; the invariants it guarantees; the
  BSV-specific notes a reader must know; an explicit "MUST NOT" list (no `OP_RETURN`, no
  BTC); and the `docs/` section it implements.
- **Every exported function/type** documents its contract: preconditions, postconditions,
  every error mode by name, and a "why," not only a "what."
- **Every script template** is annotated **opcode by opcode** — each opcode line states
  what it does and what it enforces. A reader who does not know Script must be able to
  follow it.
- **Every transaction builder** carries a comment block showing the exact input/output
  layout (index by index), the value flow, and the SIGHASH-flag rationale for each input.
- **No magic numbers.** Dust threshold, fee rate, timeouts, the abandon window Δ,
  retry/backoff — all are named constants with a documented source and units.
- **Spec traceability:** every code unit references the `docs/` section it implements;
  every `docs/` normative requirement is implemented by a referenced unit. The gate fails
  on an orphan in either direction.

## 7. What to build, in order

Follow `docs/06`. Summary: **Pre-flight first — resolve OD-4/OD-2 and stand up the BSV
regtest node** — then CI gates and repo skeleton (so §1–§2 are enforced from commit 1) and
the regtest control interface, then chain adapter, wallet core, token module, secure channel,
exchange
protocol engine, deletion module, Windows app shell, then the full test harness.

## 8. When to stop and ask

Stop and surface a question (do not guess) when:

- A `docs/` instruction appears BTC-contaminated or requires `OP_RETURN`.
- An `open decision` in `docs/07` blocks the unit you are about to write.
- A BSV node RPC, ARC endpoint, or SDK API named in `docs/` does not match the installed
  version. Mark `TODO(verify)`, do not invent a method signature.
