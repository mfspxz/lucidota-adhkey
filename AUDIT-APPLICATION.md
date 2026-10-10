# AUDIT-APPLICATION — adhkey

**Slice:** brutal-audit rollout 3/8. **Date:** 2026-10-10. **Repo:** ~/workspace/adhkey.
**Audited at:** `a5004a8` (flailer P3). **This pass:** TBD (filled after commit).

## What this is

Rust workspace: capability verifier + court (`adhkey-core`), `KeyStore` trait
(`adhkey-store`), encrypted knowledge vault with challenges/governor/guardians/
policy/receipts/rotation/Shamir (`adhkey-flailer` P3), statement prototype,
ternary verdict core, context receipts, exchange. Two audit generations exist:
AUDIT.md (2026-10-06, verdict NOT PRODUCTION) and AUDIT-FIXES-2026-10-07.md
(C1–C7 fix-verification).

## Per-finding application

- **R-1 (instance-only fix claims, one book):** APPLIED. Claim-scope preamble
  added to AUDIT-FIXES-2026-10-07.md: every FIXED verdict is `class_scope:
  instance-only` (negative tests replay each finding's exact payload; no
  dedicated red-team re-attack wave since 2026-10-07). One-book rule declared:
  future bypasses are mirrored in the same document as SUPERSEDED-BY-BYPASS.
- **R-2 (honest guardrail bounds):** APPLIED (was already strong). AUDIT-FIXES
  "Residual risks (not holes — documented, not fixed)" 1–6; FLAILER-CRYPTO-AUDIT
  §8 marks itself "machine review — NOT an independent human review";
  `KeyStore::verify` carries a fail-closed contract (pure-signer HSM must
  return `NotSupported`, never `Ok(true)`).
- **R-3 (out-of-band head copy):** N/A. No persistent hash-chained production
  log in-repo (ReceiptLog chains are per-session in-memory; AUDIT.md /
  AUDIT-FIXES are prose claim logs, not hash chains).
- **R-4 (backlog triage):** APPLIED. New TRIAGE-2026-10-10.md — see Wont-fix
  list. Closed this pass: FLAILER-CRYPTO-AUDIT D1 (unsalted SHA256 answer
  commitments) FIXED by P3 — `commitments.rs` `AnswerCommit { salt: [u8;16],
  hash }`, fresh 128-bit salt, Argon2id (measured in source 2026-10-10); D2
  (no Shamir) FIXED by P3 — `secret_sharing.rs` `split_root` + `recover_root`,
  rotation tests reconstruct the same root; challenge determinism FIXED
  (CSPRNG shuffle + stratified sampling).
- **R-5 (signature games):** N/A. No denylist/strip security games (the
  `strip_prefix` hits in source are encoding-prefix and CLI-arg parsing, not
  content filtering).
- **R-6 (detector + consumer + gate):** N/A as a gap. No warn-only detectors:
  `NonceStoreFull` fails closed (nonce NOT recorded, verification does NOT
  proceed), tombstone receipts never valid, conflict state is sticky (a signed
  Allow cannot promote a conflicted claim).
- **R-7 (property vs change-detection):** APPLIED. The three flailer suites
  (`crypto_properties.rs`, `governor_properties.rs`, `rotation_properties.rs`)
  labeled PROPERTY in their headers; policy embedded (expectations never
  rewritten to match a behavior change without adversarial sign-off).
- **R-8 (unsigned provenance):** APPLIED (verified, not changed). C7
  `SealedReceipt` is signed — Ed25519 over `ADHKEY/1/RECEIPT` canonical bytes,
  `prev_hash` chain, `ReceiptLog::verify_chain` re-checks every signature and
  link; tampered / removed / forged-seal / tombstone all fail. Challenge
  commitments are salted Argon2id. Receipt-signer key custody remains queued
  (residual #4).
- **R-9 (frozen claim schema):** APPLIED. Frozen vocabulary declared in the
  AUDIT-FIXES preamble: `FIXED | OPEN | PARTIAL | OBSERVED |
  SUPERSEDED-BY-BYPASS`. No prose statuses.
- **R-10 (record-keeping in the same motion):** APPLIED. TRIAGE-2026-10-10.md
  + AUDIT-FIXES preamble written in this motion; D1/D2 closures recorded with
  source evidence.
- **R-11:** explicit UNKNOWN list below.
- **R-12 (no unsourced footnotes):** APPLIED. None found; FLAILER-CRYPTO-AUDIT
  §8 is explicitly honest about being a machine review.

## Commits

This pass (`TBD`): AUDIT-FIXES-2026-10-07.md (preamble),
TRIAGE-2026-10-10.md (new),
crates/adhkey-flailer/tests/{crypto,governor,rotation}_properties.rs
(headers), this file. Doc-only.

## Test results

NOT re-run this pass (doc-only changes; 5.3G workspace, full run heavy).
Last measured: **144 passed, 0 failed** across the workspace at AUDIT-FIXES
time (2026-10-07) — label as not re-run, not current.

## Wont-fix list (R-4)

| Item | Decision | Budget |
|---|---|---|
| AUDIT2-ONTOLOGY #1–#22 (Statement-primitive redesign) | WON'T FIX on the 0.1 line; redesign lives in `adhkey-statement` | 0 further hardening waves on 0.1 |
| KILLLIST-STATEMENT targets | DEFERRED — Zack's standing order: "DO NOT HARDEN YET; harden only after independent convergence" (freeze, not neglect) | 0 until all four attackers converge |
| Residual #1 (lying operator) | Carried as documented bound | 0 |
| Residual #3 (nonce window sizing is the host's job) | Carried as documented bound | 0 |
| Residual #5 (single Ed25519 suite) | Carried, declared in `not_checked` | 0 until 0.2 protocol design |
| Residual #2 (policy_version bound but unenforced — no registry) | QUEUED | 1 design lane when a registry exists |
| Residual #4 (receipt-signer key custody, no rotation story) | QUEUED | 1 design lane before any production claim |

## Explicit UNKNOWN list (R-11)

1. Whether any red-team wave will re-attack C1–C7 — none scheduled; FIXED
   claims stay instance-only.
2. Receipt-signer key custody and rotation — no design exists.
3. Policy registry — does not exist; `policy_version` bound but unenforced.
4. KILLLIST convergence — round-2 converged on kill-target #1 only; the
   criterion needs all four attackers.
5. AUDIT.md's verdict NOT PRODUCTION stands.

## Top critical issues

1. **Receipt-signer key custody gap** (residual #4) — the C7 seal is only as
   good as the service key's custody; no custody or rotation story exists.
2. **Policy registry gap** (residual #2) — `policy_version` is bound into
   signed bytes but nothing enforces it against a live registry.
3. **No re-attack scheduled** — C1–C7 FIXED claims are instance-only until a
   dedicated red-team wave signs off the class; none has run since 2026-10-07.
4. **NOT PRODUCTION** — AUDIT.md's verdict stands; the queued items (#2, #4)
   are production blockers.
