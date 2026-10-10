# AdhKey — audit re-run after C1–C7 hardening

> **R-1 CLAIM SCOPE (2026-10-10, rigor-audit rollout).** Every "FIXED" verdict
> below is `class_scope: instance-only`. The negative tests replay the exact
> payload each finding was written against; no dedicated red-team re-attack
> wave has signed off the class since 2026-10-07. A FIXED claim here is a
> regression guard for the finding's own instance, not class closure.
> **One-book rule:** this document is the claim log AND the defeat log. Any
> future bypass of a FIXED claim below MUST be mirrored here as
> `SUPERSEDED-BY-BYPASS` against the original claim (with the defeating
> evidence linked) — never filed only in a separate register.
> **R-9 frozen vocabulary:** claim verdicts use only `FIXED | OPEN | PARTIAL |
> OBSERVED | SUPERSEDED-BY-BYPASS`. No prose statuses.

**Date:** 2026-10-07. **Scope:** same as AUDIT.md (`adhkey-core`,
`adhkey-crypto`, `adhkey-store`) plus new `envelopes.rs`.
**Method:** re-ran every critical finding against the new code; negative
tests per finding; dual-model adversarial review (DeepSeek v4-pro +
NVIDIA gpt-oss-20b). **New files:** `crates/adhkey-core/src/envelopes.rs`,
`crates/adhkey-store/tests/hardening.rs`.

**Test totals:** 144 passed, 0 failed across the workspace
(adhkey-core 58, adhkey-statement 23, adhkey-store 6 hardening,
luci-verdict-core 15+17, luci-context 8, muse-exchange 4+1+8+4).
Clippy: zero warnings in adhkey-core, adhkey-crypto, adhkey-store
(pre-existing warnings in untouched crates left alone).

## Adversarial review (dual model backends)

- **DeepSeek v4-pro** attacked `verify_capability` + `recover` with
  complete function bodies. Walked check ordering, first-error masking,
  nonce consume-on-success, expiry boundaries, purpose confusion, and
  threshold counting. Found no acceptance bypass. Open question it
  raised — "does `recovery_intent_bytes` bind the nonce?" — answered:
  yes, nonce is in the signed bytes (verified in source).
- **NVIDIA nemotron-3-ultra-550b** attacked `NonceStore`,
  `establish`, `refound_key`, `verify_chain`. Verified the prune
  horizon math correct (never drops a live bucket; conservative keep
  direction), `NonceStoreFull` fail-closed without recording, and no
  underflow (saturating_sub). Raised one genuine design point before
  hitting token limit: **`now` is caller-influenced if the host takes
  it from the request** — attacker-controlled `now` would steer bucket
  assignment and pruning. Mitigated the same session: documented
  `VerifierContext::now` and `NonceStore::check_and_insert` as
  HOST-CLOCK-ONLY, never from caller input.
- Neither model found a soundness hole. Both reviews are recorded
  here, not as proof — the negative tests are the proof.

## Per-finding verdicts

### C1. Signatures are not verified — FIXED
- `VerifierContext.signature_valid: bool` DELETED. The field cannot be
  re-added without changing the type signature (compile-time kill).
- `verify_capability` now takes `SignedCapability { capability, signature }`,
  canonicalizes the envelope itself (`ADHKEY/1/CAPABILITY` domain), looks
  up the key id in its OWN key table, and calls
  `KeyOperator::verify` — the caller supplies the mechanism, the core
  supplies every input.
- `KeyStore` trait gained `verify` (fail-closed contract documented).
- Negative tests: `court_c1_forged_signature_rejected`,
  `court_c1_tampered_envelope_rejected`, `court_c1_key_substitution_rejected`,
  `court_c1_no_injectable_bool`, `hardening_c1_adapter_verify_called`,
  `hardening_c1_generated_keys_end_to_end`. **PASS.**

### C2. Recovery approvals are key IDs, not signatures — FIXED
- `recover` now takes `&[SignedApproval]`; each approval's Ed25519
  signature is verified over canonical `ADHKEY/1/RECOVERY` intent bytes
  bound to (identity, old_key, new_key, nonce, policy_version).
- Ceremony binding enforced: wrong identity / wrong (old,new) pair rejected.
- Approval nonces consumed in a `NonceStore`: one approval, one ceremony.
  A retried recovery is a new ceremony with fresh nonces (documented).
- Negative tests: `court_c2_bare_key_ids_are_not_approvals`,
  `court_c2_approval_for_wrong_ceremony_rejected`,
  `court_c2_approval_nonce_replay_rejected`,
  `court_c2_non_policy_signer_rejected`,
  `hardening_c2_c6_recovery_and_refound_generated`. **PASS.**

### C3. `establish()` takes a bare bool — FIXED
- Signature is now `establish(claim, verdict: &SignedPolicyVerdict,
  keys, now, max_verdict_age_secs) -> Result<EpistemicState, Error>`.
  No bool parameter exists.
- Verdict verified: (1) evaluator in `claim.policy_authorities`,
  (2) signature over `ADHKEY/1/POLICY-VERDICT` bytes, (3) `claim_hash`
  binds this exact claim, (4) `evidence_snapshot` binds the current
  evidence set, (5) `evaluated_at` fresh. Decision is ternary
  (Allow/Deny/Unknown), not a bit.
- Negative tests: `court_c3_forged_verdict_rejected`,
  `court_c3_unauthorized_evaluator_rejected`,
  `court_c3_verdict_for_other_claim_rejected`,
  `court_c3_stale_evidence_kills_verdict`,
  `court_c3_stale_verdict_rejected`, `hardening_c3_verdict_generated_keys`.
  **PASS.**

### C4. `Conflict` is dead — FIXED
- `evaluate_claim` now detects real contradictions: two LIVE evidence
  items with the same evidence id but different artifact digests
  → `EpistemicState::Conflict`. Reachable, tested, and sticky:
  a signed Allow verdict cannot promote a conflicted claim.
- Negative tests: `court_c4_conflict_is_reachable`,
  `court_c4_same_digest_is_not_conflict`. **PASS.**

### C5. Replay protection is RAM-only — FIXED
- New `NonceStore`: time-partitioned buckets, per-bucket cap,
  `NonceStoreFull` fails closed (nonce NOT recorded, verification does
  NOT proceed). `snapshot()`/`restore()` give the host a persistence
  story (core does no I/O by design); stale buckets pruned on restore.
  Window-sizing requirement documented on the type.
- Verifier uses `NonceStore`, not `&mut BTreeSet<String>`.
- Negative tests: `court_c5_replay_within_window_rejected`,
  `court_c5_expiry_releases_nonce`, `court_c5_bounded_bucket_fails_closed`,
  `court_c5_snapshot_restore_survives_restart`,
  `hardening_c5_nonce_survives_restart_via_file`. **PASS.**

### C6. Lost → Active requires no re-verification — FIXED
- `transition_key` REJECTS Lost→Active unconditionally
  (`Error::ProofOfPossessionRequired`).
- New `refound_key`: requires `SignedPossessionProof` — Ed25519 over
  `ADHKEY/1/POSSESSION` (key, challenge, issued_at), with
  `issued_at <= now` and `now - issued_at <= max_challenge_age_secs`.
- Negative tests: `court_c6_lost_to_active_rejected_without_proof`,
  `court_c6_refound_with_fresh_proof`,
  `court_c6_refound_forged_proof_rejected`,
  `court_c6_refound_stale_challenge_rejected`. **PASS.**

### C7. Receipts are not tamper-evident — FIXED
- Old forgeable `Receipt` struct deleted. Receipts of record are
  `SealedReceipt`: body + `prev_hash` chain + service-key Ed25519 over
  `ADHKEY/1/RECEIPT` canonical bytes. `ReceiptBody` alone is not a
  receipt of record.
- `ReceiptLog::verify_chain` re-checks every signature and link;
  tampering, deletion, forged seals, and tombstones (empty signature
  from sealer failure) all → `ReceiptChainBroken`.
- Bodies carry `not_checked: Vec<String>` (AUDIT2 #15 honesty).
- Negative tests: `court_c7_receipt_chain_verifies`,
  `court_c7_tampered_receipt_breaks_chain`,
  `court_c7_removed_receipt_breaks_chain`,
  `court_c7_forged_seal_rejected`, `court_c7_tombstone_never_valid`,
  `hardening_c7_chained_receipts_across_verifications`. **PASS.**

## Residual risks (not holes — documented, not fixed)

1. **Lying operator.** A malicious `KeyOperator` implementation can make
   anything verify. Out of scope by design (like a lying HSM); the
   protocol guarantees only that no CALLER input can forge verification.
2. **`policy_version` bound but unenforced.** `RecoveryIntent` and
   `SignedPolicyVerdict` bind `policy_version` into signed bytes, but
   nothing compares it against a live policy registry — there is no
   registry yet. Prevents cross-version replay only once a registry
   enforces it.
3. **Nonce window sizing is the host's job.** `NonceStore` documents that
   `window_secs` must exceed max capability lifetime; a misconfigured
   host reopens a replay window for long-lived capabilities.
4. **Receipt-signer key management.** The seal is only as good as the
   service key's custody. No rotation story yet.
5. **Single suite (Ed25519).** No agility; documented in `not_checked`.
6. **AUDIT2 ontology cuts** (#1–#22: Statement primitive as the core,
   identity-as-derived, etc.) are a REDESIGN, not this hardening pass.
   This pass hardened the 0.1 abstraction per the task order; the
   `adhkey-statement` crate already prototypes the 0.2 direction.

## Bottom line

All 7 criticals are fixed with real implementations — no stubs, no
placeholders, no injected booleans. Every fix has negative tests that
fail against the old behavior. The three most security-critical paths
(signature verification, recovery authorization, policy input) are now
driven by the core through an explicit, auditable mechanism boundary.
