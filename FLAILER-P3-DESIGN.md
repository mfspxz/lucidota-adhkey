# FLAILER P3 — Guardian Enrollment & Approval Machinery

**Scope:** the code and ceremony for enrolling guardians, issuing approvals, rotating epochs. **Out of scope:** enrolling Zack's actual humans (his action — needs names, channels, and his direct participation).

## What gets built

### 1. `guardians.rs` extensions (enrollment)
- `enroll_guardian(guardian_id, verifying_key) -> EnrollmentReceipt` — records: guardian ID, share index, pubkey fingerprint, policy version, timestamp. Signed by the owner's root authority key.
- `EnrollmentReceipt` verification: chain of receipts proves the enrolled set for an epoch.
- Drill mode: `dry_run_recovery()` walks a full recovery against test shares without touching real credentials — required before a set is declared active (RFC §3.1).

### 2. Epoch rotation (`rotation.rs`, new module)
- `rotate_epoch(set, new_guardians) -> (new_shares, tombstone_receipts)` — re-shares the SAME root under a new guardian set; new epoch number; old share envelopes invalidated (epoch binding already enforced by `unwrap_share`).
- `rotate_root(set) -> new root` — for suspected root compromise: fresh root, re-encrypt vault, full re-enrollment.
- Rotation emits signed receipts; old sessions are tombstoned via the governor.

### 3. Approval client flow (`flailer-cli`)
- `flailer-cli request` — owner creates a recovery session, prints the session ID + nonce.
- `flailer-cli approve --guardian-key <path>` — guardian loads their enrolled signing key, is shown the minimal request description (session ID, action, expiry), signs the domain-separated statement. Never sees shares.
- `flailer-cli status` — governor evaluation: approvals counted, threshold check, next state.

### 4. Paper backup ceremony
- `flailer-cli paper --index 4` — prints the `FL1-…` encoding with transcription grouping + a verification step (re-enter to confirm checksum).
- Explicit warning text: store separately from all other recovery material; never photograph; never store digitally.

## Decisions needed from Zack (his actions, not mine)
1. The five guardians: who (mother / cousin / boss are the RFC's proposal — confirm or replace).
2. Contact channels per guardian for recovery notifications (pre-enrolled, not added mid-recovery).
3. Paper backup storage location.
4. Drill schedule: how often to run `dry_run_recovery` (recommend: enrollment day + every 6 months).

## Exit condition (RFC)
Clean-device recovery works at the required threshold with no coordinator-held plaintext root. Demonstrated via drill, recorded as a signed receipt.

## What P3 does NOT do
- No network transport for guardian messaging (P4/P5 or a later transport adapter).
- No timeline ingestion (P4), no stylometry (P5).
- No real human enrollment — machinery only, until Zack provides the humans.
