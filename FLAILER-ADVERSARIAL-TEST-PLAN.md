# FLAILER-ADVERSARIAL-TEST-PLAN.md

Reproducible tests, expected results, and release gates for AdhKey Flailer.
Companion to `FLAILER-CRYPTO-AUDIT.md` (P0) and `FLAILER-RECOVERY-RFC.md` (protocol).
Principle: test adversarial properties, not successful execution.

## Conventions

* Each test has an ID, a setup, the attack/property, and the expected result.
* `PROVEN` = test passes against the real implementation. `TRACKED` = test exists, attack not yet defeated.
* Property tests use `proptest`; adversarial scenarios are scripted harnesses, not unit tests.
* No test may log, print, or serialize secret material — enforced by T-LOG (below).

---

## T-CRYPTO — Cryptographic property tests

| ID | Test | Expected |
|---|---|---|
| T-C1 | Vault round trip (random key, random facts incl. empty/unicode/large) | Exact recovery |
| T-C2 | Flip one bit of ciphertext | AEAD auth failure, no partial plaintext |
| T-C3 | Flip one bit of nonce | Rejected |
| T-C4 | Reuse a nonce with a different plaintext under the same key | Rejected by construction (nonces are always CSPRNG-random; test asserts uniqueness over 10k seals) |
| T-C5 | Vault opened with AAD from a different set ID / epoch | Rejected |
| T-C6 | Wrong passphrase on the S0 envelope | Envelope stays sealed; no distinguishable error vs wrong-key (constant-time failure path) |
| T-C7 | Invalid KDF params (m=0, t=0, excessive m) | Rejected before allocation |
| T-C8 | All C(5,3)=10 share subsets | Each reconstructs the identical root |
| T-C9 | Any 2 shares | No information about root (assert via scheme's documented security property + reconstruction attempt fails) |
| T-C10 | Corrupted share (bit flip) | Detected before secret use (integrity mechanism of the share envelope, not assumed from `combine`) |
| T-C11 | Share from epoch N used in epoch N+1 session | Rejected (epoch tag mismatch) |
| T-C12 | Duplicate share index in a reconstruction set | Rejected |
| T-C13 | Share substitution (valid share from a different set) | Detected (set-ID binding) before secret use |
| T-C14 | Key-purpose confusion: vault key used as envelope key and vice versa | Domain separation enforced (distinct HKDF info strings / distinct key types); cross-use fails |
| T-C15 | Answer-commit guessing: attacker with a leaked challenge commitment runs a 10k-entry dictionary + mangling rules | Infeasible per attempt (Argon2id cost × attempts); assert wall-clock lower bound per guess |
| T-C16 | KDF determinism: same (passphrase, salt) → same output; different salt → different output | Holds |
| T-LOG | Secret-logging guard: test harness scans all `Debug`/`Display`/serialized output of share/key/secret types in test instrumentation | Any secret material in output fails the build |

## T-STATE — State-machine property tests (proptest)

Generate randomized sequences over: create session, submit evidence, submit approval (valid/invalid/replayed/wrong-session), expire session, revoke epoch, abort, commit, concurrent commit attempts, crash injection between durable transitions.

Invariants (all must hold for every generated trace):

| ID | Invariant |
|---|---|
| T-S1 | No trace reaches `Committed` without the cryptographic threshold AND the human-authorization threshold satisfied |
| T-S2 | Replaying an approval never increases the distinct-valid-guardian count |
| T-S3 | A session whose epoch was revoked cannot commit |
| T-S4 | A failed/aborted/denied session never mutates the active recovery set |
| T-S5 | Duplicate operations never duplicate irreversible side effects (idempotency keys) |
| T-S6 | Crash between any two durable transitions grants no access and leaves resumable-or-aborted state, never half-committed credentials |
| T-S7 | Concurrent commits cannot install conflicting credential epochs (exactly one wins; the other fails cleanly) |
| T-S8 | Malformed or unknown policy/protocol versions fail closed (never permissive defaults) |
| T-S9 | Tombstoned sessions retain their evidence records (competing-attempt evidence is never silently deleted) |

## T-ADV — Adversarial scenario harnesses

Each scenario is a scripted harness with attacker capabilities explicitly listed. Status starts at TRACKED; moves to PROVEN only when the harness demonstrates defeat.

| ID | Scenario | Attacker capability | Success = attack defeated when… |
|---|---|---|---|
| T-A1 | Vault theft | Every persisted vault record; no authorized recovery capability | Offline analysis yields no answers (T-C15), no shares (envelope sealed), no root |
| T-A2 | Guardian collusion | 2 guardians cooperate; no other capability | 2 shares < threshold; human-auth policy also unsatisfied |
| T-A3 | Owner-device compromise | Former phone + browser session | Old sessions tombstoned post-recovery; no credential reuse; new-device enrollment required |
| T-A4 | Timeline forgery | Fabricated events with manipulated timestamps | Provenance/timestamp-uncertainty checks reject; authorization unchanged |
| T-A5 | Stylometry poisoning | Imitation text injected toward the baseline | Baseline updates require authenticated sessions only; poisoned samples quarantined |
| T-A6 | Recovery flooding | Many parallel sessions | Rate limits hold; legitimate session capacity preserved; no lockout of the owner |
| T-A7 | Guardian disappearance | 1–2 guardians permanently unavailable | Recovery still possible via remaining shares + paper backup under exceptional policy |
| T-A8 | Power loss | Crash during reconstruction / rotation / commit | T-S6 holds; no half-rotated credential state |
| T-A9 | Malicious upgrade | Downgraded protocol attempting weaker proofs | Version negotiation fails closed; old proofs rejected |
| T-A10 | Coerced guardian | Legitimate guardian pressured to approve | Session-bound approvals + out-of-band verification + 2-guardian rule; single coerced approval insufficient |

## T-DRILL — Full recovery drills (clean device)

| ID | Drill | Expected |
|---|---|---|
| T-D1 | Lose every device; retain passphrase; reach 3 valid shares | Recovery completes; new credentials bound; old sessions tombstoned |
| T-D2 | Lose passphrase; retain other authorized capabilities | Recovery completes ONLY via the explicitly designed alternate path, if one exists; otherwise cleanly denied (never a backdoor) |
| T-D3 | One guardian compromised | Unilateral recovery rejected |
| T-D4 | Two guardians unavailable | Paper share + remaining capability completes recovery under exceptional policy |
| T-D5 | Owner makes mistakes (wrong answers, wrong order, retries) | Path not permanently exhausted; retry counters and lockout timers behave per policy |
| T-D6 | Recovery interrupted at every durable transition | Each interruption resumes or aborts safely (T-S6) |
| T-D7 | Post-recovery verification | Old sessions cannot regain access; rotated credentials verified live |

## Release gates

1. All T-CRYPTO pass.
2. All T-STATE invariants hold (proptest, minimum 10k cases per invariant, plus targeted regression seeds).
3. All T-ADV scenarios PROVEN (none merely TRACKED).
4. All T-DRILL drills demonstrated from a genuinely clean device, recorded.
5. Zero known critical/high-severity defects.
6. Independent human review of: this plan's results, `FLAILER-CRYPTO-AUDIT.md`, the P1 implementation, and the attack demonstrations.
7. Runbook written: enrollment, drill cadence, guardian replacement, exceptional recovery, incident response.

**Passing tests alone is not a security audit.** Gate 6 has no substitute.
