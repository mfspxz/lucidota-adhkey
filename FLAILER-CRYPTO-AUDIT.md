# FLAILER-CRYPTO-AUDIT.md — P0 Cryptographic Audit

**Date:** 2026-10-09
**Auditor:** Lucidota (machine review — NOT an independent human review; see §8)
**Scope:** `crates/adhkey-flailer/src/lib.rs` (170 lines), `crates/adhkey-flailer/Cargo.toml`, `FLAILER-DESIGN.md` (v1, 105 lines)
**Method:** Full source read, `cargo test -p adhkey-flailer` executed (4/4 pass), dependency pins checked in `Cargo.lock`.

## 1. What the crate actually is

The crate implements **three** things, not the five its module docs imply:

| Claimed | Actual |
|---|---|
| Knowledge vault (encrypt/decrypt) | ✅ Implemented: XChaCha20-Poly1305 (`chacha20poly1305` crate), random 12-byte nonce via `getrandom`, JSON-serialized facts |
| Shamir split/recombine (3-of-5) | ❌ **Does not exist.** No secret-sharing code, no `ssss`/`sharks` dependency, no share type, no combine function |
| Challenge generation/verification | ⚠️ Partially: deterministic first-n selection, unsalted SHA256 answer check |
| Passphrase → Share A (Argon2id) | ✅ Implemented: `derive_share()` — Argon2id, m=64MiB, t=3, p=4, 32-byte output |
| Human communication / behavioral analysis | Out of scope by design (v1) |

**Verdict on the foundation:** the vault encryption and KDF choices are sound primitives used correctly. The Shamir layer — the load-bearing center of every threshold claim in both the design doc and the RFC — is vapor. Every statement of the form "3 shares reconstruct" is currently untestable.

## 2. Actual key hierarchy (as built)

```
passphrase (memorized, low entropy)
  └─ Argon2id(m=65536, t=3, p=4, salt=caller-supplied) ──▶ Share A (32 bytes, deterministic)
                                                        │
vault key (32 bytes, caller-supplied, origin undocumented)
  └─ XChaCha20-Poly1305(random 96-bit nonce) ──▶ Vault { nonce, ciphertext }
        └─ JSON [ VaultFact { id, question, answer_hash=SHA256(answer), category } ]
```

**Ambiguities documented (not resolved in code):**
- The relationship between Share A and the vault key is **undefined**. Nothing combines shares into the vault key. The design doc says the vault key "is Shamir-split (3-of-5)" but no code performs or inverts a split.
- Salt for `derive_share` is caller-supplied with no specified generation, storage, or rotation policy. A reused or low-entropy salt degrades the KDF.
- No key-version or algorithm identifiers anywhere. A future algorithm change cannot distinguish old vaults from new ones.

## 3. Defects

### D1 — CRITICAL: Answer commitments are offline-guessable (unsalted SHA256)
`VaultFact.answer_hash = SHA256(answer)` and `Challenge.expected_hash` carry the same unsalted digest. Personal answers are low-entropy ("Gastown", "Smith", "blue"). Anyone obtaining a `Challenge` — which the protocol **distributes to humans** — can dictionary-attack the answer offline at billions of hashes/sec.

This directly violates the RFC invariant: *"A stolen vault must not enable practical offline guessing of personal answers."*

**Fix (required before any real data):** per-fact random salt + Argon2id (or at minimum salted SHA256 with a 128-bit per-fact salt — but answers are human-memorable, so memory-hard is the honest choice). Store `(salt, hash)`; verification re-derives. Cost budget: verification happens interactively (human in the loop), so t=3/m=64MiB per answer is acceptable.

### D2 — CRITICAL: No Shamir implementation; threshold claims are untestable
`FLAILER-DESIGN.md` §Implementation Plan item 1 lists "Shamir split/recombine" as built. It is not. Consequences:
- RFC §13.1's "every valid 3-of-5 subset reconstructs the same secret" cannot be tested.
- RFC §7.5 ("Shamir sharing alone cannot revoke a copied share") is correct but moot until shares exist.
- The `derive_share` function is misnamed: it derives a *key*, not a *share*; there is no polynomial, no share index, no threshold.

**Fix:** adopt a reviewed Shamir implementation (Rust: `sharks` is the maintained choice; do NOT hand-roll — this codebase already learned that lesson with `shard.py`). Add share-index binding and epoch tags at the share-envelope layer.

### D3 — HIGH: Passphrase-derived share caps root entropy (the §17 question)
`derive_share` makes Share A a deterministic function of the passphrase. If this share participates in reconstructing the vault key, the vault key's effective entropy is bounded by the passphrase's entropy (memorized ⇒ weak), regardless of the other shares' randomness. It also makes Share A a password-equivalent: anyone who steals a stored/transmitted copy of Share A can offline-attack the passphrase against it (re-derive and compare).

**Fix (auditor's recommendation):** random 256-bit root → Shamir-split → 5 random shares. Share A is a *random* share, stored in a passphrase-encrypted envelope (`Argon2id(passphrase, salt) → XChaCha20-Poly1305`). Offline guessing is then confined to the envelope, the root keeps full entropy, and the KDF and the sharing scheme stop sharing fate.

### D4 — MEDIUM: No associated data on the vault ciphertext
`seal_vault` encrypts with an empty AAD. Nothing binds the ciphertext to a set ID, epoch, or owner. A vault ciphertext copied across epochs or sets would decrypt cleanly under the same key.

**Fix:** AAD = `b"flailer-vault-v1" || set_id || epoch`. Reject on mismatch (the AEAD already rejects tampering; this adds context binding).

### D5 — MEDIUM: `generate_challenges` is deterministic first-n
Takes the first `n` facts, no randomization, no category balancing, `options: None` always (multiple-choice/negative facts unimplemented). An attacker who learns the fact ordering predicts the challenge set.

**Fix:** CSPRNG shuffle + stratified sampling across categories; implement `options` for negative facts.

### D6 — LOW: `Debug` derives on fact/challenge types
`VaultFact` and `Challenge` derive `Debug`. Today they hold hashes, not plaintext — acceptable. **Constraint going forward:** no `Debug`/`Display`/serde `Serialize` on any type that will hold a share, key, or reconstructed secret. Add a `#[deny]`-style clippy/test guard now (RFC §13.1's "secret logging" test).

### D7 — LOW: `expect()` on RNG failure
`seal_vault` panics if `getrandom` fails. Standard practice, acceptable for v1 — but document that this crate panics rather than returning `Result`, so callers in the governor path know.

### D8 — INFO: No `no_std`/platform notes, fine for now
`getrandom 0.2` with default features works on the VM and Android. Revisit if the crate targets a constrained device.

## 4. Dependency pins (from Cargo.lock)

| Crate | Declared | Pinned | Notes |
|---|---|---|---|
| chacha20poly1305 | 0.10 | 0.10.1 | RustCrypto; XChaCha20-Poly1305 via `aead::AeadCore` nonce gen — used correctly (random nonce, never reused in this code path) |
| argon2 | 0.5 | 0.5.3 | RustCrypto; Argon2id v0x13, sane params (64MiB/3/4) |
| sha2 | 0.10 | 0.10.9 | Fine as a hash; **not** fine as a password/answer KDF (see D1) |
| getrandom | 0.2 | 0.2.17 | — |
| serde / serde_json | 1 | 1.0.229 / 1.0.151 | JSON vault encoding — fine; canonicalization not needed since ciphertext is opaque |

No duplicate crypto primitives. No hand-rolled primitives. Dependency posture is clean.

## 5. Test coverage assessment

4/4 pass. All four are happy-path: roundtrip, wrong-key rejection, challenge verify true/false, KDF determinism. **Missing:** tamper tests (bit-flip, nonce reuse), KDF param validation, serialization failure paths, and — unavoidably — everything Shamir (D2). The RFC's §13 test plan supersedes this suite; do not extend this suite, replace it per the test plan.

## 6. Design-doc vs RFC deltas (resolved in favor of the RFC)

- Design v1: "3 shares + 4/5 challenges + 2 vouches = RECOVER" (conflated). RFC §7.4 separates cryptographic threshold from human authorization. **RFC wins.**
- Design v1: Share A passphrase-derived. RFC §17 flags it; this audit recommends the envelope design (D3). **Decision recorded, implementation pending.**
- Design v1 assumes a coordinator that notifies humans. RFC makes the coordinator an untrusted relay. **RFC wins;** P1/P2 must not place trust in it.

## 7. What P0 does NOT clear

- [ ] D1 fix (salted/memory-hard answer commitments) — P1
- [ ] D2 fix (real Shamir + share envelopes) — P1
- [ ] D3 decision implementation (envelope design) — P1
- [ ] D4 fix (AAD binding) — P1
- [ ] D5 fix (randomized challenge sampling) — P2/P3
- [ ] D6 guard (secret-logging test) — P1, with the RFC test plan
- [ ] Independent human review of this audit and the resulting design — **release gate, no substitute**

## 8. Auditor's limitation statement

This is a machine review of 170 lines plus its design doc. It is thorough for its size and every defect above is demonstrated from the source, but **it is not an independent security review**. The RFC's release gate requires a human reviewer with cryptographic-design experience to examine this audit, the fixed implementation, and the adversarial test results. Nothing in P0 waives that.
