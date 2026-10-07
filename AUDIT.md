# AdhKey — extreme audit

**Date:** 2026-10-06. **Scope:** `~/workspace/adhkey`, crates
adhkey-core (lib, lifecycle, verifier, evidence, court, court_evidence),
adhkey-crypto, adhkey-store. **Method:** adversarial re-read against the
design docs and our own invariants. **Verdict: NOT PRODUCTION.** Honest
prototype with a solid skeleton and real gaps.

## Critical findings

### C1. Signatures are not verified — the check is a stub
`VerifierContext.signature_valid: bool` is injected by the caller. The
Court passes `true`. Nothing calls `KeyStore::sign`/`verify` in the
verification path. An attacker who controls the `VerifierContext`
construction controls the outcome. This is exactly the "caller-authored
verdict" bug the verifier redesign exists to kill. **The Court is testing
a verifier with its fangs removed.**

### C2. Recovery approvals are key IDs, not signatures
`recover()` checks that approval IDs are policy-listed and usable, but
never verifies a signature over the recovery statement. Passing
`&[kid("REC-1"), kid("REC-2")]` is an assertion, not an authorization.
A compromised caller with the ID list can recover any identity.

### C3. `establish()` takes a bare bool
`policy_satisfied: bool` — the policy decision enters with no provenance:
who evaluated, under what version, on what evidence snapshot. We banned
collapsing to booleans; this is a boolean smuggled in through the back
door. It should take a signed policy verdict, not a bit.

### C4. `Conflict` is dead
Nothing ever produces `EpistemicState::Conflict`. `evaluate_claim` returns
Unknown/Claimed/Supported/Established/Revoked/Expired — never Conflict.
A state the machinery cannot reach is decoration, not a lattice.

### C5. Replay protection is RAM-only
`seen_nonces: &mut BTreeSet<String>` — unbounded growth (DoS), wiped on
restart (replay window reopens), no expiry. A production verifier needs a
persistent, bounded, time-partitioned nonce store.

### C6. Lost → Active requires no re-verification
`transition_key` allows Lost → Active ("found again") unconditionally. A
"found" key may be cloned or extracted. Finding should require fresh
proof-of-possession, or route through recovery.

### C7. Receipts are not tamper-evident
`Receipt` is a plain struct: no signature, no hash chain, no binding to
the verification event. "Receipts are derived, never caller-authored" is
asserted in comments but not enforced in types. Anyone constructing a
`Receipt` struct can author one.

## Design-vs-implementation gaps

### G1. The Statement primitive does not exist
The design's killer primitive — `Statement { subject, predicate, object,
issuer, evidence, policy, timestamp, state, signature }` — is not
implemented. `Claim` and `HumanClaim` are special cases that should be
projections of Statement. The code is one design revision behind.

### G2. Receipt ≠ Evidence ≠ Truth is not enforced
The distinction exists in prose. In code: `Receipt`, `Evidence`, and the
verdict types are independent structs with no machine-checked boundary
between "system X recorded Y" and "Y is supported". Nothing stops a
receipt from being filed as evidence.

### G3. Freshness witness is trusted implicitly
`Freshness.witness` is accepted as-is. No verification that the witness
is authorized, no signature check on the freshness attestation. A lying
clock + a lying witness = false AUTHORIZED.

### G4. No wire format
No serde, no canonical encoding. Statements cannot cross a process or
machine boundary. The "portable" in "portable identity protocol" is
currently aspirational.

### G5. Evidence digests are never checked
`Evidence.digest: [u8; 32]` — nothing verifies it against the artifact.
The witness is trusted to have it right, which reintroduces
caller-authored provenance through the side door.

## Doctrine violations (our own invariants, applied to us)

- **"The claim is an output of the machinery"** — VIOLATED by C1, C2, C3.
  Three places where caller input becomes verdict.
- **"Provenance cannot be caller-authored"** — VIOLATED by C7, G5.
- **"Unknown must remain unknown"** — HELD. CANNOT_ESTABLISH is honest;
  no default-allow path exists in the verifier.
- **"Fail closed"** — HELD for state transitions (illegal transitions
  rejected, revoked terminal). WEAK for verification (C1 stub).
- **"No new primitive without need"** — HELD. The type count is justified.

## What's actually solid

- The transition table is correct and total: revoked is terminal, lost is
  recoverable, every transition is recorded. The history IS the identity.
- The trichotomy is type-level, not conventional. It cannot silently merge.
- `evaluate_claim` never overstates: empty → CLAIMED, never ESTABLISHED.
- Revocation is sticky and checked first. Expiry is honest.
- Time is injected (`now: u64`) — testable, no hidden clock reads.
- Zero warnings, 27/27 tests. The tests are honest about what they cover.

## Fix priority

1. Wire real signature verification (store-backed) into the verifier; make
   `signature_valid` unconstructible by callers. (Kills C1.)
2. Recovery approvals become signed statements over (old_key, new_key,
   nonce). (Kills C2.)
3. Replace `policy_satisfied: bool` with a signed policy verdict struct.
   (Kills C3.)
4. Implement the Statement triple as the core primitive; re-express
   Claim/HumanClaim as projections. (Kills G1, enables G2.)
5. Hash-chain + sign receipts. (Kills C7.)
6. Persistent nonce store with expiry. (Kills C5.)
7. Lost → Active requires proof-of-possession. (Kills C6.)
8. Reachable Conflict: contradiction detector over evidence set. (Kills C4.)
9. Canonical encoding (serde + canonical CBOR/JSON). (Kills G4.)
10. Witness authorization for freshness attestations. (Kills G3.)

## Bottom line

The skeleton is right — the state machine, the lattice, the trichotomy,
the fail-closed defaults. But the three most security-critical paths
(signature verification, recovery authorization, policy input) are stubs
wearing the clothes of the real thing. The Court passes because it attacks
a verifier that was never given teeth. Fix order above is the path from
honest prototype to something auditable.
