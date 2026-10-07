# CONSOLIDATION-002 — round-2 synthesis

**Date:** 2026-10-06. **Attackers:** deepseek (full, 19.6KB), nemotron-550b
(partial, 1.1KB — truncated but verdict-bearing), NIM (queued, pending).
**Target:** `crates/adhkey-statement/src/lib.rs` + 8 kill-targets.
**Standing order still in effect: DO NOT HARDEN.** Record, rank, redesign
later.

## Convergence (independently found by 2+ attackers)

### ★ #1 Self-authority — CONVERGED BROKEN

Both attackers, unprompted, produced the same exploit shape:
`authenticate()` performs zero authorization checks. Anyone can mint a
genesis statement for any subject and bootstrap `controls[subject]` from
their own signature. Nemotron: Mallory issues genesis `Controls` for
Alice. DeepSeek: Alice self-bootstraps; Alice issues `Controls` on Bob;
`reduce` writes `controls[Bob] += K` with no check.

This is the kill-list's predicted failure, confirmed twice: the
caller-controlled identity problem moved into the Statement constructor.
**This is the #1 redesign requirement.** The model needs an authorization
layer between authentication and effect application — "Alice said X" must
not reach `reduce` effects without "Alice was authorized to say X."

## Structural BROKEN (deepseek, single source, high confidence)

### #2 Genesis / trust-root — BROKEN
No genesis anchor type, no root registry. Attacker mints
`SubjectRef{namespace:"witness:dmv"}` genesis; namespace-string filtering
downstream treats it as DMV-controlled. The Statement model has no trust
root doctrine.

### #6 Issuer/key binding — BROKEN (API level)
`verify_sig` closure resolves `SubjectRef → keys` with no model support;
no `state_version`/`controls_epoch` on the statement, so stale-snapshot
key resolution is undetectable. Doctrine #2 (freshness bound) violated by
the interface itself.

### #7 Evidence recursion — BROKEN (no termination)
Cycles encodable (`A attests B`, `B attests A`, distinct hashes, both
authenticate). `reduce` ignores evidence entirely. Doctrine #4
(independence counting) is un-representable: no trust-domain,
independence-class, or root fields.

### #8 Policy — BROKEN (not implemented)
`policy: String` decorative; `reduce` applies `Controls` effects
regardless of policy value. The `establish(bool)` pattern was not
replaced, just renamed.

### #3 Sequence — partial: merge/order/recovery BROKEN
Basics hold (dup/skip/replay rejected). Broken: branch merge has no
DAG resolution; **N1: reduce is order-dependent** (`[g,a1,child,a2]` ≠
`[g,a1,a2,child]` — most serious undetected bug); `Replaces` has no
sequence semantics; `u64` overflow uses `+` not `checked_add`.

### #4 Canonical encoding — BROKEN
Unicode (no NFC/NFD — same subject, two hashes), evidence `Vec` order
affects bytes, no length cap, no semantic normalization
(`valid_until < valid_from` canonicalizes fine).

## HOLDS (genuine good news)

### #5 Signature substitution — HOLDS (with caveat)
Cross-statement transplant requires canonical-byte collision; hash
correctly excludes signature; suite is inside signed bytes. Caveat: `suite`
is a free `String` — verifier must exact-match, model doesn't enforce.

## Live bugs in the sketch (deepseek NEW findings)

- **N3: `Withdraws` never applies.** `let _ = &st.withdrawn;` is dead code.
  A withdrawn `Controls` key stays in `controls` forever. Live bug, zero
  test coverage.
- **N2: `Replaces{old,new}` in predicate vs `object` channel duplication.**
  Object decorative; two byte-sequences, same effect.
- **N9: `reduce` accepts a forest.** Takes `&[AuthenticatedStatement]`,
  should walk from a single genesis.
- **N10: `previous` ambiguous.** Chain-per-subject (enforced by
  `authenticate`) vs global pointer (suggested by bare bytes). Wire-level
  ambiguity.

## What this means

The Statement model survived as an ONTOLOGY (authenticated statements →
history → reduction → derived state is still the right shape) but failed
as a MECHANISM in exactly the places the kill-list predicted: authority,
roots, binding, termination, policy. None of the failures require
abandoning the model — they require completing it:

1. Authorization layer between `authenticate` and `reduce` effects.
2. Genesis/trust-root doctrine (what roots exist, who mints them).
3. Issuer→key→state-version binding in the statement or its context.
4. Evidence recursion termination (depth bound + cycle detection + root
   requirement).
5. Real policy evaluation (inputs → P → deterministic eval → signed
   verdict binding input IDs, policy hash, state version).
6. Canonical encoding v2 (normalization, ordering, caps).
7. `reduce` as a DAG walk from genesis, order-independent, withdrawals
   applied.

Kill-targets 9–14 (TIG operational: laundering, weight priority,
invalidation race, ghost+weak-witness, EQL tier confusion, seams) are
queued for round 3. The five TIG ideas are not yet attacked.
