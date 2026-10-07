# luci-verdict — staged epistemic verdict organelle

**Source:** Zackary's synthesis from RFC-001 + ledger archaeology, 2026-10-06.
**Status:** IMPLEMENTED. Crate: `crates/luci-verdict-core`. 25 tests green,
62/62 across the workspace.

## The missing layer

The five lies (caller-authored authority, stale envelopes, cross-subject
replay, mutual corroboration, forged execution) are one missing layer:
assertions crossing ontology boundaries without independent state
transitions. The cure is structural, not "a smarter verifier":

> Make the machine structurally incapable of believing the wrong thing.

## The ternary cube

Every proposition carries independent axes. Do not collapse them.

| Axis | -1 | 0 | +1 |
|---|---|---|---|
| Truth | disproven | unknown | proven |
| Temporal | past/expired | current/uncertain | future/valid |
| Activation | disabled | unresolved | enabled |
| Authority stage | rejected | claimed/establishing | authorized |
| Provenance | system contradiction | user claim | independently discovered |
| Relationship | negated | unknown | established |

A thing can be truth=UNKNOWN, authority=CLAIMED, activation=ENABLED,
time=CURRENT, provenance=USER_PROVIDED — and the machine says exactly
that, instead of collapsing it to a boolean.

UNKNOWN is not FALSE. UNKNOWN propagates. There is no path from
UNKNOWN to TRUE through convenience.

## The pipeline

```
CLAIM -> NORMALIZE -> BIND -> VERIFY CRYPTO -> FRESHNESS -> SUBJECT ->
AUDIENCE -> PROVENANCE -> RELATIONSHIPS -> POLICY ->
AUTHORIZED / DEFERRED / DENIED -> RECEIPT
```

Every stage produces a typed intermediate result
(CryptoStatus, Freshness, Binding, Identity/Evidence epistemics,
activation). The final verdict is a projection of those states.

Three outcomes, never two: **Authorized** (all green), **Denied**
(terminal no — stale envelopes, binding mismatch, policy reject),
**Deferred** (UNKNOWN propagated — may authorize later with evidence).

## The five kills

- **V001 caller-authored authority:** `Claimed<T>` / `Established<T>` /
  `Authorized<T>` newtypes. `authorize(x: Established<Identity>)`
  cannot accept `Claimed<Identity>` — the compiler rejects it.
  The serialized caller field is `claimed_authority`, never `authority`.
- **V002 stale envelopes:** envelope binds nonce, issued_at,
  expires_at, policy_hash, evidence_hash, request_hash,
  previous_receipt_hash. Signature valid ≠ fresh ≠ valid-for-this-request.
- **V003 cross-subject replay:** binding check over subject, audience,
  operation, request, policy. A proof about Alice is not proof about Bob.
- **V004 mutual corroboration:** `independent_witnesses()` counts
  distinct ultimate trust roots through the `controlled_by` relation.
  Two witnesses under one root count once. Cycles terminate.
- **V005 forged execution:** EXECUTION_CLAIMED -> EXECUTION_OBSERVED ->
  EXECUTION_VERIFIED. Self-observations discarded before evaluation;
  the agent's receipt is a claim, external observers are evidence.

## Sacred invariant

> No attacker-controlled field may directly cause a transition from
> CLAIMED/UNKNOWN to ESTABLISHED/AUTHORIZED.

Enforced by types (authority newtypes), by pipeline order (evidence
before policy before activation), and by test: the 27 ternary
combinations authorize in exactly one case (+,+,+); attacker mutation
of every caller-controlled field cannot flip Deferred to Authorized.

## Relation to existing work

- AdhKey Statement model: luci-verdict is the authority-evaluation
  layer the Statement design was missing (R2 finding: authenticate()
  proves signing, not authorization to produce effects).
- TIG CLAIMED->ESTABLISHED->AUTHORIZED: this crate is the transition
  machinery, with the type-level quarantines R3 demanded.
- Failure Shape / Court: V001-V005 are the first five attack families;
  the Court challenges verdicts, luci-verdict produces them.
- Trigger-equivalence: the 27-combination sweep is a behavioral
  envelope of the core itself — boundary observed, internals explicit.
