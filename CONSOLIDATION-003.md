# CONSOLIDATION-003 — round-3 synthesis (TIG operational layer)

**Date:** 2026-10-06. **Attackers:** deepseek (full, 11.3KB), nemotron-550b
(full, 9.5KB), NIM (queued, pending). **Target:** TIG-OPERATIONAL.md (five
ideas) + kill-targets 9–14. **Standing order still in effect: DO NOT
HARDEN.**

## Convergence: all six kill-targets broken by both attackers

### #9 Laundering — CONVERGED BROKEN
`WitnessRef` and `HeuristicRunRef` share the `EvidenceRef` shape. Any
establishment path filtering on `evidence.len() > 0` promotes heuristics.
DeepSeek: "The attack is not injection — it is a well-intentioned
developer writing the obvious loop." Fix is type-level; doctrine #5 is not
a mechanism until the type system refuses the alternative.

### #10 Weight priority — CONVERGED BROKEN
Adversary saturates high-weight ghost-clumped paths; the witness
collector's bounded time budget dies on attacker-controlled candidates
while legitimate witnesses time out. DeepSeek: "The design cannot have
both 0.0–1.0 weight granularity and an epistemic firewall. Pick one."
Resolution: quarantine weight to the CLAIMED tier entirely; order
collection by witness-independence metrics, not claim strength.

### #11 Invalidation race — CONVERGED BROKEN
"O(1) retraction is theater." Real primitive: O(1) to mark revoked at the
root + O(1) per-exercise re-check of dependent witness roots. "Same clock
cycle" is not a distributed primitive; the freshness bound is. A lease
exercised between revocation commit and traversal completion authorizes on
dead authority. Specify the bound as max(exercise_interval) or the claim
dies.

### #12 Ghost + weak witness — CONVERGED BROKEN
The firewall is architectural; the gate is policy. Clumping + one forged
weak witness (OTP/SMS/self-asserted OAuth) = promotion wherever P accepts
weak witnesses. Required protocol artifact: a **signed witness-class
registry** classifying each witness type by trust root, forgery cost, and
trust-domain co-location — itself subject to doctrine #1.

### #13 EQL tier confusion — CONVERGED BROKEN
Tier as a string filter is attacker-influenceable. Required: CLAIMED and
ESTABLISHED as physically different edge types; tier as compile-time
edge-kind resolution burned into a signed plan. No syntax to cross from a
CLAIMED-resolved node to an authority-bearing one.

### #14 Seams — CONVERGED BROKEN
`au` must accept only `(genesis_id, state_version, evaluation_receipt_id)`
and reduce internally. Any caller-materialized subgraph is doctrine #1
violated at the seam. Every primitive interface (`evd→po`, `id→re`,
`st→au`) is an unspecified doctrine-reversal point until given an
invariant.

## New findings (deepseek, beyond the 6)

- **NEW-1: TIG's ternary doesn't cover issuer-permission.** Round-2
  demanded an authorization layer between authenticate and reduce
  ("Alice said X" vs "Alice was authorized to say X"). TIG's
  CLAIMED→ESTABLISHED→AUTHORIZED is a *promotion* axis; issuer-permission
  is orthogonal. A statement can be AUTHORIZED-tier and still be issued by
  an unauthorized issuer. Needs a fourth axis or an orthogonality
  declaration.
- **NEW-2: No freshness discipline for derived state.** A cached
  ESTABLISHED edge is local state claiming a remote fact (witness
  validity) — doctrine #2 requires a freshness bound ON THE EDGE
  (`valid_until`, `state_version_at_establishment`). Currently absent.
- **NEW-3: The 15-primitive mapping is a dependency list, not an
  architecture.** Naming `evd` doesn't repair round-2's evidence failures.
- **NEW-4: EQL example conflates ESTABLISHED and AUTHORIZED.** The
  financial query returns `payout_account` — that's AUTHORIZED-tier. Need
  a fourth query tier or a separate `AUTHORIZE` clause forcing the `au`
  round.
- **NEW-5: Performance claims and security claims are mutually
  attacking.** "Fast", "O(1)", "priority" all assume cached derived
  state; security assumes fresh derived state. Name the cache
  invalidation mechanism and its cost, or drop the performance claims.
- **NEW-6 (proposed doctrine): compositional risk.** No composite
  establishment may claim stronger trust than the weakest link in its
  witness-independence chain, and the chain must be tracked, not assumed.
  Status: PROPOSED, not yet carved — needs Zackary's call.

## Meta-finding across all three rounds

The pattern is now three-for-three: **the ontology survives; every
operational claim needs a mechanism with a proven bound.** Nothing has
required abandoning the model. Everything has required completing it.

What "complete" now concretely means (cumulative):

1. Authorization layer between authenticate and reduce (round-2 #1).
2. Genesis/trust-root doctrine (round-2 #2).
3. Issuer→key→state-version binding (round-2 #6).
4. Evidence recursion termination (round-2 #7).
5. Real policy evaluation with bound inputs (round-2 #8).
6. Canonical encoding v2 (round-2 #4).
7. Order-independent DAG reduce from genesis (round-2 N1/N9).
8. Type-level WitnessRef vs HeuristicRunRef (round-3 #9).
9. Weight quarantined to CLAIMED (round-3 #10).
10. Freshness bound as the revocation primitive (round-3 #11).
11. Signed witness-class registry (round-3 #12).
12. EQL tiers as edge kinds + signed plans (round-3 #13).
13. Seam invariants; `au` reduces internally (round-3 #14).
14. Issuer-permission axis (round-3 NEW-1).
15. Freshness discipline for derived state (round-3 NEW-2).

Nemotron's verdict stands as the bar for implementation: "cannot be
implemented safely until the Statement model converges AND each
operational claim gets a mechanism with a proven bound."
