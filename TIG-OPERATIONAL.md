# TIG Operational Design — five structural ideas

**Source:** Zackary's synthesis, 2026-10-06. Status: DESIGN. Do not
implement until REDTEAM-002 converges. Then attack THIS before building.

## 1. Epistemic Edge Algebra & Transition Mechanics

An edge is a state machine with strict type promotion rules, not a
weighted link.

```
[Heuristic Engine]
        │
        ▼
┌───────────────────────┐
│    E_claimed(A, B)    │  (weight: [0.0, 1.0], method: ML/Vector/Rule)
└───────────┬───────────┘
            │ + Witness Bundle W (cryptographic/hardware/attestation)
            │ + Policy Gate P_eval
            ▼
┌───────────────────────┐
│  E_established(A, B)  │  (anchored_by: W, policy: P_eval, version: V)
└───────────┬───────────┘
            │ + Capability Request C
            │ + Context / State Check S
            ▼
┌───────────────────────┐
│   E_authorized(A, B)  │  (transient capability lease)
└───────────────────────┘
```

**Transition invariants:**

- **Non-Promotability of Pure Weights:** no scalar threshold of
  E_claimed (even 0.999999) can ever evaluate to E_established. The weight
  parameter ONLY controls graph traversal priority for the witness
  collector.
- **Algebraic Monomorphism:** E_established requires a non-empty witness
  set W and a signed, versioned policy P. There is exactly one
  construction path; no alternative constructor exists.

## 2. Cascading Invalidation (O(1) Epistemic Retraction)

Every E_established edge records its supporting witness set W, so
revocation is top-down DAG invalidation:

```
[Key-01 Revoked] ──► Invalidate Witness(W_Key01)
                         │
                         ▼
             Collapse E_established(A, B) ──► Retract to E_claimed(A, B)
                         │
                         ▼
             Terminate active E_authorized(A, B) leases
```

A revoked YubiKey/passkey flips its witness node to REVOKED; dependent
E_established edges collapse to E_claimed (or E_disproven); active leases
built on them die. **Open mechanism question:** "same clock cycle" is not
a distributed primitive — the actual synchrony bound between revocation
commit and lease termination is unspecified and MUST be specified before
this claim is made. (Kill-target 11.)

## 3. Ghost Clumping (Sybil-ML) neutralization

Adversary spoofs behavioral signals (IP subnets, user-agents, geo pings,
canvas fingerprints) to force vector search to merge attacker node A with
victim node B. In commercial systems the high similarity score = "same
person" = account takeover.

In TIG the attack produces a hyper-dense cluster of E_claimed edges and
dies at the epistemic firewall: no traversal to E_authorized without the
cryptographic witness Policy P demands. No custom anti-spoofing code
needed — the architecture absorbs it.

**Sharp edge:** the firewall holds against PURE heuristic attack. The real
attack surface moves to the policy's witness bar: if P accepts any weak
witness type the attacker can forge, clumping + weak witness = promotion.
Policies, not heuristics, become the target. (Kill-target 12.)

## 4. Epistemic Query Language (EQL)

Graph query languages treat edges as uniform paths. EQL forces the
application to declare its required epistemic depth:

```cypher
-- BAD: generic identity question
MATCH (a:Identity)-[:RESOLVES_TO]->(b:Identity)
WHERE a.id = 'usr_123' RETURN b

-- EQL: heuristic candidates (fast, low trust)
MATCH (a:Identity)-[e:RESOLVES_TO {tier: 'CLAIMED'}]->(b:Identity)
WHERE a.id = 'usr_123' AND e.score > 0.85
RETURN b.preferences

-- EQL: financial execution (fail-closed, high trust)
MATCH (a:Identity)-[e:RESOLVES_TO {tier: 'ESTABLISHED'}]->(b:Identity)
WHERE a.id = 'usr_123'
  AND e.policy = 'FINANCIAL_DISBURSEMENT_v2'
  AND e.witness_status = 'VALID'
  AND e.not_after > clock.now()
RETURN b.payout_account
```

A developer cannot accidentally authorize against heuristic branches —
the tier is in the query. **Trust boundary:** the query planner. If tier is
a string parameter, it can be confused/injected. (Kill-target 13.)

## 5. TIG × 15 primitives mapping

| Primitive | TIG Role |
|---|---|
| id (Identity) | Graph nodes: actors, devices, keys, ephemeral sessions |
| re (Relationship) | Typed directed edges: E_claimed, E_established, E_authorized |
| evd (Evidence) | Witness nodes: signed EATs, passkey assertions, verified OAuth receipts |
| po (Policy) | Rule sets: witness combinations required for promotion |
| au (Authority) | Evaluator granting E_authorized from an E_established subgraph |
| st (State) | Versioned append-only journal: AS_OF(version) time travel |

TIG answers: "How does heuristic discovery safely feed deterministic
security without ever touching the steering wheel?"

**Composition seams need invariants** — especially `au`: if the evaluator
accepts a caller-constructed subgraph, doctrine #1 (no claim derives
authority from its own existence) is violated at the seam. (Kill-target
14.)
