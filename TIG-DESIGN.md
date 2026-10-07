# AdhKey Ternary Identity Graph (TIG)

**Source:** Zackary's research + design synthesis, 2026-10-06. Status: DESIGN.
Do not implement until the Statement model survives REDTEAM-002.

## What it is not

Not "identity graphs" — industry already has those (deterministic identity
graphs, rule-based + vector-search matching, academic work on pairwise
comparison / transitive closure / clustering for entity resolution).
Zackary searched for this exact combination and found adjacent work but no
obvious existing project matching it. Novelty claim is careful, not
absolute.

## The invention: an epistemically typed identity graph

Commercial systems ask: `MATCH(A,B) = 0.94`.

TIG asks:

```
A --[CLAIMED:0.94, method=heuristic-X]--> B
A --[SUPPORTED_BY]--> Evidence₁
Evidence₁ --[WITNESSED_BY]--> Witness₁
A --[ESTABLISHED_UNDER]--> Policy₇
```

Authorization consumes only the established graph.

## The ternary axis (corrected)

Not CLAIMED/SUPPORTED/ESTABLISHED. SUPPORTED describes evidence status;
the authorization-relevant axis is:

### 1. CLAIMED — "These records probably refer to the same entity."

Heuristics live here: same/similar name, phone, email, device, address,
behavioral pattern, social graph, temporal continuity, linguistic
similarity, location correlation, graph proximity, ML/vector similarity.

**Allowed to be wrong.** A score of 0.97 does not make a heuristic into
evidence. It generates a *candidate relationship*.

### 2. ESTABLISHED — "Under policy P, the evidence establishes that these
references resolve to the same subject."

Requires actual evidence + witnesses. The heuristic candidate is an input
to investigation, never an input to establishment.

### 3. AUTHORIZED — "This established subject may perform X against Y
under policy P at state/version V."

A completely different proposition from the first two.

```
heuristic inference → CLAIMED → evidence + witnesses → ESTABLISHED
    → policy evaluation → AUTHORIZED
```

**No arrow goes backward.**

## The killer property

> AI can be extremely aggressive at discovering possible identities
> without being allowed to manufacture identity authority.

This is where the heuristic/AI work belongs: a discovery engine with no
path to authority. The most aggressive inference imaginable cannot
promote itself.

## Core invariant (doctrine-grade)

> Inference may discover identity relationships. Evidence may support
> them. Only policy-governed establishment may authorize them.

## The honest question set (query API)

- Are these probably the same entity? → CLAIMED
- What evidence connects them? → SUPPORTED (evidence layer)
- Can we establish the relationship under this policy? → ESTABLISHED
- Can this subject exercise this authority right now? → AUTHORIZED
- What happens if the evidence disappears? → REVOKED / EXPIRED / CONFLICT
- What did we actually know at time T? → AS_OF(version)

## Mapping onto the Statement primitive (no new mechanism)

TIG is a projection over the authenticated statement log, not a separate
system:

- CLAIMED edge = Statement { predicate: ProbablySameAs, issuer: heuristic
  engine id, evidence: [heuristic run ref], state: CLAIMED }
- SUPPORTED = EvidenceRef graph between statements (already in the model)
- ESTABLISHED = Statement { predicate: EstablishedUnder, policy: P,
  evidence: [witness statements...], state: ESTABLISHED }
- AUTHORIZED = Statement { predicate: Authorizes, object: (action,
  resource), policy: P, policy_version, state_version, validity interval }

The reduce() function derives the typed graph. The 5-way conceptual
separation ("I know this" vs "I claim this" vs "established under P" vs
"currently authorized" vs "actually happened") becomes predicate + state +
issuer typing on statements.

## Pending refactor (after REDTEAM-002)

`evidence.rs` currently uses CLAIMED/SUPPORTED/ESTABLISHED as the lattice.
Under TIG, the lattice becomes CLAIMED → ESTABLISHED → AUTHORIZED, with
SUPPORTED/REVOKED/EXPIRED/CONFLICT as evidence/statement lifecycle states
orthogonal to the axis. Do not refactor until the Statement model
converges.
