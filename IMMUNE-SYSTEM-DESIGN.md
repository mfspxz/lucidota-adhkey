# Identity Immune System — design

**Source:** Zackary's synthesis, 2026-10-06. Status: DESIGN / RESEARCH.
Do not implement. The cryptographic primitives below (linkability tags,
triple-tree epoch commits) are research items, not build orders.

## The Monero insight

Monero's key-image mechanism: ring signatures hide which member signed,
but a deterministic key image lets everyone detect the same underlying
spend attempted twice. The network sees the image, doesn't learn the
signer, rejects the duplicate.

The pattern:

```
private key
    ├──► anonymous signature
    └──► deterministic key image ──► public uniqueness
```

Privacy and linkability are not mutually exclusive: the protocol exposes
a derived public artifact enabling a specific security property without
exposing the underlying secret.

## The identity version

```
root secret
    ├──► pseudonymous action signature
    └──► accountability/linkability tag ──► public reputation state
```

Actions: anonymous/private to ordinary observers, linkable to the same
accountable identity when the protocol's rules require it.

Three identity classes simultaneously:

1. **Private identity** — "I can prove I'm the same actor."
2. **Public pseudonymous continuity** — "Others recognize this is the
   same actor as before."
3. **Conditional disclosure** — "Under authorized investigation/policy,
   this pseudonym resolves to the underlying identity."

A spectrum between total anonymity and total surveillance, with the
linkability tag as the derived artifact that makes accountability
possible without identification.

## Triple-tree epoch commits

Three independent Merkle structures, committed together per epoch:

```
IDENTITY ROOT
    ├── IDENTITY TREE   (who/keys)
    ├── ACTION TREE    (what happened)
    └── REPUTATION TREE (consequences)

EPOCH_COMMIT = H(domain || identity_root || action_root
                 || reputation_root || previous_epoch_commit)
```

An authenticated state machine with accountability memory. Not
"blockchain identity" — the chain is a witness to history (per the
evidence-graph design), and here it witnesses three orthogonal roots at
once so identity, action, and consequence can't be rewritten independently.

## XRPL mapping

XRPL distinguishes candidate/unvalidated ledgers from validated immutable
ledger versions; a ledger hash identifies exact state, validator agreement
makes versions authoritative. Maps onto:

- CLAIMED → ESTABLISHED → AUTHORIZED (candidate → validated)
- CURRENT → AS_OF → UNKNOWN (authoritative version → historical version
  → no version)

## Irreversible evidence, reversible authority (DOCTRINE #6)

If Alice cheats: identity continuity survives, historical record survives,
violation statement survives, reputation is damaged, authority is
revoked/quarantined.

What the protocol must NOT do: turn one established violation into
permanent global condemnation with no appeal — then the immune system is
an authoritarian weapon.

Preserve: "This event was established under policy P at version V."
Never hard-code: "This human is evil forever."

**Immutable history, not immutable sentencing.** Probably the most
important constraint in the system. Sentencing (authority decisions) must
remain revisable; only the evidence record is permanent.

## Agent lineage and the Sybil problem

Killing the key doesn't work: the operator mints Agent B, C, D, E and
resets reputation. Instead preserve `derived-from` provenance:

```
Agent B ──derived-from──► Agent A (compromised)
```

Heuristic layer: "B ≈ A (0.93)" → CLAIMED. Evidence (same hardware
attestation, same recovery authority, same org witness, same signed
lineage) → ESTABLISHED. Policy (A's violations transfer under P) →
QUARANTINED.

This is where the TIG heuristic layer earns its place: aggressive
lineage discovery with no path to authority except through evidence.

## Architecture fit

```
Statement → Evidence → Witness → Identity Graph → Reputation
    → Policy → Capability → Execution → Receipt → Violation
    → Quarantine → Memory
```

An immune system for computational society. The scar is the
linkability tag + violation statement: durable, publicly detectable,
cryptographically bound to continuity — without exposing the underlying
identity or fixing the sentence.

## Research items (not build orders)

1. Linkability-tag scheme: deterministic, non-identifying, double-use
   detectable. Survey Monero key images, DAA (direct anonymous
   attestation), rate-limiting nullifiers.
2. Triple-tree epoch commit format and witness protocol.
3. Reputation-tree semantics: what is a "reputation leaf"? Who writes it?
   (Probably: signed violation/commendation statements, policy-evaluated.)
4. Conditional disclosure mechanism: who holds the trapdoor, under what
   policy does it open, what is the audit trail of openings?
5. Appeal/revision path for authority decisions (sentencing revisability).
