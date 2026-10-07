# AdhKey — ontological audit (the 22 cuts)

**Source:** Zackary's red-team critique, 2026-10-06. Filed verbatim in
spirit. **Verdict: 4/10 security prototype, 7/10 architectural sketch,
2/10 portable identity protocol.** Do NOT implement AUDIT.md C1→C10 yet —
would harden the wrong abstraction. Renamed: **AdhKey 0.2 — experimental
identity continuity and evidence protocol.**

## The four permanent Court doctrines

Carved into the repository. Every future design and implementation answers
to these:

1. **NO CLAIM MAY DERIVE AUTHORITY FROM ITS OWN EXISTENCE.**
2. **NO LOCAL STATE MAY CLAIM TO KNOW A REMOTE FACT WITHOUT A WITNESS,
   VERSION, AND FRESHNESS BOUND.**
3. **CONTROL OF A KEY ≠ IDENTITY OF A HUMAN.**
4. **MULTIPLE ATTESTATIONS ≠ INDEPENDENT ATTESTATIONS.**

## The 22 cuts (condensed)

1. **Identity is a mutable bag of asserted reality.** `pub struct Identity`
   can be constructed by anyone; no distinction between observed and
   asserted state. Comments claim authority; the type system says struct.
2. **History isn't history.** `Vec<Event>` is a mutable vector claiming
   to be history. Need: Event → canonical bytes → prev hash → issuer
   signature → sequence → AuthenticatedEvent; history RECONSTRUCTED from
   events: EventLog → reduce() → DerivedState.
3. **TOCTOU identity machine.** ESTABLISHED at T0, revoked at T2, executed
   at T3. Need VALID_AT vs VALID_DURING vs AUTHORIZED_FOR_EXECUTION.
4. **KeyId(pub String) underspecified.** Label, not identity. Decide:
   handle vs fingerprint vs content-id vs verification-method ref.
5. **Subject(pub String) same disease.** Namespace-local string; nothing
   mathematically connects Exchange's S1 to Government's S1.
6. **EvidenceKind enum is premature ontology.** Baking a worldview into
   the protocol. Evidence should be {artifact, issuer, subject, predicate,
   validity, provenance}; policy decides meaning.
7. **evaluate_claim() is almost fake.** "Evidence exists → Supported."
   No real evidence evaluator: validate provenance/issuer/subject
   binding/predicate/temporal validity/revocation → signed verdict.
8. **Witness isn't a witness.** Metadata, not attestation. Needs: WHO,
   WHAT, WHEN, UNDER WHICH AUTHORITY, WITH WHICH KEY, OVER WHICH BYTES.
9. **Recovery not atomic.** Mutate-mutate-mutate-hope. Need:
   validate → construct next state → commit once.
10. **approvals: usize destroys provenance.** Need RecoveryAuthorization
    {event, signer, key, signature, policy_version, evidence_snapshot}.
11. **No Byzantine model.** k-of-n is not enough: need independence
    assumptions, trust domains, time delay, notification, revocation.
    Threshold crypto ≠ trustworthy humans.
12. **Sybil collapse.** Five witnesses controlled by one attacker look
    great. Need: witness count × trust-domain diversity × independence ×
    continuity × acquisition cost × contradiction rate.
13. **"Human" is not one predicate.** is_person / controls / holds_credential
    / represented_by / authorized_by / was_present_at — policies compose
    predicates; is_human(S) is almost useless.
14. **No consensus story — and that's fine.** Don't solve revocation;
    REPRESENT the impossibility: CURRENT (witness W, version V, Δ) vs
    AS_OF(V) vs UNKNOWN. Offline honesty beats false freshness.
15. **Receipt is theater.** Must answer: WHAT BYTES, WHAT POLICY, WHAT
    STATE SNAPSHOT, WHAT KEY, WHAT SIGNATURE, WHAT WITNESS, WHAT TIME,
    WHAT VERSION — and **WHAT WAS NOT CHECKED**. Incomplete receipts
    manufacture confidence.
16. **Verifier too monolithic.** Decompose: Envelope → Structural →
    Signature → KeyState → SubjectBinding → Temporal → Replay → Policy →
    Evidence → Verdict. Each emits evidence; verdict is derived.
17. **Crypto footgun.** `signing_key_from_seed` + "randomness is caller's
    job" invites `[0u8; 32]`. Provide `generate()` (CSPRNG) + explicit
    low-level `from_seed()`.
18. **Ed25519-only premature.** Need SignatureSuite/PublicKey/Signature/
    KeyReference abstraction + capability negotiation. Don't build ten
    algorithms; make the boundary correct.
19. **Capability isn't signed.** No issuer, signature, algorithm, version.
    "Signed capability" is currently a comment — a semantic lie.
20. **No domain separation.** Need ADHKEY/1/CAPABILITY, /RECOVERY,
    /IDENTITY-EVENT, /WITNESS, /RECEIPT prefixes before signed payloads.
21. **Serialization is cryptographic object identity.** Without canonical
    encoding: same statement ≠ same bytes ≠ same signature. Nail before
    adapters.
22. **Statement is the missing atomic object.** Subject/predicate/object
    + issuer/evidence/policy/timestamp/state/signature. Key registration,
    human claim, recovery, witness, authorization, revocation — same
    primitive, different predicate. Graph-native, not key-manager-with-
    aspirations.

## The architecture to build

```
ADHKEY → STATEMENTS + KEYS → EVIDENCE → WITNESS → HISTORY → POLICY
       → VERDICT → CAPABILITY
```

Core: Statement, Event, Subject, KeyRef, EvidenceRef, PolicyRef, Verdict.
Around it: KeyStore, Witness, StateStore (adapters produce evidence;
policy decides what it establishes).

## Status

Design target acquired. Implementation 0.2.0 does not match it.
Next: Statement-primitive redesign (mine) + 4 external LLM attacks (this
order) before any hardening.
