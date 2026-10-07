# Failure Shape MCP — design (with ReasoningTrace)

**Source:** Zackary's design, 2026-10-06. **Status:** v0.2.0 BUILT +
selftested. Server: `~/workspace/mcp-servers/failure-shape/server.py`.

## Architecture

```
ATT&CK / CAPEC / CWE (external canonical memory, via mitre-mcp sidecar)
        │
        ▼
Failure Shape Organelles (THIS server — what LUCIDOTA learned)
        │
   ┌────┼────┐
   ▼    ▼    ▼
CLAIMED ESTABLISHED CONFLICT → AdhKey Court → Defense Rule
```

ATT&CK tells you what the world knows. This remembers what the system
has personally learned. ATT&CK/CAPEC refs are mapping assertions by the
proposer — the server never speaks for MITRE.

## ReasoningTrace (v0.2.0)

Not raw CoT as a protocol primitive. A public, auditable reasoning
representation:

```
ReasoningTrace {
    hypothesis, observations[], inferred_shape,
    evidence_refs[], counterevidence_refs[], assumptions[],
    competing_hypotheses[], confidence, decision, policy_ref
}
```

Pipeline: WORLD → EVENTS → OBSERVATIONS → FAILURE SHAPES →
REASONING/RATIONALE → EVIDENCE → VERDICT → DEFENSE → NEW OBSERVATION.

Division of labor:
- **AI gets cognition:** shapes, hypotheses, explanations, correlations,
  counter-hypotheses.
- **Deterministic machinery decides:** what evidence exists, what
  signatures verify, what witnesses are independent, what policy applies,
  what authority follows.
- **Court gets adversarial pressure:** challenges against the trace
  itself (EVIDENCE_CORRELATED, EVIDENCE_STALE, WITNESS_NOT_INDEPENDENT,
  OVER_GENERALIZATION, MISSING_FALSIFIER, ASSUMPTION_UNSTATED,
  COMPETING_HYPOTHESIS_IGNORED).
- **MCP gets interoperability.** **Ledger gets memory.**

The reasoning itself is attackable: Court takes H → E1,E2,E3 → I → V and
asks "what if E2 is correlated?" / "what observation would falsify H?" —
producing reasoning regression tests. Remember the shape of failures AND
the shape of successful reasoning about failures.

## Epistemic enforcement (server-side)

- propose → CLAIMED only. Heuristics allowed to be wrong.
- establish → requires evidence_refs + witnesses with
  independence_class + policy_hash. A heuristic generator can never be a
  witness (doctrine #5, type-level).
- defend → requires ESTABLISHED.
- attack(REFUTES) → CONFLICT, never direct to REVOKED.
- revoke → requires reason + witness.
- All transitions append parent-chained content-addressed versions.
  No mutation, no delete.

## Seed data (real incidents)

- FS: future-dated freshness bypass — ESTABLISHED, defended, regression
- FS: nonce exhaustion — ESTABLISHED, defended, regression
- FS: unbound recovery approvals — ESTABLISHED (open)
- FS: statement self-authority — ESTABLISHED (open, converged)
- FS: ghost clumping — CLAIMED (heuristic)

ATT&CK/CAPEC mappings pending mitre-mcp sidecar lookup (not hallucinated).
