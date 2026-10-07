# Rare-Signal Systems Engineering

**Source:** Zackary's cross-domain synthesis, 2026-10-06. Status: DESIGN.
Filed as the canonical framing above the MCPs — "it gives the MCPs a
reason to exist rather than making them the architecture."

## The name

> Rare-Signal Systems Engineering: finding consequential structure in
> hostile, incomplete, noisy, deceptive, and massively larger search
> spaces.

## The common problem (not "security")

> There is a hidden state of the world. You receive imperfect
> observations. Most observations are uninteresting/noisy. Some are
> misleading. A tiny subset is disproportionately consequential. You need
> to decide what deserves investigation without fooling yourself.

```
HIDDEN REALITY → SIGNAL/NOISE → imperfect observation
    → candidate anomaly → investigate/discard
    → independent evidence → structural explanation
    → action/decision → feedback
```

## Cross-domain primitives (each field reinvented part of this)

- **Uranium exploration:** EM anomaly ≠ uranium. Prospectivity =
  EM + geological position + unconformity + structure + alteration +
  geochemistry + evidence. Multi-modal model, not single signal.
- **Nonconformity (geology):** the meaningful object is a *relationship*
  — a boundary between regimes that shouldn't be interpreted
  independently. Generalizes: official story ≠ documents (journalism),
  declared invariant ≠ observed behavior (software), claimed authority ≠
  actual authority (security), expected occupancy ≠ observed detections
  (fisheries), replica A says X / replica B says ¬X (distributed
  systems), system claim ≠ adversarial result (Court).
- **Negative evidence:** weak/negative radiometrics don't preclude
  uranium at depth. Need P(detect X | X exists, instrument, depth,
  conditions) — detectability.
- **Fisheries:** absence of observation ≠ absence of organism. Model
  occupancy + detection probability; detection varies with conditions,
  gear, observer, behavior. Primitive: **OBSERVABILITY** —
  OBSERVED / NOT OBSERVED / UNOBSERVABLE / PARTIALLY OBSERVABLE /
  DEGRADED, with detection_model, instrument, coverage, conditions,
  sampling_method attached.
- **Journalism:** hypotheses as suspicion attacked by evidence; actively
  seek refuting evidence. Source independence: two reporters citing one
  source = one witness. → **INDEPENDENCE GRAPH**: evidence counted by
  independence roots, not cardinality.
- **Military (OODA):** observe→orient→decide→act→environment changes→
  observe. Adversarial: my action changes your observation. Court becomes
  "the environment the defender learns against."

## Target hypothesis (not anomaly detection)

Anomaly = "this is unusual" (too weak; unusual is often harmless).
Target = unusual + structurally meaningful + explainable +
independently supported + decision-relevant.

```
ANOMALY → why unusual? → candidate explanation
    → what should we observe if true? if false?
    → collect discriminating evidence → update belief
```

## Information gain (missing primitive)

With 10,000 collectible observations, ask: which next observation most
efficiently separates the competing hypotheses? (H1: uranium / H2: benign
conductor / H3: artifact → choose EM vs drill vs assay by information
gain.) Same in journalism (one document distinguishing corruption from
incompetence) and software (one observation distinguishing race from
stale cache from auth bug).

## The 14 inference operations

1. Observe — acquire information.
2. Characterize — what exactly was observed?
3. Measure detectability — how likely missed/distorted?
4. Generate hypotheses — what explanations could produce it?
5. Predict — what should we observe under each hypothesis?
6. Seek discriminating evidence — which next observation reduces
   uncertainty most?
7. Corroborate — does an independent channel agree?
8. Establish — what can be promoted from hypothesis to fact?
9. Abstract — what reusable shape explains the event?
10. Act — what should be done?
11. Observe consequences — did the action produce the predicted result?
12. Update — change the model.
13. Preserve provenance — don't lose how you got there.
14. Attack the model — try to falsify it.

## Layer stack

```
COMPUTER PRIMITIVES → INFORMATION → OBSERVATION → INFERENCE
    → DECISION → ACTION → FEEDBACK
```

## New first-class object: NONCONFORMITY

Not every weird thing is a failure. Before FailureShape:

```
NONCONFORMITY {
    expected_state, observed_state, delta,
    observation_method, detectability, context,
    candidate_explanations[], evidence[], independence,
    severity, persistence, novelty, consequence
}
```

```
NONCONFORMITY → investigation → Failure Shape
```

## The generalized needle-finding engine

```
REALITY → OBSERVATION → NONCONFORMITY → HYPOTHESIS SPACE
    → EXPECTED vs ALTERNATIVE models → DISCRIMINATING OBSERVATION
    → EVIDENCE → INDEPENDENCE CHECK → ESTABLISHMENT
    → PROJECT SHAPE / FAILURE SHAPE → COURT → ADVERSARY
    → ACTION → RESULT → NEW OBSERVATION → ↺
```

The uranium geologist, fish ecologist, investigative journalist,
intelligence analyst, incident responder, fraud investigator, and
adversarial engineer are all solving: find a small consequential
structure inside a huge, noisy, partially observable, potentially
deceptive information field — without confusing the model with the thing.
