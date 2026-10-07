# REDTEAM-002 — kill-list for the Statement model

**Source:** Zackary's assessment, 2026-10-06. **Standing order: DO NOT
HARDEN YET.** Attack the model; harden only after independent convergence.

**Rating update:** Architecture 7 → ~8.5/10. Security implementation 4 →
~5/10. Protocol maturity 2–3 → ~4/10. Not from test count — from the
architecture surviving attacks without abandoning its ontology.

**Convergence criterion:** if all four attackers independently converge on
roughly the same remaining weaknesses, we have the beginnings of a real
protocol specification, not just a sophisticated Rust prototype.

**Round-2 results (2026-10-06):** deepseek full report + nemotron partial
both independently BROKE kill-target #1 (self-authority) with the same
exploit shape — CONVERGED. Full synthesis in CONSOLIDATION-002.md.

## The conceptual test

The Statement primitive must eventually let us express, distinctly:

- "I know this."
- "I claim this."
- "This has been established under policy P."
- "This is currently authorized."
- "This actually happened in physical reality."

Collapse of any two is a protocol bug.

## The 8 kill-targets

### 1. Statement self-authority
Can a statement with `issuer = Alice` establish that Alice is authorized
to issue statements? If yes, the original problem recurs one level down.
The primitive must distinguish "Alice said X" from "Alice was authorized
to say X." Those cannot collapse.

### 2. Genesis / trust-root problem
`previous = [0;32]` is a trust decision. Who says the first statement
belongs to this identity? If "the statement says so," we're back at the
start. Need an explicit genesis/trust-root model.

### 3. Sequence attacks
Duplicate / skipped / replayed sequence; same sequence + different parent;
same statement under different encoding; sequence reset after recovery;
overflow; branch merge; branch resolution. Core question: does sequence
belong to the statement, the subject, the chain, or the state epoch?

### 4. Canonical encoding attacks
Unicode normalization, empty fields, huge lengths, integer boundaries,
duplicate fields, reordered fields, unknown fields, version confusion,
signature in/out inconsistency, `ADHKEY/1/` prefix collisions, equivalent
semantics with different bytes. Requirement: one semantic statement →
exactly one canonical byte sequence. Not "normally the same bytes."

### 5. Signature substitution
Transplant a valid signature from Statement A onto Statement B via
ambiguity in what gets signed. Domain separation helps; want: signature =
exact canonical bytes + exact signing context, no hidden fields.

### 6. Issuer/key relationship
What mathematically binds issuer → authorized key → signature? And that
key to the relevant identity/history? Three independently-supplied fields
just moves the caller-controlled identity problem into the constructor.

### 7. Evidence recursion
A says "Bob is human." B: "Carol attests A." C: "Dave attests Carol."
What makes Carol trustworthy? Dave? Infinite regress with no trust root.
Need a termination condition.

### 8. Policy as a statement
`establish(..., policy_satisfied: bool)` was bullshit; a signed
"policy-satisfied" statement is the same bullshit with a signature.
Distinguish policy EVALUATION from ASSERTION of evaluation. Want:
Inputs → Policy P → deterministic eval → Verdict V → signed evaluator
receipt binding exact input statement IDs, evidence IDs, policy
version/hash, state version, evaluator identity, evaluation time, validity
interval.

## Round-2 targets

- `crates/adhkey-statement/src/lib.rs` (the Statement model)
- `DOCTRINE.md` (four permanent doctrines)
- This kill-list

## 10. Weight laundering via traversal priority (from TIG idea #1)

Weight "only controls graph traversal priority for the witness collector."
Priority is influence. Attack: can an adversary manipulate weights to bias
which witnesses get collected — starving the collector, steering it toward
attacker-controlled witnesses, or timing out legitimate witness paths?
If priority affects WHICH evidence gets evaluated under time bounds, weight
has a covert promotion channel. The "epistemic firewall" must hold under
adversarial scheduling, not just in the algebra.

## 11. Invalidation race — TOCTOU on revocation (from TIG idea #2)

"Terminates leases instantly / same clock cycle" is not a distributed
primitive. Attack: lease checked between revocation commit and traversal
completion = live authorization on dead authority. What is the actual
synchrony bound? If invalidation is traversal over dependents, cost is
O(dependents), not O(1) — the O(1) claim needs a mechanism (reverse index?
eager lease binding?). Unless lease USE re-checks witness status at
exercise time, there is a window. Specify the bound or the claim is
theater.

## 12. Ghost clumping + one weak witness (from TIG idea #3)

The firewall holds against PURE heuristic attack. Attack: adversary runs
ghost clumping AND forges one weak witness type the policy accepts (email
OTP, SMS, self-asserted OAuth). Clumping manufactures the candidate;
the weak witness manufactures the promotion. The composition is the real
threat model — policies, not heuristics, become the target. Which witness
types may a HIGH-assurance policy accept? The answer belongs in the
protocol, not in each deployer's head.

## 13. EQL tier confusion (from TIG idea #4)

The query planner is now a trust boundary. Attack: query declares
{tier:'ESTABLISHED'} but receives CLAIMED edges — via planner bug, default
tier, tier parameter injection, or a confused-deputy view. If tier is a
string parameter, it is attacker-influenced input to a security decision.
The tier must be enforced in the type system or bound into a signed query,
not passed as a string.

## 14. Primitive composition seams (from TIG idea #5)

id/re/evd/po/au/st meet at interfaces; each seam needs an invariant.
Sharpest: `au` (authority evaluator) grants E_authorized from "an
E_established subgraph" — who constructed the subgraph? A
caller-constructed subgraph fed to the evaluator is doctrine #1 violated
at the seam (no claim derives authority from its own existence). The
evaluator must reduce the subgraph from the log itself, or the subgraph
must carry its own authentication. Enumerate every seam and its invariant.

## 9. CLAIMED → ESTABLISHED laundering (added after round-2 dispatch;
for the consolidation)

The TIG design says a heuristic score of 0.97 generates a candidate
relationship, never evidence. Attack: can a CLAIMED edge (predicate
ProbablySameAs, issuer = heuristic engine) be consumed by the evidence
evaluator or the establishment path as if it were a SUPPORTED_BY edge?
Concretely: does any code path treat `evidence: [heuristic-run-ref]` as
satisfying an evidence requirement, or treat a high heuristic score as a
policy input? Promotion must require NEW evidence statements from
authorized witnesses, never a re-interpretation of the CLAIMED statement.
This is doctrine #5's sharp edge.

Attackers: deepseek (round 2), nemotron-550b (round 2), NIM (statement
brief, queued). Mistral lane dead (402).
