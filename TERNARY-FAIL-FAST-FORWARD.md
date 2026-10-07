# Ternary Fail-Fast-Forward

The swarm scaling law. Named by Zackary, 2026-10-07.

## Thesis

Scaling to hundreds or thousands of disposable cognitive workers does not
require choosing between safety and throughput. The epistemic graph IS the
concurrency control. Ternary logic (Proven / Unknown / Disproven — never
binary) turns the authority pipeline into a high-throughput gate:

- **Disproven (−1):** instantly prunes a dead-end swarm branch in O(1).
  No consensus debate, no wasted tokens. Kill the path, log a receipt.
- **Unknown (0):** instantly defers the operation, fires a targeted
  evidence-gathering subtask, and shifts the worker forward to a parallel
  orthogonal task. The thread never hangs.
- **Proven (+1):** instantly promotes the node past the epistemic wall
  to Established and Authorized.

## Why it scales

1. **No statistical consensus soup.** Workers never vote on truth.
   The graph holds verdicts; workers produce claims. A thousand agents
   flooding the system with Claimed edges is the DESIRED state — claims
   are cheap, verdicts are authoritative.

2. **No error compounding.** A wrong hypothesis dies at the first
   Disproven edge instead of propagating 17x across the mesh. The
   receipt chain marks exactly where the branch died.

3. **Zero trust leakage at velocity.** No heuristic score, however high,
   can mutate state or cross the authority boundary on its own. The
   swarm is raw compute (disposable workers); muse-exchange and
   luci-verdict-core are the non-negotiable kinetic stopgaps.

4. **State compression for swarm memory.** Workers never pass around
   transcripts. Every agent drop compresses to a CAS pointer; every
   task shift leaves a cryptographic TaskReceipt. The swarm scales
   horizontally because memory is content-addressed and stateless.

## Corrections (Zackary, 2026-10-07)

- **No daemon.** There is no background process watching an evidence
  queue. Evidence subtasks are graph nodes with `needs_evidence` edges;
  workers pull them via the Exchange `/v1/claim` mechanism. The
  Exchange IS the queue.
- **No LLMs as determinism theater.** Ternary verdicts come from
  deterministic graph queries, never from asking a model whether
  something is proven. LLMs generate claims; the graph decides.
- **NVIDIA NIM is the validator.** Verification = execute the claim
  against NIM (run the code, check the output hash) and record the
  outcome. Deterministic verdict from execution, not from model opinion.
- **Everything is a graph.** Tasks, evidence, workers, verdicts — all
  nodes and edges. Durable (SurrealDB + CAS + receipts), fast
  (embedded, zero-latency), ruthless (ternary pruning).

## The honest gap (2026-10-07)

The current subagent swarm does NOT run through this pipeline yet.
Coordinators are spawned with free-form prompts; they emit no Claimed
edges, receive no ternary verdicts, leave no TaskReceipts. The
epistemic transmission exists for tool calls but not for the swarm
itself. Closing this gap is the dogfood lane: swarm tasks as Exchange
jobs, workers as subagent-spawning claimants, outcomes as ternary
receipts.

## Invariants

- A worker's claim never raises its own epistemic status.
- Unknown is a routing signal, not a failure.
- Every pruned branch leaves a receipt (the swarm learns what died).
- The graph is the only shared state; workers are stateless.
