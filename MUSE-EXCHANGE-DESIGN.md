# muse-exchange — design

**Status:** DESIGN + first organelle IMPLEMENTED (`luci-context`).
**Source:** Zackary's research filtration, 2026-10-06.

## Thesis

Muse (or Claude, Codex, Qwen, a local model) is a **disposable worker**:
high-quality temporary cognition attached to a persistent evidence
machine. The exchange is the local gateway between the model and
LUCIDOTA. Cognition is replaceable; evidence is durable; authority is
explicit.

## Architecture (REVISED 2026-10-06: sovereign organelle spec)

One daemon-less Rust binary. Embedded SurrealDB (`SurrealKv`) — no
external daemon, zero-latency epistemic graph access, pure local
sovereignty. The pt-absurd workflow engine pattern drives hook
interception and verdict routing.

```rust
use surrealdb::engine::local::{Db, SurrealKv};
use surrealdb::Surreal;
use std::sync::Arc;

pub enum AuthorityVerdict { Authorized, Unknown, Denied }

pub struct ContextPointer {
    pub hash: String,       // CAS pointer
    pub claimant: String,   // exact actor identity: "zackary", "lucidota",
                            // "subagent:g1-a", "worker:nim-claimant-01" ...
                            // NEVER collapsed into source. First-class
                            // epistemic property for multi-agent provenance.
    pub source: String,     // system | user | discovered | external (trust domain)
    pub necessity: String,   // required | optional | irrelevant
    pub verdict: i8,         // +1 | 0 | -1
}

pub struct MuseExchange { db: Arc<Surreal<Db>> }

impl MuseExchange {
    pub async fn init(path: &str) -> surrealdb::Result<Self> {
        let db = Arc::new(Surreal::new::<SurrealKv>(path).await?);
        db.use_ns("lucidota").use_db("epistemic_graph").await?;
        Ok(Self { db })
    }

    /// PreToolUse interception: query the temporal graph for authority.
    pub async fn handle_pre_tool_use(
        &self, tool: &str, _capabilities: Vec<&str>,
    ) -> AuthorityVerdict {
        // SELECT verdict FROM lifelog_edge
        //  WHERE edge_kind = 'authorizes'
        //    AND out = type::thing('tool', $tool)
        //  ORDER BY valid_from DESC LIMIT 1;
        // verdict == 1 -> Authorized; == -1 -> Denied;
        // _ -> Unknown (triggers evidence-gathering DAG)
    }

    /// Lossy projection theorem as a graph query: evict irrelevant and
    /// disproven, return only safe CAS pointers.
    pub async fn resolve_context_budget(
        &self, task_hash: &str,
    ) -> Result<Vec<ContextPointer>, ProjectionError> {
        // SELECT hash, claimant, source, necessity, verdict FROM lifelog_edge
        //  WHERE in = type::thing('task', $task_hash)
        //    AND necessity != 'irrelevant' AND verdict != -1;
        //
        // The lossy-projection check is claimant-aware: when a required
        // edge is still verdict 0 (unknown), the error names the exact
        // claimant(s) that failed to provide evidence, so the
        // evidence-gathering subtask knows who to interrogate or re-run.
        // Err(ProjectionError::LossyProjection(Vec<String> of claimants))
    }
}
```

## Workflow routing

- **Authorized:** pass the tool execution; call
  `resolve_context_budget()` to feed the worker exactly the verified
  CAS hashes it needs. The model never sees unprojected context.
- **Denied:** block immediately; append a disproven/unauthorized
  receipt to ~/ledger/.
- **Unknown:** pause the hook (Defer — not a failure); dispatch a
  sub-task to the tentacle-build-order DAG orchestrator to gather
  evidence, answer the missing authority parameters, and update the
  graph. The orchestration layer never treats an epistemic gap as a
  hard systemic failure.

## SurrealDB schema (lifelog_edge)

Phase 3 DDL (`graph-recalibration/lifelog-epistemic-schema.surql`):

```surql
DEFINE TABLE lifelog_edge SCHEMAFULL;
DEFINE FIELD in          ON lifelog_edge TYPE record;
DEFINE FIELD out         ON lifelog_edge TYPE record;
DEFINE FIELD edge_kind   ON lifelog_edge TYPE string
    ASSERT $value IN ['claims','observes','verifies','authorizes','executes'];
DEFINE FIELD hash        ON lifelog_edge TYPE string;   -- CAS pointer
DEFINE FIELD source      ON lifelog_edge TYPE string
    ASSERT $value IN ['system','user','discovered','external'];
DEFINE FIELD claimant    ON lifelog_edge TYPE string
    ASSERT $value != NONE;   -- exact actor identity; never collapsed into source
                             -- e.g. "zackary", "lucidota", "subagent:g1-a",
                             -- "worker:nim-claimant-01" 
DEFINE FIELD necessity   ON lifelog_edge TYPE string
    ASSERT $value IN ['required','optional','irrelevant'];
DEFINE FIELD verdict     ON lifelog_edge TYPE int
    ASSERT $value IN [-1, 0, 1];
DEFINE FIELD receipt_id  ON lifelog_edge TYPE string;   -- chain of custody
DEFINE FIELD valid_from  ON lifelog_edge TYPE datetime;
DEFINE FIELD valid_to    ON lifelog_edge TYPE datetime;
DEFINE INDEX idx_edge_kind    ON lifelog_edge FIELDS edge_kind;
DEFINE INDEX idx_edge_verdict ON lifelog_edge FIELDS verdict;
DEFINE INDEX idx_claimant      ON lifelog_edge FIELDS claimant;  -- O(1) multi-agent provenance traversals
```

Every edge pinned to a `receipt_id`: claims(A) → observes(B) →
verifies(C) → authorizes(D) → executes(E) is a cryptographic chain of
custody, walkable backward in O(1) to the exact epistemic failure.

## Organelles

### muse-exchange (BUILDING — the flagship)

The binary above. Replaces the earlier luci-muse-guard sketch: the
guard is not a separate organelle, it is this organelle's
`handle_pre_tool_use`. Uses luci-verdict-core (Unknown→Deferred) and
luci-context (projection semantics) as libraries.

### luci-context (BUILT, v0.1.0)

Epistemic context cache. Items tagged truth (+1/0/-1) x source
(system/user/discovered) x necessity (required/optional/irrelevant).

- `compress()`: original bytes -> CAS, item keeps summary + hash +
  length. Relocated, not destroyed. Byte-range dereference
  ("bytes 17,402-18,910 of the original").
- `evict()`: scored by safety, safest first. Required never evicts.
  Proven facts kept visible; disproven trivia drops first — but its
  hash stays recorded.
- `project()`: evict to a char budget. Every eviction is CAS-backed
  and reversible. Sets `unknown_introduced` honestly when anything
  Optional+ or Proven/Unknown left the visible set:
  LOSSY_PROJECTION = UNKNOWN, retrievable via the evicted records.

### luci-muse-guard (DESIGNED, not built)

Tiny Rust organelle on Muse's PreToolUse hook. Receives tool,
arguments, session, thread, workspace. Asks the local authority
service: WHO? WHAT? WHY? WITH WHAT CAPABILITY? BASED ON WHAT
EVIDENCE? IS IT FRESH? IS IT ALLOWED? Outputs ALLOW / DEFER / DENY.
DEFER is not DENY — the ternary permission model (AUTHORIZED /
UNKNOWN / DENIED), where UNKNOWN requests evidence.

### Authority verifier (luci-verdict-core — BUILT)

Already exists: CLAIMED -> ESTABLISHED -> AUTHORIZED with UNKNOWN
propagation. The exchange routes every capability grant through it.

## Benchmark axis: intelligence per byte

```
verified useful decisions
─────────────────────────
bytes + compute + latency
```

Token minimization alone misleads (research: 1/3 the tokens, 20-80%
slower). Measure decisions per byte, not tokens per task.

## Receipt-based memory

Agent work leaves TASK RECEIPTS (input hash, context hashes, tools,
capabilities, files, tests, observations, claims, verdicts,
artifacts), not transcripts. Tomorrow's worker needs `receipt: 7f31…`
plus selective dereference through luci-context — memory as a
content-addressed evidence graph.

## Capability-aware context

The exchange never shows a worker information it isn't authorized to
use. Observations are an authorization boundary (cf. Cloudflare
Gatekeeper pattern). Context tags carry the authority stage; the
verdict core enforces it.

## Build order

1. luci-context — DONE.
2. muse-exchange organelle — BUILDING NOW (flagship): the binary above,
   SurrealDB DDL, hook wiring, defer→evidence-subtask routing.
3. Wire luci-context into the receipt pipeline (task receipts as
   cache items).
4. Trigger-equivalence probe harness vs governor gates.
5. Intelligence-per-byte benchmark harness.

## Non-goals

- Not another MCP server. The ecosystem has those.
- Not coupling to the consumer app's connector layer; build against
  documented extension points (hooks, MCP, plugins, SDK).
- The model is never the system of record. Ever.
