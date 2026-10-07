# LANE B — Flagship Integration Report

**Date:** 2026-10-07 (UTC)
**Scope:** `muse-exchange` + `luci-verdict-core` + `luci-context` (+TaskReceipt), end to end.
**Status:** COMPLETE. 111/111 workspace tests green, zero warnings.

## What was integrated

### 1. Structural verdict integration (the weak joint, rebuilt)

**Before:** `handle_pre_tool_use` ran a raw graph query and mapped the
verdict integer directly to `AuthorityVerdict` via `from_verdict`.
The luci-verdict-core dependency was nominal — the enum mapped, but the
pipeline never ran.

**After:** `adjudicate_pre_tool_use()` fetches the full `authorizes` edge
(verdict, claimant, source, hash, receipt_id, validity window) and builds
a real `VerdictInput` for `luci_verdict_core::pipeline::adjudicate()`:

- `Claimed<Identity{tool}>` — the tool call as a cheap claim
- `Envelope` — subject=tool, audience=muse-exchange, operation=execute,
  request_hash=hash(tool_input), evidence_hash=edge hash,
  previous_receipt_hash=edge receipt_id, validity from the edge's window
- `EvidenceSet` — one `Witness{id: claimant, trust_root: source}` per edge
- `PolicyInput` — 1 independent witness required; policy_satisfied from
  the graph verdict (+1→Proven, −1→Disproven, else Unknown)
- `crypto: Valid` — the local embedded graph IS the system of record
- `activation` — driven by the graph verdict

Pipeline verdict maps: Authorized→Authorized, Denied→Denied,
Deferred→Unknown. The no-edge case runs a minimal deferred input
(zero witnesses → Deferred at the evidence stage) so the pipeline stays
the single decision point.

**Semantics preserved through the pipeline:**
- +1, fresh envelope, bound request, 1 witness → Authorized
- −1 → Denied at the Policy stage (terminal)
- 0 / missing → Deferred at Evidence/Policy (Unknown, not failure)
- +1 with expired `valid_to` → Denied at Freshness (new test proves it:
  a stale envelope can never authorize, even with a +1 verdict)

### 2. TaskReceipt closes the loop

New `MuseExchange::record_execution()`: stores the `TaskReceipt` in the
`EpistemicCache` (canonical bytes → CAS, Required/system record) and
appends a ledger entry binding the receipt hash to the verdict chain.
Returns the receipt hash — the resume address. The full flow is now:

`PreToolUse → adjudicate (verdict-core) → resolve_context_budget
(claimant-aware, luci-context) → execution → TaskReceipt → ledger`

### 3. Claimant-aware projection (carried forward)

`resolve_context_budget` returns `Result<Vec<ContextPointer>,
ProjectionError>`; required+unknown edges produce
`LossyProjection{claimants}` naming the exact failing actors, and
`route()` defers with a claimant-targeted evidence subtask.

## Test counts

| Suite | Tests | Result |
|---|---|---|
| muse-exchange lib | 4 | ✅ |
| exchange_tests (existing, now through pipeline) | 8 | ✅ |
| integration_flow (new: full flow, unknown→evidence→authorized, denied terminal, stale envelope) | 4 | ✅ |
| dogfood_binary (new: live binary stdin/stdout, 3 ternary paths) | 1 | ✅ |
| luci-verdict-core (lib + integration) | 25 | ✅ |
| luci-context | 15 | ✅ |
| adhkey-statement | 23 | ✅ |
| adhkey-core | 31 | ✅ |
| **Workspace total** | **111** | ✅ 0 failed |
| Compiler warnings | 0 | ✅ |

## Dogfood (live binary)

`tests/dogfood_binary.rs` spawns the compiled `muse-exchange` binary:
hook JSON on stdin → decision JSON on stdout. All three ternary paths
verified through the real binary (approve / block+DENIED+ledger /
block+DEFERRED+subtask), including side effects (ledger entry, evidence
subtask file).

## Live Exchange interception

12-job ternary matrix submitted in parallel to the live governor
(`lane-b-ternary-*`, one per tool×path): 10 accepted and delegated,
2 rejected with 429 — backpressure working as designed under burst.
All 10 accepted jobs executed to `done` with `['deferred', 'ok']`
receipts via the 4 drain-loop claimants. Jobs carry the ternary test
vectors as payload; receipts record the integration run in the
governor's chain. $0 (all tiny inference).

## Weak joints found and rebuilt

1. **Nominal verdict-core usage** → structural `adjudicate()` integration.
2. **Open execution loop** → `record_execution()` binds TaskReceipt to ledger.
3. **SurrealDB ORDER BY on unprojected field** → order by projected unix alias.
4. **Stale envelopes could theoretically authorize** → freshness stage denies.

## Honest gaps

- The `route()` Unknown path still writes evidence subtasks as JSON files;
  the graph-native evidence-task flow (Zackary's correction) belongs to
  the dogfood lane, not this integration.
- `crypto: Valid` is asserted for local graph reads — correct for the
  embedded DB, but a remote-graph deployment would need real attestation.

## Files

- `crates/muse-exchange/src/lib.rs` — adjudication + record_execution
- `crates/muse-exchange/tests/integration_flow.rs` — 4 flow tests
- `crates/muse-exchange/tests/dogfood_binary.rs` — live binary test
- Ledger seq: 434
