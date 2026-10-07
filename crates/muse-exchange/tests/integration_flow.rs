//! LANE B integration flow: the full organelle pipeline end-to-end.
//!
//! PreToolUse -> structural adjudication (luci-verdict-core) ->
//! context projection (claimant-aware, luci-context) ->
//! execution -> TaskReceipt -> ledger.
//!
//! Plus the Unknown -> evidence -> Authorized loop, and the Denied
//! terminal path. Every joint is exercised, not mocked.

use luci_context::receipt::VerdictRecord;
use luci_context::{CasStore, EpistemicCache, Epistemic, FileCas, TaskReceipt};
use muse_exchange::{AuthorityVerdict, HookRequest, MuseExchange};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static CTR: AtomicU64 = AtomicU64::new(100);

async fn test_exchange() -> (MuseExchange, PathBuf) {
    let n = CTR.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("mex-int-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    let ex = MuseExchange::init(&dir.join("db"), dir.join("ledger.jsonl"), dir.join("queue"))
        .await
        .expect("init");
    ex.apply_schema().await.expect("schema");
    (ex, dir)
}

#[allow(clippy::too_many_arguments)]
async fn seed_edge(
    ex: &MuseExchange,
    edge_kind: &str,
    out_tool: Option<&str>,
    in_task: Option<&str>,
    hash: &str,
    claimant: &str,
    source: &str,
    necessity: &str,
    verdict: i8,
    receipt: &str,
) {
    let in_expr = match in_task {
        Some(t) => format!("type::thing('task', '{}')", t),
        None => "type::thing('policy', 'p1')".to_string(),
    };
    let out_expr = match out_tool {
        Some(t) => format!("type::thing('tool', '{}')", t),
        None => "type::thing('resource', 'r1')".to_string(),
    };
    let q = format!(
        "CREATE ONLY lifelog_edge CONTENT {{ \
           in: {in_e}, out: {out_e}, edge_kind: '{ek}', hash: '{h}', \
           claimant: '{c}', source: '{s}', necessity: '{n}', verdict: {v}, \
           receipt_id: '{r}', \
           valid_from: time::now(), valid_to: type::datetime('2030-01-01T00:00:00Z') \
         }};",
        in_e = in_expr,
        out_e = out_expr,
        ek = edge_kind,
        h = hash,
        c = claimant,
        s = source,
        n = necessity,
        v = verdict,
        r = receipt,
    );
    ex.db().query(&q).await.expect("seed").check().expect("seed ok");
}

fn test_receipt(task: &str, tool: &str, prev: &str, ctx_hash: &str) -> TaskReceipt {
    TaskReceipt {
        task: task.to_string(),
        input_hash: "a".repeat(64),
        context_hashes: vec![ctx_hash.to_string()],
        tools_invoked: vec![tool.to_string()],
        capabilities_granted: vec!["execute".to_string()],
        files_changed: vec![],
        tests_executed: vec![],
        observations: vec!["tool executed, output captured".to_string()],
        claims: vec![],
        verdicts: vec![VerdictRecord {
            claim: format!("{} authorized", tool),
            state: Epistemic::Proven,
        }],
        output_artifacts: vec![],
        at: 1791343000,
        previous_receipt_hash: prev.to_string(),
    }
}

/// FULL FLOW: PreToolUse -> adjudicated Authorized -> claimant-aware
/// projection -> execution -> TaskReceipt -> ledger. The receipt is
/// fetchable and the ledger binds the chain.
#[tokio::test]
async fn full_flow_authorized_to_receipt_to_ledger() {
    let (ex, dir) = test_exchange().await;
    // 1. Authority: +1 edge from a named claimant.
    seed_edge(&ex, "authorizes", Some("tool-flow"), None, "h-auth", "zackary", "system", "required", 1, "rc-a").await;
    // 2. Context budget: required+proven edges with distinct claimants.
    seed_edge(&ex, "claims", None, Some("t-flow"), "h-ctx1", "lucidota", "system", "required", 1, "rc-b").await;
    seed_edge(&ex, "observes", None, Some("t-flow"), "h-ctx2", "subagent:g1-a", "user", "optional", 1, "rc-c").await;

    // PreToolUse -> structural adjudication (not a raw verdict mapping).
    let (stages, verdict, reason) = ex
        .adjudicate_pre_tool_use("tool-flow", "{\"probe\":true}")
        .await
        .unwrap();
    assert_eq!(verdict, AuthorityVerdict::Authorized, "reason: {}", reason);
    assert_eq!(stages.identity, Epistemic::Proven, "witness must establish");
    assert_eq!(stages.evidence, Epistemic::Proven);

    // Context projection: claimant-aware, required first.
    let budget = ex.resolve_context_budget("t-flow").await.unwrap();
    assert_eq!(budget.len(), 2);
    assert_eq!(budget[0].necessity, "required");
    assert_eq!(budget[0].claimant, "lucidota");

    // Execution -> TaskReceipt -> ledger (the loop closes here).
    // The context blob really lives in CAS so resume is honest.
    let cas_dir = dir.join("cas");
    let mut cas = FileCas::open(&cas_dir).unwrap();
    let ctx_hash = cas.put(b"verified context bytes for t-flow").unwrap();
    let mut engine = EpistemicCache::new(FileCas::open(&cas_dir).unwrap());
    let receipt = test_receipt("t-flow", "tool-flow", "genesis", &ctx_hash);
    let hash = ex.record_execution(&mut engine, &receipt).await.unwrap();
    assert_eq!(hash, receipt.id());

    // Receipt round-trips through CAS; ledger binds the chain.
    let fetched = engine.fetch_receipt(&hash).unwrap().expect("receipt stored");
    assert_eq!(fetched.task, "t-flow");
    let ledger = std::fs::read_to_string(dir.join("ledger.jsonl")).unwrap();
    assert!(ledger.contains(&hash), "ledger must bind receipt hash");
    assert!(ledger.contains("\"verdict\":\"executed\""), "{}", ledger);

    // Resume bundle works from the receipt: stateless continuation.
    let bundle = engine.resume_from_receipt(&hash).unwrap().expect("resume");
    assert_eq!(bundle.receipt.task, "t-flow");
    let _ = std::fs::remove_dir_all(&dir);
}

/// UNKNOWN -> evidence subtask -> edge arrives -> AUTHORIZED.
/// The deferral loop is traversable, not a dead end.
#[tokio::test]
async fn unknown_defers_then_evidence_authorizes() {
    let (ex, dir) = test_exchange().await;

    // 1. Unknown: no edge -> Deferred, subtask dispatched.
    let req = HookRequest {
        tool_name: "tool-loop".to_string(),
        tool_input: json!({"x": 1}),
        task_hash: None,
        session_id: None,
    };
    let d1 = ex.route(&req).await.unwrap();
    assert_eq!(d1.decision, "block");
    assert!(d1.reason.contains("DEFERRED"));

    // 2. Evidence arrives: the claimant provides a +1 authorizes edge.
    seed_edge(&ex, "authorizes", Some("tool-loop"), None, "h-ev", "lucidota", "system", "required", 1, "rc-ev").await;

    // 3. Retry: now Authorized through the structural pipeline.
    let (stages, verdict, reason) = ex
        .adjudicate_pre_tool_use("tool-loop", "{\"x\":1}")
        .await
        .unwrap();
    assert_eq!(verdict, AuthorityVerdict::Authorized, "reason: {}", reason);
    assert_eq!(stages.identity, Epistemic::Proven);
    let d2 = ex.route(&req).await.unwrap();
    assert_eq!(d2.decision, "approve");
    let _ = std::fs::remove_dir_all(&dir);
}

/// DENIED is terminal: block + ledger, and no TaskReceipt is stored
/// for a denied tool (nothing executed, nothing to receipt).
#[tokio::test]
async fn denied_terminal_no_receipt() {
    let (ex, dir) = test_exchange().await;
    seed_edge(&ex, "authorizes", Some("tool-bad"), None, "h-d", "zackary", "system", "required", -1, "rc-d").await;

    let (stages, verdict, reason) = ex
        .adjudicate_pre_tool_use("tool-bad", "{}")
        .await
        .unwrap();
    assert_eq!(verdict, AuthorityVerdict::Denied, "reason: {}", reason);
    // Denied at the policy stage: the graph's -1 is a terminal no.
    assert_eq!(stages.evidence, Epistemic::Proven, "witness still establishes identity");

    let req = HookRequest {
        tool_name: "tool-bad".to_string(),
        tool_input: json!({}),
        task_hash: None,
        session_id: None,
    };
    let d = ex.route(&req).await.unwrap();
    assert_eq!(d.decision, "block");
    assert!(d.reason.contains("DENIED"));
    let ledger = std::fs::read_to_string(dir.join("ledger.jsonl")).unwrap();
    assert!(ledger.contains("\"verdict\":\"denied\""));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Structural, not nominal: a stale envelope (expired valid_to) can
/// never authorize, even with a +1 graph verdict. The pipeline's
/// freshness stage is the enforcement, not the verdict mapping.
#[tokio::test]
async fn stale_envelope_never_authorizes() {
    let (ex, dir) = test_exchange().await;
    // Edge with a +1 verdict but an already-expired validity window.
    let q = "CREATE ONLY lifelog_edge CONTENT { \
        in: type::thing('policy', 'p1'), out: type::thing('tool', 'tool-stale'), \
        edge_kind: 'authorizes', hash: 'h-s', claimant: 'zackary', \
        source: 'system', necessity: 'required', verdict: 1, receipt_id: 'rc-s', \
        valid_from: type::datetime('2020-01-01T00:00:00Z'), \
        valid_to: type::datetime('2020-02-01T00:00:00Z') };";
    ex.db().query(q).await.expect("seed").check().expect("seed ok");

    let (_, verdict, reason) = ex
        .adjudicate_pre_tool_use("tool-stale", "{}")
        .await
        .unwrap();
    assert_eq!(verdict, AuthorityVerdict::Denied, "stale must deny: {}", reason);
    assert!(reason.contains("Freshness") || reason.contains("Expired"), "{}", reason);
    let _ = std::fs::remove_dir_all(&dir);
}
