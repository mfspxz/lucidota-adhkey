//! Integration tests against an embedded SurrealKv instance.
//!
//! - verdict mapping: 1/0/-1 (and missing) -> Authorized/Unknown/Denied
//! - budget query: filters irrelevant necessity and disproven verdict
//! - unknown -> defer: evidence subtask dispatched, hook deferred (not denied)

use muse_exchange::{AuthorityVerdict, HookRequest, MuseExchange, ProjectionError};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static CTR: AtomicU64 = AtomicU64::new(0);

async fn test_exchange() -> (MuseExchange, PathBuf) {
    let n = CTR.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("mex-test-{}-{}", std::process::id(), n));
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

fn req(tool: &str, task: Option<&str>) -> HookRequest {
    HookRequest {
        tool_name: tool.to_string(),
        tool_input: json!({"probe": true}),
        task_hash: task.map(|s| s.to_string()),
        session_id: None,
    }
}

#[tokio::test]
async fn schema_apply_is_idempotent() {
    let (ex, dir) = test_exchange().await;
    ex.apply_schema().await.expect("second apply");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn verdict_mapping_1_0_minus1() {
    let (ex, dir) = test_exchange().await;
    seed_edge(&ex, "authorizes", Some("tool-a"), None, "h", "zackary", "system", "required", 1, "rc1").await;
    seed_edge(&ex, "authorizes", Some("tool-b"), None, "h", "lucidota", "system", "required", 0, "rc2").await;
    seed_edge(&ex, "authorizes", Some("tool-c"), None, "h", "subagent:g1-a", "system", "required", -1, "rc3").await;

    assert_eq!(
        ex.handle_pre_tool_use("tool-a").await.unwrap(),
        AuthorityVerdict::Authorized
    );
    assert_eq!(
        ex.handle_pre_tool_use("tool-b").await.unwrap(),
        AuthorityVerdict::Unknown
    );
    assert_eq!(
        ex.handle_pre_tool_use("tool-c").await.unwrap(),
        AuthorityVerdict::Denied
    );
    // No edge at all: absence of evidence is not evidence of authority.
    assert_eq!(
        ex.handle_pre_tool_use("tool-ghost").await.unwrap(),
        AuthorityVerdict::Unknown
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn budget_filters_irrelevant_and_disproven() {
    let (ex, dir) = test_exchange().await;
    seed_edge(&ex, "claims", None, Some("t1"), "h-keep1", "zackary", "system", "required", 1, "rc1").await;
    seed_edge(&ex, "observes", None, Some("t1"), "h-keep2", "lucidota", "user", "optional", 0, "rc2").await;
    seed_edge(&ex, "claims", None, Some("t1"), "h-drop1", "zackary", "system", "irrelevant", 1, "rc3").await;
    seed_edge(&ex, "claims", None, Some("t1"), "h-drop2", "lucidota", "system", "required", -1, "rc4").await;
    // Different task: must not leak into t1's budget.
    seed_edge(&ex, "claims", None, Some("t2"), "h-other", "zackary", "system", "required", 1, "rc5").await;

    let budget = ex.resolve_context_budget("t1").await.unwrap();
    let hashes: Vec<&str> = budget.iter().map(|p| p.hash.as_str()).collect();
    assert!(hashes.contains(&"h-keep1"), "{:?}", hashes);
    assert!(hashes.contains(&"h-keep2"), "{:?}", hashes);
    assert!(!hashes.contains(&"h-drop1"), "{:?}", hashes);
    assert!(!hashes.contains(&"h-drop2"), "{:?}", hashes);
    assert!(!hashes.contains(&"h-other"), "{:?}", hashes);
    assert_eq!(budget.len(), 2);
    // Claimant survives the projection: first-class, not collapsed.
    let keep1 = budget.iter().find(|p| p.hash == "h-keep1").unwrap();
    assert_eq!(keep1.claimant, "zackary");
    assert_eq!(keep1.source, "system");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn lossy_projection_names_failing_claimants() {
    let (ex, dir) = test_exchange().await;
    // Required evidence still unknown (verdict 0) from two claimants.
    seed_edge(&ex, "claims", None, Some("t3"), "h-u1", "subagent:g1-a", "system", "required", 0, "rc1").await;
    seed_edge(&ex, "observes", None, Some("t3"), "h-u2", "worker:nim-claimant-01", "discovered", "required", 0, "rc2").await;
    // Proven required edge: not a failure, must not be named.
    seed_edge(&ex, "claims", None, Some("t3"), "h-ok", "zackary", "system", "required", 1, "rc3").await;
    // Unknown but merely optional: not lossy, must not be named.
    seed_edge(&ex, "claims", None, Some("t3"), "h-opt", "lucidota", "user", "optional", 0, "rc4").await;

    match ex.resolve_context_budget("t3").await {
        Err(ProjectionError::LossyProjection { claimants }) => {
            assert!(claimants.contains(&"subagent:g1-a".to_string()), "{:?}", claimants);
            assert!(claimants.contains(&"worker:nim-claimant-01".to_string()), "{:?}", claimants);
            assert!(!claimants.contains(&"zackary".to_string()), "{:?}", claimants);
            assert!(!claimants.contains(&"lucidota".to_string()), "{:?}", claimants);
            assert_eq!(claimants.len(), 2);
        }
        other => panic!("expected LossyProjection, got {:?}", other.is_ok()),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn authorized_with_lossy_budget_defers_naming_claimants() {
    let (ex, dir) = test_exchange().await;
    seed_edge(&ex, "authorizes", Some("tool-z"), None, "h", "zackary", "system", "required", 1, "rc7").await;
    // Tool is authorized, but its task budget has required+unknown evidence.
    seed_edge(&ex, "claims", None, Some("t-lossy"), "h-u", "subagent:g1-a", "system", "required", 0, "rc8").await;

    let decision = ex.route(&req("tool-z", Some("t-lossy"))).await.unwrap();
    assert_eq!(decision.decision, "block");
    assert!(decision.reason.contains("DEFERRED"), "reason: {}", decision.reason);
    assert!(
        decision.reason.contains("subagent:g1-a"),
        "reason must name the failing claimant: {}",
        decision.reason
    );
    // The evidence subtask targets the failing claimant.
    let queue = dir.join("queue");
    let files: Vec<_> = std::fs::read_dir(&queue)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(files.len(), 1);
    let sub: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(files[0].path()).unwrap()).unwrap();
    let targets = sub["target_claimants"].as_array().unwrap();
    assert!(targets.iter().any(|t| t == "subagent:g1-a"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn unknown_defers_with_evidence_subtask() {
    let (ex, dir) = test_exchange().await;
    let decision = ex.route(&req("ghost-tool", None)).await.unwrap();

    assert_eq!(decision.decision, "block");
    assert!(
        decision.reason.contains("DEFERRED"),
        "reason: {}",
        decision.reason
    );
    // Exactly one evidence subtask was dispatched, naming the tool.
    let queue = dir.join("queue");
    let files: Vec<_> = std::fs::read_dir(&queue)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(files.len(), 1, "queue: {:?}", queue);
    let body = std::fs::read_to_string(files[0].path()).unwrap();
    let sub: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(sub["tool"], "ghost-tool");
    assert_eq!(sub["status"], "pending_evidence");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn denied_blocks_and_appends_ledger() {
    let (ex, dir) = test_exchange().await;
    seed_edge(&ex, "authorizes", Some("tool-x"), None, "h", "lucidota", "system", "required", -1, "rc9").await;

    let decision = ex.route(&req("tool-x", None)).await.unwrap();
    assert_eq!(decision.decision, "block");
    assert!(decision.reason.contains("DENIED"), "reason: {}", decision.reason);

    let ledger = std::fs::read_to_string(dir.join("ledger.jsonl")).unwrap();
    assert!(ledger.contains("\"verdict\":\"denied\""), "{}", ledger);
    assert!(ledger.contains("tool-x"), "{}", ledger);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn authorized_approves_with_cas_pointers() {
    let (ex, dir) = test_exchange().await;
    seed_edge(&ex, "authorizes", Some("tool-y"), None, "h", "zackary", "system", "required", 1, "rc7").await;
    seed_edge(&ex, "claims", None, Some("t9"), "h-ctx1", "lucidota", "system", "required", 1, "rc8").await;

    let decision = ex.route(&req("tool-y", Some("t9"))).await.unwrap();
    assert_eq!(decision.decision, "approve");
    let ctx = decision.additional_context.unwrap();
    assert!(ctx.contains("h-ctx1"), "ctx: {}", ctx);
    let _ = std::fs::remove_dir_all(&dir);
}
