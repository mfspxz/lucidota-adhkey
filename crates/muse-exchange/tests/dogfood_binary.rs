//! LANE B dogfood: the REAL muse-exchange binary, end to end.
//!
//! Seeds a SurrealDB via the library API, then spawns the compiled
//! binary as a child process: hook JSON on stdin, decision JSON on
//! stdout. All three ternary paths through the live binary, no mocks.

use muse_exchange::MuseExchange;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

async fn seed_db(dir: &PathBuf) {
    let ex = MuseExchange::init(
        &dir.join("db"),
        dir.join("ledger.jsonl"),
        dir.join("queue"),
    )
    .await
    .expect("init");
    ex.apply_schema().await.expect("schema");
    for (tool, verdict, rc) in [
        ("tool-ok", 1, "rc-ok"),
        ("tool-no", -1, "rc-no"),
        // tool-missing: no edge -> Unknown
    ] {
        let q = format!(
            "CREATE ONLY lifelog_edge CONTENT {{ \
               in: type::thing('policy', 'p1'), out: type::thing('tool', '{t}'), \
               edge_kind: 'authorizes', hash: 'h-{t}', claimant: 'zackary', \
               source: 'system', necessity: 'required', verdict: {v}, \
               receipt_id: '{r}', valid_from: time::now(), \
               valid_to: type::datetime('2030-01-01T00:00:00Z') }};",
            t = tool,
            v = verdict,
            r = rc
        );
        ex.db().query(&q).await.expect("seed").check().expect("ok");
    }
}

fn run_binary(dir: &PathBuf, tool: &str) -> serde_json::Value {
    let bin = env!("CARGO_BIN_EXE_muse-exchange");
    let mut child = Command::new(bin)
        .arg("--db")
        .arg(dir.join("db"))
        .arg("--ledger")
        .arg(dir.join("ledger.jsonl"))
        .arg("--evidence-queue")
        .arg(dir.join("queue"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn binary");
    let req = serde_json::json!({
        "tool_name": tool,
        "tool_input": {"probe": true},
    });
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(serde_json::to_string(&req).unwrap().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "binary failed for {}: {}",
        tool,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The binary prints the hook decision JSON (to_json shape).
    let v: serde_json::Value = serde_json::from_str(
        stdout
            .lines()
            .find(|l| l.trim_start().starts_with('{'))
            .expect("decision line"),
    )
    .expect("decision json");
    v
}

#[tokio::test]
async fn dogfood_ternary_paths_through_live_binary() {
    let dir = std::env::temp_dir().join(format!("mex-dogfood-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    seed_db(&dir).await;

    // AUTHORIZED path: +1 edge -> approve.
    let ok = run_binary(&dir, "tool-ok");
    assert_eq!(ok["decision"], "approve", "{}", ok);
    assert!(
        ok["reason"].as_str().unwrap().contains("AUTHORIZED"),
        "{}",
        ok
    );

    // DENIED path: -1 edge -> block + DENIED + ledger receipt.
    let no = run_binary(&dir, "tool-no");
    assert_eq!(no["decision"], "block", "{}", no);
    assert!(
        no["reason"].as_str().unwrap().contains("DENIED"),
        "{}",
        no
    );

    // UNKNOWN path: no edge -> block + DEFERRED + evidence subtask.
    let missing = run_binary(&dir, "tool-missing");
    assert_eq!(missing["decision"], "block", "{}", missing);
    let reason = missing["reason"].as_str().unwrap();
    assert!(reason.contains("DEFERRED"), "{}", reason);

    // Side effects landed: ledger has the denial, queue has the subtask.
    let ledger = std::fs::read_to_string(dir.join("ledger.jsonl")).unwrap();
    assert!(ledger.contains("tool-no"), "{}", ledger);
    let queue_files: Vec<_> = std::fs::read_dir(dir.join("queue"))
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(!queue_files.is_empty(), "evidence subtask must exist");

    let _ = std::fs::remove_dir_all(&dir);
}
