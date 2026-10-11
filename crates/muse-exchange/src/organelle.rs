//! muse-exchange as an organelle (Tier A native migration).
//!
//! The sovereign PreToolUse authority gateway as callable ops:
//!   route         {tool_name, tool_input, task_hash?, session_id?} -> hook decision JSON
//!   apply_schema  {} -> {applied: true}
//!
//! `route` runs the full adjudication: embedded SurrealDB authority graph
//! -> luci-verdict-core staged pipeline (CLAIMED -> ESTABLISHED ->
//! AUTHORIZED, UNKNOWN propagates) -> hook decision. The graph verdict is
//! an input, never a direct authorization. Unknown (or no edge) triggers
//! the evidence-gathering path, never a hard failure.
//!
//! The exchange is async (SurrealDB); the organelle owns a tokio runtime
//! and blocks on it per call. State: the embedded SurrealKv database at
//! the supplied path (suspend checkpoints; kill drops in-flight, the DB
//! itself is crash-safe).
//!
//! Execution personality: fs read-write on db/ledger/queue paths; network
//! none; no secrets in manifests. Valence Candidate (embedded DB writes,
//! evidence-queue side effects).
//! Envelope: 2 cpu / 1 GB / 120 s wall-time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::{HookRequest, MuseExchange};

fn obj_schema(props: Value, required: &[&str]) -> Value {
    serde_json::json!({ "type": "object", "properties": props, "required": required })
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "muse-exchange".to_string(),
        codon: "mx".to_string(),
        version: "0.1.0".to_string(),
        description: "sovereign PreToolUse authority gateway: embedded epistemic graph + staged ternary verdict pipeline".to_string(),
        contracts: vec![
            Contract {
                op: "route".to_string(),
                description: "adjudicate a hook request through the authority graph + verdict pipeline".to_string(),
                input_schema: obj_schema(
                    serde_json::json!({
                        "tool_name": {"type": "string"},
                        "tool_input": {},
                        "task_hash": {"type": "string"},
                        "session_id": {"type": "string"}
                    }),
                    &["tool_name"],
                ),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("mx.route".to_string()),
            },
            Contract {
                op: "apply_schema".to_string(),
                description: "apply the epistemic schema (idempotent)".to_string(),
                input_schema: obj_schema(serde_json::json!({}), &[]),
                mutation_class: Some(MutationClass::Write),
                required_capability: Some("mx.admin".to_string()),
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::Write,
            declared_valence: Valence::Candidate,
            required_capability: Some("mx.route".to_string()),
            granted_capabilities: vec![],
        },
        transports: vec![Transport::Native, Transport::UnixSocket],
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

pub struct MuseExchangeOrganelle {
    manifest: OrganelleManifest,
    rt: tokio::runtime::Runtime,
    ex: Mutex<MuseExchange>,
}

pub fn organelle(
    db_path: &Path,
    ledger_path: PathBuf,
    evidence_queue: PathBuf,
) -> Result<Arc<dyn Organelle>, OrganelleError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| OrganelleError::failed(format!("tokio runtime: {e}")))?;
    let ex = rt
        .block_on(MuseExchange::init(db_path, ledger_path, evidence_queue))
        .map_err(|e| OrganelleError::failed(format!("exchange init: {e}")))?;
    Ok(Arc::new(MuseExchangeOrganelle {
        manifest: manifest(),
        rt,
        ex: Mutex::new(ex),
    }))
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

impl Organelle for MuseExchangeOrganelle {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "route" => {
                let req: HookRequest = serde_json::from_value(input)
                    .map_err(|e| failed(format!("bad HookRequest: {e}")))?;
                let ex = self.ex.lock().map_err(|e| failed(e.to_string()))?;
                let decision = self
                    .rt
                    .block_on(ex.route(&req))
                    .map_err(|e| failed(format!("route: {e}")))?;
                Ok(decision.to_json())
            }
            "apply_schema" => {
                let ex = self.ex.lock().map_err(|e| failed(e.to_string()))?;
                self.rt
                    .block_on(ex.apply_schema())
                    .map_err(|e| failed(format!("apply_schema: {e}")))?;
                Ok(serde_json::json!({"applied": true}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use organelle_manifest::validate_manifest_json;

    fn manifest_json() -> Value {
        let txt = include_str!("../../../organelles/muse-exchange.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("muse-exchange-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "muse-exchange");
        assert_eq!(m.codon, "mx");
    }

    #[test]
    fn rust_manifest_matches_static_json() {
        let from_rust = serde_json::to_value(manifest()).unwrap();
        assert_eq!(from_rust, manifest_json(), "Rust manifest() and organelles/*.json must agree");
    }

    #[test]
    fn registers_and_serves_through_host_with_receipts() {
        let dir = tmp("a");
        let org = organelle(
            &dir.join("epistemic.db"),
            dir.join("ledger.jsonl"),
            dir.join("evidence-queue"),
        )
        .expect("organelle init");
        let host = Host::new();
        host.register(org).expect("registration must succeed");
        let ctx = CallContext::new("mx-test", vec!["mx.route".to_string(), "mx.admin".to_string()]);
        let ro = CallContext::new("mx-ro", vec![]);

        // capability gates
        assert!(host
            .call(&ro, "mx", "route", serde_json::json!({"tool_name": "Bash"}))
            .is_err());
        assert!(host
            .call(&ro, "mx", "apply_schema", serde_json::json!({}))
            .is_err());

        host.call(&ctx, "mx", "apply_schema", serde_json::json!({}))
            .expect("apply_schema");

        // no authorizes edge for Bash -> UNKNOWN path: never a hard failure,
        // always a produced decision (exit-0 semantics)
        let d = host
            .call(
                &ctx,
                "mx",
                "route",
                serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
            )
            .expect("route");
        assert!(d["decision"].as_str().is_some(), "a decision was produced: {d}");
        assert!(d["reason"].as_str().is_some());

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 3, "register + calls = >=3 receipts, got {n}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
