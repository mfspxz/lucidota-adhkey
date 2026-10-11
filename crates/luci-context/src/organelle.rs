//! luci-context as an organelle (Tier A native migration).
//!
//! The epistemic context cache as callable ops:
//!   insert        {key, content, truth, source, necessity, provenance} -> {inserted}
//!   get           {key} -> item or {found: false}
//!   compress      {key, summary} -> {compressed} (original bytes -> CAS)
//!   dereference   {key, start?, end?} -> {bytes_b64} (CAS reconstruction)
//!   eviction_order {} -> [{key, score}]
//!   project       {budget_chars} -> Projection (lossy-safe projection)
//!   len           {} -> {len}
//!
//! Compression never destroys information: content is replaced with
//! (summary, CAS pointer, hash, provenance, reconstruction path). Eviction
//! follows the projection theorem: losssy projection is marked UNKNOWN,
//! never silent loss.
//!
//! State: EpistemicCache<FileCas> in a Mutex; CAS dir supplied at
//! construction. Suspend checkpoints the item map; kill drops in-flight.
//! Envelope: 1 cpu / 256 MB / 60 s wall-time.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::{CasStore, ContextItem, EpistemicCache, FileCas, Necessity, Source};
use luci_verdict_core::Epistemic;

fn str_in(v: &Value, key: &str) -> Result<String, OrganelleError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| OrganelleError::failed(format!("missing string field {key:?}")))
}

fn obj_schema(props: Value, required: &[&str]) -> Value {
    serde_json::json!({ "type": "object", "properties": props, "required": required })
}

fn contract(op: &str, description: &str, schema: Value) -> Contract {
    Contract {
        op: op.to_string(),
        description: description.to_string(),
        input_schema: schema,
        mutation_class: None,
        required_capability: None,
    }
}

fn contract_write(op: &str, description: &str, schema: Value, cap: &str) -> Contract {
    Contract {
        op: op.to_string(),
        description: description.to_string(),
        input_schema: schema,
        mutation_class: Some(MutationClass::Write),
        required_capability: Some(cap.to_string()),
    }
}

fn manifest() -> OrganelleManifest {
    let item_schema = serde_json::json!({
        "key": {"type": "string"},
        "content": {"type": "string"},
        "truth": {"type": "string", "enum": ["Proven", "Unknown", "Disproven"]},
        "source": {"type": "string", "enum": ["System", "User", "Discovered"]},
        "necessity": {"type": "string", "enum": ["Required", "Optional", "Irrelevant"]},
        "provenance": {"type": "string"}
    });
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "luci-context".to_string(),
        codon: "lz".to_string(),
        version: "0.1.0".to_string(),
        description: "luci-context epistemic cache: truth/provenance/necessity-scored context with CAS-backed lossless compression".to_string(),
        contracts: vec![
            contract_write(
                "insert",
                "insert a context item",
                obj_schema(item_schema.clone(), &["key", "content", "truth", "source", "necessity"]),
                "lz.write",
            ),
            contract(
                "get",
                "fetch one item by key",
                obj_schema(serde_json::json!({"key": {"type": "string"}}), &["key"]),
            ),
            contract_write(
                "compress",
                "relocate an item's bytes to CAS, keep summary + reconstruction path",
                obj_schema(
                    serde_json::json!({"key": {"type": "string"}, "summary": {"type": "string"}}),
                    &["key", "summary"],
                ),
                "lz.write",
            ),
            contract(
                "dereference",
                "reconstruct original bytes (or byte range) from CAS",
                obj_schema(
                    serde_json::json!({
                        "key": {"type": "string"},
                        "start": {"type": "integer"},
                        "end": {"type": "integer"}
                    }),
                    &["key"],
                ),
            ),
            contract(
                "eviction_order",
                "eviction safety scores, highest first (None = never evict, omitted)",
                obj_schema(serde_json::json!({}), &[]),
            ),
            contract_write(
                "project",
                "project the cache to a char budget (lossy-safe: unknown_introduced flags loss)",
                obj_schema(serde_json::json!({"budget_chars": {"type": "integer"}}), &["budget_chars"]),
                "lz.write",
            ),
            contract(
                "len",
                "number of cached items",
                obj_schema(serde_json::json!({}), &[]),
            ),
        ],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: Valence::Proven,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: Transport::all().to_vec(),
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

pub struct LuciContext {
    manifest: OrganelleManifest,
    cache: Mutex<EpistemicCache<FileCas>>,
    #[allow(dead_code)]
    cas_dir: PathBuf,
}

pub fn organelle(cas_dir: &Path) -> io::Result<Arc<dyn Organelle>> {
    let cas = FileCas::open(cas_dir)?;
    Ok(Arc::new(LuciContext {
        manifest: manifest(),
        cache: Mutex::new(EpistemicCache::new(cas)),
        cas_dir: cas_dir.to_path_buf(),
    }))
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

fn io_failed(e: io::Error) -> OrganelleError {
    failed(format!("io: {e}"))
}

fn to_json<T: serde::Serialize>(t: &T) -> Result<Value, OrganelleError> {
    serde_json::to_value(t).map_err(|e| failed(e.to_string()))
}

fn parse_enum<T>(v: &Value, key: &str) -> Result<T, OrganelleError>
where
    T: serde::de::DeserializeOwned,
{
    let sub = v
        .get(key)
        .ok_or_else(|| failed(format!("missing field {key:?}")))?;
    serde_json::from_value(sub.clone()).map_err(|e| failed(format!("bad {key}: {e}")))
}

impl Organelle for LuciContext {
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
            "insert" => {
                let item = ContextItem::new(
                    &str_in(&input, "key")?,
                    &str_in(&input, "content")?,
                    parse_enum::<Epistemic>(&input, "truth")?,
                    parse_enum::<Source>(&input, "source")?,
                    parse_enum::<Necessity>(&input, "necessity")?,
                    input.get("provenance").and_then(|v| v.as_str()).unwrap_or(""),
                );
                let key = item.key.clone();
                self.cache
                    .lock()
                    .map_err(|e| failed(e.to_string()))?
                    .insert(item);
                Ok(serde_json::json!({"inserted": key}))
            }
            "get" => {
                let key = str_in(&input, "key")?;
                let c = self.cache.lock().map_err(|e| failed(e.to_string()))?;
                match c.get(&key) {
                    Some(item) => Ok(serde_json::json!({"found": true, "item": to_json(item)?})),
                    None => Ok(serde_json::json!({"found": false, "key": key})),
                }
            }
            "compress" => {
                let key = str_in(&input, "key")?;
                let summary = str_in(&input, "summary")?;
                let done = self
                    .cache
                    .lock()
                    .map_err(|e| failed(e.to_string()))?
                    .compress(&key, &summary)
                    .map_err(io_failed)?;
                Ok(serde_json::json!({"compressed": done}))
            }
            "dereference" => {
                let key = str_in(&input, "key")?;
                let range = match (input.get("start").and_then(|v| v.as_u64()), input.get("end").and_then(|v| v.as_u64())) {
                    (Some(s), Some(e)) => Some((s, e)),
                    _ => None,
                };
                let c = self.cache.lock().map_err(|e| failed(e.to_string()))?;
                match c.dereference(&key, range).map_err(io_failed)? {
                    Some(bytes) => Ok(serde_json::json!({"found": true, "bytes_b64": B64.encode(&bytes)})),
                    None => Ok(serde_json::json!({"found": false, "key": key})),
                }
            }
            "eviction_order" => {
                let c = self.cache.lock().map_err(|e| failed(e.to_string()))?;
                let order = c.eviction_order();
                Ok(serde_json::json!({
                    "order": order.iter().map(|(k, s)| serde_json::json!({"key": k, "score": s})).collect::<Vec<_>>()
                }))
            }
            "project" => {
                let budget = input
                    .get("budget_chars")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| failed("missing integer field \"budget_chars\"".to_string()))?
                    as usize;
                let proj = self
                    .cache
                    .lock()
                    .map_err(|e| failed(e.to_string()))?
                    .project(budget)
                    .map_err(io_failed)?;
                to_json(&proj)
            }
            "len" => {
                let c = self.cache.lock().map_err(|e| failed(e.to_string()))?;
                Ok(serde_json::json!({"len": c.len()}))
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
        let txt = include_str!("../../../organelles/luci-context.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    fn tmp_cas(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("luci-context-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn test_organelle(tag: &str) -> (Arc<dyn Organelle>, PathBuf) {
        let dir = tmp_cas(tag);
        let o = organelle(&dir).expect("open organelle");
        (o, dir)
    }

    fn insert_input(key: &str, content: &str) -> Value {
        serde_json::json!({
            "key": key, "content": content,
            "truth": "Proven", "source": "System", "necessity": "Required",
            "provenance": "test"
        })
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "luci-context");
        assert_eq!(m.codon, "lz");
    }

    #[test]
    fn rust_manifest_matches_static_json() {
        let from_rust = serde_json::to_value(manifest()).unwrap();
        assert_eq!(from_rust, manifest_json(), "Rust manifest() and organelles/*.json must agree");
    }

    #[test]
    fn registers_and_serves_through_host_with_receipts() {
        let (org, dir) = test_organelle("a");
        let host = Host::new();
        host.register(org).expect("registration must succeed");
        let ctx = CallContext::new("lz-test", vec!["lz.write".to_string()]);
        let ro = CallContext::new("lz-ro", vec![]);

        // write gate
        assert!(host.call(&ro, "lz", "insert", insert_input("k1", "hello world")).is_err());

        host.call(&ctx, "lz", "insert", insert_input("k1", "hello world")).expect("insert");
        host.call(&ctx, "lz", "insert", insert_input("k2", &"x".repeat(5000))).expect("insert k2");

        let g = host.call(&ro, "lz", "get", serde_json::json!({"key": "k1"})).expect("get");
        assert_eq!(g.output["found"], true);
        assert_eq!(g.output["item"]["key"], "k1");

        // compress relocates bytes to CAS; dereference reconstructs them
        let c = host
            .call(&ctx, "lz", "compress", serde_json::json!({"key": "k2", "summary": "lots of x"}))
            .expect("compress");
        assert_eq!(c.output["compressed"], true);
        let d = host
            .call(&ro, "lz", "dereference", serde_json::json!({"key": "k2"}))
            .expect("dereference");
        assert_eq!(d.output["found"], true);
        let bytes = d.output["bytes_b64"].as_str().unwrap();
        assert_eq!(bytes.len(), 6668, "5000 bytes -> ceil(5000/3)*4 b64 chars");

        // byte-range dereference
        let dr = host
            .call(&ro, "lz", "dereference", serde_json::json!({"key": "k2", "start": 0, "end": 3}))
            .expect("range");
        assert_eq!(dr.output["bytes_b64"], "eHh4"); // "xxx"

        // projection under a tight budget flags loss honestly
        let p = host
            .call(&ctx, "lz", "project", serde_json::json!({"budget_chars": 10}))
            .expect("project");
        assert!(p.output.get("unknown_introduced").is_some());

        let l = host.call(&ro, "lz", "len", serde_json::json!({})).expect("len");
        assert_eq!(l.output["len"], 2);

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 8, "register + calls = >=8 receipts, got {n}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
