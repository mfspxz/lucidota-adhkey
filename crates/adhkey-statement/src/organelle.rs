//! adhkey-statement as an organelle (Tier A native migration).
//!
//! The atomic object as pure, vault-independent ops:
//!   canonical_bytes {statement} -> {bytes_hex}
//!   statement_hash  {statement} -> {hash_hex}
//!
//! Canonical byte encoding: fixed field order, length-prefixed, evidence
//! sorted by digest — the same statement yields the same bytes (and the
//! same signature) across implementations. Domain-separated SHA-256.
//!
//! Deliberate exclusion: authenticate() needs a signature-verification
//! closure over real keys (a KeyRef names the key; verification is the
//! caller's crypto backend). It is exercised by the crate's own tests.
//!
//! Execution personality: no fs, no network, no secrets, no state.
//! Stateless: suspend = no-op, kill = drop in-flight.
//! Envelope: 1 cpu / 64 MB / 10 s wall-time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::sync::Arc;

use crate::{canonical_bytes, statement_hash, Statement};

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

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "adhkey-statement".to_string(),
        codon: "as".to_string(),
        version: "0.1.0".to_string(),
        description: "AdhKey statement primitive: canonical byte encoding and hashing of the atomic object".to_string(),
        contracts: vec![
            contract(
                "canonical_bytes",
                "canonical byte encoding of a statement (hex)",
                obj_schema(serde_json::json!({"statement": {"type": "object"}}), &["statement"]),
            ),
            contract(
                "statement_hash",
                "domain-separated SHA-256 of a statement (hex)",
                obj_schema(serde_json::json!({"statement": {"type": "object"}}), &["statement"]),
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

pub struct AdhkeyStatement {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(AdhkeyStatement { manifest: manifest() })
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

fn statement_of(input: &Value) -> Result<Statement, OrganelleError> {
    let sub = input
        .get("statement")
        .ok_or_else(|| failed("missing field \"statement\"".to_string()))?;
    serde_json::from_value(sub.clone()).map_err(|e| failed(format!("bad Statement: {e}")))
}

impl Organelle for AdhkeyStatement {
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
            "canonical_bytes" => {
                let s = statement_of(&input)?;
                Ok(serde_json::json!({"bytes_hex": hex(&canonical_bytes(&s))}))
            }
            "statement_hash" => {
                let s = statement_of(&input)?;
                Ok(serde_json::json!({"hash_hex": hex(&statement_hash(&s))}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvidenceRef, KeyRef, Object, Predicate, SubjectRef};
    use organelle_host::Host;
    use organelle_manifest::validate_manifest_json;

    fn manifest_json() -> Value {
        let txt = include_str!("../../../organelles/adhkey-statement.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    fn stmt() -> Statement {
        Statement {
            subject: SubjectRef { namespace: "ns".into(), id: "alice".into() },
            predicate: Predicate::Attests,
            object: Object::Text("alice controls key K".into()),
            issuer: SubjectRef { namespace: "ns".into(), id: "authority".into() },
            issuer_key: KeyRef([0xABu8; 32]),
            evidence: vec![EvidenceRef {
                digest: [0x01u8; 32],
                issuer: SubjectRef { namespace: "ns".into(), id: "witness".into() },
                predicate: Predicate::Attests,
                valid_from: 1000,
                valid_until: None,
                revoked: false,
            }],
            policy: "p1".into(),
            policy_version: 1,
            timestamp: 2000,
            sequence: 7,
            previous: [0u8; 32],
            signature: vec![0xEEu8; 64],
            suite: "ed25519".into(),
        }
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "adhkey-statement");
        assert_eq!(m.codon, "as");
    }

    #[test]
    fn rust_manifest_matches_static_json() {
        let from_rust = serde_json::to_value(manifest()).unwrap();
        assert_eq!(from_rust, manifest_json(), "Rust manifest() and organelles/*.json must agree");
    }

    #[test]
    fn registers_and_serves_through_host_with_receipts() {
        let host = Host::new();
        host.register(organelle()).expect("registration must succeed");
        let ctx = CallContext::new("as-test", vec![]);
        let s = serde_json::to_value(stmt()).unwrap();

        // canonical bytes are deterministic: same statement -> same bytes
        let b1 = host
            .call(&ctx, "as", "canonical_bytes", serde_json::json!({"statement": s}))
            .expect("canonical_bytes");
        let b2 = host
            .call(&ctx, "as", "canonical_bytes", serde_json::json!({"statement": s}))
            .expect("canonical_bytes");
        assert_eq!(b1["bytes_hex"], b2["bytes_hex"]);
        assert!(b1["bytes_hex"].as_str().unwrap().len() > 64);

        // evidence order does not change the bytes (sorted by digest)
        let mut s2 = stmt();
        s2.evidence.push(EvidenceRef {
            digest: [0x00u8; 32],
            issuer: SubjectRef { namespace: "ns".into(), id: "w2".into() },
            predicate: Predicate::Attests,
            valid_from: 999,
            valid_until: None,
            revoked: false,
        });
        let mut s3 = s2.clone();
        s3.evidence.reverse();
        let h2 = host
            .call(&ctx, "as", "statement_hash", serde_json::json!({"statement": serde_json::to_value(&s2).unwrap()}))
            .expect("hash2");
        let h3 = host
            .call(&ctx, "as", "statement_hash", serde_json::json!({"statement": serde_json::to_value(&s3).unwrap()}))
            .expect("hash3");
        assert_eq!(h2["hash_hex"], h3["hash_hex"], "evidence set order must not change the hash");
        assert_eq!(h2["hash_hex"].as_str().unwrap().len(), 64);

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 5, "register + calls = >=5 receipts, got {n}");
    }
}
