//! adhkey-core as an organelle (Tier A native migration).
//!
//! The portable identity/key-lifecycle protocol as pure, by-value ops:
//!   create_identity {identifier, subject, recovery_threshold, recovery_key_ids} -> Identity
//!   activate_key    {identity, key_id, purpose} -> Identity
//!   transition_key  {identity, key_id, next, reason} -> Identity
//!   can_transition  {from, to} -> {legal}
//!   key_state       {identity, key_id} -> {state}
//!   active_keys     {identity, purpose} -> [KeyRecord]
//!
//! The state machine is explicit and recorded: every legal move appends to
//! the identity's history. Lost -> Active is REJECTED without fresh proof
//! of possession (use the crate's refound_key with a KeyOperator).
//!
//! Deliberate exclusions: refound_key / recover need a KeyOperator
//! (signature verification against real keys) which the host does not
//! inject; they are exercised by the crate's own tests, not the organelle.
//!
//! No key material flows here: KeyId is an opaque identifier string.
//! Execution personality: no fs, no network, no secrets, no state.
//! Stateless: suspend = no-op, kill = drop in-flight.
//! Envelope: 1 cpu / 64 MB / 10 s wall-time.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::lifecycle::{activate_key, transition_key};
use crate::{Identity, KeyId, KeyPurpose, KeyRecord, KeyState, RecoveryPolicy, Subject};

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

fn purpose_schema() -> Value {
    serde_json::json!({"type": "string", "enum": ["Authentication", "Signing", "Recovery", "Encryption"]})
}

fn state_schema() -> Value {
    serde_json::json!({"type": "string", "enum": ["Active", "Lost", "Revoked", "Expired"]})
}

fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "adhkey-lifecycle".to_string(),
        codon: "ak".to_string(),
        version: "0.1.0".to_string(),
        description: "AdhKey portable identity/key-lifecycle protocol: explicit state machine, recorded transitions, recovery policy".to_string(),
        contracts: vec![
            contract(
                "create_identity",
                "create an identity with a recovery policy (no keys yet)",
                obj_schema(
                    serde_json::json!({
                        "identifier": {"type": "string"},
                        "subject": {"type": "string"},
                        "recovery_threshold": {"type": "integer"},
                        "recovery_key_ids": {"type": "array", "items": {"type": "string"}}
                    }),
                    &["identifier", "subject"],
                ),
            ),
            contract(
                "activate_key",
                "activate a new key on the identity (by value)",
                obj_schema(
                    serde_json::json!({
                        "identity": {"type": "object"},
                        "key_id": {"type": "string"},
                        "purpose": purpose_schema()
                    }),
                    &["identity", "key_id", "purpose"],
                ),
            ),
            contract(
                "transition_key",
                "move a key along the legal transition table (by value; Lost->Active rejected)",
                obj_schema(
                    serde_json::json!({
                        "identity": {"type": "object"},
                        "key_id": {"type": "string"},
                        "next": state_schema(),
                        "reason": {"type": "string"}
                    }),
                    &["identity", "key_id", "next"],
                ),
            ),
            contract(
                "can_transition",
                "is this key-state move legal?",
                obj_schema(
                    serde_json::json!({"from": state_schema(), "to": state_schema()}),
                    &["from", "to"],
                ),
            ),
            contract(
                "key_state",
                "current state of one key",
                obj_schema(
                    serde_json::json!({"identity": {"type": "object"}, "key_id": {"type": "string"}}),
                    &["identity", "key_id"],
                ),
            ),
            contract(
                "active_keys",
                "usable keys of one purpose",
                obj_schema(
                    serde_json::json!({"identity": {"type": "object"}, "purpose": purpose_schema()}),
                    &["identity", "purpose"],
                ),
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

pub struct AdhkeyLifecycle {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(AdhkeyLifecycle { manifest: manifest() })
}

fn failed(e: String) -> OrganelleError {
    OrganelleError::failed(e)
}

fn identity_of(v: &Value) -> Result<Identity, OrganelleError> {
    let sub = v
        .get("identity")
        .ok_or_else(|| failed("missing field \"identity\"".to_string()))?;
    serde_json::from_value(sub.clone()).map_err(|e| failed(format!("bad Identity: {e}")))
}

fn to_json<T: serde::Serialize>(t: &T) -> Result<Value, OrganelleError> {
    serde_json::to_value(t).map_err(|e| failed(e.to_string()))
}

impl Organelle for AdhkeyLifecycle {
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
            "create_identity" => {
                let threshold = input
                    .get("recovery_threshold")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as usize;
                let key_ids: Vec<String> = input
                    .get("recovery_key_ids")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let policy = RecoveryPolicy {
                    threshold,
                    recovery_key_ids: key_ids.into_iter().map(KeyId).collect(),
                };
                if !policy.valid() {
                    return Err(failed("invalid recovery policy".to_string()));
                }
                let id = Identity {
                    identifier: str_in(&input, "identifier")?,
                    subject: Subject(str_in(&input, "subject")?),
                    verification_methods: vec![],
                    keys: BTreeMap::new(),
                    recovery_policy: policy,
                    history: vec![],
                };
                to_json(&id)
            }
            "activate_key" => {
                let mut id = identity_of(&input)?;
                let purpose: KeyPurpose = serde_json::from_value(
                    input
                        .get("purpose")
                        .ok_or_else(|| failed("missing field \"purpose\"".to_string()))?
                        .clone(),
                )
                .map_err(|e| failed(format!("bad purpose: {e}")))?;
                activate_key(&mut id, KeyId(str_in(&input, "key_id")?), purpose)
                    .map_err(|e| failed(format!("{e:?}")))?;
                to_json(&id)
            }
            "transition_key" => {
                let mut id = identity_of(&input)?;
                let next: KeyState = serde_json::from_value(
                    input
                        .get("next")
                        .ok_or_else(|| failed("missing field \"next\"".to_string()))?
                        .clone(),
                )
                .map_err(|e| failed(format!("bad state: {e}")))?;
                let reason = input
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                transition_key(&mut id, &KeyId(str_in(&input, "key_id")?), next, &reason)
                    .map_err(|e| failed(format!("{e:?}")))?;
                to_json(&id)
            }
            "can_transition" => {
                let from: KeyState = serde_json::from_value(
                    input
                        .get("from")
                        .ok_or_else(|| failed("missing field \"from\"".to_string()))?
                        .clone(),
                )
                .map_err(|e| failed(format!("bad state: {e}")))?;
                let to: KeyState = serde_json::from_value(
                    input
                        .get("to")
                        .ok_or_else(|| failed("missing field \"to\"".to_string()))?
                        .clone(),
                )
                .map_err(|e| failed(format!("bad state: {e}")))?;
                Ok(serde_json::json!({"legal": from.can_transition_to(to)}))
            }
            "key_state" => {
                let id = identity_of(&input)?;
                let key = KeyId(str_in(&input, "key_id")?);
                match id.key_state(&key) {
                    Some(s) => Ok(serde_json::json!({"found": true, "state": to_json(&s)?})),
                    None => Ok(serde_json::json!({"found": false})),
                }
            }
            "active_keys" => {
                let id = identity_of(&input)?;
                let purpose: KeyPurpose = serde_json::from_value(
                    input
                        .get("purpose")
                        .ok_or_else(|| failed("missing field \"purpose\"".to_string()))?
                        .clone(),
                )
                .map_err(|e| failed(format!("bad purpose: {e}")))?;
                let keys: Vec<&KeyRecord> = id.active_keys(purpose);
                to_json(&keys)
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
        let txt = include_str!("../../../organelles/adhkey-lifecycle.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    fn new_identity(host: &Host, ctx: &CallContext) -> Value {
        host.call(
            ctx,
            "ak",
            "create_identity",
            serde_json::json!({
                "identifier": "ID-1", "subject": "zackary",
                "recovery_threshold": 2,
                "recovery_key_ids": ["REC-1", "REC-2", "REC-3"]
            }),
        )
        .expect("create_identity")
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "adhkey-lifecycle");
        assert_eq!(m.codon, "ak");
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
        let ctx = CallContext::new("ak-test", vec![]);

        let id = new_identity(&host, &ctx);
        assert_eq!(id["identifier"], "ID-1");

        // activate a key (by value)
        let id = host
            .call(&ctx, "ak", "activate_key",
                serde_json::json!({"identity": id, "key_id": "KEY-01", "purpose": "Authentication"}))
            .expect("activate_key");
        let st = host
            .call(&ctx, "ak", "key_state",
                serde_json::json!({"identity": id, "key_id": "KEY-01"}))
            .expect("key_state");
        assert_eq!(st["state"], "Active");

        // duplicate activation is refused
        assert!(host
            .call(&ctx, "ak", "activate_key",
                serde_json::json!({"identity": id, "key_id": "KEY-01", "purpose": "Authentication"}))
            .is_err());

        // legal transition: Active -> Lost
        let id = host
            .call(&ctx, "ak", "transition_key",
                serde_json::json!({"identity": id, "key_id": "KEY-01", "next": "Lost", "reason": "device stolen"}))
            .expect("transition to Lost");
        // Lost -> Active REJECTED without proof of possession
        assert!(host
            .call(&ctx, "ak", "transition_key",
                serde_json::json!({"identity": id, "key_id": "KEY-01", "next": "Active", "reason": "found"}))
            .is_err());
        // Lost -> Revoked is legal
        let id = host
            .call(&ctx, "ak", "transition_key",
                serde_json::json!({"identity": id, "key_id": "KEY-01", "next": "Revoked", "reason": "stolen"}))
            .expect("transition to Revoked");

        // history recorded every move (activate + 2 transitions)
        let hist = id["history"].as_array().unwrap();
        assert!(hist.len() >= 3, "every transition recorded: {hist:?}");

        // can_transition oracle
        let c = host
            .call(&ctx, "ak", "can_transition", serde_json::json!({"from": "Active", "to": "Lost"}))
            .expect("can_transition");
        assert_eq!(c["legal"], true);
        let c = host
            .call(&ctx, "ak", "can_transition", serde_json::json!({"from": "Revoked", "to": "Active"}))
            .expect("can_transition");
        assert_eq!(c["legal"], false);

        // no usable auth keys left
        let ak = host
            .call(&ctx, "ak", "active_keys",
                serde_json::json!({"identity": id, "purpose": "Authentication"}))
            .expect("active_keys");
        assert_eq!(ak.as_array().unwrap().len(), 0);

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 9, "register + calls = >=9 receipts, got {n}");
    }
}
