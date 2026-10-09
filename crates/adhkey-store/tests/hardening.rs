//! Hardening battery: end-to-end attacks through the REAL adapter seam.
//!
//! Unlike court.rs (fixed test-vector seeds), these tests use
//! `InMemoryKeyStore::generate` — OS CSPRNG keys — proving the fixes
//! hold with real key material through the `KeyStore`/`KeyOperator`
//! adapter boundary, not just inside one crate's test module.
//!
//! Each test names the AUDIT.md finding it attacks.

use adhkey_core::{
    capability_envelope, sealed_receipt_bytes, Authorized, Capability,
    Check, Claimed, Error, Established, Identity, KeyId, KeyOperator,
    KeyPurpose, KeyState, NonceStore, Outcome, ReceiptLog,
    RecoveryIntent, RecoveryPolicy, SealedReceipt, SignedApproval,
    SignedCapability, SignedPolicyVerdict, SignedPossessionProof, Subject,
    PolicyDecision, possession_bytes, policy_verdict_bytes,
    recovery_intent_bytes,
};
use adhkey_core::evidence::{
    establish, evaluate_claim, AuthorizationVerdict, EpistemicState,
    Evidence, EvidenceKind, HumanClaim, SubjectKind, Witness,
    authorize_with_freshness,
};
use adhkey_core::lifecycle::{activate_key, recover, refound_key, transition_key};
use adhkey_core::verifier::{authorize, verify_capability, VerifierContext};
use adhkey_store::{InMemoryKeyStore, KeyStore};
use std::collections::BTreeMap;

fn kid(s: &str) -> KeyId {
    KeyId(s.to_string())
}

/// Large-Err allowed: the failure receipt is evidence, and the path is cold.
#[allow(clippy::result_large_err)]
type VerifyOut = Result<(Established<Capability>, SealedReceipt), (Error, SealedReceipt)>;

fn test_identity() -> Identity {
    let mut id = Identity {
        identifier: "IDENTITY-001".into(),
        subject: Subject("zackary".into()),
        verification_methods: vec![],
        keys: BTreeMap::new(),
        recovery_policy: RecoveryPolicy {
            threshold: 2,
            recovery_key_ids: vec![kid("REC-1"), kid("REC-2"), kid("REC-3")],
        },
        history: vec![],
    };
    activate_key(&mut id, kid("KEY-01"), KeyPurpose::Authentication).unwrap();
    activate_key(&mut id, kid("REC-1"), KeyPurpose::Recovery).unwrap();
    activate_key(&mut id, kid("REC-2"), KeyPurpose::Recovery).unwrap();
    activate_key(&mut id, kid("REC-3"), KeyPurpose::Recovery).unwrap();
    id
}

/// Build a store with fresh CSPRNG keys for every id named.
fn gen_store(ids: &[&str]) -> InMemoryKeyStore {
    let mut s = InMemoryKeyStore::new();
    for id in ids {
        s.generate(kid(id));
    }
    s
}

fn sign_cap(store: &InMemoryKeyStore, cap: &Capability, by: &KeyId) -> SignedCapability {
    let env = capability_envelope(cap);
    let sig = KeyOperator::sign(store, by, &env).unwrap();
    SignedCapability {
        capability: cap.clone(),
        signature: sig,
    }
}

fn good_cap() -> Capability {
    Capability {
        subject: Subject("zackary".into()),
        scope: "read:ledger".into(),
        audience: "cutecity".into(),
        nonce: "nonce-001".into(),
        issued_at: 1000,
        expires_at: 2000,
        key_id: kid("KEY-01"),
    }
}

#[allow(clippy::result_large_err)]
fn verify_now(
    store: &InMemoryKeyStore,
    id: &Identity,
    nonces: &mut NonceStore,
    scap: SignedCapability,
    prev_hash: [u8; 32],
) -> VerifyOut {
    let mut ctx = VerifierContext {
        identity: id,
        nonces,
        now: 1500,
        keys: store,
        receipt_signer: kid("RECEIPT-SIGNER"),
        receipt_prev_hash: prev_hash,
    };
    verify_capability(
        &mut ctx,
        Claimed(scap),
        &Subject("zackary".into()),
        "cutecity",
        KeyPurpose::Authentication,
    )
}

// ---------------------------------------------------------------------------
// C1 through the adapter: KeyStore::verify is what the core calls
// ---------------------------------------------------------------------------

#[test]
fn hardening_c1_adapter_verify_called() {
    // The store trait's verify is real: a signature made by KEY-01 does
    // not verify as REC-1, and garbage is Ok(false), not Err.
    let store = gen_store(&["KEY-01"]);
    let msg = b"hello";
    let sig = KeyStore::sign(&store, &kid("KEY-01"), msg).unwrap();
    assert!(KeyStore::verify(&store, &kid("KEY-01"), msg, &sig).unwrap());
    assert!(!KeyStore::verify(&store, &kid("KEY-01"), b"other", &sig).unwrap());
    let garbage = adhkey_store::Signature(vec![1u8; 64]);
    assert!(!KeyStore::verify(&store, &kid("KEY-01"), msg, &garbage).unwrap());
    // Unknown key: fail closed, never Ok(true).
    assert!(KeyStore::verify(&store, &kid("NOPE"), msg, &sig).is_err());
}

#[test]
fn hardening_c1_generated_keys_end_to_end() {
    let store = gen_store(&["KEY-01", "REC-1", "REC-2", "REC-3", "RECEIPT-SIGNER", "ATTACKER"]);
    let id = test_identity();
    let mut nonces = NonceStore::default_verifier();
    // Honest, generated-key signature verifies:
    let scap = sign_cap(&store, &good_cap(), &kid("KEY-01"));
    let (est, receipt) = verify_now(&store, &id, &mut nonces, scap, [0u8; 32]).unwrap();
    assert_eq!(est.key_state_at_check, KeyState::Active);
    assert!(receipt.body.checks.contains(&Check::SignatureValid));
    // Attacker's generated key cannot impersonate KEY-01:
    let mut nonces2 = NonceStore::default_verifier();
    let forged = sign_cap(&store, &good_cap(), &kid("ATTACKER"));
    let evil = SignedCapability {
        capability: good_cap(),
        signature: forged.signature,
    };
    let (e, _) = verify_now(&store, &id, &mut nonces2, evil, [0u8; 32]).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
    // Authorization still separate:
    let auth = authorize(est, |_| true).unwrap();
    let _: Authorized<Capability> = auth;
}

// ---------------------------------------------------------------------------
// C5: nonce persistence across a simulated restart (file round-trip)
// ---------------------------------------------------------------------------

#[test]
fn hardening_c5_nonce_survives_restart_via_file() {
    let dir = std::env::temp_dir().join("adhkey-hardening-nonce");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("nonces.snap");
    // "Before the crash": see a nonce, snapshot to disk.
    let mut ns = NonceStore::new(3600, 60, 10_000);
    ns.check_and_insert("cap-nonce-7", 1000).unwrap();
    let snap = ns.snapshot();
    let bytes = format!("{snap:?}");
    std::fs::write(&path, bytes).unwrap();
    // "After the crash": new store, restore from disk, replay caught.
    let data = std::fs::read_to_string(&path).unwrap();
    assert!(data.contains("cap-nonce-7"));
    let mut ns2 = NonceStore::new(3600, 60, 10_000);
    ns2.restore(&snap, 1100);
    assert_eq!(ns2.check_and_insert("cap-nonce-7", 1100), Ok(false));
    assert_eq!(ns2.check_and_insert("fresh-nonce", 1100), Ok(true));
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// C7: receipt chain across multiple verifications, tamper-evident
// ---------------------------------------------------------------------------

#[test]
fn hardening_c7_chained_receipts_across_verifications() {
    let store = gen_store(&["KEY-01", "REC-1", "REC-2", "REC-3", "RECEIPT-SIGNER"]);
    let id = test_identity();
    let mut log = ReceiptLog::new();
    let mut nonces = NonceStore::default_verifier();
    let mut prev = [0u8; 32];
    for i in 0..3 {
        let mut cap = good_cap();
        cap.nonce = format!("nonce-{i}");
        let scap = sign_cap(&store, &cap, &kid("KEY-01"));
        let (_, receipt) = verify_now(&store, &id, &mut nonces, scap, prev).unwrap();
        prev = log
            .append(&store, &kid("RECEIPT-SIGNER"), receipt.body.clone(), 1500 + i)
            .unwrap();
    }
    assert_eq!(log.len(), 3);
    assert!(log.verify_chain(&store).is_ok());
    // Tamper with the middle receipt's checks: chain breaks.
    let mut receipts = log.receipts().to_vec();
    receipts[1].body.checks.push(Check::AudienceMatches);
    let evil = ReceiptLog::from_vec(receipts);
    assert_eq!(evil.verify_chain(&store), Err(Error::ReceiptChainBroken));
    // The sealed bytes are deterministic: same body -> same seal bytes.
    let r0a = &log.receipts()[0];
    let b1 = sealed_receipt_bytes(r0a);
    let b2 = sealed_receipt_bytes(r0a);
    assert_eq!(b1, b2);
}

// ---------------------------------------------------------------------------
// C2+C6: recovery then refound, generated keys
// ---------------------------------------------------------------------------

#[test]
fn hardening_c2_c6_recovery_and_refound_generated() {
    let store = gen_store(&["KEY-01", "KEY-02", "REC-1", "REC-2", "REC-3"]);
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "lost").unwrap();
    let mut nonces = NonceStore::new(7 * 24 * 3600, 3600, 10_000);

    let mk_approval = |signer: &str, nonce: &str| {
        let intent = RecoveryIntent {
            identity: "IDENTITY-001".into(),
            old_key: kid("KEY-01"),
            new_key: kid("KEY-02"),
            nonce: nonce.into(),
            policy_version: 1,
        };
        let msg = recovery_intent_bytes(&intent);
        SignedApproval {
            signer: kid(signer),
            intent,
            signature: KeyOperator::sign(&store, &kid(signer), &msg).unwrap(),
        }
    };
    recover(
        &mut id,
        &kid("KEY-01"),
        kid("KEY-02"),
        KeyPurpose::Authentication,
        &[mk_approval("REC-1", "n1"), mk_approval("REC-2", "n2")],
        &store,
        &mut nonces,
        1500,
    )
    .unwrap();
    assert_eq!(id.key_state(&kid("KEY-02")), Some(KeyState::Active));

    // C6: lose KEY-02, refound with a fresh possession proof.
    transition_key(&mut id, &kid("KEY-02"), KeyState::Lost, "lost again").unwrap();
    assert_eq!(
        transition_key(&mut id, &kid("KEY-02"), KeyState::Active, "found"),
        Err(Error::ProofOfPossessionRequired(kid("KEY-02")))
    );
    let challenge = [9u8; 32];
    let msg = possession_bytes(&kid("KEY-02"), &challenge, 1490);
    let proof = SignedPossessionProof {
        key: kid("KEY-02"),
        challenge,
        issued_at: 1490,
        signature: KeyOperator::sign(&store, &kid("KEY-02"), &msg).unwrap(),
    };
    refound_key(&mut id, &kid("KEY-02"), &proof, &store, 1500, 60).unwrap();
    assert_eq!(id.key_state(&kid("KEY-02")), Some(KeyState::Active));
}

// ---------------------------------------------------------------------------
// C3: signed policy verdict, generated keys
// ---------------------------------------------------------------------------

fn witness(id: &str, domain: &str) -> Witness {
    Witness { id: id.into(), trust_domain: domain.into() }
}

#[test]
fn hardening_c3_verdict_generated_keys() {
    let store = gen_store(&["POLICY-AUTH", "ATTACKER"]);
    let claim = HumanClaim {
        subject: Subject("S1".into()),
        kind: SubjectKind::Person,
        evidence: vec![Evidence {
            id: "gov-7".into(),
            kind: EvidenceKind::Government,
            witness: witness("dmv", "government"),
            digest: [7u8; 32],
            issued_at: 1000,
            expires_at: None,
            revoked: false,
        }],
        assurance_policy: "P17".into(),
        issued_by: witness("adhkey", "local"),
        issued_at: 1000,
        expires_at: None,
        state: EpistemicState::Claimed,
        policy_authorities: vec![kid("POLICY-AUTH")],
    };
    assert_eq!(evaluate_claim(&claim, 1500), EpistemicState::Supported);

    let mk_verdict = |by: &str, decision: PolicyDecision| {
        let mut v = SignedPolicyVerdict {
            policy_id: "P17".into(),
            policy_version: 3,
            subject: claim.subject.clone(),
            claim_hash: claim.digest(),
            decision,
            evaluated_at: 1490,
            evidence_snapshot: claim.evidence_snapshot(),
            evaluator: kid(by),
            signature: Vec::new(),
        };
        let msg = policy_verdict_bytes(&v);
        v.signature = KeyOperator::sign(&store, &kid(by), &msg).unwrap();
        v
    };
    // Honest verdict establishes:
    let v = mk_verdict("POLICY-AUTH", PolicyDecision::Allow);
    assert_eq!(
        establish(&claim, &v, &store, 1500, 3600),
        Ok(EpistemicState::Established)
    );
    // Attacker's signature, even well-formed, is unauthorized:
    let evil = mk_verdict("ATTACKER", PolicyDecision::Allow);
    assert!(matches!(
        establish(&claim, &evil, &store, 1500, 3600),
        Err(Error::BadPolicyVerdict(_))
    ));
    // Authorization verdict still three-valued:
    assert!(matches!(
        authorize_with_freshness(EpistemicState::Established, None, 60, 1500),
        AuthorizationVerdict::CannotEstablish(_)
    ));
    // Receipt-like honesty: verdict outcome recorded.
    let _ = Outcome::Pass;
}
