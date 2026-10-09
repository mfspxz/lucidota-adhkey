//! The tiny Court. Every implementation must survive these.
//!
//! Each test is an attack. Green means the attack failed (correct).
//! Red means the verifier is broken.
//!
//! Post-hardening (AUDIT.md C1-C7): signatures are REAL Ed25519 here,
//! produced by `TestKeys` (an in-test `KeyOperator` over adhkey-crypto).
//! There is no `signature_valid` field to inject — it was deleted.

use crate::lifecycle::*;
use crate::verifier::*;
use crate::*;
use std::collections::BTreeMap;

fn kid(s: &str) -> KeyId {
    KeyId(s.to_string())
}

/// Real Ed25519 key operator for tests. Deterministic seeds = test
/// vectors. This is REAL cryptography (ed25519-dalek), not a stub:
/// a forged signature fails here exactly as it would in production.
struct TestKeys {
    seeds: BTreeMap<KeyId, [u8; 32]>,
}

impl TestKeys {
    fn new() -> Self {
        let mut seeds = BTreeMap::new();
        // Fixed test-vector seeds. Production MUST use generate_signing_key.
        seeds.insert(kid("KEY-01"), [1u8; 32]);
        seeds.insert(kid("KEY-02"), [2u8; 32]);
        seeds.insert(kid("REC-1"), [11u8; 32]);
        seeds.insert(kid("REC-2"), [12u8; 32]);
        seeds.insert(kid("REC-3"), [13u8; 32]);
        seeds.insert(kid("RECEIPT-SIGNER"), [21u8; 32]);
        seeds.insert(kid("ATTACKER"), [99u8; 32]);
        TestKeys { seeds }
    }
}

impl KeyOperator for TestKeys {
    fn sign(&self, key: &KeyId, message: &[u8]) -> Result<Vec<u8>, Error> {
        let seed = self
            .seeds
            .get(key)
            .ok_or_else(|| Error::UnknownKey(key.clone()))?;
        let sk = adhkey_crypto::signing_key_from_seed(seed);
        Ok(adhkey_crypto::signature_to_bytes(&adhkey_crypto::sign(&sk, message)).to_vec())
    }

    fn verify(&self, key: &KeyId, message: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let seed = self
            .seeds
            .get(key)
            .ok_or_else(|| Error::KeyOperatorFailed(format!("unknown key {key}")))?;
        let sk = adhkey_crypto::signing_key_from_seed(seed);
        let vk = adhkey_crypto::verifying_key(&sk);
        if signature.len() != 64 {
            return Ok(false); // malformed: invalid, not an error
        }
        let mut b = [0u8; 64];
        b.copy_from_slice(signature);
        let sig = adhkey_crypto::signature_from_bytes(&b)
            .map_err(Error::KeyOperatorFailed)?;
        Ok(adhkey_crypto::verify(&vk, message, &sig))
    }
}

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

/// Sign a capability with the named key (default: its own key_id).
fn sign_cap(keys: &TestKeys, cap: &Capability, by: &KeyId) -> SignedCapability {
    let env = capability_envelope(cap);
    let sig = keys.sign(by, &env).unwrap();
    SignedCapability {
        capability: cap.clone(),
        signature: sig,
    }
}

fn ctx<'a>(
    id: &'a Identity,
    nonces: &'a mut NonceStore,
    keys: &'a TestKeys,
) -> VerifierContext<'a> {
    VerifierContext {
        identity: id,
        nonces,
        now: 1500,
        keys,
        receipt_signer: kid("RECEIPT-SIGNER"),
        receipt_prev_hash: [0u8; 32],
    }
}

/// Large-Err allowed: the failure receipt is evidence, and the path is cold.
#[allow(clippy::result_large_err)]
fn verify(
    id: &Identity,
    nonces: &mut NonceStore,
    keys: &TestKeys,
    scap: SignedCapability,
) -> Result<(Established<Capability>, SealedReceipt), (Error, SealedReceipt)> {
    let mut c = ctx(id, nonces, keys);
    verify_capability(
        &mut c,
        Claimed(scap),
        &Subject("zackary".into()),
        "cutecity",
        KeyPurpose::Authentication,
    )
}

fn fresh_nonces() -> NonceStore {
    NonceStore::new(48 * 3600, 3600, 100_000)
}

// ---------------------------------------------------------------------------
// Baseline: honest paths still work
// ---------------------------------------------------------------------------

#[test]
fn court_honest_capability_passes() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let scap = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    let r = verify(&id, &mut nonces, &keys, scap);
    assert!(r.is_ok(), "honest capability must verify");
    let (est, receipt) = r.unwrap();
    assert_eq!(est.key_state_at_check, KeyState::Active);
    // The receipt is sealed and records the signature check:
    assert_eq!(receipt.body.outcome, Outcome::Pass);
    assert!(receipt.body.checks.contains(&Check::SignatureValid));
    assert!(!receipt.signature.is_empty(), "receipt must be sealed");
    // ...and the seal verifies under the receipt signer:
    let log_ok = {
        let mut log = ReceiptLog::new();
        log.append(&keys, &kid("RECEIPT-SIGNER"), receipt.body.clone(), 1500)
            .unwrap();
        log.verify_chain(&keys).is_ok()
    };
    assert!(log_ok, "sealed receipt chain must verify");
    // And authorization is a SEPARATE judgment:
    let auth = authorize(est, |c| c.scope == "read:ledger");
    assert!(auth.is_ok());
}

#[test]
fn court_unknown_key() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let mut cap = good_cap();
    cap.key_id = kid("NOPE");
    // Attacker signs with their own key, but the identity doesn't know NOPE:
    let scap = sign_cap(&keys, &cap, &kid("ATTACKER"));
    let (e, receipt) = verify(&id, &mut nonces, &keys, scap).unwrap_err();
    assert_eq!(e, Error::UnknownKey(kid("NOPE")));
    assert_eq!(receipt.body.outcome, Outcome::Fail);
}

#[test]
fn court_wrong_key_state_revoked() {
    let keys = TestKeys::new();
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Revoked, "compromised").unwrap();
    let mut nonces = fresh_nonces();
    let scap = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    let (e, _) = verify(&id, &mut nonces, &keys, scap).unwrap_err();
    assert_eq!(e, Error::KeyNotUsable(kid("KEY-01"), KeyState::Revoked));
}

#[test]
fn court_revoked_key_stays_revoked() {
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Revoked, "x").unwrap();
    assert!(!KeyState::Revoked.can_transition_to(KeyState::Active));
    assert!(!KeyState::Revoked.can_transition_to(KeyState::Lost));
    let err = transition_key(&mut id, &kid("KEY-01"), KeyState::Active, "x");
    assert_eq!(
        err,
        Err(Error::IllegalTransition(KeyState::Revoked, KeyState::Active))
    );
}

#[test]
fn court_expired_capability() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let mut cap = good_cap();
    cap.expires_at = 1400; // now is 1500
    let scap = sign_cap(&keys, &cap, &kid("KEY-01"));
    let (e, receipt) = verify(&id, &mut nonces, &keys, scap).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
    assert_eq!(receipt.body.outcome, Outcome::Fail);
}

#[test]
fn court_wrong_subject() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let mut cap = good_cap();
    cap.subject = Subject("mallory".into());
    let scap = sign_cap(&keys, &cap, &kid("KEY-01"));
    assert!(verify(&id, &mut nonces, &keys, scap).is_err());
}

#[test]
fn court_wrong_audience() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let mut cap = good_cap();
    cap.audience = "evil-corp".into();
    let scap = sign_cap(&keys, &cap, &kid("KEY-01"));
    assert!(verify(&id, &mut nonces, &keys, scap).is_err());
}

#[test]
fn court_empty_scope_rejected() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let mut cap = good_cap();
    cap.scope = "".into();
    let scap = sign_cap(&keys, &cap, &kid("KEY-01"));
    assert!(verify(&id, &mut nonces, &keys, scap).is_err());
}

#[test]
fn court_replay_rejected() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let scap = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    assert!(verify(&id, &mut nonces, &keys, scap).is_ok());
    // Same nonce again — the verifier owns the nonce store:
    let scap2 = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    let (e, receipt) = verify(&id, &mut nonces, &keys, scap2).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
    assert!(receipt.body.checks.contains(&Check::NonceReplayed));
}

#[test]
fn court_nonce_not_consumed_on_failure() {
    // Red-team A5: a failed verification (bad signature) must NOT burn the
    // nonce. Attacker submits garbage sig with fresh nonce; honest holder's
    // later valid attempt with the same nonce must still succeed.
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let mut scap = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    scap.signature = vec![0u8; 64]; // garbage
    let (e, _) = verify(&id, &mut nonces, &keys, scap).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
    assert!(
        !nonces.contains("nonce-001", 1500),
        "failed verification must not consume the nonce"
    );
    // Honest retry with the same nonce now succeeds:
    let scap2 = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    assert!(verify(&id, &mut nonces, &keys, scap2).is_ok());
}

#[test]
fn court_wrong_purpose() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let mut cap = good_cap();
    cap.key_id = kid("REC-1"); // a recovery key, not authentication
    cap.nonce = "nonce-rec1".into();
    let scap = sign_cap(&keys, &cap, &kid("REC-1"));
    let (e, _) = verify(&id, &mut nonces, &keys, scap).unwrap_err();
    assert!(matches!(e, Error::WrongPurpose { .. }));
}

// ---------------------------------------------------------------------------
// C1 negative tests: the signature stub is dead
// ---------------------------------------------------------------------------

#[test]
fn court_c1_forged_signature_rejected() {
    // Attacker signs the capability with THEIR key but claims KEY-01.
    // The verifier checks against the identity's key for KEY-01. Fails.
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let scap = sign_cap(&keys, &good_cap(), &kid("ATTACKER"));
    let (e, receipt) = verify(&id, &mut nonces, &keys, scap).unwrap_err();
    assert!(
        matches!(&e, Error::InvalidPolicy(m) if m == "signature invalid"),
        "forged signature must fail, got: {e:?}"
    );
    assert_eq!(receipt.body.outcome, Outcome::Fail);
    assert!(!receipt.body.checks.contains(&Check::SignatureValid));
}

#[test]
fn court_c1_tampered_envelope_rejected() {
    // Sign honestly, then flip a byte in the capability (privilege
    // escalation: read -> admin). Signature no longer matches. Fails.
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let mut scap = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    scap.capability.scope = "admin:everything".into();
    let (e, _) = verify(&id, &mut nonces, &keys, scap).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
}

#[test]
fn court_c1_key_substitution_rejected() {
    // Attacker takes a VALID signature from KEY-01 over one capability
    // and attaches it to a DIFFERENT capability (different nonce/scope).
    // Cross-capability signature replay fails.
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let scap = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    let mut evil = good_cap();
    evil.nonce = "nonce-evil".into();
    evil.scope = "admin:everything".into();
    let evil_signed = SignedCapability {
        capability: evil,
        signature: scap.signature, // transplanted
    };
    let (e, _) = verify(&id, &mut nonces, &keys, evil_signed).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
}

#[test]
fn court_c1_no_injectable_bool() {
    // The old `signature_valid: bool` field is GONE. This test pins the
    // new shape: VerifierContext has no boolean the caller can set.
    // (Compile-time property; runtime check: even a perfect liar who
    // controls capability construction cannot pass without the key.)
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    // Attacker controls everything about the SignedCapability EXCEPT a
    // valid signature from KEY-01's private key:
    let evil = SignedCapability {
        capability: good_cap(),
        signature: vec![0xAB; 64],
    };
    assert!(verify(&id, &mut nonces, &keys, evil).is_err());
}

// ---------------------------------------------------------------------------
// C5: NonceStore — bounded, time-partitioned, restorable
// ---------------------------------------------------------------------------

#[test]
fn court_c5_replay_within_window_rejected() {
    let mut ns = NonceStore::new(3600, 60, 1000);
    assert_eq!(ns.check_and_insert("n1", 1000), Ok(true));
    assert_eq!(ns.check_and_insert("n1", 1001), Ok(false)); // replay
}

#[test]
fn court_c5_expiry_releases_nonce() {
    // Time-partitioning: after the window, the bucket is dropped.
    // (Safe for capabilities: the capability's own expiry is the real bound.)
    let mut ns = NonceStore::new(100, 10, 1000);
    assert_eq!(ns.check_and_insert("n1", 0), Ok(true));
    assert!(!ns.contains("n1", 500), "stale bucket must be pruned");
    assert_eq!(ns.check_and_insert("n1", 500), Ok(true));
}

#[test]
fn court_c5_bounded_bucket_fails_closed() {
    let mut ns = NonceStore::new(3600, 3600, 2);
    assert_eq!(ns.check_and_insert("a", 100), Ok(true));
    assert_eq!(ns.check_and_insert("b", 100), Ok(true));
    // Bucket full: FAIL CLOSED. The nonce is not recorded, verification
    // must not proceed. Never silently drop replay protection.
    assert_eq!(ns.check_and_insert("c", 100), Err(Error::NonceStoreFull));
    assert!(!ns.contains("c", 100));
}

#[test]
fn court_c5_snapshot_restore_survives_restart() {
    // Persistence story: snapshot -> "restart" (new store) -> restore.
    // A replayed nonce is still caught after the restart.
    let mut ns = NonceStore::new(3600, 60, 1000);
    ns.check_and_insert("seen-before-crash", 1000).unwrap();
    let snap = ns.snapshot();
    let mut ns2 = NonceStore::new(3600, 60, 1000);
    ns2.restore(&snap, 1100);
    assert_eq!(ns2.check_and_insert("seen-before-crash", 1100), Ok(false));
    // Stale buckets don't survive the restore:
    let mut ns3 = NonceStore::new(100, 10, 1000);
    ns3.check_and_insert("old", 0).unwrap();
    let snap3 = ns3.snapshot();
    let mut ns4 = NonceStore::new(100, 10, 1000);
    ns4.restore(&snap3, 9999);
    assert!(ns4.is_empty(), "stale buckets pruned on restore");
}

// ---------------------------------------------------------------------------
// C6: Lost -> Active requires proof of possession
// ---------------------------------------------------------------------------

fn possession_proof(
    keys: &TestKeys,
    key: &KeyId,
    by: &KeyId,
    challenge: [u8; 32],
    issued_at: u64,
) -> SignedPossessionProof {
    let msg = possession_bytes(key, &challenge, issued_at);
    SignedPossessionProof {
        key: key.clone(),
        challenge,
        issued_at,
        signature: keys.sign(by, &msg).unwrap(),
    }
}

#[test]
fn court_c6_lost_to_active_rejected_without_proof() {
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "phone gone").unwrap();
    // The direct path is now closed, unconditionally:
    let err = transition_key(&mut id, &kid("KEY-01"), KeyState::Active, "found");
    assert_eq!(err, Err(Error::ProofOfPossessionRequired(kid("KEY-01"))));
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Lost));
}

#[test]
fn court_c6_refound_with_fresh_proof() {
    let keys = TestKeys::new();
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "phone gone").unwrap();
    let proof = possession_proof(&keys, &kid("KEY-01"), &kid("KEY-01"), [5u8; 32], 1490);
    refound_key(&mut id, &kid("KEY-01"), &proof, &keys, 1500, 60).unwrap();
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Active));
}

#[test]
fn court_c6_refound_forged_proof_rejected() {
    // Attacker "finds" the key but doesn't hold the private key.
    let keys = TestKeys::new();
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "phone gone").unwrap();
    let proof = possession_proof(&keys, &kid("KEY-01"), &kid("ATTACKER"), [5u8; 32], 1490);
    let err = refound_key(&mut id, &kid("KEY-01"), &proof, &keys, 1500, 60);
    assert!(matches!(err, Err(Error::BadPossessionProof(_))));
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Lost));
}

#[test]
fn court_c6_refound_stale_challenge_rejected() {
    // "I held it last year" is not proof of possession.
    let keys = TestKeys::new();
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "phone gone").unwrap();
    let proof = possession_proof(&keys, &kid("KEY-01"), &kid("KEY-01"), [5u8; 32], 1000);
    let err = refound_key(&mut id, &kid("KEY-01"), &proof, &keys, 1500, 60);
    assert!(matches!(err, Err(Error::BadPossessionProof(_))));
}

// ---------------------------------------------------------------------------
// C2: signed recovery approvals
// ---------------------------------------------------------------------------

fn approval(
    keys: &TestKeys,
    signer: &KeyId,
    old_key: &KeyId,
    new_key: &KeyId,
    nonce: &str,
) -> SignedApproval {
    let intent = RecoveryIntent {
        identity: "IDENTITY-001".into(),
        old_key: old_key.clone(),
        new_key: new_key.clone(),
        nonce: nonce.into(),
        policy_version: 1,
    };
    let msg = recovery_intent_bytes(&intent);
    SignedApproval {
        signer: signer.clone(),
        intent,
        signature: keys.sign(signer, &msg).unwrap(),
    }
}

fn recover2(
    id: &mut Identity,
    keys: &TestKeys,
    nonces: &mut NonceStore,
    old: &str,
    new: &str,
    approvals: &[SignedApproval],
) -> Result<(), Error> {
    recover(
        id,
        &kid(old),
        kid(new),
        KeyPurpose::Authentication,
        approvals,
        keys,
        nonces,
        1500,
    )
}

#[test]
fn court_c2_honest_signed_recovery() {
    let keys = TestKeys::new();
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "lost").unwrap();
    let mut nonces = fresh_nonces();
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-02"), "r1");
    let a2 = approval(&keys, &kid("REC-2"), &kid("KEY-01"), &kid("KEY-02"), "r2");
    recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-02", &[a1, a2]).unwrap();
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Revoked));
    assert_eq!(id.key_state(&kid("KEY-02")), Some(KeyState::Active));
}

#[test]
fn court_c2_bare_key_ids_are_not_approvals() {
    // The old attack: pass key IDs as assertions. The type no longer
    // allows it — approvals MUST carry signatures. A caller who just
    // names the keys cannot construct a SignedApproval that verifies
    // without the private keys.
    let keys = TestKeys::new();
    let mut id = test_identity();
    let mut nonces = fresh_nonces();
    // Attacker knows the IDs and even the intent format, but not the keys:
    let intent = RecoveryIntent {
        identity: "IDENTITY-001".into(),
        old_key: kid("KEY-01"),
        new_key: kid("KEY-99"),
        nonce: "evil".into(),
        policy_version: 1,
    };
    let fake = SignedApproval {
        signer: kid("REC-1"),
        intent,
        signature: vec![0xCD; 64], // no private key, no signature
    };
    let err = recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-99", &[fake.clone(), fake]);
    assert!(matches!(err, Err(Error::BadApproval(_))));
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Active));
}

#[test]
fn court_c2_approval_for_wrong_ceremony_rejected() {
    // Approval signed for (KEY-01 -> KEY-02) cannot authorize (KEY-01 -> KEY-99).
    let keys = TestKeys::new();
    let mut id = test_identity();
    let mut nonces = fresh_nonces();
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-02"), "r1");
    let a2 = approval(&keys, &kid("REC-2"), &kid("KEY-01"), &kid("KEY-02"), "r2");
    let err = recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-99", &[a1, a2]);
    assert!(matches!(err, Err(Error::BadApproval(_))));
}

#[test]
fn court_c2_approval_nonce_replay_rejected() {
    // Same signed approval twice in one ceremony: the second use is a
    // replay — one approval, one ceremony. Threshold 1 isolates the
    // nonce-replay path (distinct-signer counting passes; the replayed
    // nonce must still kill it).
    let keys = TestKeys::new();
    let mut id = test_identity();
    id.recovery_policy.threshold = 1;
    let mut nonces = fresh_nonces();
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-02"), "r1");
    let a1_dup = a1.clone();
    let err = recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-02", &[a1, a1_dup]);
    assert!(
        matches!(&err, Err(Error::BadApproval(m)) if m.contains("replayed")),
        "replayed approval nonce must be rejected, got: {err:?}"
    );
    // And the identity is untouched:
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Active));
    assert_eq!(id.key_state(&kid("KEY-02")), None);
}

#[test]
fn court_c2_non_policy_signer_rejected() {
    // Signed by a VALID key that is not in the recovery policy.
    let keys = TestKeys::new();
    let mut id = test_identity();
    let mut nonces = fresh_nonces();
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-02"), "r1");
    // ATTACKER key signs a well-formed intent — but isn't policy-listed:
    let evil_intent = RecoveryIntent {
        identity: "IDENTITY-001".into(),
        old_key: kid("KEY-01"),
        new_key: kid("KEY-02"),
        nonce: "evil".into(),
        policy_version: 1,
    };
    let msg = recovery_intent_bytes(&evil_intent);
    let evil = SignedApproval {
        signer: kid("ATTACKER"),
        intent: evil_intent,
        signature: keys.sign(&kid("ATTACKER"), &msg).unwrap(),
    };
    let err = recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-02", &[a1, evil]);
    assert!(matches!(err, Err(Error::BadApproval(_))));
}

#[test]
fn court_recovery_noop_rejected_cleanly() {
    // Red-team A10: recover(new_key == old_key) must fail BEFORE any
    // mutation — no history record, no revocation.
    let keys = TestKeys::new();
    let mut id = test_identity();
    let mut nonces = fresh_nonces();
    let h0 = id.history.len();
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-01"), "r1");
    let r = recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-01", &[a1]);
    assert!(r.is_err());
    assert_eq!(id.history.len(), h0, "no history on rejected recovery");
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Active));
}

#[test]
fn court_recovery_preserves_purpose() {
    // Red-team A3: recovery must not change key purpose (privilege esc.).
    let keys = TestKeys::new();
    let mut id = test_identity();
    let mut nonces = fresh_nonces();
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-02"), "r1");
    let r = recover(
        &mut id,
        &kid("KEY-01"),
        kid("KEY-02"),
        KeyPurpose::Recovery, // KEY-01 is Authentication
        &[a1],
        &keys,
        &mut nonces,
        1500,
    );
    assert!(r.is_err());
}

#[test]
fn court_unauthorized_recovery() {
    let keys = TestKeys::new();
    let mut id = test_identity();
    let mut nonces = fresh_nonces();
    // Attacker signs with a non-recovery key:
    let evil_intent = RecoveryIntent {
        identity: "IDENTITY-001".into(),
        old_key: kid("KEY-01"),
        new_key: kid("KEY-02"),
        nonce: "evil".into(),
        policy_version: 1,
    };
    let msg = recovery_intent_bytes(&evil_intent);
    let evil = SignedApproval {
        signer: kid("KEY-01"),
        intent: evil_intent,
        signature: keys.sign(&kid("KEY-01"), &msg).unwrap(),
    };
    let err = recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-02", &[evil]);
    assert!(matches!(err, Err(Error::BadApproval(_))));
}

#[test]
fn court_partial_recovery() {
    let keys = TestKeys::new();
    let mut id = test_identity();
    let mut nonces = fresh_nonces();
    // Only 1 of 2 required approvals:
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-02"), "r1");
    let err = recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-02", &[a1]);
    assert_eq!(
        err,
        Err(Error::RecoveryThresholdNotMet { have: 1, need: 2 })
    );
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Active));
}

#[test]
fn court_honest_recovery_preserves_identity() {
    let keys = TestKeys::new();
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "phone lost").unwrap();
    let mut nonces = fresh_nonces();
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-02"), "r1");
    let a2 = approval(&keys, &kid("REC-2"), &kid("KEY-01"), &kid("KEY-02"), "r2");
    recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-02", &[a1, a2]).unwrap();
    assert_eq!(id.identifier, "IDENTITY-001");
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Revoked));
    assert_eq!(id.key_state(&kid("KEY-02")), Some(KeyState::Active));
    // New key verifies (KEY-02 needs a registered seed — add it):
    let mut nonces2 = fresh_nonces();
    let mut cap = good_cap();
    cap.key_id = kid("KEY-02");
    cap.nonce = "nonce-002".into();
    let scap = sign_cap(&keys, &cap, &kid("KEY-02"));
    assert!(verify(&id, &mut nonces2, &keys, scap).is_ok());
}

#[test]
fn court_stale_recovery_key_rejected() {
    let keys = TestKeys::new();
    let mut id = test_identity();
    transition_key(&mut id, &kid("REC-3"), KeyState::Revoked, "rotated").unwrap();
    let mut nonces = fresh_nonces();
    let a1 = approval(&keys, &kid("REC-1"), &kid("KEY-01"), &kid("KEY-02"), "r1");
    let a3 = approval(&keys, &kid("REC-3"), &kid("KEY-01"), &kid("KEY-02"), "r3");
    let err = recover2(&mut id, &keys, &mut nonces, "KEY-01", "KEY-02", &[a1, a3]);
    assert_eq!(err, Err(Error::RecoveryKeyNotUsable(kid("REC-3"))));
}

// ---------------------------------------------------------------------------
// C7: tamper-evident sealed receipts
// ---------------------------------------------------------------------------

#[test]
fn court_c7_receipt_chain_verifies() {
    let keys = TestKeys::new();
    let mut log = ReceiptLog::new();
    let body = ReceiptBody {
        subject: Subject("zackary".into()),
        key_id: kid("KEY-01"),
        key_state: KeyState::Active,
        checks: vec![Check::KeyKnown, Check::SignatureValid],
        not_checked: vec!["scope semantics".into()],
        outcome: Outcome::Pass,
    };
    let t1 = log.append(&keys, &kid("RECEIPT-SIGNER"), body.clone(), 1500).unwrap();
    let t2 = log.append(&keys, &kid("RECEIPT-SIGNER"), body, 1501).unwrap();
    assert_ne!(t1, t2, "chain advances");
    assert!(log.verify_chain(&keys).is_ok());
    assert_eq!(log.len(), 2);
}

#[test]
fn court_c7_tampered_receipt_breaks_chain() {
    // Attacker flips a check in a sealed receipt. The signature no
    // longer matches -> chain verification fails, loudly.
    let keys = TestKeys::new();
    let body = ReceiptBody {
        subject: Subject("zackary".into()),
        key_id: kid("KEY-01"),
        key_state: KeyState::Active,
        checks: vec![Check::KeyKnown],
        not_checked: vec![],
        outcome: Outcome::Fail,
    };
    let mut log = ReceiptLog::new();
    log.append(&keys, &kid("RECEIPT-SIGNER"), body, 1500).unwrap();
    assert!(log.verify_chain(&keys).is_ok());
    // Tamper: rewrite the recorded outcome to Pass (signature was over Fail).
    let mut tampered = log.receipts()[0].clone();
    tampered.body.outcome = Outcome::Pass;
    let evil_log = ReceiptLog::from_vec(vec![tampered]);
    assert_eq!(evil_log.verify_chain(&keys), Err(Error::ReceiptChainBroken));
}

#[test]
fn court_c7_removed_receipt_breaks_chain() {
    // Attacker deletes the middle receipt. The next receipt's prev_hash
    // no longer links -> chain verification fails.
    let keys = TestKeys::new();
    let body = || ReceiptBody {
        subject: Subject("zackary".into()),
        key_id: kid("KEY-01"),
        key_state: KeyState::Active,
        checks: vec![Check::KeyKnown],
        not_checked: vec![],
        outcome: Outcome::Pass,
    };
    let mut log = ReceiptLog::new();
    log.append(&keys, &kid("RECEIPT-SIGNER"), body(), 1500).unwrap();
    log.append(&keys, &kid("RECEIPT-SIGNER"), body(), 1501).unwrap();
    log.append(&keys, &kid("RECEIPT-SIGNER"), body(), 1502).unwrap();
    assert!(log.verify_chain(&keys).is_ok());
    // Delete receipt #2:
    let mut receipts = log.receipts().to_vec();
    receipts.remove(1);
    let evil_log = ReceiptLog::from_vec(receipts);
    assert_eq!(evil_log.verify_chain(&keys), Err(Error::ReceiptChainBroken));
}

#[test]
fn court_c7_forged_seal_rejected() {
    // Attacker authors a receipt and signs it with THEIR key, claiming
    // the receipt-signer identity. Signature check is against the actual
    // RECEIPT-SIGNER key -> fails.
    let keys = TestKeys::new();
    let body = ReceiptBody {
        subject: Subject("mallory".into()),
        key_id: kid("ATTACKER"),
        key_state: KeyState::Active,
        checks: vec![Check::SignatureValid], // a lie
        not_checked: vec![],
        outcome: Outcome::Pass, // a lie
    };
    // Sealed "by" RECEIPT-SIGNER but actually signed by ATTACKER:
    let mut forged = seal_receipt(&keys, &kid("RECEIPT-SIGNER"), body, [0u8; 32], 1500).unwrap();
    let evil_bytes = sealed_receipt_bytes(&forged);
    forged.signature = keys.sign(&kid("ATTACKER"), &evil_bytes).unwrap();
    let log = ReceiptLog::from_vec(vec![forged]);
    assert_eq!(log.verify_chain(&keys), Err(Error::ReceiptChainBroken));
}

#[test]
fn court_c7_tombstone_never_valid() {
    // A seal failure produces a tombstone (empty signature). It must
    // NEVER verify as a real receipt.
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    // Break the sealer: receipt signer key unknown to the operator.
    let mut broken_ctx = VerifierContext {
        identity: &id,
        nonces: &mut nonces,
        now: 1500,
        keys: &keys,
        receipt_signer: kid("NO-SUCH-SIGNER"),
        receipt_prev_hash: [0u8; 32],
    };
    let scap = sign_cap(&keys, &good_cap(), &kid("KEY-01"));
    let (e, tombstone) = verify_capability(
        &mut broken_ctx,
        Claimed(scap),
        &Subject("zackary".into()),
        "cutecity",
        KeyPurpose::Authentication,
    )
    .unwrap_err();
    assert!(matches!(e, Error::KeyOperatorFailed(_)));
    assert!(tombstone.signature.is_empty());
    let log = ReceiptLog::from_vec(vec![tombstone]);
    assert_eq!(log.verify_chain(&keys), Err(Error::ReceiptChainBroken));
}

// ---------------------------------------------------------------------------
// Trichotomy still distinct
// ---------------------------------------------------------------------------

#[test]
fn court_trichotomy_never_collapses() {
    let keys = TestKeys::new();
    let id = test_identity();
    let mut nonces = fresh_nonces();
    let claimed: Claimed<Capability> = Claimed(good_cap());
    let scap = sign_cap(&keys, &claimed.0, &kid("KEY-01"));
    let (established, _) = verify(&id, &mut nonces, &keys, scap).unwrap();
    let authorized: Authorized<Capability> = authorize(established, |_| true).unwrap();
    assert!(authorized.capability.nonce == "nonce-001");
}
