//! The tiny Court. Every implementation must survive these.
//!
//! Each test is an attack. Green means the attack failed (correct).
//! Red means the verifier is broken.

use crate::lifecycle::*;
use crate::verifier::*;
use crate::*;
use std::collections::BTreeSet;

fn kid(s: &str) -> KeyId {
    KeyId(s.to_string())
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

fn ctx<'a>(
    id: &'a Identity,
    nonces: &'a mut BTreeSet<String>,
    sig_valid: bool,
) -> VerifierContext<'a> {
    VerifierContext {
        identity: id,
        seen_nonces: nonces,
        now: 1500,
        signature_valid: sig_valid,
        _signed_message: b"envelope",
    }
}

fn verify(
    id: &Identity,
    nonces: &mut BTreeSet<String>,
    cap: Capability,
    sig_valid: bool,
) -> Result<Established<Capability>, (Error, Receipt)> {
    let mut c = ctx(id, nonces, sig_valid);
    verify_capability(
        &mut c,
        Claimed(cap),
        &Subject("zackary".into()),
        "cutecity",
        KeyPurpose::Authentication,
    )
}

#[test]
fn court_honest_capability_passes() {
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let r = verify(&id, &mut nonces, good_cap(), true);
    assert!(r.is_ok(), "honest capability must verify");
    let est = r.unwrap();
    assert_eq!(est.key_state_at_check, KeyState::Active);
    // And authorization is a SEPARATE judgment:
    let auth = authorize(est, |c| c.scope == "read:ledger");
    assert!(auth.is_ok());
    let denied = authorize(
        verify(&id, &mut BTreeSet::new(), good_cap(), true).unwrap(),
        |_| false,
    );
    assert!(denied.is_err(), "policy denial must not verify-fail, it authorizes-fail");
}

#[test]
fn court_unknown_key() {
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let mut cap = good_cap();
    cap.key_id = kid("NOPE");
    let (e, receipt) = verify(&id, &mut nonces, cap, true).unwrap_err();
    assert_eq!(e, Error::UnknownKey(kid("NOPE")));
    assert_eq!(receipt.outcome, Outcome::Fail);
}

#[test]
fn court_wrong_key_state_revoked() {
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Revoked, "compromised").unwrap();
    let mut nonces = BTreeSet::new();
    let (e, _) = verify(&id, &mut nonces, good_cap(), true).unwrap_err();
    assert_eq!(e, Error::KeyNotUsable(kid("KEY-01"), KeyState::Revoked));
}

#[test]
fn court_revoked_key_stays_revoked() {
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Revoked, "x").unwrap();
    // No transition out of Revoked exists:
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
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let mut cap = good_cap();
    cap.expires_at = 1400; // now is 1500
    let (e, receipt) = verify(&id, &mut nonces, cap, true).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
    assert_eq!(receipt.outcome, Outcome::Fail);
}

#[test]
fn court_wrong_subject() {
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let mut cap = good_cap();
    cap.subject = Subject("mallory".into());
    assert!(verify(&id, &mut nonces, cap, true).is_err());
}

#[test]
fn court_wrong_audience() {
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let mut cap = good_cap();
    cap.audience = "evil-corp".into();
    assert!(verify(&id, &mut nonces, cap, true).is_err());
}

#[test]
fn court_empty_scope_rejected() {
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let mut cap = good_cap();
    cap.scope = "".into();
    assert!(verify(&id, &mut nonces, cap, true).is_err());
}

#[test]
fn court_replay_rejected() {
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    assert!(verify(&id, &mut nonces, good_cap(), true).is_ok());
    // Same nonce again — the verifier owns the seen-set:
    let (e, _) = verify(&id, &mut nonces, good_cap(), true).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
}

#[test]
fn court_nonce_not_consumed_on_failure() {
    // Red-team A5: a failed verification (bad signature) must NOT burn the
    // nonce. Attacker submits garbage sig with fresh nonce; honest holder's
    // later valid attempt with the same nonce must still succeed.
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let (e, _) = verify(&id, &mut nonces, good_cap(), false).unwrap_err();
    assert!(matches!(e, Error::InvalidPolicy(_)));
    assert!(
        !nonces.contains("nonce-001"),
        "failed verification must not consume the nonce"
    );
    // Honest retry with the same nonce now succeeds:
    assert!(verify(&id, &mut nonces, good_cap(), true).is_ok());
}

#[test]
fn court_recovery_noop_rejected_cleanly() {
    // Red-team A10: recover(new_key == old_key) must fail BEFORE any
    // mutation — no history record, no revocation.
    let mut id = test_identity();
    let h0 = id.history.len();
    let r = recover(
        &mut id,
        &kid("KEY-01"),
        kid("KEY-01"),
        KeyPurpose::Authentication,
        &[kid("REC-1"), kid("REC-2")],
    );
    assert!(r.is_err());
    assert_eq!(id.history.len(), h0, "no history on rejected recovery");
    assert_eq!(
        id.key_state(&kid("KEY-01")),
        Some(KeyState::Active),
        "old key untouched on rejected recovery"
    );
}

#[test]
fn court_recovery_preserves_purpose() {
    // Red-team A3: recovery must not change key purpose (privilege esc.).
    let mut id = test_identity();
    let r = recover(
        &mut id,
        &kid("KEY-01"),
        kid("KEY-02"),
        KeyPurpose::Recovery, // KEY-01 is Authentication
        &[kid("REC-1"), kid("REC-2")],
    );
    assert!(r.is_err());
}

#[test]
fn court_wrong_purpose() {
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let mut cap = good_cap();
    cap.key_id = kid("REC-1"); // a recovery key, not authentication
    let (e, _) = verify(&id, &mut nonces, cap, true).unwrap_err();
    assert!(matches!(e, Error::WrongPurpose { .. }));
}

#[test]
fn court_bad_signature() {
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    // The store reports the signature is invalid. Caller can't override.
    assert!(verify(&id, &mut nonces, good_cap(), false).is_err());
}

#[test]
fn court_lost_key_not_usable_until_found() {
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "phone gone").unwrap();
    let mut nonces = BTreeSet::new();
    assert!(verify(&id, &mut nonces, good_cap(), true).is_err());
    // Found again -> usable:
    transition_key(&mut id, &kid("KEY-01"), KeyState::Active, "found").unwrap();
    let mut nonces2 = BTreeSet::new();
    assert!(verify(&id, &mut nonces2, good_cap(), true).is_ok());
}

#[test]
fn court_unauthorized_recovery() {
    let mut id = test_identity();
    // Attacker tries recovery with non-policy keys:
    let err = recover(
        &mut id,
        &kid("KEY-01"),
        kid("KEY-02"),
        KeyPurpose::Authentication,
        &[kid("KEY-01")], // not a recovery key, not in policy
    );
    assert!(matches!(
        err,
        Err(Error::RecoveryThresholdNotMet { .. })
    ));
}

#[test]
fn court_partial_recovery() {
    let mut id = test_identity();
    // Only 1 of 2 required approvals:
    let err = recover(
        &mut id,
        &kid("KEY-01"),
        kid("KEY-02"),
        KeyPurpose::Authentication,
        &[kid("REC-1")],
    );
    assert_eq!(
        err,
        Err(Error::RecoveryThresholdNotMet { have: 1, need: 2 })
    );
    // Old key untouched:
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Active));
}

#[test]
fn court_honest_recovery_preserves_identity() {
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Lost, "phone lost").unwrap();
    recover(
        &mut id,
        &kid("KEY-01"),
        kid("KEY-02"),
        KeyPurpose::Authentication,
        &[kid("REC-1"), kid("REC-2")],
    )
    .unwrap();
    // Identity persists; old key revoked; new key active:
    assert_eq!(id.identifier, "IDENTITY-001");
    assert_eq!(id.key_state(&kid("KEY-01")), Some(KeyState::Revoked));
    assert_eq!(id.key_state(&kid("KEY-02")), Some(KeyState::Active));
    // New key verifies:
    let mut nonces = BTreeSet::new();
    let mut cap = good_cap();
    cap.key_id = kid("KEY-02");
    cap.nonce = "nonce-002".into();
    assert!(verify(&id, &mut nonces, cap, true).is_ok());
    // Old key does not:
    let mut nonces2 = BTreeSet::new();
    let mut cap2 = good_cap();
    cap2.nonce = "nonce-003".into();
    assert!(verify(&id, &mut nonces2, cap2, true).is_err());
}

#[test]
fn court_stale_recovery_key_rejected() {
    let mut id = test_identity();
    // Revoke one recovery key, then try to use it in a quorum:
    transition_key(&mut id, &kid("REC-3"), KeyState::Revoked, "rotated").unwrap();
    let err = recover(
        &mut id,
        &kid("KEY-01"),
        kid("KEY-02"),
        KeyPurpose::Authentication,
        &[kid("REC-1"), kid("REC-3")], // REC-3 revoked
    );
    assert_eq!(err, Err(Error::RecoveryKeyNotUsable(kid("REC-3"))));
}

#[test]
fn court_key_substitution() {
    // Attacker swaps the key id on an otherwise-valid envelope.
    // Verification is against the identity's key table, not the envelope's
    // self-description — substitution fails at KeyKnown/KeyUsable.
    let mut id = test_identity();
    transition_key(&mut id, &kid("KEY-01"), KeyState::Revoked, "x").unwrap();
    activate_key(&mut id, kid("KEY-99"), KeyPurpose::Authentication).unwrap();
    let mut nonces = BTreeSet::new();
    let mut cap = good_cap();
    cap.key_id = kid("KEY-99"); // attacker's key, validly activated... 
    // ...but the point stands: only keys in THIS identity's table verify.
    // A key from another identity is UnknownKey here:
    let mut cap2 = good_cap();
    cap2.key_id = kid("ATTACKER-KEY");
    let (e, _) = verify(&id, &mut nonces, cap2, true).unwrap_err();
    assert_eq!(e, Error::UnknownKey(kid("ATTACKER-KEY")));
    // And the legitimately-added KEY-99 verifies (it IS this identity's key):
    let mut nonces2 = BTreeSet::new();
    cap.nonce = "nonce-099".into();
    assert!(verify(&id, &mut nonces2, cap, true).is_ok());
}

#[test]
fn court_trichotomy_never_collapses() {
    // CLAIMED, ESTABLISHED, AUTHORIZED are distinct types.
    // This test exists so a future refactor cannot silently merge them:
    // it would fail to compile if they became one boolean.
    let id = test_identity();
    let mut nonces = BTreeSet::new();
    let claimed: Claimed<Capability> = Claimed(good_cap());
    let established: Established<Capability> =
        verify(&id, &mut nonces, claimed.0.clone(), true).unwrap();
    let authorized: Authorized<Capability> =
        authorize(established, |_| true).unwrap();
    // Each stage carries strictly more evidence than the last:
    assert!(authorized.capability.nonce == "nonce-001");
}
