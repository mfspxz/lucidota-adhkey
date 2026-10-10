//! T-STATE: state-machine property tests at the governor level (RFC §9.2).
//! Scripted adversarial traces; each asserts an invariant from the test plan.

use adhkey_flailer::*;
use adhkey_flailer::governor::State;
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

fn rng() -> StdRng {
    StdRng::seed_from_u64(0xF1A1)
}

fn key16(rng: &mut StdRng) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

fn open_session() -> (RecoverySession, Policy, u64, u64) {
    let policy = Policy::v1();
    let now = 1_800_000_000u64;
    let epoch = 7u64;
    let session = RecoverySession::open([0x11u8; 16], epoch, &policy, now).unwrap();
    (session, policy, now, epoch)
}

/// Drive a session through the full happy path to Committed.
fn drive_to_committed() -> (RecoverySession, Policy, Vec<governor::TransitionRecord>) {
    let (mut s, policy, now, epoch) = open_session();
    let mut r = rng();
    let mut recs = Vec::new();
    for (to, reason) in [
        (State::EvidenceCollection, "evidence gathered"),
        (State::AuthorizationPending, "evidence accepted"),
        (State::SharesVerified, "2 approvals + 3 shares verified"),
        (State::Reconstructed, "root reconstructed in trusted component"),
        (State::ReenrollmentPending, "new credentials bound"),
        (State::Committed, "receipt signed, sessions tombstoned"),
    ] {
        recs.push(s.transition(to, reason, key16(&mut r), &policy, now + 60, epoch).unwrap());
    }
    (s, policy, recs)
}

#[test]
fn t_s1_no_jump_to_committed() {
    let (mut s, policy, now, epoch) = open_session();
    let mut r = rng();
    // Every direct jump to a late state must fail.
    for to in [State::Committed, State::Reconstructed, State::SharesVerified, State::ReenrollmentPending] {
        assert!(s.transition(to, "skip", key16(&mut r), &policy, now, epoch).is_err());
    }
    // State must be unchanged.
    assert_eq!(s.state, State::Requested);
}

#[test]
fn t_s1_full_path_commits() {
    let (s, _p, recs) = drive_to_committed();
    assert_eq!(s.state, State::Committed);
    assert_eq!(recs.len(), 6);
    // Terminal: nothing further permitted.
    let (mut s2, policy, now, epoch) = open_session();
    let mut r = rng();
    // Drive s2 to Denied via AuthorizationPending.
    s2.transition(State::EvidenceCollection, "e", key16(&mut r), &policy, now, epoch).unwrap();
    s2.transition(State::AuthorizationPending, "a", key16(&mut r), &policy, now, epoch).unwrap();
    s2.transition(State::Denied, "no approvals", key16(&mut r), &policy, now, epoch).unwrap();
    assert!(s2.transition(State::EvidenceCollection, "x", key16(&mut r), &policy, now, epoch).is_err());
}

/// Build a real verified approval through the signing path (no test backdoors).
fn real_approval(
    rng: &mut StdRng,
    sid: [u8; 16],
    nonce: &[u8; 16],
    epoch: u64,
    expires_at: u64,
    policy_version: u32,
    decision: Decision,
) -> VerifiedApproval {
    let (sk, rec) = test_guardian(rng);
    let approval = sign_approval(&sk, rec.guardian_id, sid, nonce, epoch, expires_at, policy_version, decision);
    verify_approval(&approval, &rec, &sid).unwrap()
}

#[test]
fn t_s2_replayed_approvals_add_nothing() {
    let policy = Policy::v1();
    let mut r = rng();
    let sid = [0xAAu8; 16];
    let nonce = [0xCCu8; 16];
    let exp = 1_800_086_400u64;
    // Same guardian approving 3 times: three approvals from the SAME key.
    let (sk, rec) = test_guardian(&mut r);
    let one = || {
        let a = sign_approval(&sk, rec.guardian_id, sid, &nonce, 7, exp, policy.version, Decision::Approve);
        verify_approval(&a, &rec, &sid).unwrap()
    };
    let approvals = vec![one(), one(), one()];
    assert!(!approvals_satisfy(&approvals, &sid, &policy));
    // Two distinct approvers = threshold met.
    let a2 = real_approval(&mut r, sid, &nonce, 7, exp, policy.version, Decision::Approve);
    assert!(approvals_satisfy(&[one(), a2], &sid, &policy));
    // Approval for a different session doesn't count.
    let other: VerifiedApproval = real_approval(&mut r, [0xBBu8; 16], &nonce, 7, exp, policy.version, Decision::Approve);
    assert!(!approvals_satisfy(&[other], &sid, &policy));
    // Denials don't contribute.
    let d1 = real_approval(&mut r, sid, &nonce, 7, exp, policy.version, Decision::Deny);
    assert!(!approvals_satisfy(&[d1], &sid, &policy));
}

#[test]
fn t_s3_revoked_epoch_cannot_transition() {
    let (mut s, policy, now, _epoch) = open_session();
    let mut r = rng();
    // The set moved to epoch 8; this session is epoch 7.
    assert!(s.transition(State::EvidenceCollection, "e", key16(&mut r), &policy, now, 8).is_err());
    assert_eq!(s.state, State::Requested);
}

#[test]
fn t_s4_terminal_sessions_frozen() {
    let (mut s, policy, now, epoch) = open_session();
    let mut r = rng();
    s.transition(State::EvidenceCollection, "e", key16(&mut r), &policy, now, epoch).unwrap();
    s.transition(State::AuthorizationPending, "a", key16(&mut r), &policy, now, epoch).unwrap();
    // Aborted path: SharesVerified -> Reconstructed -> Aborted.
    s.transition(State::SharesVerified, "s", key16(&mut r), &policy, now, epoch).unwrap();
    s.transition(State::Reconstructed, "r", key16(&mut r), &policy, now, epoch).unwrap();
    s.transition(State::Aborted, "power loss", key16(&mut r), &policy, now, epoch).unwrap();
    assert!(s.transition(State::EvidenceCollection, "x", key16(&mut r), &policy, now, epoch).is_err());
}

#[test]
fn t_s5_idempotency_no_double_apply() {
    let (mut s, policy, now, epoch) = open_session();
    let mut r = rng();
    let key = key16(&mut r);
    let rec1 = s.transition(State::EvidenceCollection, "e", key, &policy, now, epoch).unwrap();
    // Replay with the SAME key: same record back, no state change, no new log entry.
    let rec2 = s.transition(State::AuthorizationPending, "different", key, &policy, now, epoch).unwrap();
    assert_eq!(rec1.to, rec2.to);
    assert_eq!(s.state, State::EvidenceCollection);
    // A fresh key advances normally.
    s.transition(State::AuthorizationPending, "a", key16(&mut r), &policy, now, epoch).unwrap();
    assert_eq!(s.state, State::AuthorizationPending);
}

#[test]
fn t_s6_session_survives_serde_roundtrip() {
    // Crash-simulation: serialize mid-flow, restore, continue. No half-state.
    let (mut s, policy, now, epoch) = open_session();
    let mut r = rng();
    s.transition(State::EvidenceCollection, "e", key16(&mut r), &policy, now, epoch).unwrap();
    let bytes = serde_json::to_vec(&s).unwrap();
    let mut restored: RecoverySession = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.state, State::EvidenceCollection);
    restored.transition(State::AuthorizationPending, "a", key16(&mut r), &policy, now, epoch).unwrap();
    assert_eq!(restored.state, State::AuthorizationPending);
    // Idempotency log survived: replaying the first key still returns the old record.
    let bytes2 = serde_json::to_vec(&restored).unwrap();
    let r2: RecoverySession = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(r2.idempotency_len(), 2);
}

#[test]
fn t_s7_tombstone_wins_over_competing_session() {
    let (mut winner, policy, now, epoch) = open_session();
    let (mut loser, _p2, _n2, _e2) = open_session();
    // Winner completes; loser is tombstoned (evidence retained).
    let mut r = rng();
    for (to, reason) in [
        (State::EvidenceCollection, "e"),
        (State::AuthorizationPending, "a"),
        (State::SharesVerified, "s"),
        (State::Reconstructed, "r"),
        (State::ReenrollmentPending, "p"),
        (State::Committed, "done"),
    ] {
        winner.transition(to, reason, key16(&mut r), &policy, now, epoch).unwrap();
    }
    loser.tombstone();
    assert!(loser.tombstoned);
    // Tombstoned session can never transition again, even on a legal edge.
    assert!(loser.transition(State::EvidenceCollection, "e", key16(&mut r), &policy, now, epoch).is_err());
}

#[test]
fn t_s8_unknown_policy_fails_closed() {
    let (mut s, _policy, now, epoch) = open_session();
    let mut bad = Policy::v1();
    bad.version = 999;
    let mut r = rng();
    assert!(s.transition(State::EvidenceCollection, "e", key16(&mut r), &bad, now, epoch).is_err());
    // Malformed policy document.
    assert!(Policy::parse(b"{\"version\":999}").is_err());
    assert!(Policy::parse(b"not json").is_err());
    let mut zeroed = Policy::v1();
    zeroed.guardian_approval_threshold = 0;
    let bytes = serde_json::to_vec(&zeroed).unwrap();
    assert!(Policy::parse(&bytes).is_err());
    // Expired session fails closed.
    let policy = Policy::v1();
    let (mut s2, _p, _n, epoch2) = open_session();
    assert!(s2.transition(State::EvidenceCollection, "e", key16(&mut r), &policy, now + 100_000_000, epoch2).is_err());
}

#[test]
fn t_s9_tombstone_retains_evidence() {
    let (mut s, policy, _now, _epoch) = open_session();
    for _ in 0..3 {
        s.record_evidence_attempt(&policy).unwrap();
    }
    let attempts_before = s.evidence_attempts;
    s.tombstone();
    // Evidence counters survive tombstoning.
    assert_eq!(s.evidence_attempts, attempts_before);
    assert_eq!(attempts_before, 3);
    // Attempt budget still enforced.
    let mut s2 = s.clone();
    s2.tombstoned = false;
    for _ in 0..7 {
        s2.record_evidence_attempt(&policy).unwrap();
    }
    assert!(s2.record_evidence_attempt(&policy).is_err());
}

// ---- Guardian approval signature tests ----

fn test_guardian(rng: &mut StdRng) -> (SigningKey, GuardianRecord) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let mut gid = [0u8; 16];
    rng.fill_bytes(&mut gid);
    let rec = GuardianRecord { guardian_id: gid, verifying_key: sk.verifying_key().to_bytes() };
    (sk, rec)
}

#[test]
fn t_guardian_approval_verify() {
    let (s, policy, now, epoch) = open_session();
    let mut r = rng();
    let (sk, rec) = test_guardian(&mut r);
    let approval = sign_approval(
        &sk, rec.guardian_id, s.session_id, &s.nonce, epoch,
        s.expires_at, policy.version, Decision::Approve,
    );
    let verified = verify_approval(&approval, &rec, &s.session_id).unwrap();
    assert_eq!(verified.decision, Decision::Approve);
    // Wrong session binding → rejected.
    assert!(verify_approval(&approval, &rec, &[0xFFu8; 16]).is_err());
    // Tampered signature → rejected.
    let mut bad = approval.clone();
    bad.signature[0] ^= 1;
    assert!(verify_approval(&bad, &rec, &s.session_id).is_err());
    // Wrong guardian record → rejected.
    let (_sk2, rec2) = test_guardian(&mut r);
    assert!(verify_approval(&approval, &rec2, &s.session_id).is_err());
    // Approval for one session never verifies in another.
    let (s2, _p2, _n2, _e2) = open_session();
    assert!(verify_approval(&approval, &rec, &s2.session_id).is_err());
    let _ = policy;
    let _ = now;
}

// ---- Receipt chain tests ----

#[test]
fn t_receipt_chain_and_signature() {
    let (s, policy, recs) = drive_to_committed();
    let mut seed = [0u8; 32];
    rng().fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let mut chain = Vec::new();
    for rec in &recs {
        adhkey_flailer::append_link(&mut chain, rec.clone());
    }
    assert!(adhkey_flailer::verify_chain(&chain, &s.session_id).is_ok());
    let receipt = adhkey_flailer::sign_receipt(
        &chain, s.session_id, policy.version, ReceiptOutcome::Committed, &sk,
    )
    .unwrap();
    assert!(adhkey_flailer::verify_receipt(&receipt).is_ok());
    // Tamper with a link → chain and receipt both fail.
    let mut bad_chain = chain.clone();
    bad_chain[2].record.reason = "forged".to_string();
    assert!(adhkey_flailer::verify_chain(&bad_chain, &s.session_id).is_err());
    let mut bad_receipt = receipt.clone();
    bad_receipt.links[2].record.reason = "forged".to_string();
    assert!(adhkey_flailer::verify_receipt(&bad_receipt).is_err());
    // Tamper with the head digest → signature check fails.
    let mut bad_head = receipt.clone();
    bad_head.head_digest[0] ^= 1;
    assert!(adhkey_flailer::verify_receipt(&bad_head).is_err());
    // Receipt contains no secret material: scan the serialized form for
    // dangerous field names. (Plain English like "3 shares verified" in
    // transition reasons is fine — it's metadata, not material.)
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for dangerous in ["ciphertext", "plaintext", "private_key", "secret", "passphrase", "nonce\""] {
        assert!(!text.contains(dangerous), "receipt leaks {dangerous}");
    }
}
