//! The Court, part 2: the evidence graph.
//!
//! AdhKey cannot manufacture human identity from cryptography.
//! These tests enforce: the four questions stay separate, "verified human"
//! never becomes a boolean, unknown remains unknown, and freshness is
//! honest about staleness.

use crate::evidence::*;
use crate::*;
use std::collections::BTreeMap;

fn kid(s: &str) -> KeyId {
    KeyId(s.to_string())
}

/// Real Ed25519 operator (same test-vector approach as court.rs).
struct TestKeys {
    seeds: BTreeMap<KeyId, [u8; 32]>,
}

impl TestKeys {
    fn new() -> Self {
        let mut seeds = BTreeMap::new();
        seeds.insert(kid("POLICY-AUTH"), [31u8; 32]);
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
            return Ok(false);
        }
        let mut b = [0u8; 64];
        b.copy_from_slice(signature);
        let sig =
            adhkey_crypto::signature_from_bytes(&b).map_err(Error::KeyOperatorFailed)?;
        Ok(adhkey_crypto::verify(&vk, message, &sig))
    }
}

fn witness(id: &str, domain: &str) -> Witness {
    Witness {
        id: id.into(),
        trust_domain: domain.into(),
    }
}

fn ev(id: &str, kind: EvidenceKind, w: Witness) -> Evidence {
    Evidence {
        id: id.into(),
        kind,
        witness: w,
        digest: [7u8; 32],
        issued_at: 1000,
        expires_at: None,
        revoked: false,
    }
}

fn human_claim() -> HumanClaim {
    HumanClaim {
        subject: Subject("S1".into()),
        kind: SubjectKind::Person,
        evidence: vec![
            ev("gov-7", EvidenceKind::Government, witness("dmv", "government")),
            ev("bank-4", EvidenceKind::Institutional, witness("bank", "financial")),
            ev(
                "wit-2",
                EvidenceKind::Social,
                witness("friend-a", "community"),
            ),
        ],
        assurance_policy: "P17".into(),
        issued_by: witness("adhkey", "local"),
        issued_at: 1000,
        expires_at: None,
        state: EpistemicState::Claimed,
        policy_authorities: vec![kid("POLICY-AUTH")],
    }
}

/// Build a signed policy verdict over `claim` with the given decision,
/// signed by `by` at `evaluated_at`.
fn verdict(
    keys: &TestKeys,
    claim: &HumanClaim,
    decision: PolicyDecision,
    by: &KeyId,
    evaluated_at: u64,
) -> SignedPolicyVerdict {
    let mut v = SignedPolicyVerdict {
        policy_id: "P17".into(),
        policy_version: 3,
        subject: claim.subject.clone(),
        claim_hash: claim.digest(),
        decision,
        evaluated_at,
        evidence_snapshot: claim.evidence_snapshot(),
        evaluator: by.clone(),
        signature: Vec::new(),
    };
    let msg = policy_verdict_bytes(&v);
    v.signature = keys.sign(by, &msg).unwrap();
    v
}

#[test]
fn court_no_boolean_human() {
    // There is no is_real_human() -> bool anywhere in this crate.
    // The lattice is the only path. This test pins the lattice states:
    let states = [
        EpistemicState::Unknown,
        EpistemicState::Claimed,
        EpistemicState::Supported,
        EpistemicState::Established,
        EpistemicState::Revoked,
        EpistemicState::Expired,
        EpistemicState::Conflict,
    ];
    assert_eq!(states.len(), 7);
    // Only ONE state authorizes. Everything else fails closed.
    let authorizable: Vec<_> = states.iter().filter(|s| s.authorizable()).collect();
    assert_eq!(authorizable.len(), 1);
    assert_eq!(*authorizable[0], EpistemicState::Established);
}

#[test]
fn court_empty_evidence_is_claimed_not_established() {
    let mut c = human_claim();
    c.evidence = vec![];
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Claimed);
    // And CLAIMED cannot authorize:
    let v = authorize_with_freshness(EpistemicState::Claimed, None, 60, 1500);
    assert!(matches!(v, AuthorizationVerdict::CannotEstablish(_)));
}

#[test]
fn court_evidence_without_policy_is_supported_not_established() {
    // The core refuses to guess what "enough evidence" means.
    let keys = TestKeys::new();
    let c = human_claim();
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Supported);
    // Only a SIGNED verdict from an authorized evaluator promotes:
    let v = verdict(&keys, &c, PolicyDecision::Allow, &kid("POLICY-AUTH"), 1490);
    assert_eq!(
        establish(&c, &v, &keys, 1500, 3600),
        Ok(EpistemicState::Established),
        "signed Allow verdict promotes"
    );
    // Deny does not promote; Unknown does not promote:
    let v_deny = verdict(&keys, &c, PolicyDecision::Deny, &kid("POLICY-AUTH"), 1490);
    assert_eq!(
        establish(&c, &v_deny, &keys, 1500, 3600),
        Ok(EpistemicState::Supported),
        "Deny leaves Supported"
    );
    let v_unk = verdict(&keys, &c, PolicyDecision::Unknown, &kid("POLICY-AUTH"), 1490);
    assert_eq!(
        establish(&c, &v_unk, &keys, 1500, 3600),
        Ok(EpistemicState::Supported),
        "Unknown fails closed"
    );
}

#[test]
fn court_c3_forged_verdict_rejected() {
    // Attacker forges a verdict "signature" without the evaluator key.
    let keys = TestKeys::new();
    let c = human_claim();
    let mut v = verdict(&keys, &c, PolicyDecision::Allow, &kid("POLICY-AUTH"), 1490);
    v.signature = vec![0xEE; 64];
    let err = establish(&c, &v, &keys, 1500, 3600);
    assert!(matches!(err, Err(Error::BadPolicyVerdict(_))));
}

#[test]
fn court_c3_unauthorized_evaluator_rejected() {
    // Well-formed signature — but from a key with no authority over
    // this claim. Valid crypto, zero authority.
    let keys = TestKeys::new();
    let c = human_claim();
    let v = verdict(&keys, &c, PolicyDecision::Allow, &kid("ATTACKER"), 1490);
    let err = establish(&c, &v, &keys, 1500, 3600);
    assert!(matches!(err, Err(Error::BadPolicyVerdict(_))));
}

#[test]
fn court_c3_verdict_for_other_claim_rejected() {
    // A verdict for claim A replayed against claim B. The claim_hash
    // binding kills it.
    let keys = TestKeys::new();
    let c = human_claim();
    let mut other = human_claim();
    other.subject = Subject("S2".into());
    let v = verdict(&keys, &other, PolicyDecision::Allow, &kid("POLICY-AUTH"), 1490);
    let err = establish(&c, &v, &keys, 1500, 3600);
    assert!(matches!(err, Err(Error::BadPolicyVerdict(_))));
}

#[test]
fn court_c3_stale_evidence_kills_verdict() {
    // Verdict evaluated over evidence set E; evidence changes after.
    // The snapshot binding kills the stale verdict.
    let keys = TestKeys::new();
    let c = human_claim();
    let v = verdict(&keys, &c, PolicyDecision::Allow, &kid("POLICY-AUTH"), 1490);
    let mut c2 = c.clone();
    c2.evidence.push(ev("new-9", EvidenceKind::Physical, witness("x", "y")));
    let err = establish(&c2, &v, &keys, 1500, 3600);
    assert!(matches!(err, Err(Error::BadPolicyVerdict(_))));
}

#[test]
fn court_c3_stale_verdict_rejected() {
    // Verdict evaluated too long ago. Freshness is enforced.
    let keys = TestKeys::new();
    let c = human_claim();
    let v = verdict(&keys, &c, PolicyDecision::Allow, &kid("POLICY-AUTH"), 1000);
    let err = establish(&c, &v, &keys, 1500, 60);
    assert!(matches!(err, Err(Error::BadPolicyVerdict(_))));
}

#[test]
fn court_c3_no_bool_parameter() {
    // The old `establish(claim, policy_satisfied: bool, now)` is gone.
    // This pins the new shape: promotion requires a signed verdict.
    // (Compile-time property; the tests above prove the runtime half.)
    let keys = TestKeys::new();
    let c = human_claim();
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Supported);
    let v = verdict(&keys, &c, PolicyDecision::Allow, &kid("POLICY-AUTH"), 1490);
    assert!(establish(&c, &v, &keys, 1500, 3600).is_ok());
}

#[test]
fn court_revocation_is_sticky() {
    let keys = TestKeys::new();
    let mut c = human_claim();
    c.evidence[0].revoked = true;
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Revoked);
    // Even with a valid signed Allow verdict, revoked stays revoked:
    // (verdict must be over the CURRENT claim, including the revocation)
    let v = verdict(&keys, &c, PolicyDecision::Allow, &kid("POLICY-AUTH"), 1490);
    assert_eq!(
        establish(&c, &v, &keys, 1500, 3600),
        Ok(EpistemicState::Revoked)
    );
}

#[test]
fn court_expiry_is_honest() {
    let mut c = human_claim();
    c.expires_at = Some(1400);
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Expired);
    // Expired evidence doesn't count:
    let mut c2 = human_claim();
    for e in &mut c2.evidence {
        e.expires_at = Some(1400);
    }
    assert_eq!(
        evaluate_claim(&c2, 1500),
        EpistemicState::Claimed,
        "all evidence expired -> back to mere claim"
    );
}

#[test]
fn court_freshness_future_is_not_fresh() {
    // A witness claiming known_at in the future must fail closed.
    // saturating_sub would have returned 0 -> false AUTHORIZED. Caught by
    // red-team (nemotron). Never regress.
    let w = witness("liar", "evil");
    let f = Freshness {
        known_at: 9999,
        state_version: 1,
        witness: w,
    };
    assert!(matches!(
        authorize_with_freshness(EpistemicState::Established, Some(&f), 60, 1500),
        AuthorizationVerdict::CannotEstablish(_)
    ));
}

#[test]
fn court_freshness_three_answers() {
    let w = witness("verifier", "local");
    // Fresh:
    let f = Freshness {
        known_at: 1490,
        state_version: 12,
        witness: w.clone(),
    };
    assert_eq!(
        authorize_with_freshness(EpistemicState::Established, Some(&f), 60, 1500),
        AuthorizationVerdict::Authorized
    );
    // Stale: honest about WHEN, doesn't pretend now:
    let f_old = Freshness {
        known_at: 1000,
        state_version: 9,
        witness: w.clone(),
    };
    assert_eq!(
        authorize_with_freshness(EpistemicState::Established, Some(&f_old), 60, 1500),
        AuthorizationVerdict::AuthorizedAsOf(1000)
    );
    // No witness: cannot establish. Unknown remains unknown.
    assert!(matches!(
        authorize_with_freshness(EpistemicState::Established, None, 60, 1500),
        AuthorizationVerdict::CannotEstablish(_)
    ));
}

#[test]
fn court_four_questions_stay_separate() {
    // A valid key + valid capability, but NO evidence for the human claim:
    // authorization of the *action* may proceed on key+capability, but the
    // *human assurance* stays UNKNOWN. One answer never stands in for another.
    let req = AuthorizationRequest {
        subject: Subject("S1".into()),
        subject_kind: SubjectKind::Person,
        evidence: vec![], // no evidence
        assurance_policy: "P17".into(),
        current_key: KeyId("K42".into()),
        capability_scope: "deploy:exchange".into(),
        capability_audience: "cutecity".into(),
    };
    let claim = HumanClaim {
        subject: req.subject.clone(),
        kind: req.subject_kind,
        evidence: req.evidence.clone(),
        assurance_policy: req.assurance_policy.clone(),
        issued_by: witness("none", "none"),
        issued_at: 1000,
        expires_at: None,
        state: EpistemicState::Unknown,
        policy_authorities: vec![kid("POLICY-AUTH")],
    };
    let state = evaluate_claim(&claim, 1500);
    assert_eq!(state, EpistemicState::Claimed);
    // Human assurance: cannot establish.
    let v = authorize_with_freshness(state, None, 60, 1500);
    assert!(matches!(v, AuthorizationVerdict::CannotEstablish(_)));
    // The KEY question is separate and answered elsewhere (verifier.rs).
    // The point: this verdict says nothing about K42, and K42's validity
    // says nothing about the human. No collapse.
}

#[test]
fn court_conflict_is_not_established() {
    // Conflict is a distinct state, not a quiet fail, not a pass.
    let v = authorize_with_freshness(EpistemicState::Conflict, None, 60, 1500);
    assert!(matches!(v, AuthorizationVerdict::CannotEstablish(_)));
    assert!(!EpistemicState::Conflict.authorizable());
}

#[test]
fn court_c4_conflict_is_reachable() {
    // C4: two LIVE evidence items about the SAME evidence id with
    // DIFFERENT artifact digests = two witnesses disagreeing about what
    // the artifact is. That is a real contradiction, and the machinery
    // reaches Conflict.
    let mut c = human_claim();
    let mut conflicting = ev("gov-7", EvidenceKind::Government, witness("dmv2", "government"));
    conflicting.digest = [0xAA; 32]; // same id, different artifact
    c.evidence.push(conflicting);
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Conflict);
    // Conflict is sticky against promotion: even a signed Allow verdict
    // cannot establish a conflicted claim.
    let keys = TestKeys::new();
    let v = verdict(&keys, &c, PolicyDecision::Allow, &kid("POLICY-AUTH"), 1490);
    assert_eq!(
        establish(&c, &v, &keys, 1500, 3600),
        Ok(EpistemicState::Conflict)
    );
}

#[test]
fn court_c4_same_digest_is_not_conflict() {
    // Same id AND same digest (e.g. two witnesses referencing the same
    // artifact) is agreement, not conflict.
    let mut c = human_claim();
    let mut dup = ev("gov-7", EvidenceKind::Government, witness("dmv2", "government"));
    dup.digest = [7u8; 32]; // same artifact
    c.evidence.push(dup);
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Supported);
}

#[test]
fn court_subject_kinds_are_distinct() {
    // A DEVICE claim and a PERSON claim are different things;
    // the kind travels with the claim and policy can require more
    // evidence for PERSON than for DEVICE.
    let kinds = [
        SubjectKind::Person,
        SubjectKind::Organization,
        SubjectKind::Device,
        SubjectKind::Software,
        SubjectKind::Agent,
        SubjectKind::Unknown,
    ];
    assert_eq!(kinds.len(), 6);
    let mut c = human_claim();
    c.kind = SubjectKind::Device;
    // Evaluation is kind-agnostic in the core (policy decides the bar),
    // but the kind is preserved — never silently dropped:
    assert_eq!(c.kind, SubjectKind::Device);
}
