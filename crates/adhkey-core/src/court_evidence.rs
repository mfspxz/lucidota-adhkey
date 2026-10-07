//! The Court, part 2: the evidence graph.
//!
//! AdhKey cannot manufacture human identity from cryptography.
//! These tests enforce: the four questions stay separate, "verified human"
//! never becomes a boolean, unknown remains unknown, and freshness is
//! honest about staleness.

use crate::evidence::*;
use crate::*;

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
    }
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
    let c = human_claim();
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Supported);
    // Only an explicit policy satisfaction promotes:
    assert_eq!(
        establish(&c, false, 1500),
        EpistemicState::Supported,
        "core must not promote without policy"
    );
    assert_eq!(
        establish(&c, true, 1500),
        EpistemicState::Established,
        "explicit policy satisfaction promotes"
    );
}

#[test]
fn court_revocation_is_sticky() {
    let mut c = human_claim();
    c.evidence[0].revoked = true;
    assert_eq!(evaluate_claim(&c, 1500), EpistemicState::Revoked);
    // Even with policy satisfied, revoked stays revoked:
    assert_eq!(establish(&c, true, 1500), EpistemicState::Revoked);
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
