//! Attack families V001-V005 against the full pipeline, plus the
//! 27 ternary combinations and the sacred invariant:
//!
//! No attacker-controlled field may directly cause a transition from
//! CLAIMED/UNKNOWN to ESTABLISHED/AUTHORIZED.

use luci_verdict_core::authority::{Claimed, EstablishmentPolicy};
use luci_verdict_core::envelope::Envelope;
use luci_verdict_core::pipeline::{
    adjudicate, Attempt, CryptoStatus, Identity, PolicyInput, Verdict, VerdictInput,
};
use luci_verdict_core::receipt::Stage;
use luci_verdict_core::ternary::Epistemic;
use luci_verdict_core::witness::{EvidenceSet, ProvenanceGraph, Witness};

fn witness(id: &str, root: &str) -> Witness {
    Witness { id: id.into(), trust_root: root.into() }
}

fn good_envelope() -> Envelope {
    Envelope {
        envelope_id: "env-1".into(),
        subject_id: "alice".into(),
        audience_id: "vault".into(),
        operation_id: "read".into(),
        request_hash: "rh".into(),
        evidence_hash: "eh".into(),
        policy_hash: "ph".into(),
        policy_version: 7,
        nonce: "n-1".into(),
        issued_at: 1000,
        expires_at: 2000,
        previous_receipt_hash: "genesis".into(),
    }
}

fn good_attempt() -> Attempt {
    Attempt {
        subject_id: "alice".into(),
        audience_id: "vault".into(),
        operation_id: "read".into(),
        request_hash: "rh".into(),
        policy_hash: "ph".into(),
        now: 1500,
        max_skew_secs: 60,
    }
}

fn good_input() -> VerdictInput {
    VerdictInput {
        claimed_identity: Claimed::new(Identity { subject_id: "alice".into() }),
        envelope: good_envelope(),
        attempt: good_attempt(),
        evidence: EvidenceSet {
            witnesses: vec![witness("w1", "root-a"), witness("w2", "root-b")],
        },
        provenance: ProvenanceGraph::default(),
        policy: PolicyInput {
            establishment: EstablishmentPolicy { required_independent_witnesses: 2 },
            policy_satisfied: Epistemic::Proven,
        },
        crypto: CryptoStatus::Valid,
        activation: Epistemic::Proven,
    }
}

#[test]
fn honest_path_authorizes() {
    let (_stages, verdict) = adjudicate(good_input());
    assert!(matches!(verdict, Verdict::Authorized { .. }), "{:?}", verdict);
}

/// V001: caller-asserted authority. "I am governor" with no evidence
/// must not authorize. It defers (unknown), it does not deny-forever
/// and it certainly does not authorize.
#[test]
fn v001_caller_asserted_authority_defers() {
    let mut input = good_input();
    input.evidence = EvidenceSet { witnesses: vec![] };
    let (stages, verdict) = adjudicate(input);
    assert_eq!(stages.identity, Epistemic::Unknown);
    assert!(matches!(verdict, Verdict::Deferred { stage: Stage::Evidence, .. }),
            "{:?}", verdict);
}

/// V002: stale envelope. Valid signature, expired window -> Denied.
/// Time only moves forward: denial is terminal, not deferrable.
#[test]
fn v002_stale_envelope_denied() {
    let mut input = good_input();
    input.attempt.now = 2000; // expires_at
    let (_stages, verdict) = adjudicate(input);
    assert!(matches!(verdict, Verdict::Denied { stage: Stage::Freshness, .. }),
            "{:?}", verdict);
}

/// V003: cross-subject replay. Alice's envelope presented for Bob.
#[test]
fn v003_cross_subject_replay_denied() {
    let mut input = good_input();
    input.attempt.subject_id = "bob".into();
    let (_stages, verdict) = adjudicate(input);
    assert!(matches!(verdict, Verdict::Denied { stage: Stage::Binding, .. }),
            "{:?}", verdict);
}

/// V004: correlated witnesses. Two witnesses, one trust root, policy
/// needs two independent -> identity stays Unknown -> Deferred.
#[test]
fn v004_correlated_witnesses_do_not_establish() {
    let mut input = good_input();
    input.evidence = EvidenceSet {
        witnesses: vec![witness("w1", "root-c"), witness("w2", "root-c")],
    };
    // root-c controls both witnesses' roots transitively
    input.provenance = ProvenanceGraph { controlled_by: vec![] };
    let (stages, verdict) = adjudicate(input);
    assert_eq!(stages.evidence, Epistemic::Unknown);
    assert!(matches!(verdict, Verdict::Deferred { .. }), "{:?}", verdict);
}

/// V005 is covered at the execution-module level (self-observations
/// discarded). Here: pipeline never consults execution claims at all —
/// execution evidence arrives only as witnesses in the evidence set.

/// Sacred invariant, pipeline level: across the 27 ternary combinations
/// of (truth, authority_stage, activation), NO combination where the
/// attacker controls the claim reaches Authorized without evidence and
/// policy both proving out.
#[test]
fn ternary_27_combinations_no_false_authorization() {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Axis { Neg, Zero, Pos }
    let vals = [Axis::Neg, Axis::Zero, Axis::Pos];
    let mut authorized_count = 0;
    for &truth in &vals {
        for &auth in &vals {
            for &active in &vals {
                let mut input = good_input();
                // Map axes onto pipeline inputs.
                // truth: controls witness count (evidence for the claim)
                input.evidence = match truth {
                    Axis::Pos => EvidenceSet {
                        witnesses: vec![witness("w1", "r1"), witness("w2", "r2")],
                    },
                    _ => EvidenceSet { witnesses: vec![] },
                };
                // authority_stage: controls policy evaluation
                input.policy.policy_satisfied = match auth {
                    Axis::Pos => Epistemic::Proven,
                    Axis::Zero => Epistemic::Unknown,
                    Axis::Neg => Epistemic::Disproven,
                };
                // activation: the ternary cube's third axis. Unresolved
                // activation defers (unknown propagates); disabled denies.
                input.activation = match active {
                    Axis::Pos => Epistemic::Proven,
                    Axis::Zero => Epistemic::Unknown,
                    Axis::Neg => Epistemic::Disproven,
                };
                let (_stages, verdict) = adjudicate(input);
                let authorized = matches!(verdict, Verdict::Authorized { .. });
                if authorized {
                    authorized_count += 1;
                    // Authorization requires all three positive.
                    assert_eq!(truth, Axis::Pos, "truth={:?} auth={:?} active={:?}", truth, auth, active);
                    assert_eq!(auth, Axis::Pos, "truth={:?} auth={:?} active={:?}", truth, auth, active);
                    assert_eq!(active, Axis::Pos, "truth={:?} auth={:?} active={:?}", truth, auth, active);
                } else {
                    // Anything not all-positive must NOT authorize.
                    // In particular: truth Unknown/Disproven never authorizes,
                    // even if the attacker maxes the other axes.
                    if truth != Axis::Pos {
                        assert!(!authorized);
                    }
                }
            }
        }
    }
    // Exactly one combination authorizes: (+,+,+).
    assert_eq!(authorized_count, 1);
}

/// UNKNOWN propagation end-to-end: crypto Unknown -> Deferred, never
/// Authorized, even with perfect evidence and policy.
#[test]
fn unknown_crypto_propagates_to_deferred() {
    let mut input = good_input();
    input.crypto = CryptoStatus::Unknown;
    let (_stages, verdict) = adjudicate(input);
    assert!(matches!(verdict, Verdict::Deferred { stage: Stage::Crypto, .. }),
            "{:?}", verdict);
}

/// Attacker mutates every caller-controlled string field; none may flip
/// a Deferred verdict to Authorized.
#[test]
fn attacker_controlled_fields_cannot_flip_verdict() {
    // Baseline: no evidence -> Deferred.
    let mut input = good_input();
    input.evidence = EvidenceSet { witnesses: vec![] };
    let (_, base) = adjudicate(input.clone());
    assert!(matches!(base, Verdict::Deferred { .. }));

    // Attacker rewrites all caller-controlled fields to attractive lies.
    input.claimed_identity = Claimed::new(Identity { subject_id: "governor".into() });
    input.envelope.subject_id = "governor".into();
    input.envelope.audience_id = "everything".into();
    input.envelope.operation_id = "admin".into();
    input.envelope.policy_hash = "attacker-policy".into();
    // Attempt must still match envelope binding, else it's just Denied
    // (also fine) — attacker keeps binding consistent to try to pass.
    input.attempt.subject_id = "governor".into();
    input.attempt.audience_id = "everything".into();
    input.attempt.operation_id = "admin".into();
    input.attempt.policy_hash = "attacker-policy".into();
    let (_, verdict) = adjudicate(input);
    assert!(
        !matches!(verdict, Verdict::Authorized { .. }),
        "attacker fields flipped verdict: {:?}",
        verdict
    );
}
