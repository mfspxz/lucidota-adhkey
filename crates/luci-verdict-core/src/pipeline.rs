//! The staged verdict pipeline.
//!
//! CLAIM -> NORMALIZE -> BIND -> VERIFY CRYPTO -> FRESHNESS -> SUBJECT ->
//! AUDIENCE -> PROVENANCE -> RELATIONSHIPS -> POLICY -> AUTHORIZED /
//! UNKNOWN / DISPROVEN -> RECEIPT
//!
//! Every stage produces a typed intermediate result. The final verdict
//! is a projection of those states — never one giant boolean, never a
//! single caller-controlled bit flipping the outcome.

use crate::authority::{authorize, establish, Claimed, Denial, EstablishmentPolicy};
use crate::envelope::{Binding, Envelope, Freshness};
use crate::receipt::{Receipt, Stage};
use crate::ternary::Epistemic;
use crate::witness::{EvidenceSet, ProvenanceGraph};

/// Identity under evaluation. Kept minimal: the pipeline reasons about
/// authority structure, not identity semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject_id: String,
}

/// What the crypto layer reports. This crate never verifies signatures;
/// it reasons about the *report*. A lying crypto layer is out of scope
/// for the verdict core (defense in depth, not infinite regress).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoStatus {
    Valid,
    Invalid,
    /// Crypto layer could not evaluate (unknown algorithm, etc.).
    Unknown,
}

/// The attempted use the envelope is presented for.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub subject_id: String,
    pub audience_id: String,
    pub operation_id: String,
    pub request_hash: String,
    pub policy_hash: String,
    pub now: u64,
    pub max_skew_secs: u64,
}

#[derive(Debug, Clone)]
pub struct PolicyInput {
    pub establishment: EstablishmentPolicy,
    /// Policy evaluation result for (established identity, operation).
    /// Supplied by the policy engine; Unknown defers, Disproven denies.
    pub policy_satisfied: Epistemic,
}

#[derive(Debug, Clone)]
pub struct VerdictInput {
    pub claimed_identity: Claimed<Identity>,
    pub envelope: Envelope,
    pub attempt: Attempt,
    pub evidence: EvidenceSet,
    pub provenance: ProvenanceGraph,
    pub policy: PolicyInput,
    pub crypto: CryptoStatus,
    /// Activation axis of the ternary cube: disabled / unresolved /
    /// enabled. Unknown propagates: unresolved activation defers,
    /// it never authorizes through convenience.
    pub activation: Epistemic,
}

/// Typed intermediate results. Inspectable, auditable, non-collapsible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageResults {
    pub crypto: CryptoStatus,
    pub freshness: Freshness,
    pub binding: Binding,
    /// Epistemic state of "the claimed identity is established".
    pub identity: Epistemic,
    /// Epistemic state of "evidence satisfies the establishment policy".
    pub evidence: Epistemic,
    /// Activation axis as evaluated.
    pub activation: Epistemic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Authorized { receipt: Receipt },
    /// Terminal no. Will not become yes with more evidence.
    Denied { stage: Stage, reason: String },
    /// UNKNOWN propagated. May become authorized later with evidence.
    /// Never confused with Denied, never confused with Authorized.
    Deferred { stage: Stage, reason: String },
}

/// Run the full pipeline. Returns stage results AND the verdict;
/// callers must handle all three verdict variants.
pub fn adjudicate(input: VerdictInput) -> (StageResults, Verdict) {
    let mut stages = StageResults {
        crypto: input.crypto,
        freshness: Freshness::Fresh,
        binding: Binding::Bound,
        identity: Epistemic::Unknown,
        evidence: Epistemic::Unknown,
        activation: input.activation,
    };

    // 1. Cryptography report. Invalid or Unknown crypto never authorizes.
    match input.crypto {
        CryptoStatus::Valid => {}
        CryptoStatus::Invalid => {
            return (
                StageResults { crypto: CryptoStatus::Invalid, ..stages },
                Verdict::Denied {
                    stage: Stage::Crypto,
                    reason: "signature invalid".into(),
                },
            );
        }
        CryptoStatus::Unknown => {
            return (
                StageResults { crypto: CryptoStatus::Unknown, ..stages },
                Verdict::Deferred {
                    stage: Stage::Crypto,
                    reason: "crypto status unknown; cannot authorize on unknown".into(),
                },
            );
        }
    }

    // 2. Freshness. Stale envelopes are denied, not deferred: time only
    // moves forward, so a stale envelope will never become fresh.
    let freshness = input.envelope.freshness(input.attempt.now, input.attempt.max_skew_secs);
    stages.freshness = freshness;
    match freshness {
        Freshness::Fresh => {}
        Freshness::Expired | Freshness::Malformed => {
            return (
                stages,
                Verdict::Denied { stage: Stage::Freshness, reason: format!("{:?}", freshness) },
            );
        }
        Freshness::NotYetValid => {
            return (
                stages,
                Verdict::Deferred {
                    stage: Stage::Freshness,
                    reason: "envelope not yet valid".into(),
                },
            );
        }
    }

    // 3. Binding. A proof about Alice is not proof about Bob.
    let binding = input.envelope.check_binding(
        &input.attempt.subject_id,
        &input.attempt.audience_id,
        &input.attempt.operation_id,
        &input.attempt.request_hash,
        &input.attempt.policy_hash,
    );
    stages.binding = binding;
    if binding != Binding::Bound {
        return (
            stages,
            Verdict::Denied { stage: Stage::Binding, reason: format!("{:?}", binding) },
        );
    }

    // 4-5. Identity establishment through evidence. The ONLY transition
    // from Claimed to Established in this crate.
    let established = match establish(
        &input.claimed_identity,
        &input.evidence,
        &input.provenance,
        &input.policy.establishment,
    ) {
        Ok(e) => {
            stages.identity = Epistemic::Proven;
            stages.evidence = Epistemic::Proven;
            e
        }
        Err(_) => {
            stages.identity = Epistemic::Unknown;
            stages.evidence = Epistemic::Unknown;
            // UNKNOWN propagates: defer, do not deny, do not authorize.
            return (
                stages,
                Verdict::Deferred {
                    stage: Stage::Evidence,
                    reason: "insufficient independent evidence; identity unestablished"
                        .into(),
                },
            );
        }
    };

    // 6. Policy application. The ONLY transition to Authorized.
    match authorize(established, input.policy.policy_satisfied) {
        Ok(_auth) => {
            // 7. Activation axis. Even a proven, policy-satisfied identity
            // does not authorize while activation is unresolved or
            // disabled. UNKNOWN propagates; it never authorizes.
            match input.activation {
                Epistemic::Proven => {
                    let receipt = Receipt {
                        receipt_id: format!("rcpt-{}", input.envelope.envelope_id),
                        envelope_id: input.envelope.envelope_id.clone(),
                        outcome: "authorized".into(),
                        terminal_stage: Stage::Policy,
                        reason: "all stages green".into(),
                        at: input.attempt.now,
                        previous_receipt_hash: input.envelope.previous_receipt_hash.clone(),
                        receipt_hash: String::new(), // filled by crypto layer
                    };
                    (stages, Verdict::Authorized { receipt })
                }
                Epistemic::Unknown => (
                    stages,
                    Verdict::Deferred {
                        stage: Stage::Activation,
                        reason: "activation unresolved; unknown propagates".into(),
                    },
                ),
                Epistemic::Disproven => (
                    stages,
                    Verdict::Denied {
                        stage: Stage::Activation,
                        reason: "activation disabled".into(),
                    },
                ),
            }
        }
        Err(Denial::PolicyRejects) => (
            stages,
            Verdict::Denied { stage: Stage::Policy, reason: "policy rejects".into() },
        ),
        Err(Denial::EvidenceUnknown) => (
            stages,
            Verdict::Deferred {
                stage: Stage::Policy,
                reason: "policy undecided; unknown propagates".into(),
            },
        ),
    }
}
