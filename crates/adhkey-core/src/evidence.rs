//! Evidence graph: the machinery for saying what connects a claim to reality.
//!
//! AdhKey does not determine whether a subject is human. It provides the
//! machinery to say: subject S has claim C, supported by evidence E,
//! witnessed by W, under policy P, represented currently by key K, with
//! history H, possessing capability X.
//!
//! Identity is not PROOF OF HUMAN. It is COST OF FALSE CLAIM.

use crate::{KeyId, Subject};
use std::collections::BTreeMap;

/// What kind of subject this is. The protocol treats them differently;
/// a PERSON claim requires evidence a DEVICE claim does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectKind {
    Person,
    Organization,
    Device,
    Software,
    Agent,
    Unknown,
}

/// Where evidence came from. None is sufficient alone; their intersection
/// is what carries weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    Government,
    Institutional,
    Social,
    Physical,
    Biometric,
    Historical,
    Cryptographic,
}

/// Who attests. A witness is identified; "trust me" is not a witness.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Witness {
    pub id: String,
    pub trust_domain: String,
}

/// One piece of evidence. Content lives with the issuer; AdhKey holds the
/// reference, the digest, and the provenance — never the raw PII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub id: String,
    pub kind: EvidenceKind,
    pub witness: Witness,
    /// Digest of the underlying evidence artifact (held by the witness).
    pub digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub revoked: bool,
}

/// A claim about a subject: "S corresponds to X", supported by evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub subject: Subject,
    pub statement: String,
    pub evidence_ids: Vec<String>,
    pub policy: String,
}

/// The epistemic lattice. "Verified human" MUST NOT be a boolean.
/// Each state says what is known, by whom, on what evidence — or that
/// nothing is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EpistemicState {
    /// No information. The honest default.
    Unknown,
    /// Someone asserted it. Worth nothing by itself.
    Claimed,
    /// Evidence exists and is referenced. Not yet evaluated.
    Supported,
    /// Evaluated against the assurance policy and passed.
    Established,
    /// Was established; withdrawn by the issuer or the subject.
    Revoked,
    /// Was established; time passed beyond its validity.
    Expired,
    /// Conflicting evidence or attestations exist. Unresolved.
    Conflict,
}

impl EpistemicState {
    /// Can this state authorize action? Only ESTABLISHED — and even then,
    /// freshness is a separate question (see Freshness).
    pub fn authorizable(&self) -> bool {
        matches!(self, EpistemicState::Established)
    }
}

/// A human-identity claim with full provenance. Never a boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanClaim {
    pub subject: Subject,
    pub kind: SubjectKind,
    pub evidence: Vec<Evidence>,
    pub assurance_policy: String,
    pub issued_by: Witness,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub state: EpistemicState,
}

/// Freshness: when was this state known, at what version, witnessed by whom.
/// Offline verification is honest about staleness instead of pretending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freshness {
    pub known_at: u64,
    pub state_version: u64,
    pub witness: Witness,
}

/// The authorization verdict. Three answers, not two.
/// CANNOT_ESTABLISH is a first-class answer: unknown remains unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationVerdict {
    /// Currently authorized. Freshness established within policy.
    Authorized,
    /// Was authorized at time T; freshness cannot be established now.
    /// The caller decides whether T is good enough. The protocol does not.
    AuthorizedAsOf(u64),
    /// Cannot establish current authority. Fail closed.
    CannotEstablish(String),
}

/// Evaluate a human claim against its assurance policy and evidence set.
/// Pure function: no I/O, no network. Returns the epistemic state the
/// evidence actually supports — never stronger.
pub fn evaluate_claim(claim: &HumanClaim, now: u64) -> EpistemicState {
    // Revocation is sticky and checked first.
    if claim.evidence.iter().any(|e| e.revoked) {
        return EpistemicState::Revoked;
    }
    if let Some(exp) = claim.expires_at {
        if now >= exp {
            return EpistemicState::Expired;
        }
    }
    if claim.evidence.is_empty() {
        return EpistemicState::Claimed;
    }
    // Expired evidence does not count toward support.
    let live: Vec<&Evidence> = claim
        .evidence
        .iter()
        .filter(|e| e.expires_at.map(|x| now < x).unwrap_or(true))
        .collect();
    if live.is_empty() {
        return EpistemicState::Claimed;
    }
    // Policy evaluation: the policy names a minimum evidence bar.
    // The core does not know what "medium" means — the policy does.
    // Here: SUPPORTED unless the policy's bar is met AND no conflict.
    // Conflict detection: two live evidence items from different witnesses
    // disagreeing is out of scope for the core; witnesses report conflict
    // via revocation. A policy hook can upgrade this.
    let _ = &live;
    EpistemicState::Supported
}

/// Promote SUPPORTED to ESTABLISHED. Only a policy evaluator does this,
/// and only with the policy's own criteria. The core refuses to guess.
pub fn establish(
    claim: &HumanClaim,
    policy_satisfied: bool,
    now: u64,
) -> EpistemicState {
    match evaluate_claim(claim, now) {
        EpistemicState::Supported if policy_satisfied => EpistemicState::Established,
        s => s,
    }
}

/// Authorize an action against the full chain:
/// subject -> identity -> evidence -> key -> capability -> policy,
/// with freshness. Returns the three-valued verdict.
pub fn authorize_with_freshness(
    state: EpistemicState,
    freshness: Option<&Freshness>,
    max_staleness_secs: u64,
    now: u64,
) -> AuthorizationVerdict {
    if !state.authorizable() {
        return AuthorizationVerdict::CannotEstablish(format!(
            "epistemic state {:?} is not authorizable",
            state
        ));
    }
    match freshness {
        None => AuthorizationVerdict::CannotEstablish(
            "no freshness witness; cannot establish current authority".into(),
        ),
        Some(f) => {
            // A witness claiming to have seen the state IN THE FUTURE is
            // lying or broken. Fail closed, never treat as fresh.
            if f.known_at > now {
                return AuthorizationVerdict::CannotEstablish(format!(
                    "freshness witness claims future time {} > now {}",
                    f.known_at, now
                ));
            }
            if now - f.known_at <= max_staleness_secs {
                AuthorizationVerdict::Authorized
            } else {
                AuthorizationVerdict::AuthorizedAsOf(f.known_at)
            }
        }
    }
}

/// The four questions, kept separate. A request for authorization must
/// answer all four; the protocol never lets one answer stand in for another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// 1. WHO IS THIS? (subject identifier)
    pub subject: Subject,
    pub subject_kind: SubjectKind,
    /// 2. WHAT EVIDENCE connects the claim to a real subject?
    pub evidence: Vec<Evidence>,
    pub assurance_policy: String,
    /// 3. WHAT KEY currently represents the subject?
    pub current_key: KeyId,
    /// 4. WHAT is the subject authorized to do here?
    pub capability_scope: String,
    pub capability_audience: String,
}

/// Registry of evidence by id, for claim evaluation.
pub type EvidenceRegistry = BTreeMap<String, Evidence>;
