//! Evidence graph: the machinery for saying what connects a claim to reality.
//!
//! AdhKey does not determine whether a subject is human. It provides the
//! machinery to say: subject S has claim C, supported by evidence E,
//! witnessed by W, under policy P, represented currently by key K, with
//! history H, possessing capability X.
//!
//! Identity is not PROOF OF HUMAN. It is COST OF FALSE CLAIM.

use crate::{
    policy_verdict_bytes, sha256d, Error, KeyId, KeyOperator, PolicyDecision,
    SignedPolicyVerdict, Subject,
};
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
    /// C3: keys authorized to sign policy verdicts over this claim.
    /// A verdict from any other key is rejected, not evaluated.
    pub policy_authorities: Vec<KeyId>,
}

fn push_field(out: &mut Vec<u8>, tag: &[u8], data: &[u8]) {
    out.extend_from_slice(tag);
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
}

fn evidence_digest_bytes(e: &Evidence, out: &mut Vec<u8>) {
    push_field(out, b"id", e.id.as_bytes());
    push_field(out, b"kind", format!("{:?}", e.kind).as_bytes());
    push_field(out, b"witness", e.witness.id.as_bytes());
    push_field(out, b"domain", e.witness.trust_domain.as_bytes());
    push_field(out, b"digest", &e.digest);
    push_field(out, b"issued_at", &e.issued_at.to_be_bytes());
    match e.expires_at {
        Some(x) => push_field(out, b"expires_at", &x.to_be_bytes()),
        None => push_field(out, b"expires_at", b"none"),
    }
    push_field(out, b"revoked", &[e.revoked as u8]);
}

impl HumanClaim {
    /// Digest of the evidence set, order-independent (sorted by id).
    /// A policy verdict snapshots this; if the evidence changes after
    /// the verdict was signed, the verdict no longer applies.
    pub fn evidence_snapshot(&self) -> [u8; 32] {
        let mut sorted: Vec<&Evidence> = self.evidence.iter().collect();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        let mut out = Vec::new();
        for e in sorted {
            evidence_digest_bytes(e, &mut out);
        }
        sha256d(b"ADHKEY/1/EVIDENCE-SNAPSHOT", &out)
    }

    /// Canonical claim hash. A signed policy verdict binds to this —
    /// a verdict for claim A cannot be replayed against claim B.
    pub fn digest(&self) -> [u8; 32] {
        let mut out = Vec::new();
        out.extend_from_slice(b"ADHKEY/1/CLAIM\n");
        push_field(&mut out, b"subject", self.subject.0.as_bytes());
        push_field(&mut out, b"kind", format!("{:?}", self.kind).as_bytes());
        push_field(&mut out, b"evidence_snapshot", &self.evidence_snapshot());
        push_field(&mut out, b"policy", self.assurance_policy.as_bytes());
        push_field(&mut out, b"issued_by", self.issued_by.id.as_bytes());
        push_field(&mut out, b"issued_at", &self.issued_at.to_be_bytes());
        match self.expires_at {
            Some(x) => push_field(&mut out, b"expires_at", &x.to_be_bytes()),
            None => push_field(&mut out, b"expires_at", b"none"),
        }
        let mut auth: Vec<&KeyId> = self.policy_authorities.iter().collect();
        auth.sort();
        for a in auth {
            push_field(&mut out, b"authority", a.0.as_bytes());
        }
        sha256d(b"ADHKEY/1/CLAIM-HASH", &out)
    }
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
    // C4: contradiction detection. Two live evidence items making
    // incompatible statements about the SAME evidence id (same id,
    // different artifact digests) is a real, reachable conflict — not
    // decoration. (Revocation stays sticky and is checked above.)
    {
        let mut by_id: BTreeMap<&str, &[u8; 32]> = BTreeMap::new();
        for e in &live {
            match by_id.get(e.id.as_str()) {
                Some(d) if *d != &e.digest => return EpistemicState::Conflict,
                Some(_) => {}
                None => {
                    by_id.insert(e.id.as_str(), &e.digest);
                }
            }
        }
    }
    // Policy evaluation: the policy names a minimum evidence bar.
    // The core does not know what "medium" means — the policy does.
    // Here: SUPPORTED unless the policy's bar is met AND no conflict.
    // Conflict is detected above, over the evidence set, for real.
    let _ = &live;
    EpistemicState::Supported
}

/// Promote SUPPORTED to ESTABLISHED. C3: the bare `policy_satisfied: bool`
/// is dead. Promotion requires a SIGNED policy verdict, verified here:
///
///  1. the evaluator's signature checks out over the canonical verdict
///     bytes (built here);
///  2. the evaluator is in `claim.policy_authorities`;
///  3. the verdict binds THIS claim (`claim_hash` matches);
///  4. the verdict binds the CURRENT evidence set (`evidence_snapshot`
///     matches — evidence changed since evaluation = verdict is stale);
///  5. the verdict is fresh (`evaluated_at` within `max_verdict_age_secs`).
///
/// Non-Supported states pass through untouched: revocation is sticky,
/// conflict stays conflict, expiry is honest. A forged, unauthorized,
/// mismatched, or stale verdict is an ERROR (loud, fail-closed) — never
/// a silent non-promotion.
pub fn establish(
    claim: &HumanClaim,
    verdict: &SignedPolicyVerdict,
    keys: &dyn KeyOperator,
    now: u64,
    max_verdict_age_secs: u64,
) -> Result<EpistemicState, Error> {
    match evaluate_claim(claim, now) {
        EpistemicState::Supported => {}
        s => return Ok(s),
    }
    // 2. Authorized evaluator?
    if !claim.policy_authorities.contains(&verdict.evaluator) {
        return Err(Error::BadPolicyVerdict(format!(
            "evaluator {} not authorized for this claim",
            verdict.evaluator
        )));
    }
    // 1. Signature over canonical bytes.
    let msg = policy_verdict_bytes(verdict);
    let ok = keys
        .verify(&verdict.evaluator, &msg, &verdict.signature)
        .map_err(|e| Error::KeyOperatorFailed(format!("verdict check failed: {e}")))?;
    if !ok {
        return Err(Error::BadPolicyVerdict("verdict signature invalid".into()));
    }
    // 3. Bound to THIS claim?
    if verdict.claim_hash != claim.digest() {
        return Err(Error::BadPolicyVerdict(
            "verdict binds a different claim".into(),
        ));
    }
    // 4. Bound to the CURRENT evidence set?
    if verdict.evidence_snapshot != claim.evidence_snapshot() {
        return Err(Error::BadPolicyVerdict(
            "evidence changed since verdict was evaluated".into(),
        ));
    }
    // 5. Fresh?
    if verdict.evaluated_at > now {
        return Err(Error::BadPolicyVerdict(
            "verdict evaluated in the future".into(),
        ));
    }
    if now - verdict.evaluated_at > max_verdict_age_secs {
        return Err(Error::BadPolicyVerdict("verdict stale".into()));
    }
    // The verdict is authentic, authorized, bound, and fresh.
    // Its ternary decision — not a bool — drives promotion.
    match verdict.decision {
        PolicyDecision::Allow => Ok(EpistemicState::Established),
        PolicyDecision::Deny | PolicyDecision::Unknown => Ok(EpistemicState::Supported),
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
