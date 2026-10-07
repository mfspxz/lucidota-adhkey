//! The Statement primitive: the atomic AdhKey object.
//!
//! Everything else is a projection:
//! - Key registration:  S1 --controls--> K1
//! - Human claim:       S1 --is_person--> P
//! - Recovery:          S1 --replaces--> (K1, K2)
//! - Witness:           W1 --attests--> (S1 --is_person--> P)
//! - Authorization:     S1 --may--> (action on resource)
//! - Revocation:        W1 --withdraws--> statement_hash
//!
//! Two-phase authority (red-team round 2):
//! - `authenticate()` verifies signature + chain. It returns
//!   `Claimed<AuthenticatedStatement>`: proof that the issuer SIGNED
//!   these bytes, NOT proof the issuer was authorized to produce effects.
//! - `authorize_issuance()` crosses the authority boundary
//!   (Claimed -> Established, via luci-verdict-core): genesis must anchor
//!   in `TrustRoots`; otherwise the issuer's key must already control the
//!   subject, and the issuance policy must evaluate to Proven.
//! - `reduce()` walks the DAG deterministically (fork subtrees excluded,
//!   chain continuity enforced, authorization before effects) and applies
//!   withdrawals for real.
//!
//! Cuts addressed structurally:
//! #1  No Identity struct to construct: identity is DERIVED (reduce).
//! #2  History is a hash-chained, signed event log, not a Vec.
//! #4  KeyRef is a fingerprint, not a label.
//! #5  SubjectRef is namespaced; empty namespace/id rejected.
//! #6  Evidence is bounded, window-checked, acyclic-as-far-as-visible.
//! #15 Receipts record what was NOT checked (rejected[] with reasons).
//! #19 Capabilities ARE statements (predicate Authorizes), signed.
//! #20 Domain separation prefixes on all signed bytes.
//! #21 Canonical encoding defined HERE, before anything signs; evidence
//!     order-independent; field length caps enforced.
//!
//! Open (documented, not fixed): Unicode normalization (no NFC without a
//! unicode dep); evidence recursion depth beyond self-reference (needs the
//! artifact resolver); cross-implementation decoder spec.

use luci_verdict_core::authority::{establish, Claimed, EstablishmentPolicy, Established};
use luci_verdict_core::witness::{EvidenceSet, ProvenanceGraph, Witness};
use luci_verdict_core::Epistemic;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[cfg(test)]
mod tests;

/// A subject reference: namespace + id. Never a bare string.
/// `namespace` scopes the id: "exchange", "government", "witness:dmv"...
/// Empty namespace or id is rejected at authenticate (nim-resub #11).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectRef {
    pub namespace: String,
    pub id: String,
}

/// A key reference: SHA-256 fingerprint of the public key bytes.
/// Not a label. Two systems referring to the same key compute the same ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyRef(pub [u8; 32]);

/// Statement hash. Alias also sidesteps a rustc parser quirk where
/// `[u8; 32]` directly inside nested generics (e.g.
/// `BTreeMap<[u8; 32], &Claimed<..>>`) misparses.
pub type Hash = [u8; 32];

impl KeyRef {
    pub fn of_public_key(bytes: &[u8]) -> Self {
        KeyRef(sha256(b"ADHKEY/1/KEYREF", bytes))
    }
}

/// Predicates. Structural variants the core reasons about; Custom for
/// everything policy-defined. The core never pretends Custom is closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Predicate {
    Controls,
    Replaces { old: KeyRef, new: KeyRef },
    Attests,
    Authorizes,
    Withdraws,
    Supersedes,
    Custom(String),
}

/// The object of a statement: what the predicate relates the subject to.
/// Predicate/object compatibility is enforced: e.g. Controls requires a
/// Key object, Withdraws a StatementHash (nim-resub #13, deepseek N2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    Key(KeyRef),
    StatementHash([u8; 32]),
    Text(String),
    Bytes(Vec<u8>),
}

/// Reference to evidence: digest of the artifact + where it lives.
/// The artifact itself is never in the protocol.
/// Validity windows are enforced at authenticate (nim-resub #9); the
/// fan-out is bounded and self-reference rejected (nim-resub #7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    pub digest: [u8; 32],
    pub issuer: SubjectRef,
    pub predicate: Predicate,
    pub valid_from: u64,
    pub valid_until: Option<u64>,
    pub revoked: bool,
}

/// A statement: the atomic object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub subject: SubjectRef,
    pub predicate: Predicate,
    pub object: Object,
    pub issuer: SubjectRef,
    /// The key that purportedly signed this statement (fingerprint).
    /// Bound into the canonical bytes; the verifier receives it explicitly
    /// (nim-resub #6: previously no field named the issuing key).
    pub issuer_key: KeyRef,
    pub evidence: Vec<EvidenceRef>,
    /// Policy identifier (non-empty). The policy is EVALUATED by the
    /// issuance policy at authorize time; the string alone authorizes
    /// nothing (nim-resub #8).
    pub policy: String,
    pub policy_version: u64,
    pub timestamp: u64,
    /// Per-(issuer, subject) sequence. Gaps are detectable.
    pub sequence: u64,
    /// Hash of the issuer's previous statement for this subject (genesis = zero).
    pub previous: [u8; 32],
    /// Issuer's signature over canonical_bytes() (domain-separated).
    pub signature: Vec<u8>,
    /// Which signature suite produced `signature`. Must be in the
    /// authenticator's allowlist; exact match (nim-resub #12).
    pub suite: String,
}

fn sha256(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(data);
    h.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

fn push_field(out: &mut Vec<u8>, tag: &[u8], data: &[u8]) {
    out.extend_from_slice(tag);
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
}

/// Canonical byte encoding. Fixed field order, length-prefixed.
/// Evidence is sorted by digest: the same evidence SET always yields the
/// same bytes regardless of vec order (deepseek 4e).
/// Same statement -> same bytes -> same signature, across implementations.
pub fn canonical_bytes(s: &Statement) -> Vec<u8> {
    let mut out = Vec::new();
    // Domain separation: what KIND of thing is being signed.
    out.extend_from_slice(b"ADHKEY/1/STATEMENT\n");
    push_field(&mut out, b"sub-ns", s.subject.namespace.as_bytes());
    push_field(&mut out, b"sub-id", s.subject.id.as_bytes());
    push_field(&mut out, b"pred", &canonical_predicate(&s.predicate));
    push_field(&mut out, b"object", &canonical_object(&s.object));
    push_field(&mut out, b"iss-ns", s.issuer.namespace.as_bytes());
    push_field(&mut out, b"iss-id", s.issuer.id.as_bytes());
    push_field(&mut out, b"iss-key", &s.issuer_key.0);
    let mut ev: Vec<&EvidenceRef> = s.evidence.iter().collect();
    ev.sort_by(|a, b| a.digest.cmp(&b.digest));
    for e in ev {
        push_field(&mut out, b"ev", &canonical_evidence(e));
    }
    push_field(&mut out, b"policy", s.policy.as_bytes());
    push_field(&mut out, b"pol-ver", &s.policy_version.to_be_bytes());
    push_field(&mut out, b"ts", &s.timestamp.to_be_bytes());
    push_field(&mut out, b"seq", &s.sequence.to_be_bytes());
    push_field(&mut out, b"prev", &s.previous);
    push_field(&mut out, b"suite", s.suite.as_bytes());
    out
}

fn canonical_predicate(p: &Predicate) -> Vec<u8> {
    match p {
        Predicate::Controls => b"controls".to_vec(),
        Predicate::Replaces { old, new } => {
            let mut v = b"replaces:".to_vec();
            v.extend_from_slice(&old.0);
            v.extend_from_slice(b":");
            v.extend_from_slice(&new.0);
            v
        }
        Predicate::Attests => b"attests".to_vec(),
        Predicate::Authorizes => b"authorizes".to_vec(),
        Predicate::Withdraws => b"withdraws".to_vec(),
        Predicate::Supersedes => b"supersedes".to_vec(),
        Predicate::Custom(s) => {
            let mut v = b"custom:".to_vec();
            v.extend_from_slice(s.as_bytes());
            v
        }
    }
}

fn canonical_object(o: &Object) -> Vec<u8> {
    match o {
        Object::Key(k) => {
            let mut v = b"key:".to_vec();
            v.extend_from_slice(&k.0);
            v
        }
        Object::StatementHash(h) => {
            let mut v = b"stmthash:".to_vec();
            v.extend_from_slice(h);
            v
        }
        Object::Text(t) => {
            let mut v = b"text:".to_vec();
            v.extend_from_slice(t.as_bytes());
            v
        }
        Object::Bytes(b) => {
            let mut v = b"bytes:".to_vec();
            v.extend_from_slice(b);
            v
        }
    }
}

fn canonical_evidence(e: &EvidenceRef) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&e.digest);
    push_field(&mut v, b"e-iss-ns", e.issuer.namespace.as_bytes());
    push_field(&mut v, b"e-iss-id", e.issuer.id.as_bytes());
    push_field(&mut v, b"e-pred", &canonical_predicate(&e.predicate));
    push_field(&mut v, b"e-from", &e.valid_from.to_be_bytes());
    if let Some(u) = e.valid_until {
        push_field(&mut v, b"e-until", &u.to_be_bytes());
    }
    push_field(&mut v, b"e-rev", &[e.revoked as u8]);
    v
}

/// Hash of a statement's canonical bytes (for chaining / references).
/// Excludes the signature: the hash identifies the statement, not the
/// particular signature bytes over it.
pub fn statement_hash(s: &Statement) -> [u8; 32] {
    sha256(b"ADHKEY/1/STMTHASH", &canonical_bytes(s))
}

/// An authenticated statement: signature and chain already verified.
/// Constructing this type REQUIRES passing verification — it has no
/// public fields settable without the check (see `authenticate`).
/// NOTE: this is still only a CLAIM. Authorization is a separate phase
/// (`authorize_issuance`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedStatement {
    inner: Statement,
    hash: [u8; 32],
}

impl AuthenticatedStatement {
    pub fn statement(&self) -> &Statement {
        &self.inner
    }
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

/// Configuration for `authenticate`. The caller declares what it will
/// accept; anything else is rejected fail-closed.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Exact-match allowlist for `suite`. Empty allowlist rejects all.
    pub allowed_suites: Vec<String>,
    /// Maximum evidence refs per statement (fan-out bound).
    pub max_evidence_refs: usize,
    /// Maximum byte length of any variable-length field.
    pub max_field_len: usize,
}

impl AuthConfig {
    pub fn strict(allowed_suites: Vec<String>) -> Self {
        AuthConfig {
            allowed_suites,
            max_evidence_refs: 16,
            max_field_len: 1 << 20,
        }
    }
}

fn check_len(len: usize, max: usize) -> Result<(), AuthError> {
    if len > max {
        Err(AuthError::FieldTooLarge)
    } else {
        Ok(())
    }
}

fn valid_subjectref(r: &SubjectRef) -> bool {
    !r.namespace.is_empty() && !r.id.is_empty()
}

/// Predicate/object compatibility (nim-resub #13, deepseek N2).
/// Two channels for one semantic is a bug: Replaces draws old/new from
/// the predicate, so the object MUST be Key(new) — anything else is a
/// mismatch, not an alternative encoding.
fn check_predicate_object(p: &Predicate, o: &Object) -> Result<(), AuthError> {
    let ok = match (p, o) {
        (Predicate::Controls, Object::Key(_)) => true,
        (Predicate::Withdraws, Object::StatementHash(_)) => true,
        (Predicate::Replaces { new, .. }, Object::Key(k)) => k == new,
        (Predicate::Attests, Object::StatementHash(_)) => true,
        (Predicate::Supersedes, Object::StatementHash(_)) => true,
        (Predicate::Authorizes, _) => true,
        (Predicate::Custom(_), _) => true,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AuthError::PredicateObjectMismatch)
    }
}

/// Verify a statement: syntax, suite, predicate/object compatibility,
/// evidence windows, chain continuity, signature.
/// Returns `Claimed<AuthenticatedStatement>`: the issuer SIGNED these
/// bytes and the chain is continuous. It does NOT mean the issuer was
/// authorized to produce effects — that is `authorize_issuance()`.
pub fn authenticate<F>(
    s: Statement,
    prev_auth: Option<&AuthenticatedStatement>,
    verify_sig: F,
    cfg: &AuthConfig,
) -> Result<Claimed<AuthenticatedStatement>, AuthError>
where
    F: Fn(&KeyRef, &[u8], &[u8], &str) -> bool,
{
    // 0. Syntactic validity.
    if !valid_subjectref(&s.subject) || !valid_subjectref(&s.issuer) {
        return Err(AuthError::EmptySubject);
    }
    if s.policy.is_empty() {
        return Err(AuthError::EmptyPolicy);
    }
    if s.suite.is_empty() || !cfg.allowed_suites.iter().any(|a| a == &s.suite) {
        return Err(AuthError::UnknownSuite);
    }
    for len in [
        s.subject.namespace.len(),
        s.subject.id.len(),
        s.issuer.namespace.len(),
        s.issuer.id.len(),
        s.policy.len(),
        s.suite.len(),
    ] {
        check_len(len, cfg.max_field_len)?;
    }
    match &s.predicate {
        Predicate::Custom(c) => check_len(c.len(), cfg.max_field_len)?,
        _ => {}
    }
    match &s.object {
        Object::Text(t) => check_len(t.len(), cfg.max_field_len)?,
        Object::Bytes(b) => check_len(b.len(), cfg.max_field_len)?,
        _ => {}
    }
    check_predicate_object(&s.predicate, &s.object)?;
    // Evidence: bounded fan-out, coherent windows, live at statement time,
    // not revoked, no self-reference (cycle of length 1).
    if s.evidence.len() > cfg.max_evidence_refs {
        return Err(AuthError::InvalidEvidence);
    }
    for e in &s.evidence {
        if !valid_subjectref(&e.issuer) {
            return Err(AuthError::InvalidEvidence);
        }
        if let Some(u) = e.valid_until {
            if e.valid_from > u {
                return Err(AuthError::InvalidEvidence);
            }
            if s.timestamp > u {
                return Err(AuthError::InvalidEvidence);
            }
        }
        if s.timestamp < e.valid_from {
            return Err(AuthError::InvalidEvidence);
        }
        if e.revoked {
            return Err(AuthError::InvalidEvidence);
        }
    }
    // 1. Chain: sequence increments (checked), previous hash matches.
    match prev_auth {
        None => {
            if s.sequence != 0 {
                return Err(AuthError::SequenceGap);
            }
            if s.previous != [0u8; 32] {
                return Err(AuthError::ChainBreak);
            }
        }
        Some(prev) => {
            let next = prev
                .inner
                .sequence
                .checked_add(1)
                .ok_or(AuthError::SequenceOverflow)?;
            if s.sequence != next {
                return Err(AuthError::SequenceGap);
            }
            if s.previous != prev.hash {
                return Err(AuthError::ChainBreak);
            }
            if s.issuer != prev.inner.issuer || s.subject != prev.inner.subject {
                return Err(AuthError::ChainBreak);
            }
        }
    }
    // 2. Signature over canonical bytes. The caller supplies the crypto;
    //    this function decides what it MEANS — and it means "signed", not
    //    "authorized". The verifier receives the issuing KEY explicitly.
    let bytes = canonical_bytes(&s);
    if !verify_sig(&s.issuer_key, &bytes, &s.signature, &s.suite) {
        return Err(AuthError::BadSignature);
    }
    let hash = statement_hash(&s);
    // Self-reference check needs the hash: evidence may not cite this
    // statement itself (evidence recursion, cycle of length 1).
    if s.evidence.iter().any(|e| e.digest == hash) {
        return Err(AuthError::InvalidEvidence);
    }
    Ok(Claimed::new(AuthenticatedStatement { inner: s, hash }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    BadSignature,
    SequenceGap,
    SequenceOverflow,
    ChainBreak,
    EmptySubject,
    EmptyPolicy,
    FieldTooLarge,
    UnknownSuite,
    PredicateObjectMismatch,
    InvalidEvidence,
    UnauthorizedIssuer,
    UntrustedGenesis,
    PolicyRejected,
    PolicyUnknown,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            AuthError::BadSignature => "signature invalid",
            AuthError::SequenceGap => "sequence gap",
            AuthError::SequenceOverflow => "sequence overflow",
            AuthError::ChainBreak => "chain break: previous hash or (issuer,subject) mismatch",
            AuthError::EmptySubject => "empty subject/issuer namespace or id",
            AuthError::EmptyPolicy => "empty policy identifier",
            AuthError::FieldTooLarge => "field exceeds max_field_len",
            AuthError::UnknownSuite => "suite not in allowlist",
            AuthError::PredicateObjectMismatch => "predicate/object incompatible",
            AuthError::InvalidEvidence => "evidence invalid (window, revoked, unbounded, self-ref)",
            AuthError::UnauthorizedIssuer => "issuer key not authorized for subject",
            AuthError::UntrustedGenesis => "genesis not anchored in trust roots",
            AuthError::PolicyRejected => "issuance policy disproven",
            AuthError::PolicyUnknown => "issuance policy undecided",
        };
        write!(f, "{}", s)
    }
}

/// Trust roots: (namespace, key fingerprint) pairs permitted to originate
/// a chain for that namespace. Genesis without a registered root is
/// rejected (nim-resub #2, deepseek #2). Who maintains the registry is
/// deployment-specific; the model requires that SOME registry exists —
/// there is no self-rooting without it.
#[derive(Debug, Clone, Default)]
pub struct TrustRoots {
    pub roots: BTreeSet<(String, KeyRef)>,
}

/// Issuance policy: evaluated at authorize time with bound inputs
/// (statement + derived state). Returns an epistemic verdict, not a bool:
/// Unknown fails closed (nim-resub #8: the string alone authorizes nothing).
pub trait IssuancePolicy {
    fn evaluate(&self, s: &Statement, state: &DerivedState) -> Epistemic;
}

/// Permissive policy for tests and migration. Production callers supply
/// a real evaluator.
#[derive(Debug, Clone, Copy)]
pub struct AcceptAll;
impl IssuancePolicy for AcceptAll {
    fn evaluate(&self, _s: &Statement, _state: &DerivedState) -> Epistemic {
        Epistemic::Proven
    }
}

/// Cross the authority boundary: Claimed -> Established (luci-verdict-core).
///
/// 1. Issuer authorization: genesis requires a registered trust root for
///    the subject's namespace; otherwise the issuer's KEY must already
///    control the subject. This kills self-authority (nim-resub #1),
///    cross-subject issuance, and unauthorized issuers — at the type
///    level the result can only be built here.
/// 2. Policy evaluation with bound inputs; Disproven/Unknown fail closed.
pub fn authorize_issuance(
    claimed: &Claimed<AuthenticatedStatement>,
    state: &DerivedState,
    roots: &TrustRoots,
    policy: &dyn IssuancePolicy,
) -> Result<Established<AuthenticatedStatement>, AuthError> {
    let s = claimed.inner().statement();
    if s.sequence == 0 {
        // Genesis: the issuer's key must be a trust root for the namespace,
        // OR already authorized for this subject by prior delegation. The
        // second disjunct is what makes delegation work: Bob grants Alice's
        // key for Bob, then Alice can open her own (Alice, Bob) chain without
        // being a namespace root. Self-bootstrap is impossible: granting
        // yourself requires already being authorized.
        let rooted = roots
            .roots
            .contains(&(s.subject.namespace.clone(), s.issuer_key));
        let delegated = state
            .controls
            .get(&s.subject)
            .map(|v| v.contains(&s.issuer_key))
            .unwrap_or(false);
        if !rooted && !delegated {
            return Err(AuthError::UntrustedGenesis);
        }
    } else {
        let authorized = state
            .controls
            .get(&s.subject)
            .map(|v| v.contains(&s.issuer_key))
            .unwrap_or(false);
        if !authorized {
            return Err(AuthError::UnauthorizedIssuer);
        }
    }
    match policy.evaluate(s, state) {
        Epistemic::Proven => {}
        Epistemic::Disproven => return Err(AuthError::PolicyRejected),
        Epistemic::Unknown => return Err(AuthError::PolicyUnknown),
    }
    // The membership test above is the domain rule; establish() is the
    // type-level boundary crossing — the only constructor of Established.
    let evidence = EvidenceSet {
        witnesses: vec![Witness {
            id: hex(&s.issuer_key.0),
            trust_root: hex(&s.issuer_key.0),
        }],
    };
    establish(
        claimed,
        &evidence,
        &ProvenanceGraph::default(),
        &EstablishmentPolicy {
            required_independent_witnesses: 1,
        },
    )
    .map_err(|_| AuthError::UnauthorizedIssuer)
}

/// Why a statement was not applied. Recorded, never silent (cut #15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    UnauthorizedIssuer,
    UntrustedGenesis,
    PolicyRejected,
    PolicyUnknown,
    BrokenChain,
    UnknownOldKey,
    ForkExcluded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub hash: [u8; 32],
    pub reason: RejectReason,
}

/// Derived state: the REDUCE of an authenticated event log.
/// There is no Identity struct to construct. This is computed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DerivedState {
    /// subject -> currently controlling keys (fingerprints).
    pub controls: BTreeMap<SubjectRef, Vec<KeyRef>>,
    /// withdrawn statement hashes.
    pub withdrawn: Vec<[u8; 32]>,
    /// latest sequence per (issuer, subject).
    pub sequences: BTreeMap<(SubjectRef, SubjectRef), u64>,
    /// Equivocation: two different statements claiming the same predecessor.
    /// First-class Conflict: neither branch's effects are applied, and neither
    /// are any descendant's. Never tie-break silently.
    pub conflicts: Vec<([u8; 32], [u8; 32])>,
    /// Statements seen but not applied, with reasons. Failing closed,
    /// out loud.
    pub rejected: Vec<Rejection>,
}

/// Reduce an authenticated log to derived state. Deterministic and
/// order-independent (deepseek N1, N9):
/// - Pass 1: index by hash; detect forks over the WHOLE log keyed by
///   (issuer, subject, previous); exclude both branches AND all
///   descendants (transitive closure over previous-links).
/// - Pass 2: walk remaining statements in (issuer, subject, sequence)
///   order from genesis, enforcing chain continuity (previous must match
///   the tip). Authorization before effects: each statement crosses
///   Claimed -> Established before anything is applied.
/// - Withdrawals are applied for real: a withdrawn Controls statement's
///   key is removed (deepseek N3 was a live bug: withdrawals accumulated
///   in a list nothing read).
/// Reduce a log of authenticated statements to a derived state.
///
/// Pass 1 (order-independent): fork detection over the whole log. Any two
/// statements sharing (issuer, subject, previous) with different hashes are
/// a fork; both branches and all descendants (transitive closure over
/// previous-links) are excluded, and every excluded statement is recorded
/// as rejected (ForkExcluded) — nothing disappears silently.
///
/// Pass 2 (static): chain-continuity validation per (issuer, subject).
/// Statements are grouped, sorted by (sequence, hash), and walked: genesis
/// must have sequence 0 and zero previous; each successor must link to its
/// predecessor's hash. A break rejects that statement (BrokenChain) without
/// advancing the expected link, so breaks cascade. Hash-link continuity is
/// the invariant; sequence-number density is not enforced (gaps are legal).
///
/// Pass 3 (fixpoint): authorization before effects. Statements are retried
/// in deterministic order until a full round applies nothing. This is what
/// makes delegation work: Alice's genesis-about-Bob cannot authorize until
/// Bob's grant of her key is applied, but sort order may present Alice
/// first. Bounded by len+1 rounds; anything still pending is rejected with
/// its last authorization error. Unauthorized statements are recorded in
/// `rejected`, never applied.
///
/// Only `Claimed<AuthenticatedStatement>` is accepted: unauthenticated
/// statements cannot enter.
pub fn reduce(
    log: &[Claimed<AuthenticatedStatement>],
    roots: &TrustRoots,
    policy: &dyn IssuancePolicy,
) -> DerivedState {
    let mut st = DerivedState::default();
    let by_hash: BTreeMap<Hash, &Claimed<AuthenticatedStatement>> =
        log.iter().map(|c| (c.inner().hash(), c)).collect();
    // Children index for fork-subtree exclusion.
    let mut children: BTreeMap<Hash, Vec<Hash>> = BTreeMap::new();
    for (h, c) in &by_hash {
        children
            .entry(c.inner().statement().previous)
            .or_default()
            .push(*h);
    }
    // Pass 1: fork detection over the whole log (order-independent).
    let mut first_seen: BTreeMap<(SubjectRef, SubjectRef, Hash), Hash> = BTreeMap::new();
    let mut excluded: BTreeSet<Hash> = BTreeSet::new();
    // Deterministic iteration: by_hash is a BTreeMap (hash order).
    for (h, c) in &by_hash {
        let s = c.inner().statement();
        let key = (s.issuer.clone(), s.subject.clone(), s.previous);
        match first_seen.get(&key) {
            Some(prev_h) if *prev_h != *h => {
                st.conflicts.push((*prev_h, *h));
                // Exclude both branches and all descendants.
                let mut stack = vec![*prev_h, *h];
                while let Some(x) = stack.pop() {
                    if excluded.insert(x) {
                        if let Some(kids) = children.get(&x) {
                            stack.extend(kids.iter().cloned());
                        }
                    }
                }
            }
            Some(_) => {}
            None => {
                first_seen.insert(key, *h);
            }
        }
    }
    for h in &excluded {
        st.rejected.push(Rejection {
            hash: *h,
            reason: RejectReason::ForkExcluded,
        });
    }
    // Pass 2: static chain-continuity validation per (issuer, subject).
    let mut chains: BTreeMap<(SubjectRef, SubjectRef), Vec<&Claimed<AuthenticatedStatement>>> =
        BTreeMap::new();
    for c in by_hash.values().filter(|c| !excluded.contains(&c.inner().hash())) {
        let s = c.inner().statement();
        chains
            .entry((s.issuer.clone(), s.subject.clone()))
            .or_default()
            .push(*c);
    }
    let mut valid: Vec<&Claimed<AuthenticatedStatement>> = Vec::new();
    for (_, mut grp) in chains {
        grp.sort_by(|a, b| {
            let sa = a.inner().statement();
            let sb = b.inner().statement();
            (sa.sequence, a.inner().hash()).cmp(&(sb.sequence, b.inner().hash()))
        });
        let mut expected: Option<Hash> = None; // None = expecting genesis
        for c in grp {
            let s = c.inner().statement();
            let h = c.inner().hash();
            let ok = match expected {
                None => s.sequence == 0 && s.previous == [0u8; 32],
                Some(e) => s.sequence > 0 && s.previous == e,
            };
            if ok {
                valid.push(c);
                expected = Some(h);
            } else {
                st.rejected.push(Rejection {
                    hash: h,
                    reason: RejectReason::BrokenChain,
                });
            }
        }
    }
    // Pass 3: fixpoint authorization before effects, deterministic order.
    valid.sort_by(|a, b| {
        let sa = a.inner().statement();
        let sb = b.inner().statement();
        (
            sa.issuer.clone(),
            sa.subject.clone(),
            sa.sequence,
            a.inner().hash(),
        )
            .cmp(&(
                sb.issuer.clone(),
                sb.subject.clone(),
                sb.sequence,
                b.inner().hash(),
            ))
    });
    let mut applied: BTreeSet<Hash> = BTreeSet::new();
    let mut last_err: BTreeMap<Hash, RejectReason> = BTreeMap::new();
    for _ in 0..=valid.len() {
        let mut progress = false;
        for c in &valid {
            let h = c.inner().hash();
            if applied.contains(&h) {
                continue;
            }
            match authorize_issuance(c, &st, roots, policy) {
                Ok(est) => {
                    let s = est.inner().statement();
                    st.sequences
                        .insert((s.issuer.clone(), s.subject.clone()), s.sequence);
                    apply_effects(&mut st, s, h, &by_hash);
                    applied.insert(h);
                    progress = true;
                }
                Err(e) => {
                    last_err.insert(h, auth_reject_reason(&e));
                }
            }
        }
        if !progress {
            break;
        }
    }
    for c in &valid {
        let h = c.inner().hash();
        if !applied.contains(&h) {
            st.rejected.push(Rejection {
                hash: h,
                reason: last_err
                    .remove(&h)
                    .unwrap_or(RejectReason::UnauthorizedIssuer),
            });
        }
    }
    st
}

/// Map an authorization failure to its rejection receipt. Fail closed:
/// anything unrecognized becomes UnauthorizedIssuer, never a pass.
fn auth_reject_reason(e: &AuthError) -> RejectReason {
    match e {
        AuthError::UntrustedGenesis => RejectReason::UntrustedGenesis,
        AuthError::UnauthorizedIssuer => RejectReason::UnauthorizedIssuer,
        AuthError::PolicyRejected => RejectReason::PolicyRejected,
        AuthError::PolicyUnknown => RejectReason::PolicyUnknown,
        _ => RejectReason::UnauthorizedIssuer, // fail closed
    }
}

fn apply_effects(
    st: &mut DerivedState,
    s: &Statement,
    h: Hash,
    by_hash: &BTreeMap<Hash, &Claimed<AuthenticatedStatement>>,
) {
    match &s.predicate {
        Predicate::Controls => {
            if let Object::Key(k) = &s.object {
                // Controls is a set: re-assertion is idempotent.
                let v = st.controls.entry(s.subject.clone()).or_default();
                if !v.contains(k) {
                    v.push(*k);
                }
            }
        }
        Predicate::Replaces { old, new } => {
            let v = st.controls.entry(s.subject.clone()).or_default();
            // The old key must actually be controlled: rotation replaces a
            // live key, it does not conjure authority (deepseek 3c).
            if v.contains(old) {
                v.retain(|k| k != old);
                if !v.contains(new) {
                    v.push(*new);
                }
            } else {
                st.rejected.push(Rejection {
                    hash: h,
                    reason: RejectReason::UnknownOldKey,
                });
            }
        }
        Predicate::Withdraws => {
            if let Object::StatementHash(target) = &s.object {
                st.withdrawn.push(*target);
                // Applied for real: remove the withdrawn Controls key.
                if let Some(tc) = by_hash.get(target) {
                    let ts = tc.inner().statement();
                    if ts.predicate == Predicate::Controls {
                        if let Object::Key(k) = &ts.object {
                            if let Some(v) = st.controls.get_mut(&ts.subject) {
                                v.retain(|x| x != k);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}
