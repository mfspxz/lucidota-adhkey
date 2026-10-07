//! adhkey-core: identity/key-lifecycle protocol types and state machine.
//!
//! No cryptography here. No I/O. Pure types + transitions.
//! The security-critical core. Keep it small enough to audit.

pub mod evidence;
pub mod lifecycle;
pub mod verifier;

#[cfg(test)]
mod court;

#[cfg(test)]
mod court_evidence;

use std::collections::BTreeMap;
use std::fmt;

/// Opaque key identifier. Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub String);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What a key is for. A key MUST NOT be used outside its purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    Authentication,
    Signing,
    Recovery,
    Encryption,
}

/// Lifecycle state of a key. Transitions are explicit and recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyState {
    Active,
    Lost,
    Revoked,
    Expired,
}

impl KeyState {
    /// Is this key usable for signing/authentication right now?
    pub fn usable(&self) -> bool {
        matches!(self, KeyState::Active)
    }

    /// Legal transitions. Everything else is rejected.
    pub fn can_transition_to(&self, next: KeyState) -> bool {
        use KeyState::*;
        matches!(
            (self, next),
            (Active, Lost)
                | (Active, Revoked)
                | (Active, Expired)
                | (Lost, Active) // found again
                | (Lost, Revoked)
        )
    }
}

/// Who or what the identity belongs to. Opaque to the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subject(pub String);

/// A verification method: how this identity can be verified.
/// Method-neutral: could be a raw public key, a DID URL, a WebAuthn
/// credential id — the core does not care.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethod {
    pub id: String,
    pub method_type: String,
    pub public_key_multibase: String,
}

/// Recovery policy: k-of-n recovery keys can authorize a successor key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicy {
    pub threshold: usize,
    pub recovery_key_ids: Vec<KeyId>,
}

impl RecoveryPolicy {
    pub fn valid(&self) -> bool {
        self.threshold >= 1
            && self.threshold <= self.recovery_key_ids.len()
            && !self.recovery_key_ids.is_empty()
    }
}

/// A point-in-time record of one key's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub id: KeyId,
    pub purpose: KeyPurpose,
    pub state: KeyState,
    /// Monotonic sequence within this identity's history.
    pub seq: u64,
}

/// The identity. Method-neutral, offline-capable, no accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub identifier: String,
    pub subject: Subject,
    pub verification_methods: Vec<VerificationMethod>,
    pub keys: BTreeMap<KeyId, KeyRecord>,
    pub recovery_policy: RecoveryPolicy,
    /// Append-only history of lifecycle events.
    pub history: Vec<Event>,
}

impl Identity {
    pub fn active_keys(&self, purpose: KeyPurpose) -> Vec<&KeyRecord> {
        self.keys
            .values()
            .filter(|k| k.purpose == purpose && k.state.usable())
            .collect()
    }

    pub fn key_state(&self, id: &KeyId) -> Option<KeyState> {
        self.keys.get(id).map(|k| k.state)
    }
}

/// Lifecycle events. Append-only; history is the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    IdentityCreated { seq: u64 },
    KeyActivated { key: KeyId, purpose: KeyPurpose, seq: u64 },
    KeyLost { key: KeyId, seq: u64 },
    KeyFound { key: KeyId, seq: u64 },
    KeyRevoked { key: KeyId, reason: String, seq: u64 },
    KeyExpired { key: KeyId, seq: u64 },
    RecoveryCompleted {
        old_key: KeyId,
        new_key: KeyId,
        approvals: usize,
        seq: u64,
    },
}

/// A capability: a signed envelope authorizing an action.
/// Verification is separate from issuance (see verifier module).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub subject: Subject,
    pub scope: String,
    pub audience: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub key_id: KeyId,
}

/// The three epistemic states. These are DISTINCT TYPES.
/// They MUST NOT collapse into one boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed<T>(pub T);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Established<T> {
    pub value: T,
    /// Which key established it, and in what state.
    pub by_key: KeyId,
    pub key_state_at_check: KeyState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized<T> {
    pub value: T,
    pub capability: Capability,
}

/// A verification receipt: what was checked, by whom, with what result.
/// Receipts are derived, never caller-authored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub subject: Subject,
    pub key_id: KeyId,
    pub key_state: KeyState,
    pub checks: Vec<Check>,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    KeyKnown,
    KeyUsable,
    PurposeMatches,
    SubjectMatches,
    ScopeMatches,
    AudienceMatches,
    NonceFresh,
    NonceReplayed,
    NotExpired,
    SignatureValid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
}

/// Errors. Fail closed: unknown state is an error, never a default-allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnknownKey(KeyId),
    KeyNotUsable(KeyId, KeyState),
    IllegalTransition(KeyState, KeyState),
    WrongPurpose { expected: KeyPurpose, actual: KeyPurpose },
    RecoveryThresholdNotMet { have: usize, need: usize },
    RecoveryKeyNotUsable(KeyId),
    InvalidPolicy(String),
    DuplicateEvent(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}
