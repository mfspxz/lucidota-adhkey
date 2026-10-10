//! Recovery governor: typed states, validated transitions, session binding.
//!
//! Every transition is authenticated (session binding), authorized (policy),
//! and recorded (receipt chain). Unknown states, stale epochs, expired
//! sessions, and replayed operations all fail closed.

use crate::{random_bytes, Error};
use serde::{Deserialize, Serialize};

/// Recovery session states (RFC §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Requested,
    EvidenceCollection,
    AuthorizationPending,
    SharesVerified,
    Reconstructed,
    ReenrollmentPending,
    Committed,
    Deferred,
    Denied,
    Aborted,
}

/// Allowed transition edges. Anything not listed here is forbidden.
fn allowed(from: State, to: State) -> bool {
    use State::*;
    matches!(
        (from, to),
        (Requested, EvidenceCollection)
            | (EvidenceCollection, AuthorizationPending)
            | (EvidenceCollection, Deferred)
            | (Deferred, EvidenceCollection)
            | (AuthorizationPending, SharesVerified)
            | (AuthorizationPending, Deferred)
            | (AuthorizationPending, Denied)
            | (SharesVerified, Reconstructed)
            | (Reconstructed, ReenrollmentPending)
            | (Reconstructed, Aborted)
            | (ReenrollmentPending, Committed)
    )
}

/// Terminal states: no further transitions permitted.
fn terminal(s: State) -> bool {
    matches!(s, State::Committed | State::Denied | State::Aborted)
}

/// A recovery session. `tombstoned` marks sessions retired by a completed
/// recovery: evidence is retained, but no transition is ever permitted again.
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    pub session_id: [u8; 16],
    pub set_id: [u8; 16],
    pub epoch: u64,
    pub nonce: [u8; 16],
    pub state: State,
    pub policy_version: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub evidence_attempts: u32,
    pub tombstoned: bool,
    #[serde(default)]
    pub(crate) idempotency_log: Vec<([u8; 16], TransitionRecord)>,
}

impl RecoverySession {
    /// Open a new session. `now` is unix seconds; the crate takes no clock.
    pub fn open(
        set_id: [u8; 16],
        epoch: u64,
        policy: &crate::Policy,
        now: u64,
    ) -> Result<Self, Error> {
        Ok(RecoverySession {
            session_id: random_bytes()?,
            set_id,
            epoch,
            nonce: random_bytes()?,
            state: State::Requested,
            policy_version: policy.version,
            created_at: now,
            expires_at: now.saturating_add(policy.session_ttl_secs),
            evidence_attempts: 0,
            tombstoned: false,
            idempotency_log: Vec::new(),
        })
    }

    fn check_live(&self, policy: &crate::Policy, now: u64) -> Result<(), Error> {
        if self.tombstoned {
            return Err(Error::BindingMismatch("session tombstoned"));
        }
        if terminal(self.state) {
            return Err(Error::BindingMismatch("session is terminal"));
        }
        if self.policy_version != policy.version {
            return Err(Error::BindingMismatch("policy version mismatch"));
        }
        if now > self.expires_at {
            return Err(Error::BindingMismatch("session expired"));
        }
        Ok(())
    }

    /// Attempt a state transition. Idempotency keys make retries safe:
    /// repeating a key returns the recorded outcome instead of re-applying.
    /// `current_epoch` is the recovery set's live epoch: a session from a
    /// revoked epoch can never transition (T-S3).
    pub fn transition(
        &mut self,
        to: State,
        reason: &str,
        idempotency_key: [u8; 16],
        policy: &crate::Policy,
        now: u64,
        current_epoch: u64,
    ) -> Result<TransitionRecord, Error> {
        if reason.len() > 512 {
            return Err(Error::InvalidShare("reason too long"));
        }
        // True idempotency: a replayed key returns the originally recorded
        // outcome instead of re-applying the transition.
        if let Some((_, rec)) = self.idempotency_log.iter().find(|(k, _)| k == &idempotency_key)
        {
            return Ok(rec.clone());
        }
        self.check_live(policy, now)?;
        if self.epoch != current_epoch {
            return Err(Error::BindingMismatch("session epoch revoked"));
        }
        if !allowed(self.state, to) {
            return Err(Error::BindingMismatch("transition not allowed"));
        }
        let from = self.state;
        self.state = to;
        let rec = TransitionRecord {
            session_id: self.session_id,
            from,
            to,
            reason: reason.to_string(),
            policy_version: self.policy_version,
            at: now,
        };
        self.idempotency_log.push((idempotency_key, rec.clone()));
        Ok(rec)
    }

    /// Retire this session because a competing session completed recovery.
    /// Evidence is retained; the session can never transition again.
    pub fn tombstone(&mut self) {
        self.tombstoned = true;
    }

    /// Number of recorded idempotent transitions (observability for tests).
    pub fn idempotency_len(&self) -> usize {
        self.idempotency_log.len()
    }

    /// Record one evidence submission; enforces the attempt bound.
    pub fn record_evidence_attempt(&mut self, policy: &crate::Policy) -> Result<(), Error> {
        if self.evidence_attempts >= policy.max_evidence_attempts {
            return Err(Error::BindingMismatch("evidence attempt budget exhausted"));
        }
        self.evidence_attempts += 1;
        Ok(())
    }
}

/// One recorded state transition, chained into receipts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransitionRecord {
    pub session_id: [u8; 16],
    pub from: State,
    pub to: State,
    pub reason: String,
    pub policy_version: u32,
    pub at: u64,
}
