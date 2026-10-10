//! Versioned recovery policy. Parsing is fail-closed: unknown versions,
//! missing fields, or out-of-range values are errors, never defaults.

use crate::Error;
use serde::{Deserialize, Serialize};

/// Current policy version.
pub const POLICY_VERSION: u32 = 1;

/// Recovery policy. All thresholds explicit; no silent defaults.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Policy {
    pub version: u32,
    /// Independent guardian approvals required (human authorization).
    pub guardian_approval_threshold: usize,
    /// Cryptographic share threshold (must match `THRESHOLD`).
    pub share_threshold: u8,
    /// Total shares in the set (must match `SHARE_COUNT`).
    pub share_count: usize,
    /// Challenges the owner must answer.
    pub challenge_count: usize,
    /// Max evidence submissions per session before lockout timer.
    pub max_evidence_attempts: u32,
    /// Session lifetime in seconds.
    pub session_ttl_secs: u64,
}

impl Policy {
    /// The v1 policy: 3-of-5 shares, 2 independent guardian approvals.
    pub fn v1() -> Self {
        Policy {
            version: POLICY_VERSION,
            guardian_approval_threshold: 2,
            share_threshold: crate::THRESHOLD,
            share_count: crate::SHARE_COUNT,
            challenge_count: 5,
            max_evidence_attempts: 10,
            session_ttl_secs: 24 * 3600,
        }
    }

    /// Parse a policy document. Fail-closed on any problem.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let p: Policy =
            serde_json::from_slice(bytes).map_err(|e| Error::Serialization(e.to_string()))?;
        p.validate()
    }

    fn validate(self) -> Result<Self, Error> {
        if self.version != POLICY_VERSION {
            return Err(Error::BindingMismatch("unknown policy version"));
        }
        if self.share_threshold != crate::THRESHOLD || self.share_count != crate::SHARE_COUNT {
            return Err(Error::BindingMismatch("policy/share-threshold mismatch"));
        }
        if self.guardian_approval_threshold == 0 || self.guardian_approval_threshold > self.share_count
        {
            return Err(Error::BindingMismatch("invalid guardian threshold"));
        }
        if self.challenge_count == 0 || self.max_evidence_attempts == 0 || self.session_ttl_secs == 0
        {
            return Err(Error::BindingMismatch("policy value out of range"));
        }
        Ok(self)
    }
}
