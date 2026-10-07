//! Bound envelopes: an authorization attempt, not a reusable certificate.
//!
//! V002/V003 killers. A valid signature is not a valid decision.
//! signature valid ≠ fresh ≠ valid-for-this-request ≠ authorized.
//!
//! Every envelope binds: who, for whom, what operation, which request,
//! which evidence, which policy version, which nonce, which validity
//! window, and which receipt came before it. A proof about Alice cannot
//! become proof about Bob merely because the bytes remain valid.

/// An authorization attempt. All binding fields are mandatory;
/// there is no "optional audience" or "implicit subject".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub envelope_id: String,
    pub subject_id: String,
    pub audience_id: String,
    pub operation_id: String,
    pub request_hash: String,
    pub evidence_hash: String,
    pub policy_hash: String,
    pub policy_version: u64,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Hash of the previous receipt in the chain. Genesis uses "genesis".
    pub previous_receipt_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    /// issued_at is in the future beyond skew, or expires_at <= issued_at.
    Malformed,
    /// now is outside [issued_at, expires_at).
    Expired,
    /// issued_at is in the future (beyond allowed skew): not yet valid.
    NotYetValid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    Bound,
    SubjectMismatch,
    AudienceMismatch,
    OperationMismatch,
    RequestMismatch,
    PolicyMismatch,
}

impl Envelope {
    /// Freshness against a caller-supplied `now` and allowed clock skew.
    /// No clock access here: time is an input, like everything else.
    pub fn freshness(&self, now: u64, max_skew_secs: u64) -> Freshness {
        if self.expires_at <= self.issued_at {
            return Freshness::Malformed;
        }
        if self.issued_at > now.saturating_add(max_skew_secs) {
            return Freshness::NotYetValid;
        }
        if now >= self.expires_at {
            return Freshness::Expired;
        }
        Freshness::Fresh
    }

    /// Every binding must match the attempted use. One mismatch fails all.
    pub fn check_binding(
        &self,
        subject_id: &str,
        audience_id: &str,
        operation_id: &str,
        request_hash: &str,
        policy_hash: &str,
    ) -> Binding {
        if self.subject_id != subject_id {
            return Binding::SubjectMismatch;
        }
        if self.audience_id != audience_id {
            return Binding::AudienceMismatch;
        }
        if self.operation_id != operation_id {
            return Binding::OperationMismatch;
        }
        if self.request_hash != request_hash {
            return Binding::RequestMismatch;
        }
        if self.policy_hash != policy_hash {
            return Binding::PolicyMismatch;
        }
        Binding::Bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Envelope {
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

    #[test]
    fn v002_stale_envelope_is_not_fresh() {
        let e = env();
        assert_eq!(e.freshness(1999, 60), Freshness::Fresh);
        assert_eq!(e.freshness(2000, 60), Freshness::Expired);
        assert_eq!(e.freshness(9999, 60), Freshness::Expired);
    }

    #[test]
    fn v002_future_issued_envelope_is_not_yet_valid() {
        let e = env();
        assert_eq!(e.freshness(500, 60), Freshness::NotYetValid);
        // Within skew tolerance it is usable.
        assert_eq!(e.freshness(950, 60), Freshness::Fresh);
    }

    #[test]
    fn v003_cross_subject_replay_fails_binding() {
        let e = env();
        // Alice's envelope presented for Bob.
        assert_eq!(
            e.check_binding("bob", "vault", "read", "rh", "ph"),
            Binding::SubjectMismatch
        );
        // Right subject, wrong operation.
        assert_eq!(
            e.check_binding("alice", "vault", "write", "rh", "ph"),
            Binding::OperationMismatch
        );
        // Exact use binds cleanly.
        assert_eq!(
            e.check_binding("alice", "vault", "read", "rh", "ph"),
            Binding::Bound
        );
    }
}
