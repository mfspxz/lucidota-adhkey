//! The verifier. Establishes claims against independent grounds.
//!
//! The verifier never trusts the caller. It checks: key known, key usable,
//! purpose matches, subject/scope/audience match, nonce fresh, not expired,
//! signature valid (via the store). Every check is recorded in the receipt.
//!
//! CLAIMED -> ESTABLISHED -> AUTHORIZED are distinct types. The verifier
//! produces ESTABLISHED; authorization policy produces AUTHORIZED.

use crate::{
    Authorized, Capability, Check, Claimed, Error, Established, Identity,
    KeyPurpose, KeyState, Outcome, Receipt, Subject,
};
use std::collections::BTreeSet;

/// What the verifier needs that the caller cannot supply.
pub struct VerifierContext<'a> {
    pub identity: &'a Identity,
    /// Nonces already seen (replay protection). The verifier owns this.
    pub seen_nonces: &'a mut BTreeSet<String>,
    /// Current time (unix secs). Injected for testability.
    pub now: u64,
    /// Signature check: delegated to the store, result reported back.
    /// `true` = the store confirms this key signed this message.
    pub signature_valid: bool,
    /// The message that was signed (capability envelope bytes).
    pub _signed_message: &'a [u8],
}

/// Verify a claimed capability. Returns ESTABLISHED on success, or the
/// first failing check with a complete receipt.
/// checked so far.
pub fn verify_capability(
    ctx: &mut VerifierContext<'_>,
    claimed: Claimed<Capability>,
    expected_subject: &Subject,
    expected_audience: &str,
    expected_purpose: KeyPurpose,
) -> Result<Established<Capability>, (Error, Receipt)> {
    let cap = claimed.0.clone();
    let mut checks = Vec::new();
    let mut failed: Option<Error> = None;

    // Key known?
    let key_state = match ctx.identity.key_state(&cap.key_id) {
        Some(s) => {
            checks.push(Check::KeyKnown);
            s
        }
        None => {
            return Err((
                Error::UnknownKey(cap.key_id.clone()),
                fail_receipt(ctx, &cap, checks, KeyState::Revoked),
            ))
        }
    };

    // Key usable?
    if key_state.usable() {
        checks.push(Check::KeyUsable);
    } else {
        failed = Some(Error::KeyNotUsable(cap.key_id.clone(), key_state));
    }

    // Purpose matches?
    let purpose_ok = ctx
        .identity
        .keys
        .get(&cap.key_id)
        .map(|k| k.purpose == expected_purpose)
        .unwrap_or(false);
    if purpose_ok {
        checks.push(Check::PurposeMatches);
    } else if failed.is_none() {
        failed = Some(Error::WrongPurpose {
            expected: expected_purpose,
            actual: ctx
                .identity
                .keys
                .get(&cap.key_id)
                .map(|k| k.purpose)
                .unwrap_or(expected_purpose),
        });
    }

    // Subject matches?
    if &cap.subject == expected_subject {
        checks.push(Check::SubjectMatches);
    } else if failed.is_none() {
        failed = Some(Error::InvalidPolicy("subject mismatch".into()));
    }

    // Scope non-empty? (scope policy itself is the authorizer's job;
    // the verifier only checks structural presence here)
    if !cap.scope.is_empty() {
        checks.push(Check::ScopeMatches);
    } else if failed.is_none() {
        failed = Some(Error::InvalidPolicy("empty scope".into()));
    }

    // Audience matches?
    if cap.audience == expected_audience {
        checks.push(Check::AudienceMatches);
    } else if failed.is_none() {
        failed = Some(Error::InvalidPolicy("audience mismatch".into()));
    }

    // Nonce: checked for replay here, CONSUMED only on success.
    // Consuming before the signature verifies lets an attacker burn nonces
    // with invalid signatures (nonce-exhaustion DoS, red-team A5).
    if !ctx.seen_nonces.contains(&cap.nonce) {
        checks.push(Check::NonceFresh);
    } else if failed.is_none() {
        checks.push(Check::NonceReplayed);
        failed = Some(Error::InvalidPolicy("nonce replay".into()));
    }

    // Not expired?
    if ctx.now < cap.expires_at && ctx.now >= cap.issued_at {
        checks.push(Check::NotExpired);
    } else if failed.is_none() {
        failed = Some(Error::InvalidPolicy("capability expired or not yet valid".into()));
    }

    // Signature valid? (reported by the store, not the caller)
    if ctx.signature_valid {
        checks.push(Check::SignatureValid);
    } else if failed.is_none() {
        failed = Some(Error::InvalidPolicy("signature invalid".into()));
    }

    let receipt = Receipt {
        subject: cap.subject.clone(),
        key_id: cap.key_id.clone(),
        key_state,
        checks,
        outcome: if failed.is_none() {
            Outcome::Pass
        } else {
            Outcome::Fail
        },
    };

    match failed {
        None => {
            // All checks passed: consume the nonce NOW, only now.
            ctx.seen_nonces.insert(cap.nonce.clone());
            Ok(Established {
                value: cap,
                by_key: receipt.key_id.clone(),
                key_state_at_check: key_state,
            })
        }
        Some(e) => Err((e, receipt)),
    }
}

fn fail_receipt(
    ctx: &VerifierContext<'_>,
    cap: &Capability,
    checks: Vec<Check>,
    key_state: KeyState,
) -> Receipt {
    let _ = ctx;
    Receipt {
        subject: cap.subject.clone(),
        key_id: cap.key_id.clone(),
        key_state,
        checks,
        outcome: Outcome::Fail,
    }
}

/// Authorize an established capability against a policy.
/// This is the relying-party judgment — separate from verification.
pub fn authorize<F>(
    established: Established<Capability>,
    policy: F,
) -> Result<Authorized<Capability>, Error>
where
    F: Fn(&Capability) -> bool,
{
    if policy(&established.value) {
        Ok(Authorized {
            value: established.value.clone(),
            capability: established.value,
        })
    } else {
        Err(Error::InvalidPolicy("policy denied".into()))
    }
}

/// For tests: type-level proof that the three states are distinct.
#[allow(dead_code)]
fn _trichotomy_distinct(c: Claimed<Capability>, e: Established<Capability>, a: Authorized<Capability>) {
    let _ = (c, e, a);
    // If these were one boolean, this function could not exist.
}
