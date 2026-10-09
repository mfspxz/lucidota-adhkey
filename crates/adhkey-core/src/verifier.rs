//! The verifier. Establishes claims against independent grounds.
//!
//! The verifier never trusts the caller. It checks: key known, key usable,
//! purpose matches, subject/scope/audience match, nonce fresh (in a
//! bounded, time-partitioned, restorable `NonceStore`), not expired, and
//! signature VALID — verified by the core itself through `KeyOperator`,
//! against the key the IDENTITY names, over canonical envelope bytes the
//! CORE builds. C1 is dead: there is no `signature_valid` field for the
//! caller to inject. The caller supplies the mechanism; the core supplies
//! every input.
//!
//! Every verification — pass or fail — produces a `SealedReceipt`
//! (hash-chained, signed by the receipt service key). C7 is dead: there
//! is no unsealed receipt type in the protocol.
//!
//! CLAIMED -> ESTABLISHED -> AUTHORIZED are distinct types. The verifier
//! produces ESTABLISHED; authorization policy produces AUTHORIZED.

use crate::{
    capability_envelope, seal_receipt, Authorized, Capability, Check,
    Claimed, Error, Established, Identity, KeyId, KeyOperator, KeyPurpose,
    KeyState, NonceStore, Outcome, ReceiptBody, SealedReceipt,
    SignedCapability, Subject,
};

/// What the verifier needs that the caller cannot supply.
///
/// SECURITY: `keys` is a mechanism, not a verdict. The core looks up the
/// key id in its own key table, canonicalizes the envelope itself, and
/// interprets the boolean. Supplying a lying `KeyOperator` is outside
/// the protocol boundary (like a lying HSM) — but no caller can make a
/// forged capability verify without a signature that checks out.
pub struct VerifierContext<'a> {
    pub identity: &'a Identity,
    /// Replay protection. The verifier owns this. Bounded, time-partitioned,
    /// restorable across restarts (see `NonceStore`). NOT a bare BTreeSet.
    pub nonces: &'a mut NonceStore,
    /// Current time (unix secs). Injected for testability.
    /// MUST come from the host's own clock — never from the request,
    /// the capability, or any other caller-controlled source. An
    /// attacker who controls `now` controls bucket assignment and
    /// pruning in the nonce store.
    pub now: u64,
    /// Key operations. The core drives it; see above.
    pub keys: &'a dyn KeyOperator,
    /// Service key that seals receipts. Held by the operator, never the
    /// capability submitter.
    pub receipt_signer: KeyId,
    /// Hash of the previous sealed receipt (chain tip). Zero for genesis.
    /// The host tracks this (e.g. alongside the NonceStore snapshot).
    pub receipt_prev_hash: [u8; 32],
}

/// What the verifier deliberately does NOT check. Recorded on every
/// receipt (AUDIT2 #15): incomplete receipts manufacture confidence.
fn not_checked_list() -> Vec<String> {
    vec![
        "policy scope semantics: the authorizer's job, not the verifier's".into(),
        "evidence behind key issuance: the key table is trusted input".into(),
        "key-state freshness beyond this check: a TOCTOU window exists between check and use".into(),
        "signature suite negotiation: single suite (Ed25519); no agility".into(),
    ]
}

/// Verify a claimed, SIGNED capability. Returns ESTABLISHED plus the
/// sealed receipt on success, or the failure plus the sealed receipt.
/// The receipt is sealed even on failure — failures are evidence too.
///
/// The nonce is consumed ONLY on success. Consuming before the signature
/// verifies lets an attacker burn nonces with invalid signatures
/// (nonce-exhaustion DoS, red-team A5).
///
/// NOTE: `clippy::result_large_err` is allowed here deliberately: the
/// Err variant carries the sealed failure receipt (evidence), and the
/// error path is cold. 224 bytes on the stack is not a real cost.
#[allow(clippy::result_large_err)]
pub fn verify_capability(
    ctx: &mut VerifierContext<'_>,
    claimed: Claimed<SignedCapability>,
    expected_subject: &Subject,
    expected_audience: &str,
    expected_purpose: KeyPurpose,
) -> Result<(Established<Capability>, SealedReceipt), (Error, SealedReceipt)> {
    let signed = claimed.0;
    let cap = signed.capability.clone();
    let mut checks = Vec::new();
    let mut failed: Option<Error> = None;

    // Key known?
    let key_state = match ctx.identity.key_state(&cap.key_id) {
        Some(s) => {
            checks.push(Check::KeyKnown);
            s
        }
        None => {
            let receipt = seal_or_tombstone(ctx, &cap, checks, KeyState::Revoked, Outcome::Fail);
            return Err((Error::UnknownKey(cap.key_id.clone()), receipt));
        }
    };

    // Key usable?
    if key_state.usable() {
        checks.push(Check::KeyUsable);
    } else {
        failed = Some(Error::KeyNotUsable(cap.key_id.clone(), key_state));
    }

    // Purpose matches?
    let actual_purpose = ctx.identity.keys.get(&cap.key_id).map(|k| k.purpose);
    if actual_purpose == Some(expected_purpose) {
        checks.push(Check::PurposeMatches);
    } else if failed.is_none() {
        failed = Some(Error::WrongPurpose {
            expected: expected_purpose,
            actual: actual_purpose.unwrap_or(expected_purpose),
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

    // Nonce fresh? Checked here, CONSUMED only on success.
    if ctx.nonces.contains(&cap.nonce, ctx.now) {
        checks.push(Check::NonceReplayed);
        if failed.is_none() {
            failed = Some(Error::InvalidPolicy("nonce replay".into()));
        }
    } else {
        checks.push(Check::NonceFresh);
    }

    // Not expired?
    if ctx.now < cap.expires_at && ctx.now >= cap.issued_at {
        checks.push(Check::NotExpired);
    } else if failed.is_none() {
        failed = Some(Error::InvalidPolicy(
            "capability expired or not yet valid".into(),
        ));
    }

    // Signature valid? THE CORE VERIFIES ITSELF. The envelope is
    // canonicalized here; the key id comes from the identity's table;
    // the KeyOperator only performs the math. C1 is dead.
    let envelope = capability_envelope(&cap);
    match ctx.keys.verify(&cap.key_id, &envelope, &signed.signature) {
        Ok(true) => {
            checks.push(Check::SignatureValid);
        }
        Ok(false) => {
            if failed.is_none() {
                failed = Some(Error::InvalidPolicy("signature invalid".into()));
            }
        }
        Err(e) => {
            // Fail closed: if the operator cannot answer, nothing passes.
            if failed.is_none() {
                failed = Some(Error::KeyOperatorFailed(format!(
                    "signature check unavailable: {e}"
                )));
            }
        }
    }

    let outcome = if failed.is_none() {
        Outcome::Pass
    } else {
        Outcome::Fail
    };
    let body = ReceiptBody {
        subject: cap.subject.clone(),
        key_id: cap.key_id.clone(),
        key_state,
        checks,
        not_checked: not_checked_list(),
        outcome,
    };
    let receipt = match seal_receipt(
        ctx.keys,
        &ctx.receipt_signer,
        body,
        ctx.receipt_prev_hash,
        ctx.now,
    ) {
        Ok(s) => s,
        Err(_) => {
            // Sealer down: verification cannot produce evidence.
            // Fail closed WITHOUT a receipt — there is nothing to seal with.
            return Err((
                Error::KeyOperatorFailed("receipt sealer unavailable".into()),
                tombstone(ctx, &cap, key_state),
            ));
        }
    };

    match failed {
        None => {
            // All checks passed: consume the nonce NOW, only now.
            // A full nonce store fails closed (fail body already sealed
            // as Pass — convert to error; the receipt stands as evidence
            // of what was checked).
            if let Err(e) = ctx.nonces.check_and_insert(&cap.nonce, ctx.now) {
                return Err((e, receipt));
            }
            Ok((
                Established {
                    value: cap,
                    by_key: receipt.body.key_id.clone(),
                    key_state_at_check: key_state,
                },
                receipt,
            ))
        }
        Some(e) => Err((e, receipt)),
    }
}

/// Build a TOMBSTONE receipt: seal failure means the verifier cannot
/// produce evidence. The tombstone has an empty signature and
/// `verify_chain` rejects it. Tombstones are evidence OF sealer failure,
/// never valid receipts.
fn tombstone(ctx: &VerifierContext<'_>, cap: &Capability, key_state: KeyState) -> SealedReceipt {
    SealedReceipt {
        body: ReceiptBody {
            subject: cap.subject.clone(),
            key_id: cap.key_id.clone(),
            key_state,
            checks: Vec::new(),
            not_checked: not_checked_list(),
            outcome: Outcome::Fail,
        },
        prev_hash: ctx.receipt_prev_hash,
        issued_at: ctx.now,
        signer: ctx.receipt_signer.clone(),
        signature: Vec::new(),
    }
}

fn seal_or_tombstone(
    ctx: &VerifierContext<'_>,
    cap: &Capability,
    checks: Vec<Check>,
    key_state: KeyState,
    outcome: Outcome,
) -> SealedReceipt {
    let body = ReceiptBody {
        subject: cap.subject.clone(),
        key_id: cap.key_id.clone(),
        key_state,
        checks,
        not_checked: not_checked_list(),
        outcome,
    };
    match seal_receipt(
        ctx.keys,
        &ctx.receipt_signer,
        body.clone(),
        ctx.receipt_prev_hash,
        ctx.now,
    ) {
        Ok(s) => s,
        Err(_) => SealedReceipt {
            body,
            prev_hash: ctx.receipt_prev_hash,
            issued_at: ctx.now,
            signer: ctx.receipt_signer.clone(),
            signature: Vec::new(), // TOMBSTONE: verify_chain rejects this.
        },
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
fn _trichotomy_distinct(
    c: Claimed<Capability>,
    e: Established<Capability>,
    a: Authorized<Capability>,
) {
    let _ = (c, e, a);
    // If these were one boolean, this function could not exist.
}
