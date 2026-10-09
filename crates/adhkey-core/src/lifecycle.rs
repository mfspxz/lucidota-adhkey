//! Key lifecycle state machine. All transitions explicit, all recorded.
//!
//! C2: recovery approvals are SIGNATURES over a `RecoveryIntent` bound to
//! (identity, old_key, new_key, nonce) — not bare key ids. Each approval
//! is verified here, against the signer's key, over canonical bytes built
//! here. Approval nonces are consumed in a `NonceStore`: one approval,
//! one ceremony, no replays.
//!
//! C6: Lost -> Active ("found again") requires fresh proof of possession
//! via `refound_key`. `transition_key` REJECTS Lost -> Active outright —
//! the table still lists it as reachable, but only through the proof.

use crate::{
    possession_bytes, recovery_intent_bytes, Error, Event, Identity, KeyId,
    KeyOperator, KeyPurpose, KeyRecord, KeyState, NonceStore,
    SignedApproval, SignedPossessionProof,
};
use std::collections::BTreeSet;

fn next_seq(id: &Identity) -> u64 {
    id.history.len() as u64 + 1
}

fn record(id: &mut Identity, event: Event) {
    id.history.push(event);
}

/// Activate a new key on the identity.
pub fn activate_key(
    id: &mut Identity,
    key: KeyId,
    purpose: KeyPurpose,
) -> Result<(), Error> {
    if id.keys.contains_key(&key) {
        return Err(Error::IllegalTransition(KeyState::Active, KeyState::Active));
    }
    let seq = next_seq(id);
    id.keys.insert(
        key.clone(),
        KeyRecord {
            id: key.clone(),
            purpose,
            state: KeyState::Active,
            seq,
        },
    );
    record(id, Event::KeyActivated { key, purpose, seq });
    Ok(())
}

/// Transition a key's state, enforcing the legal transition table.
///
/// C6: Lost -> Active is REJECTED here — unconditionally. A "found" key
/// may be cloned or extracted; re-activation requires fresh proof of
/// possession. Use `refound_key`.
pub fn transition_key(
    id: &mut Identity,
    key: &KeyId,
    next: KeyState,
    reason: &str,
) -> Result<(), Error> {
    let rec = id.keys.get_mut(key).ok_or(Error::UnknownKey(key.clone()))?;
    let cur = rec.state;
    if cur == KeyState::Lost && next == KeyState::Active {
        return Err(Error::ProofOfPossessionRequired(key.clone()));
    }
    if !cur.can_transition_to(next) {
        return Err(Error::IllegalTransition(cur, next));
    }
    rec.state = next;
    let seq = next_seq(id);
    let event = match next {
        KeyState::Lost => Event::KeyLost {
            key: key.clone(),
            seq,
        },
        KeyState::Active => Event::KeyFound {
            key: key.clone(),
            seq,
        },
        KeyState::Revoked => Event::KeyRevoked {
            key: key.clone(),
            reason: reason.to_string(),
            seq,
        },
        KeyState::Expired => Event::KeyExpired {
            key: key.clone(),
            seq,
        },
    };
    record(id, event);
    Ok(())
}

/// Re-activate a lost key ("found again") — ONLY with fresh proof of
/// possession: a signature by the key over (key, challenge, issued_at),
/// where the challenge is fresh (`max_challenge_age_secs`).
///
/// Why: a found device may have been cloned while lost. Possession THEN
/// proves nothing about possession NOW. The signature proves the
/// requester holds the private key at challenge time.
pub fn refound_key(
    id: &mut Identity,
    key: &KeyId,
    proof: &SignedPossessionProof,
    keys: &dyn KeyOperator,
    now: u64,
    max_challenge_age_secs: u64,
) -> Result<(), Error> {
    let rec = id.keys.get(key).ok_or(Error::UnknownKey(key.clone()))?;
    if rec.state != KeyState::Lost {
        return Err(Error::IllegalTransition(rec.state, KeyState::Active));
    }
    if proof.key != *key {
        return Err(Error::BadPossessionProof("proof is for a different key".into()));
    }
    if proof.issued_at > now {
        return Err(Error::BadPossessionProof(
            "proof issued in the future".into(),
        ));
    }
    if now - proof.issued_at > max_challenge_age_secs {
        return Err(Error::BadPossessionProof("challenge stale: re-issue".into()));
    }
    let msg = possession_bytes(&proof.key, &proof.challenge, proof.issued_at);
    let ok = keys
        .verify(key, &msg, &proof.signature)
        .map_err(|e| Error::KeyOperatorFailed(format!("possession check failed: {e}")))?;
    if !ok {
        return Err(Error::BadPossessionProof("signature invalid".into()));
    }
    // Proof holds. Transition.
    let rec = id.keys.get_mut(key).ok_or(Error::UnknownKey(key.clone()))?;
    rec.state = KeyState::Active;
    let seq = next_seq(id);
    record(
        id,
        Event::KeyFound {
            key: key.clone(),
            seq,
        },
    );
    Ok(())
}

/// Recovery: k-of-n recovery keys approve a successor. The old key is
/// revoked, the new key activated, the identity persists.
///
/// C2: `approvals` are SIGNED intents, not key ids. Each approval is
/// verified here:
///  1. signature checks out under the signer's key, over the canonical
///     intent bytes (built here, not by the caller);
///  2. the intent is bound to THIS ceremony: identity, old_key, new_key
///     must match; the nonce must be fresh (consumed here — one
///     approval, one ceremony; a failed-then-retried recovery needs a
///     fresh ceremony with fresh nonces);
///  3. the signer is policy-listed, distinct, and a usable recovery key.
///
/// A compromised caller with the ID list but without the private keys
/// can approve nothing.
#[allow(clippy::too_many_arguments)]
pub fn recover(
    id: &mut Identity,
    old_key: &KeyId,
    new_key: KeyId,
    new_purpose: KeyPurpose,
    approvals: &[SignedApproval],
    keys: &dyn KeyOperator,
    approval_nonces: &mut NonceStore,
    now: u64,
) -> Result<(), Error> {
    if !id.recovery_policy.valid() {
        return Err(Error::InvalidPolicy("threshold/policy invalid".into()));
    }
    // Old key must exist (it may be Lost — that is the normal case).
    let old = id.keys.get(old_key).ok_or(Error::UnknownKey(old_key.clone()))?;
    if old.state == KeyState::Revoked {
        return Err(Error::IllegalTransition(old.state, KeyState::Revoked));
    }
    // Validate the ENTIRE transition before mutating anything (red-team A10):
    // a no-op or duplicate recovery must not record history or revoke.
    if new_key == *old_key {
        return Err(Error::InvalidPolicy(
            "recovery new_key must differ from old_key".into(),
        ));
    }
    if id.keys.contains_key(&new_key) {
        return Err(Error::InvalidPolicy("recovery new_key already exists".into()));
    }
    // Purpose must not change across recovery (red-team A3): replacing an
    // authentication key with a recovery key is privilege escalation.
    if new_purpose != old.purpose {
        return Err(Error::InvalidPolicy(
            "recovery must preserve key purpose".into(),
        ));
    }
    // Verify every approval. All-or-nothing: any bad approval aborts
    // BEFORE any nonce is consumed or state mutated.
    let mut verified_signers: Vec<&SignedApproval> = Vec::new();
    for a in approvals {
        // 2a. Ceremony binding: this approval must be FOR this recovery.
        if a.intent.identity != id.identifier {
            return Err(Error::BadApproval("approval for a different identity".into()));
        }
        if a.intent.old_key != *old_key || a.intent.new_key != new_key {
            return Err(Error::BadApproval(
                "approval binds a different (old_key, new_key)".into(),
            ));
        }
        // 1. Signature over canonical intent bytes.
        let msg = recovery_intent_bytes(&a.intent);
        let ok = keys
            .verify(&a.signer, &msg, &a.signature)
            .map_err(|e| Error::KeyOperatorFailed(format!("approval check failed: {e}")))?;
        if !ok {
            return Err(Error::BadApproval(format!(
                "bad signature from {}",
                a.signer
            )));
        }
        // 3. Signer authorized: policy-listed, usable, recovery-purpose.
        if !id.recovery_policy.recovery_key_ids.contains(&a.signer) {
            return Err(Error::BadApproval(format!(
                "{} not in recovery policy",
                a.signer
            )));
        }
        let rec = id
            .keys
            .get(&a.signer)
            .ok_or(Error::UnknownKey(a.signer.clone()))?;
        if rec.purpose != KeyPurpose::Recovery || !rec.state.usable() {
            return Err(Error::RecoveryKeyNotUsable(a.signer.clone()));
        }
        verified_signers.push(a);
    }
    // Distinct signers; threshold.
    let mut counted = BTreeSet::new();
    for a in &verified_signers {
        counted.insert(&a.signer);
    }
    if counted.len() < id.recovery_policy.threshold {
        return Err(Error::RecoveryThresholdNotMet {
            have: counted.len(),
            need: id.recovery_policy.threshold,
        });
    }
    // 2b. Consume approval nonces — AFTER all approvals verify, so a
    // failed recovery doesn't burn honest approvals... no: it DOES burn
    // them, deliberately. An approval is single-use; a retried recovery
    // is a new ceremony with fresh nonces. What we guarantee: no state
    // mutates unless every approval verified.
    for a in &verified_signers {
        let fresh = approval_nonces
            .check_and_insert(&a.intent.nonce, now)
            .map_err(|e| Error::BadApproval(format!("approval nonce store: {e}")))?;
        if !fresh {
            return Err(Error::BadApproval(format!(
                "approval nonce replayed: {}",
                a.intent.nonce
            )));
        }
    }
    // Revoke the old key (from whatever state it was in).
    let seq = next_seq(id);
    if let Some(rec) = id.keys.get_mut(old_key) {
        rec.state = KeyState::Revoked;
    }
    record(
        id,
        Event::RecoveryCompleted {
            old_key: old_key.clone(),
            new_key: new_key.clone(),
            approvals: counted.len(),
            seq,
        },
    );
    activate_key(id, new_key, new_purpose)?;
    Ok(())
}
