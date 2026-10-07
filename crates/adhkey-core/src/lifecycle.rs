//! Key lifecycle state machine. All transitions explicit, all recorded.

use crate::{Error, Event, Identity, KeyId, KeyPurpose, KeyRecord, KeyState};

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
    record(
        id,
        Event::KeyActivated {
            key,
            purpose,
            seq,
        },
    );
    Ok(())
}

/// Transition a key's state, enforcing the legal transition table.
pub fn transition_key(
    id: &mut Identity,
    key: &KeyId,
    next: KeyState,
    reason: &str,
) -> Result<(), Error> {
    let rec = id.keys.get_mut(key).ok_or(Error::UnknownKey(key.clone()))?;
    let cur = rec.state;
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

/// Recovery: k-of-n recovery keys approve a successor. The old key is
/// revoked, the new key activated, the identity persists.
///
/// `approvals` are key ids that signed the recovery statement. Each must
/// be a known, usable recovery-purpose key in the recovery policy.
pub fn recover(
    id: &mut Identity,
    old_key: &KeyId,
    new_key: KeyId,
    new_purpose: KeyPurpose,
    approvals: &[KeyId],
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
        return Err(Error::InvalidPolicy(
            "recovery new_key already exists".into(),
        ));
    }
    // Purpose must not change across recovery (red-team A3): replacing an
    // authentication key with a recovery key is privilege escalation.
    if new_purpose != old.purpose {
        return Err(Error::InvalidPolicy(
            "recovery must preserve key purpose".into(),
        ));
    }
    // Count distinct, usable, policy-listed recovery approvals.
    let mut counted = std::collections::BTreeSet::new();
    for a in approvals {
        if !id.recovery_policy.recovery_key_ids.contains(a) {
            continue;
        }
        let rec = id.keys.get(a).ok_or(Error::UnknownKey(a.clone()))?;
        if rec.purpose != KeyPurpose::Recovery || !rec.state.usable() {
            return Err(Error::RecoveryKeyNotUsable(a.clone()));
        }
        counted.insert(a);
    }
    if counted.len() < id.recovery_policy.threshold {
        return Err(Error::RecoveryThresholdNotMet {
            have: counted.len(),
            need: id.recovery_policy.threshold,
        });
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
