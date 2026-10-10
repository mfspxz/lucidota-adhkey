//! Guardian approvals: Ed25519-signed, session-bound, replay-resistant.
//!
//! Signature verification happens here, at the trust boundary. The governor
//! only ever sees `VerifiedApproval`, which cannot be constructed without
//! passing verification (or via the test-only constructor).

use crate::Error;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A guardian's enrolled authentication record (P3 enrollment owns the lifecycle).
#[derive(Clone, Serialize, Deserialize)]
pub struct GuardianRecord {
    pub guardian_id: [u8; 16],
    pub verifying_key: [u8; 32],
}

/// A raw approval submitted by a guardian. Untrusted until verified.
#[derive(Clone, Serialize, Deserialize)]
pub struct GuardianApproval {
    pub guardian_id: [u8; 16],
    pub session_id: [u8; 16],
    pub decision: Decision,
    /// Domain-separated statement the guardian signed.
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Decision {
    Approve,
    Deny,
}

/// An approval that passed signature verification and session binding.
/// The constructor is crate-private; tests use `test_only`.
#[derive(Clone)]
pub struct VerifiedApproval {
    pub guardian_id: [u8; 16],
    pub session_id: [u8; 16],
    pub decision: Decision,
}

/// The exact bytes the guardian signs. Domain separation binds session,
/// nonce, epoch, expiry, and policy version (RFC §3.3).
pub fn approval_statement(
    session_id: &[u8; 16],
    nonce: &[u8; 16],
    epoch: u64,
    expires_at: u64,
    policy_version: u32,
    decision: Decision,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(16 + 16 + 8 + 8 + 4 + 1 + 16);
    s.extend_from_slice(b"flailer-approval-v1");
    s.extend_from_slice(session_id);
    s.extend_from_slice(nonce);
    s.extend_from_slice(&epoch.to_be_bytes());
    s.extend_from_slice(&expires_at.to_be_bytes());
    s.extend_from_slice(&policy_version.to_be_bytes());
    s.push(match decision {
        Decision::Approve => 1,
        Decision::Deny => 0,
    });
    s
}

/// Verify an approval against the enrolled guardian record and the expected
/// session context. Checks: guardian enrolled, signature valid, session bound,
/// statement to the session the guardian was shown. Expiry and policy-version
/// enforcement belong to the governor.
pub fn verify_approval(
    approval: &GuardianApproval,
    guardian: &GuardianRecord,
    expected_session_id: &[u8; 16],
) -> Result<VerifiedApproval, Error> {
    if approval.guardian_id != guardian.guardian_id {
        return Err(Error::BindingMismatch("guardian id mismatch"));
    }
    if &approval.session_id != expected_session_id {
        return Err(Error::BindingMismatch("approval for wrong session"));
    }
    let vk = VerifyingKey::from_bytes(&guardian.verifying_key)
        .map_err(|_| Error::InvalidShare("bad guardian pubkey"))?;
    let sig_bytes: [u8; 64] = approval.signature.as_slice().try_into()
        .map_err(|_| Error::InvalidShare("bad signature length"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&approval.statement, &sig)
        .map_err(|_| Error::InvalidShare("bad approval signature"))?;
    Ok(VerifiedApproval {
        guardian_id: approval.guardian_id,
        session_id: approval.session_id,
        decision: approval.decision,
    })
}

/// Evaluate a set of verified approvals against policy. Returns true iff at
/// least `policy.guardian_approval_threshold` DISTINCT guardians approved.
/// Replays add nothing; denials don't subtract (a denial is evidence, and a
/// separate human-review path handles contested sessions).
pub fn approvals_satisfy(
    approvals: &[VerifiedApproval],
    session_id: &[u8; 16],
    policy: &crate::Policy,
) -> bool {
    let mut approvers: HashSet<[u8; 16]> = HashSet::new();
    for a in approvals {
        if &a.session_id != session_id {
            continue;
        }
        if a.decision == Decision::Approve {
            approvers.insert(a.guardian_id);
        }
    }
    approvers.len() >= policy.guardian_approval_threshold
}

/// Signed record that a guardian was enrolled for a set/epoch. The authority
/// key (owner's offline key) attests: this guardian, this share index, this
/// pubkey, this epoch. P3 enrollment ceremony produces these; the drill
/// requirement (RFC §3.1) is enforced by the CLI, not the type.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollmentReceipt {
    pub guardian_id: [u8; 16],
    pub share_index: u8,
    pub set_id: [u8; 16],
    pub epoch: u64,
    pub pubkey_fingerprint: [u8; 32],
    pub enrolled_at: u64,
    pub authority_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

fn enrollment_message(
    guardian_id: &[u8; 16],
    share_index: u8,
    set_id: &[u8; 16],
    epoch: u64,
    pubkey_fingerprint: &[u8; 32],
    enrolled_at: u64,
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"flailer-enrollment-v1");
    m.extend_from_slice(guardian_id);
    m.push(share_index);
    m.extend_from_slice(set_id);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(pubkey_fingerprint);
    m.extend_from_slice(&enrolled_at.to_be_bytes());
    m
}

/// Enroll a guardian: bind their identity, share index, and pubkey for an epoch.
pub fn enroll_guardian(
    guardian_id: [u8; 16],
    share_index: u8,
    verifying_key: &[u8; 32],
    set_id: [u8; 16],
    epoch: u64,
    authority_key: &SigningKey,
    now: u64,
) -> Result<EnrollmentReceipt, Error> {
    if (share_index as usize) >= crate::SHARE_COUNT {
        return Err(Error::BindingMismatch("share index out of range"));
    }
    use sha2::{Digest, Sha256};
    let fingerprint: [u8; 32] = Sha256::digest(verifying_key).into();
    let msg = enrollment_message(&guardian_id, share_index, &set_id, epoch, &fingerprint, now);
    let signature = authority_key.sign(&msg);
    Ok(EnrollmentReceipt {
        guardian_id,
        share_index,
        set_id,
        epoch,
        pubkey_fingerprint: fingerprint,
        enrolled_at: now,
        authority_pubkey: authority_key.verifying_key().to_bytes(),
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verify an enrollment receipt against the guardian's claimed pubkey.
pub fn verify_enrollment_receipt(
    receipt: &EnrollmentReceipt,
    verifying_key: &[u8; 32],
) -> Result<(), Error> {
    use sha2::{Digest, Sha256};
    let fingerprint: [u8; 32] = Sha256::digest(verifying_key).into();
    if fingerprint != receipt.pubkey_fingerprint {
        return Err(Error::BindingMismatch("enrollment pubkey mismatch"));
    }
    let vk = VerifyingKey::from_bytes(&receipt.authority_pubkey)
        .map_err(|_| Error::InvalidShare("bad authority pubkey"))?;
    let msg = enrollment_message(
        &receipt.guardian_id,
        receipt.share_index,
        &receipt.set_id,
        receipt.epoch,
        &receipt.pubkey_fingerprint,
        receipt.enrolled_at,
    );
    let sig_bytes: [u8; 64] = receipt
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidShare("bad signature length"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&msg, &sig).map_err(|_| Error::InvalidShare("bad enrollment signature"))?;
    Ok(())
}

/// Helper for tests and the (future) guardian client: sign an approval.
pub fn sign_approval(
    signing_key: &SigningKey,
    guardian_id: [u8; 16],
    session_id: [u8; 16],
    nonce: &[u8; 16],
    epoch: u64,
    expires_at: u64,
    policy_version: u32,
    decision: Decision,
) -> GuardianApproval {
    let statement = approval_statement(&session_id, &nonce, epoch, expires_at, policy_version, decision);
    let signature = signing_key.sign(&statement);
    GuardianApproval {
        guardian_id,
        session_id,
        decision,
        statement,
        signature: signature.to_bytes().to_vec(),
    }
}
