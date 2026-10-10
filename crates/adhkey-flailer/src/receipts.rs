//! Tamper-evident, signed recovery receipts.
//!
//! Every transition is appended to a hash chain; the chain head is signed
//! with a dedicated receipt-signing key. Receipts contain digests and
//! metadata only — never secrets, answers, shares, or raw evidence.

use crate::governor::TransitionRecord;
use crate::Error;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One link in the receipt chain.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReceiptLink {
    pub prev_digest: [u8; 32],
    pub record: TransitionRecord,
    pub digest: [u8; 32],
}

/// A signed recovery receipt: the full chain plus a signature over the head.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub session_id: [u8; 16],
    pub policy_version: u32,
    pub outcome: ReceiptOutcome,
    pub links: Vec<ReceiptLink>,
    pub head_digest: [u8; 32],
    pub signer_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ReceiptOutcome {
    Committed,
    Denied,
    Aborted,
    Tombstoned,
}

fn link_digest(prev: &[u8; 32], rec: &TransitionRecord) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"flailer-receipt-v1");
    h.update(prev);
    h.update(rec.session_id);
    h.update([rec.from as u8]);
    h.update([rec.to as u8]);
    h.update(rec.policy_version.to_be_bytes());
    h.update(rec.at.to_be_bytes());
    let reason_hash = Sha256::digest(rec.reason.as_bytes());
    h.update(reason_hash);
    h.finalize().into()
}

/// Append a transition to the chain. The first link chains from zeros.
pub fn append_link(chain: &mut Vec<ReceiptLink>, rec: TransitionRecord) {
    let prev = chain.last().map(|l| l.digest).unwrap_or([0u8; 32]);
    let digest = link_digest(&prev, &rec);
    chain.push(ReceiptLink { prev_digest: prev, record: rec, digest });
}

/// Verify the hash chain's integrity (does not check signatures).
pub fn verify_chain(chain: &[ReceiptLink], session_id: &[u8; 16]) -> Result<(), Error> {
    let mut prev = [0u8; 32];
    for link in chain {
        if link.prev_digest != prev {
            return Err(Error::InvalidShare("chain prev-link mismatch"));
        }
        if &link.record.session_id != session_id {
            return Err(Error::BindingMismatch("chain session mismatch"));
        }
        if link.digest != link_digest(&prev, &link.record) {
            return Err(Error::InvalidShare("chain digest mismatch"));
        }
        prev = link.digest;
    }
    Ok(())
}

/// Sign the chain head into a receipt.
pub fn sign_receipt(
    chain: &[ReceiptLink],
    session_id: [u8; 16],
    policy_version: u32,
    outcome: ReceiptOutcome,
    signing_key: &SigningKey,
) -> Result<SignedReceipt, Error> {
    let head = chain.last().map(|l| l.digest).unwrap_or([0u8; 32]);
    let mut msg = Vec::with_capacity(16 + 4 + 1 + 32);
    msg.extend_from_slice(b"flailer-receipt-v1");
    msg.extend_from_slice(&session_id);
    msg.extend_from_slice(&policy_version.to_be_bytes());
    msg.push(outcome as u8);
    msg.extend_from_slice(&head);
    let signature = signing_key.sign(&msg);
    Ok(SignedReceipt {
        session_id,
        policy_version,
        outcome,
        links: chain.to_vec(),
        head_digest: head,
        signer_pubkey: signing_key.verifying_key().to_bytes(),
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verify a signed receipt: chain integrity + head signature. Independently
/// verifiable without vault access (RFC §8).
pub fn verify_receipt(receipt: &SignedReceipt) -> Result<(), Error> {
    verify_chain(&receipt.links, &receipt.session_id)?;
    let vk = VerifyingKey::from_bytes(&receipt.signer_pubkey)
        .map_err(|_| Error::InvalidShare("bad receipt pubkey"))?;
    let mut msg = Vec::with_capacity(16 + 4 + 1 + 32);
    msg.extend_from_slice(b"flailer-receipt-v1");
    msg.extend_from_slice(&receipt.session_id);
    msg.extend_from_slice(&receipt.policy_version.to_be_bytes());
    msg.push(receipt.outcome as u8);
    msg.extend_from_slice(&receipt.head_digest);
    let sig_bytes: [u8; 64] = receipt.signature.as_slice().try_into()
        .map_err(|_| Error::InvalidShare("bad signature length"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(&msg, &sig).map_err(|_| Error::InvalidShare("bad receipt signature"))?;
    // The signed head must match the chain's actual head.
    let actual_head = receipt.links.last().map(|l| l.digest).unwrap_or([0u8; 32]);
    if actual_head != receipt.head_digest {
        return Err(Error::InvalidShare("receipt head mismatch"));
    }
    Ok(())
}
