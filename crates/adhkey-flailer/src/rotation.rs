//! Epoch and root rotation.
//!
//! Guardian changes re-share the same root under a new epoch (old shares
//! stop verifying via epoch binding). Suspected root compromise rotates the
//! root itself and re-encrypts the vault. Both emit signed receipts; the
//! governor tombstones the old epoch's sessions.

use crate::{
    derive_vault_key, recover_root, seal_vault, split_root, wrap_share, Error, RootSecret,
    ShareEnvelope, Vault, VaultFact, VerifiedShare,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signed record of a rotation event.
#[derive(Clone, Serialize, Deserialize)]
pub struct RotationReceipt {
    pub set_id: [u8; 16],
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub root_rotated: bool,
    pub rotated_at: u64,
    pub reason: String,
    pub authority_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

fn receipt_message(
    set_id: &[u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    root_rotated: bool,
    rotated_at: u64,
    reason: &str,
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"flailer-rotation-v1");
    m.extend_from_slice(set_id);
    m.extend_from_slice(&old_epoch.to_be_bytes());
    m.extend_from_slice(&new_epoch.to_be_bytes());
    m.push(root_rotated as u8);
    m.extend_from_slice(&rotated_at.to_be_bytes());
    let rh = Sha256::digest(reason.as_bytes());
    m.extend_from_slice(&rh);
    m
}

fn sign_rotation(
    set_id: [u8; 16],
    old_epoch: u64,
    new_epoch: u64,
    root_rotated: bool,
    rotated_at: u64,
    reason: &str,
    authority_key: &SigningKey,
) -> RotationReceipt {
    let msg = receipt_message(&set_id, old_epoch, new_epoch, root_rotated, rotated_at, reason);
    let signature = authority_key.sign(&msg);
    RotationReceipt {
        set_id,
        old_epoch,
        new_epoch,
        root_rotated,
        rotated_at,
        reason: reason.to_string(),
        authority_pubkey: authority_key.verifying_key().to_bytes(),
        signature: signature.to_bytes().to_vec(),
    }
}

/// Verify a rotation receipt's signature and bindings.
pub fn verify_rotation_receipt(receipt: &RotationReceipt) -> Result<(), Error> {
    let vk = VerifyingKey::from_bytes(&receipt.authority_pubkey)
        .map_err(|_| Error::InvalidShare("bad authority pubkey"))?;
    let msg = receipt_message(
        &receipt.set_id,
        receipt.old_epoch,
        receipt.new_epoch,
        receipt.root_rotated,
        receipt.rotated_at,
        &receipt.reason,
    );
    let sig_bytes: [u8; 64] = receipt
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidShare("bad signature length"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(&msg, &sig).map_err(|_| Error::InvalidShare("bad rotation signature"))?;
    if receipt.new_epoch <= receipt.old_epoch {
        return Err(Error::BindingMismatch("rotation must advance the epoch"));
    }
    Ok(())
}

/// Rotate the epoch: re-share the SAME root for a new guardian set/epoch.
/// `verified_shares` must be ≥ threshold from the OLD epoch (proves authority
/// to rotate). Old share envelopes stop verifying via epoch binding.
pub fn rotate_epoch(
    verified_shares: &[VerifiedShare],
    old_epoch: u64,
    new_epoch: u64,
    set_id: [u8; 16],
    new_wrapping_keys: &[[u8; 32]],
    authority_key: &SigningKey,
    now: u64,
    reason: &str,
) -> Result<(Vec<ShareEnvelope>, RotationReceipt), Error> {
    if new_epoch <= old_epoch {
        return Err(Error::BindingMismatch("new epoch must exceed old"));
    }
    if new_wrapping_keys.len() != crate::SHARE_COUNT {
        return Err(Error::BindingMismatch("need one wrapping key per share"));
    }
    if reason.len() > 512 {
        return Err(Error::InvalidShare("reason too long"));
    }
    let root = recover_root(verified_shares)?;
    let shares = split_root(&root)?;
    let mut envelopes = Vec::with_capacity(crate::SHARE_COUNT);
    for (i, share) in shares.iter().enumerate() {
        envelopes.push(wrap_share(share, &new_wrapping_keys[i], set_id, new_epoch, i as u8)?);
    }
    let receipt = sign_rotation(set_id, old_epoch, new_epoch, false, now, reason, authority_key);
    Ok((envelopes, receipt))
}

/// Result of a root rotation.
pub struct RootRotation {
    pub new_root: RootSecret,
    pub new_vault: Vault,
    pub new_envelopes: Vec<ShareEnvelope>,
    pub receipt: RotationReceipt,
}

/// Rotate the root itself (suspected compromise): fresh random root, vault
/// re-encrypted, full re-share. The caller supplies the decrypted facts —
/// this function never sees the old root.
pub fn rotate_root(
    old_facts: &[VaultFact],
    old_set_id: [u8; 16],
    old_epoch: u64,
    new_set_id: [u8; 16],
    new_epoch: u64,
    new_wrapping_keys: &[[u8; 32]],
    authority_key: &SigningKey,
    now: u64,
    reason: &str,
) -> Result<RootRotation, Error> {
    if new_epoch <= old_epoch && new_set_id == old_set_id {
        return Err(Error::BindingMismatch("new epoch must exceed old"));
    }
    if new_wrapping_keys.len() != crate::SHARE_COUNT {
        return Err(Error::BindingMismatch("need one wrapping key per share"));
    }
    if reason.len() > 512 {
        return Err(Error::InvalidShare("reason too long"));
    }
    let new_root = RootSecret::generate()?;
    let new_vault_key = derive_vault_key(&new_root, &new_set_id, new_epoch)?;
    let new_vault = seal_vault(old_facts, &new_vault_key, new_set_id, new_epoch)?;
    let shares = split_root(&new_root)?;
    let mut envelopes = Vec::with_capacity(crate::SHARE_COUNT);
    for (i, share) in shares.iter().enumerate() {
        envelopes.push(wrap_share(share, &new_wrapping_keys[i], new_set_id, new_epoch, i as u8)?);
    }
    let receipt =
        sign_rotation(new_set_id, old_epoch, new_epoch, true, now, reason, authority_key);
    Ok(RootRotation { new_root, new_vault, new_envelopes: envelopes, receipt })
}
