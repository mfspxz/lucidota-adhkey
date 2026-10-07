//! adhkey-crypto: audited FOSS primitives only. No custom cryptography.
//!
//! Suites:
//! - Ed25519 (ed25519-dalek) for signatures.
//! - SHA-256 (sha2) for hashing / commitments.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Build a signing key from 32 bytes of caller-supplied randomness.
/// Randomness is the caller's job; this function never invents it.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn verifying_key(sk: &SigningKey) -> VerifyingKey {
    sk.verifying_key()
}

pub fn sign(sk: &SigningKey, message: &[u8]) -> Signature {
    sk.sign(message)
}

pub fn verify(vk: &VerifyingKey, message: &[u8], sig: &Signature) -> bool {
    vk.verify(message, sig).is_ok()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Commitment: hash of (label || value). Binding, hiding (for high-entropy values).
pub fn commit(label: &[u8], value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(value);
    h.finalize().into()
}
