//! adhkey-crypto: audited FOSS primitives only. No custom cryptography.
//!
//! Suites:
//! - Ed25519 (ed25519-dalek) for signatures.
//! - SHA-256 (sha2) for hashing / commitments.

use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha256};

/// Re-exported so downstream crates can name key/signature types
/// without depending on ed25519-dalek directly.
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// Generate a fresh signing key from the OS CSPRNG.
///
/// This is the ONLY key-generation entry point callers should use.
/// `signing_key_from_seed` remains for deterministic tests and explicit
/// low-level control — never feed it `[0u8; 32]` or any low-entropy seed
/// in production (red-team cut #17).
pub fn generate_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS CSPRNG failure");
    SigningKey::from_bytes(&seed)
}

/// Build a signing key from 32 bytes of caller-supplied randomness.
/// Randomness is the caller's job; this function never invents it.
/// FOR TESTS AND EXPLICIT LOW-LEVEL USE ONLY. Production code must use
/// `generate_signing_key()`.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn verifying_key(sk: &SigningKey) -> VerifyingKey {
    sk.verifying_key()
}

/// Raw 32-byte Ed25519 public key, for storage/transport.
pub fn verifying_key_to_bytes(vk: &VerifyingKey) -> [u8; 32] {
    vk.to_bytes()
}

pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(bytes).map_err(|e| format!("bad verifying key: {e}"))
}

pub fn signature_to_bytes(sig: &Signature) -> [u8; 64] {
    sig.to_bytes()
}

pub fn signature_from_bytes(bytes: &[u8; 64]) -> Result<Signature, String> {
    Ok(Signature::from_bytes(bytes))
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
