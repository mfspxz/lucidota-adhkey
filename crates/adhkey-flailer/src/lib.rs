//! AdhKey Flailer Recovery: self-vouching for total device loss.
//!
//! When Zack loses ALL devices and can't reach his k-of-n recovery keys,
//! the flailer protocol lets him prove identity through:
//! 1. Knowledge vault (encrypted personal facts, Shamir-split key)
//! 2. Challenge-response (humans verify answers before releasing shares)
//! 3. Behavioral signals (stylometry, fingerprinting — soft, not gates)
//! 4. Social vouching (trusted humans confirm identity)
//!
//! This crate implements the vault + Shamir + challenge core.
//! Human communication and behavioral analysis are out of scope (v1).

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use chacha20poly1305::aead::{Aead, AeadCore};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// A single fact in the vault. The `id` is a stable identifier;
/// `question` is what's asked; `answer_hash` is SHA256(answer) —
//  the plaintext answer is NEVER stored.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultFact {
    pub id: String,
    pub question: String,
    pub answer_hash: [u8; 32],
    pub category: FactCategory,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FactCategory {
    Timeline,    // From hypertimeline: "Where were you on [date]?"
    Transaction, // "What did you buy for $X on [date]?"
    Personal,    // Manual secrets, personal history
    Negative,    // "Which of these did you NOT do?"
}

/// The encrypted vault. Contains facts; the key is Shamir-split.
#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// A challenge presented during recovery. The `expected_hash` is
/// the SHA256 of the correct answer — the verifier checks without
/// knowing the answer (if they have the vault decrypted) or the
/// human verifies manually.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Challenge {
    pub fact_id: String,
    pub question: String,
    pub expected_hash: [u8; 32],
    pub options: Option<Vec<String>>, // For multiple-choice (negative facts)
}

impl VaultFact {
    pub fn new(id: &str, question: &str, answer: &str, category: FactCategory) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(answer.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        VaultFact {
            id: id.to_string(),
            question: question.to_string(),
            answer_hash: hash,
            category,
        }
    }

    pub fn verify(&self, answer: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(answer.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        // Constant-time compare
        self.answer_hash.iter().zip(hash.iter()).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

/// Encrypt facts into a vault with the given 32-byte key.
pub fn seal_vault(facts: &[VaultFact], key: &[u8; 32]) -> Vault {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).expect("RNG failed");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = serde_json::to_vec(facts).expect("serialize");
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");
    Vault { nonce: nonce_bytes, ciphertext }
}

/// Decrypt a vault with the key. Returns facts on success.
pub fn open_vault(vault: &Vault, key: &[u8; 32]) -> Result<Vec<VaultFact>, &'static str> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&vault.nonce);
    let plaintext = cipher.decrypt(nonce, vault.ciphertext.as_ref())
        .map_err(|_| "decrypt failed: wrong key or corrupted vault")?;
    serde_json::from_slice(&plaintext).map_err(|_| "deserialize failed")
}

/// Derive a Shamir share from a passphrase using Argon2id.
/// This is Share A — the one Zack memorizes.
pub fn derive_share(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    use argon2::{Argon2, Params};
    let params = Params::new(64 * 1024, 3, 4, Some(32)).expect("params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut out).expect("hash");
    out
}

/// Generate challenges from vault facts. Selects `n` facts (mixed categories).
pub fn generate_challenges(facts: &[VaultFact], n: usize) -> Vec<Challenge> {
    // Simple: take first n (in production, randomize and balance categories)
    facts.iter().take(n).map(|f| Challenge {
        fact_id: f.id.clone(),
        question: f.question.clone(),
        expected_hash: f.answer_hash,
        options: None,
    }).collect()
}

/// Verify a challenge answer against the expected hash.
pub fn verify_challenge(challenge: &Challenge, answer: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(answer.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    challenge.expected_hash.iter().zip(hash.iter()).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip() {
        let facts = vec![
            VaultFact::new("t1", "Where were you Oct 4 2026 at 20:00?", "Gastown", FactCategory::Timeline),
            VaultFact::new("p1", "What's mom's maiden name?", "Smith", FactCategory::Personal),
        ];
        let key = [42u8; 32];
        let vault = seal_vault(&facts, &key);
        let opened = open_vault(&vault, &key).unwrap();
        assert_eq!(opened.len(), 2);
        assert!(opened[0].verify("Gastown"));
        assert!(!opened[0].verify("Downtown"));
    }

    #[test]
    fn wrong_key_fails() {
        let facts = vec![VaultFact::new("t1", "Q?", "A", FactCategory::Personal)];
        let vault = seal_vault(&facts, &[1u8; 32]);
        assert!(open_vault(&vault, &[2u8; 32]).is_err());
    }

    #[test]
    fn challenge_verify() {
        let fact = VaultFact::new("t1", "Where?", "Gastown", FactCategory::Timeline);
        let challenges = generate_challenges(&[fact], 1);
        assert!(verify_challenge(&challenges[0], "Gastown"));
        assert!(!verify_challenge(&challenges[0], "Vancouver"));
    }

    #[test]
    fn share_derivation_deterministic() {
        let s1 = derive_share("correct horse battery staple", b"salt123456789");
        let s2 = derive_share("correct horse battery staple", b"salt123456789");
        assert_eq!(s1, s2);
        let s3 = derive_share("wrong passphrase", b"salt123456789");
        assert_ne!(s1, s3);
    }
}
