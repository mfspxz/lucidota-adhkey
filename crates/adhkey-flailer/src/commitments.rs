//! Answer commitments: salted Argon2id, never bare hashes (P0/D1).
//!
//! A `Challenge` travels to humans; its commitment must resist offline
//! dictionary attacks. Each answer gets a fresh 128-bit salt and a
//! memory-hard hash. Verification cost is acceptable (human in the loop).

use crate::{random_bytes, Error};
use argon2::{Argon2, Params};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Argon2id parameters for answer commitments.
fn commitment_params() -> Result<Params, Error> {
    Params::new(64 * 1024, 3, 4, Some(32)).map_err(|e| Error::Kdf(e.to_string()))
}

/// A salted, memory-hard commitment to one answer.
#[derive(Serialize, Deserialize, Clone)]
pub struct AnswerCommit {
    pub salt: [u8; 16],
    pub hash: [u8; 32],
}

/// Commit to an answer with a fresh random salt.
pub fn commit_answer(answer: &str) -> Result<AnswerCommit, Error> {
    let salt: [u8; 16] = random_bytes()?;
    let params = commitment_params()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut hash = [0u8; 32];
    argon2
        .hash_password_into(answer.as_bytes(), &salt, &mut hash)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(AnswerCommit { salt, hash })
}

/// Verify an answer against its commitment (constant-time hash comparison).
pub fn verify_answer(commit: &AnswerCommit, answer: &str) -> Result<bool, Error> {
    let params = commitment_params()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut hash = [0u8; 32];
    argon2
        .hash_password_into(answer.as_bytes(), &commit.salt, &mut hash)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(hash.ct_eq(&commit.hash).unwrap_u8() == 1)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FactCategory {
    Timeline,
    Transaction,
    Personal,
    Negative,
}

/// A single fact in the vault. The plaintext answer is NEVER stored —
/// only its salted memory-hard commitment.
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultFact {
    pub id: String,
    pub question: String,
    pub commitment: AnswerCommit,
    pub category: FactCategory,
}

impl VaultFact {
    pub fn new(id: &str, question: &str, answer: &str, category: FactCategory) -> Result<Self, Error> {
        Ok(VaultFact {
            id: id.to_string(),
            question: question.to_string(),
            commitment: commit_answer(answer)?,
            category,
        })
    }

    pub fn verify(&self, answer: &str) -> Result<bool, Error> {
        verify_answer(&self.commitment, answer)
    }
}
