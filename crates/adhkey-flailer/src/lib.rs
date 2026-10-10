//! AdhKey Flailer Recovery — P1 cryptographic contract.
//!
//! Adversarial identity recovery after total device loss. This crate is the
//! cryptographic core only: no network, no UI, no storage backends.
//!
//! Key hierarchy (normative):
//! ```text
//! root: random 256-bit (CSPRNG), NEVER derived from the passphrase
//!   ├─ Shamir 3-of-5 → S0..S4 (via the reviewed `sharks` crate)
//!   │    ├─ S0: sealed in a passphrase envelope (Argon2id → XChaCha20-Poly1305)
//!   │    ├─ S1..S3: guardian-held ShareEnvelopes (AAD-bound to set/epoch/index)
//!   │    └─ S4: paper backup (checksummed encoding, offline capability)
//!   └─ vault key = HKDF-SHA256(root, "flailer-vault-key" || set_id || epoch)
//!        └─ XChaCha20-Poly1305 vault, AAD-bound to set/epoch
//! ```
//! Answer commitments are salted Argon2id — never bare hashes (P0/D1).

pub mod challenge;
pub mod commitments;
pub mod governor;
pub mod guardians;
pub mod key_hierarchy;
pub mod policy;
pub mod receipts;
pub mod rotation;
pub mod secret_sharing;
pub mod vault;

pub use challenge::{generate_challenges, verify_challenge, Challenge};
pub use commitments::{commit_answer, verify_answer, AnswerCommit, FactCategory, VaultFact};
pub use governor::{RecoverySession, State, TransitionRecord};
pub use guardians::{approvals_satisfy, enroll_guardian, sign_approval, verify_approval, verify_enrollment_receipt, Decision, EnrollmentReceipt, GuardianApproval, GuardianRecord, VerifiedApproval};
pub use key_hierarchy::{derive_vault_key, generate_root, open_share_envelope, seal_share_envelope, PassphraseEnvelope, RootSecret};
pub use policy::{Policy, POLICY_VERSION};
pub use receipts::{append_link, sign_receipt, verify_chain, verify_receipt, ReceiptOutcome, SignedReceipt};
pub use rotation::{rotate_epoch, rotate_root, verify_rotation_receipt, RootRotation, RotationReceipt};
pub use secret_sharing::{recover_root, split_root, unwrap_share, wrap_share, ShareEnvelope, VerifiedShare, THRESHOLD, SHARE_COUNT};
pub use vault::{open_vault, seal_vault, Vault};

use std::fmt;

/// Crate error type. Never carries secret material.
#[derive(Debug)]
pub enum Error {
    Rng,
    Kdf(String),
    Aead,
    Hkdf,
    Serialization(String),
    InvalidShare(&'static str),
    BindingMismatch(&'static str),
    InsufficientShares,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rng => write!(f, "randomness generation failed"),
            Error::Kdf(e) => write!(f, "key derivation failed: {e}"),
            Error::Aead => write!(f, "authenticated decryption failed"),
            Error::Hkdf => write!(f, "HKDF expand failed"),
            Error::Serialization(e) => write!(f, "serialization failed: {e}"),
            Error::InvalidShare(e) => write!(f, "invalid share: {e}"),
            Error::BindingMismatch(e) => write!(f, "binding mismatch: {e}"),
            Error::InsufficientShares => write!(f, "fewer than threshold distinct shares"),
        }
    }
}

impl std::error::Error for Error {}

/// Generate `n` cryptographically random bytes.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Rng)?;
    Ok(buf)
}
