//! Key hierarchy: random root, HKDF vault keys, passphrase envelope for S0.
//!
//! The root secret is ALWAYS a fresh 256-bit CSPRNG value. The memorized
//! passphrase never derives a share — it only seals the S0 envelope (P0/D3).

use crate::{random_bytes, Error};
use argon2::{Argon2, Params};
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation constants.
pub const VAULT_KEY_INFO: &[u8] = b"flailer-vault-key-v1";
pub const HKDF_SALT: &[u8] = b"flailer-hkdf-v1";
pub const ENVELOPE_AAD: &[u8] = b"flailer-envelope-v1";

/// Argon2id parameters for the passphrase envelope KEK.
fn envelope_params() -> Result<Params, Error> {
    Params::new(64 * 1024, 3, 4, Some(32)).map_err(|e| Error::Kdf(e.to_string()))
}

/// The 256-bit recovery root. Zeroized on drop. No Debug/Display impl —
/// it must never appear in logs (T-LOG).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RootSecret([u8; 32]);

impl RootSecret {
    /// Generate a fresh random root.
    pub fn generate() -> Result<Self, Error> {
        Ok(RootSecret(random_bytes()?))
    }

    /// Access the raw bytes for cryptographic operations only.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuild from reconstructed bytes. Crate-internal: only `recover_root`
    /// may mint a RootSecret from shares.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        RootSecret(bytes)
    }
}

/// Standalone root generation (convenience wrapper).
pub fn generate_root() -> Result<RootSecret, Error> {
    RootSecret::generate()
}

/// Derive the vault encryption key: HKDF-SHA256(root, info = purpose || set_id || epoch).
/// A different (set_id, epoch) always yields a different vault key (T-C14).
pub fn derive_vault_key(root: &RootSecret, set_id: &[u8; 16], epoch: u64) -> Result<[u8; 32], Error> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), root.as_bytes());
    let mut info = Vec::with_capacity(VAULT_KEY_INFO.len() + 16 + 8);
    info.extend_from_slice(VAULT_KEY_INFO);
    info.extend_from_slice(set_id);
    info.extend_from_slice(&epoch.to_be_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).map_err(|_| Error::Hkdf)?;
    Ok(out)
}

/// The S0 share sealed under the passphrase. Re-exported as PassphraseEnvelope.
#[derive(Clone)]
pub struct PassphraseEnvelope {
    pub(crate) salt: [u8; 16],
    pub(crate) nonce: [u8; 12],
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) set_id: [u8; 16],
    pub(crate) epoch: u64,
}

fn envelope_kek(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], Error> {
    let params = envelope_params()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(kek)
}

fn envelope_aad(set_id: &[u8; 16], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENVELOPE_AAD.len() + 16 + 8);
    aad.extend_from_slice(ENVELOPE_AAD);
    aad.extend_from_slice(set_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Seal share bytes under the passphrase. The envelope binds set_id/epoch via AAD.
pub fn seal_share_envelope(
    share_bytes: &[u8],
    passphrase: &str,
    set_id: [u8; 16],
    epoch: u64,
) -> Result<PassphraseEnvelope, Error> {
    let salt: [u8; 16] = random_bytes()?;
    let mut kek = envelope_kek(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    kek.zeroize();
    let nonce_bytes: [u8; 12] = random_bytes()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = envelope_aad(&set_id, epoch);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: share_bytes, aad: &aad })
        .map_err(|_| Error::Aead)?;
    Ok(PassphraseEnvelope { salt, nonce: nonce_bytes, ciphertext, set_id, epoch })
}

/// Open the S0 envelope. Wrong passphrase → `Error::Aead`, indistinguishable
/// from corruption (no oracle beyond try-rate, which the governor rate-limits).
pub fn open_share_envelope(env: &PassphraseEnvelope, passphrase: &str) -> Result<Vec<u8>, Error> {
    let mut kek = envelope_kek(passphrase, &env.salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    kek.zeroize();
    let nonce = Nonce::from_slice(&env.nonce);
    let aad = envelope_aad(&env.set_id, env.epoch);
    cipher
        .decrypt(nonce, Payload { msg: env.ciphertext.as_ref(), aad: &aad })
        .map_err(|_| Error::Aead)
}
