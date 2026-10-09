//! Versioned, AAD-bound encrypted vault (P0/D4).

use crate::{random_bytes, Error};
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

use crate::commitments::VaultFact;

/// Vault format version.
pub const VAULT_VERSION: u8 = 1;
const VAULT_AAD_DOMAIN: &[u8] = b"flailer-vault-v1";

/// The encrypted vault. AAD binds version || set_id || epoch at seal/open.
#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub version: u8,
    pub set_id: [u8; 16],
    pub epoch: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn vault_aad(version: u8, set_id: &[u8; 16], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VAULT_AAD_DOMAIN.len() + 1 + 16 + 8);
    aad.extend_from_slice(VAULT_AAD_DOMAIN);
    aad.push(version);
    aad.extend_from_slice(set_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Seal facts into a vault. The vault key must come from `derive_vault_key`.
pub fn seal_vault(
    facts: &[VaultFact],
    vault_key: &[u8; 32],
    set_id: [u8; 16],
    epoch: u64,
) -> Result<Vault, Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(vault_key));
    let nonce_bytes: [u8; 12] = random_bytes()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext =
        serde_json::to_vec(facts).map_err(|e| Error::Serialization(e.to_string()))?;
    let aad = vault_aad(VAULT_VERSION, &set_id, epoch);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| Error::Aead)?;
    Ok(Vault { version: VAULT_VERSION, set_id, epoch, nonce: nonce_bytes, ciphertext })
}

/// Open a vault, enforcing the expected set/epoch bindings.
pub fn open_vault(
    vault: &Vault,
    vault_key: &[u8; 32],
    expected_set_id: &[u8; 16],
    expected_epoch: u64,
) -> Result<Vec<VaultFact>, Error> {
    if vault.version != VAULT_VERSION {
        return Err(Error::BindingMismatch("unsupported vault version"));
    }
    if &vault.set_id != expected_set_id {
        return Err(Error::BindingMismatch("vault set id mismatch"));
    }
    if vault.epoch != expected_epoch {
        return Err(Error::BindingMismatch("vault epoch mismatch"));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(vault_key));
    let nonce = Nonce::from_slice(&vault.nonce);
    let aad = vault_aad(vault.version, &vault.set_id, vault.epoch);
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: vault.ciphertext.as_ref(), aad: &aad })
        .map_err(|_| Error::Aead)?;
    serde_json::from_slice(&plaintext).map_err(|e| Error::Serialization(e.to_string()))
}
