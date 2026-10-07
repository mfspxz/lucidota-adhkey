//! adhkey-store: the KeyStore trait. Adapters, not allegiance.
//!
//! AdhKey asks: "can this key sign this thing?" It does not care whether
//! the key lives in KeePass, Android Keystore, WebAuthn, YubiKey, TPM,
//! HSM, Bitwarden, a hardware wallet, or some future weird anarchist shit.

use adhkey_core::KeyId;
use std::fmt;

/// Public key material (opaque bytes; format depends on the suite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub Vec<u8>);

/// Signature bytes (opaque; format depends on the suite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    KeyNotFound(KeyId),
    SigningFailed(String),
    NotSupported(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for StoreError {}

/// The magic interface. Everything else is an adapter.
pub trait KeyStore {
    fn public_key(&self, id: &KeyId) -> Result<PublicKey, StoreError>;
    fn sign(&self, id: &KeyId, message: &[u8]) -> Result<Signature, StoreError>;
}
