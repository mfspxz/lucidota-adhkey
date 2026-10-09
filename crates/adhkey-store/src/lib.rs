//! adhkey-store: the KeyStore trait. Adapters, not allegiance.
//!
//! AdhKey asks: "can this key sign this thing?" It does not care whether
//! the key lives in KeePass, Android Keystore, WebAuthn, YubiKey, TPM,
//! HSM, Bitwarden, a hardware wallet, or some future weird anarchist shit.
//!
//! C1: the trait now has `verify` — the verifier calls it in the
//! verification path instead of accepting an injected boolean.

use adhkey_core::{Error as CoreError, KeyId, KeyOperator};
use std::collections::BTreeMap;
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
///
/// SECURITY: `verify` is part of the interface because the CORE must be
/// able to check signatures itself (AUDIT.md C1). An adapter that
/// cannot verify (pure-signer HSM) must return
/// `Err(StoreError::NotSupported)` — fail closed, never `Ok(true)`.
pub trait KeyStore {
    fn public_key(&self, id: &KeyId) -> Result<PublicKey, StoreError>;
    fn sign(&self, id: &KeyId, message: &[u8]) -> Result<Signature, StoreError>;
    /// Verify `signature` over `message` under the public key for `id`.
    /// Ok(true) = valid, Ok(false) = invalid, Err = fail closed.
    fn verify(
        &self,
        id: &KeyId,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, StoreError>;
}

/// Reference in-memory key store. REAL Ed25519 via adhkey-crypto —
/// not a stub. For tests, tools, and as the adapter reference.
/// Production deployments replace this with their HSM/keystore adapter;
/// the core cannot tell the difference, which is the point.
///
/// Key material is held as 32-byte seeds; keys are rebuilt per operation
/// (this is a reference, not a performance piece).
#[derive(Default)]
pub struct InMemoryKeyStore {
    seeds: BTreeMap<KeyId, [u8; 32]>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        InMemoryKeyStore {
            seeds: BTreeMap::new(),
        }
    }

    /// Generate a fresh key from the OS CSPRNG and register it under `id`.
    /// Returns the id. (Production keygen policy — e.g. HSM-backed —
    /// lives in the real adapter; this is the reference.)
    pub fn generate(&mut self, id: KeyId) -> KeyId {
        let sk = adhkey_crypto::generate_signing_key();
        self.seeds.insert(id.clone(), sk.to_bytes());
        id
    }

    /// Import an explicit seed. TESTS ONLY — production code must use
    /// `generate` (or a real adapter). Named to make misuse grep-able.
    pub fn import_test_seed(&mut self, id: KeyId, seed: [u8; 32]) -> KeyId {
        self.seeds.insert(id.clone(), seed);
        id
    }

    fn signing_key(&self, id: &KeyId) -> Result<adhkey_crypto::SigningKey, StoreError> {
        let seed = self
            .seeds
            .get(id)
            .ok_or_else(|| StoreError::KeyNotFound(id.clone()))?;
        Ok(adhkey_crypto::signing_key_from_seed(seed))
    }
}

impl KeyStore for InMemoryKeyStore {
    fn public_key(&self, id: &KeyId) -> Result<PublicKey, StoreError> {
        let sk = self.signing_key(id)?;
        let vk = adhkey_crypto::verifying_key(&sk);
        Ok(PublicKey(
            adhkey_crypto::verifying_key_to_bytes(&vk).to_vec(),
        ))
    }

    fn sign(&self, id: &KeyId, message: &[u8]) -> Result<Signature, StoreError> {
        let sk = self.signing_key(id)?;
        let sig = adhkey_crypto::sign(&sk, message);
        Ok(Signature(adhkey_crypto::signature_to_bytes(&sig).to_vec()))
    }

    fn verify(
        &self,
        id: &KeyId,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, StoreError> {
        let sk = self.signing_key(id)?;
        let vk = adhkey_crypto::verifying_key(&sk);
        if signature.0.len() != 64 {
            return Ok(false); // malformed: invalid, not an error
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&signature.0);
        let sig = adhkey_crypto::signature_from_bytes(&bytes).map_err(StoreError::SigningFailed)?;
        Ok(adhkey_crypto::verify(&vk, message, &sig))
    }
}

/// The core drives key operations through this trait (AUDIT.md C1).
/// The reference store implements it directly.
impl KeyOperator for InMemoryKeyStore {
    fn sign(&self, key: &KeyId, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        KeyStore::sign(self, key, message)
            .map(|s| s.0)
            .map_err(|e| CoreError::KeyOperatorFailed(format!("{e}")))
    }

    fn verify(
        &self,
        key: &KeyId,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CoreError> {
        KeyStore::verify(self, key, message, &Signature(signature.to_vec()))
            .map_err(|e| CoreError::KeyOperatorFailed(format!("{e}")))
    }
}
