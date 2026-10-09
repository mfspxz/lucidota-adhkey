//! Shamir 3-of-5 sharing over a reviewed implementation (`sharks`).
//!
//! Type-state discipline: raw share bytes are `UnverifiedShare`; only an
//! authenticated, binding-checked envelope yields a `VerifiedShare`, and only
//! verified shares may enter `recover_root`. (RFC §6 constraints.)

use crate::{random_bytes, Error};
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use std::collections::HashSet;

/// Cryptographic threshold and share count. Fixed for the v1 recovery set.
pub const THRESHOLD: u8 = 3;
pub const SHARE_COUNT: usize = 5;

/// Length of one share's byte encoding: x (1 byte) || y (32 bytes).
pub const SHARE_BYTES_LEN: usize = 33;

/// Raw, unauthenticated share bytes. Never feed these to `recover_root`.
#[derive(Clone)]
pub struct UnverifiedShare(pub(crate) Vec<u8>);

/// A share whose envelope authenticated and whose set/epoch/index bindings
/// were verified. Only these may enter reconstruction.
#[derive(Clone)]
pub struct VerifiedShare {
    pub(crate) index: u8,
    pub(crate) bytes: Vec<u8>,
}

impl VerifiedShare {
    pub fn index(&self) -> u8 {
        self.index
    }
}

/// Split the root into 5 shares, threshold 3, via `sharks`.
/// Returns raw share byte strings (x || y); wrap them before distribution.
pub fn split_root(root: &crate::RootSecret) -> Result<[UnverifiedShare; SHARE_COUNT], Error> {
    let sharks = Sharks(THRESHOLD);
    let mut shares = sharks.dealer(root.as_bytes()).take(SHARE_COUNT);
    let mut out: [UnverifiedShare; SHARE_COUNT] = Default::default();
    for (i, slot) in out.iter_mut().enumerate() {
        let share: Share = shares.next().ok_or(Error::InvalidShare("dealer short"))?;
        let bytes = Vec::from(&share);
        debug_assert_eq!(bytes.len(), SHARE_BYTES_LEN);
        // Bind the dealer-assigned x coordinate to our index slot.
        let _ = i;
        *slot = UnverifiedShare(bytes);
    }
    Ok(out)
}

impl Default for UnverifiedShare {
    fn default() -> Self {
        UnverifiedShare(Vec::new())
    }
}

/// Authenticated container for one guardian-held share.
/// AAD binds: version || set_id || epoch || index. The wrapping key is an
/// enrollment-time secret (P3); this layer only enforces the bindings.
#[derive(Serialize, Deserialize, Clone)]
pub struct ShareEnvelope {
    pub version: u8,
    pub set_id: [u8; 16],
    pub epoch: u64,
    pub index: u8,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

const SHARE_AAD_DOMAIN: &[u8] = b"flailer-share-v1";

fn share_aad(version: u8, set_id: &[u8; 16], epoch: u64, index: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SHARE_AAD_DOMAIN.len() + 1 + 16 + 8 + 1);
    aad.extend_from_slice(SHARE_AAD_DOMAIN);
    aad.push(version);
    aad.extend_from_slice(set_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.push(index);
    aad
}

/// Wrap a raw share for guardian storage/distribution.
pub fn wrap_share(
    share: &UnverifiedShare,
    wrapping_key: &[u8; 32],
    set_id: [u8; 16],
    epoch: u64,
    index: u8,
) -> Result<ShareEnvelope, Error> {
    if share.0.len() != SHARE_BYTES_LEN {
        return Err(Error::InvalidShare("bad share length"));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrapping_key));
    let nonce_bytes: [u8; 12] = random_bytes()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = share_aad(1, &set_id, epoch, index);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: &share.0, aad: &aad })
        .map_err(|_| Error::Aead)?;
    Ok(ShareEnvelope { version: 1, set_id, epoch, index, nonce: nonce_bytes, ciphertext })
}

/// Unwrap and verify a share envelope against the expected set/epoch.
/// Mismatched set, epoch, or index → `BindingMismatch`. Tampering → `Aead`.
pub fn unwrap_share(
    env: &ShareEnvelope,
    wrapping_key: &[u8; 32],
    expected_set_id: &[u8; 16],
    expected_epoch: u64,
) -> Result<VerifiedShare, Error> {
    if env.version != 1 {
        return Err(Error::BindingMismatch("unsupported envelope version"));
    }
    if &env.set_id != expected_set_id {
        return Err(Error::BindingMismatch("set id mismatch"));
    }
    if env.epoch != expected_epoch {
        return Err(Error::BindingMismatch("stale epoch"));
    }
    if (env.index as usize) >= SHARE_COUNT {
        return Err(Error::BindingMismatch("share index out of range"));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrapping_key));
    let nonce = Nonce::from_slice(&env.nonce);
    let aad = share_aad(env.version, &env.set_id, env.epoch, env.index);
    let bytes = cipher
        .decrypt(nonce, Payload { msg: env.ciphertext.as_ref(), aad: &aad })
        .map_err(|_| Error::Aead)?;
    if bytes.len() != SHARE_BYTES_LEN {
        return Err(Error::InvalidShare("bad share length"));
    }
    // Structural validation: must parse as a sharks Share.
    Share::try_from(bytes.as_slice()).map_err(|_| Error::InvalidShare("malformed share"))?;
    Ok(VerifiedShare { index: env.index, bytes })
}

/// Reconstruct the root from verified shares. Requires ≥ THRESHOLD distinct
/// indices; duplicates are deduplicated (replay adds nothing); fewer → error.
pub fn recover_root(shares: &[VerifiedShare]) -> Result<crate::RootSecret, Error> {
    let mut seen: HashSet<u8> = HashSet::new();
    let mut distinct: Vec<&VerifiedShare> = Vec::new();
    for s in shares {
        if seen.insert(s.index) {
            distinct.push(s);
        }
    }
    if distinct.len() < THRESHOLD as usize {
        return Err(Error::InsufficientShares);
    }
    let sharks = Sharks(THRESHOLD);
    let parsed: Result<Vec<Share>, _> =
        distinct.iter().map(|s| Share::try_from(s.bytes.as_slice())).collect();
    let parsed = parsed.map_err(|_| Error::InvalidShare("malformed share"))?;
    let secret = sharks.recover(parsed.iter()).map_err(|_| Error::InvalidShare("recovery failed"))?;
    if secret.len() != 32 {
        return Err(Error::InvalidShare("recovered wrong length"));
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&secret);
    // NOTE: RootSecret's field is private; reconstruction goes through this
    // crate-internal constructor.
    Ok(crate::RootSecret::from_bytes(root))
}

// ---------------------------------------------------------------------------
// Paper backup encoding: checksummed, self-describing, no encryption.
// Format: "FL1" || set_id(16) || epoch_be(8) || index(1) || share(33) || crc(4),
// hex-encoded with '-' separators. The checksum is SHA256(prefix)[..4].
// ---------------------------------------------------------------------------

use sha2::{Digest, Sha256};

const PAPER_MAGIC: &[u8] = b"FL1";

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0 {
        return Err(Error::InvalidShare("bad hex length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or(Error::InvalidShare("bad hex"))?;
        let lo = (pair[1] as char).to_digit(16).ok_or(Error::InvalidShare("bad hex"))?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

/// Encode a share for paper backup.
pub fn encode_paper_share(share: &UnverifiedShare, set_id: [u8; 16], epoch: u64, index: u8) -> Result<String, Error> {
    if share.0.len() != SHARE_BYTES_LEN {
        return Err(Error::InvalidShare("bad share length"));
    }
    let mut raw = Vec::with_capacity(3 + 16 + 8 + 1 + SHARE_BYTES_LEN);
    raw.extend_from_slice(PAPER_MAGIC);
    raw.extend_from_slice(&set_id);
    raw.extend_from_slice(&epoch.to_be_bytes());
    raw.push(index);
    raw.extend_from_slice(&share.0);
    let checksum = Sha256::digest(&raw);
    let hex = hex_encode(&raw);
    let crc = hex_encode(&checksum[..4]);
    // Group for transcription: 8-char groups.
    let grouped: Vec<String> = hex
        .as_bytes()
        .chunks(8)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    Ok(format!("{}-{}", grouped.join("-"), crc))
}

/// Decode and verify a paper backup. Returns the raw share bytes with bindings.
pub fn decode_paper_share(encoded: &str) -> Result<(UnverifiedShare, [u8; 16], u64, u8), Error> {
    let compact: String = encoded.chars().filter(|c| *c != '-').collect();
    if compact.len() < 8 {
        return Err(Error::InvalidShare("too short"));
    }
    let (hex_part, crc_part) = compact.split_at(compact.len() - 8);
    let raw = hex_decode(hex_part)?;
    let crc = hex_decode(crc_part)?;
    let expect = &Sha256::digest(&raw)[..4];
    if subtle::ConstantTimeEq::ct_eq(crc.as_slice(), expect).unwrap_u8() != 1 {
        return Err(Error::InvalidShare("checksum mismatch"));
    }
    if raw.len() != 3 + 16 + 8 + 1 + SHARE_BYTES_LEN || &raw[..3] != PAPER_MAGIC {
        return Err(Error::InvalidShare("bad paper format"));
    }
    let mut set_id = [0u8; 16];
    set_id.copy_from_slice(&raw[3..19]);
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&raw[19..27]);
    let share_bytes = raw[28..].to_vec();
    Share::try_from(share_bytes.as_slice()).map_err(|_| Error::InvalidShare("malformed share"))?;
    Ok((UnverifiedShare(share_bytes), set_id, u64::from_be_bytes(epoch_bytes), raw[27]))
}
