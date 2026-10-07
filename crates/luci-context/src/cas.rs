//! Content-addressed storage for original bytes.
//!
//! The reconstruction path behind every compressed item. `put` returns
//! the SHA-256 hex of the bytes; `get` retrieves all or a byte range,
//! so a consumer can ask for "bytes 17,402-18,910 of the original"
//! without materializing the whole object.

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Abstract store. The cache never assumes where bytes live.
pub trait CasStore {
    fn put(&mut self, bytes: &[u8]) -> io::Result<String>;
    fn get(&self, hash: &str, range: Option<(u64, u64)>) -> io::Result<Vec<u8>>;
    fn contains(&self, hash: &str) -> bool;
}

/// File-backed CAS: one file per hash, hex-named, under `dir`.
/// No locking, no GC — the cache owns lifecycle policy.
pub struct FileCas {
    dir: PathBuf,
}

impl FileCas {
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(FileCas { dir: dir.to_path_buf() })
    }

    fn path(&self, hash: &str) -> PathBuf {
        self.dir.join(hash)
    }
}

impl CasStore for FileCas {
    fn put(&mut self, bytes: &[u8]) -> io::Result<String> {
        let hash = hash_bytes(bytes);
        let p = self.path(&hash);
        if !p.exists() {
            fs::write(&p, bytes)?;
        }
        Ok(hash)
    }

    fn get(&self, hash: &str, range: Option<(u64, u64)>) -> io::Result<Vec<u8>> {
        // Hash format check: 64 lowercase hex chars. Anything else is
        // rejected before touching the filesystem (no path traversal).
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cas hash must be 64 hex chars",
            ));
        }
        let bytes = fs::read(self.path(hash))?;
        // Verify integrity on read: the address IS the checksum.
        if hash_bytes(&bytes) != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cas integrity mismatch",
            ));
        }
        match range {
            None => Ok(bytes),
            Some((start, end)) => {
                let len = bytes.len() as u64;
                let s = (start as usize).min(bytes.len());
                let e = (end as usize).min(bytes.len()).max(s);
                let _ = len;
                Ok(bytes[s..e].to_vec())
            }
        }
    }

    fn contains(&self, hash: &str) -> bool {
        hash.len() == 64
            && hash.bytes().all(|b| b.is_ascii_hexdigit())
            && self.path(hash).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip_with_range() {
        let dir = std::env::temp_dir().join("luci-cas-test-1");
        let _ = fs::remove_dir_all(&dir);
        let mut cas = FileCas::open(&dir).unwrap();
        let data = b"abcdefghijklmnopqrstuvwxyz".repeat(1000);
        let h = cas.put(&data).unwrap();
        assert_eq!(cas.get(&h, None).unwrap(), data);
        assert_eq!(cas.get(&h, Some((17402, 18910))).unwrap(), data[17402..18910]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_hash_rejected() {
        let dir = std::env::temp_dir().join("luci-cas-test-2");
        let _ = fs::remove_dir_all(&dir);
        let cas = FileCas::open(&dir).unwrap();
        assert!(cas.get("../escape", None).is_err());
        assert!(cas.get("zzzz", None).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
