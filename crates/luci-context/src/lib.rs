//! luci-context: the epistemic context cache.
//!
//! Context compression by truth/provenance/decision-relevance — not by
//! token count. Compression never destroys information: it replaces
//! content with (summary, CAS pointer, hash, provenance, reconstruction
//! path). The original bytes remain dereferenceable, including by byte
//! range.
//!
//! Eviction follows the projection theorem operationally: an item may be
//! evicted only if its eviction cannot change the next permitted
//! decision. What the cache cannot prove safe, it marks UNKNOWN and
//! keeps retrievable — LOSSY_PROJECTION = UNKNOWN, never silent loss.

pub mod organelle;

pub mod cache;
pub mod cas;
pub mod item;
pub mod receipt;

pub use cache::{EpistemicCache, EvictedRecord, Projection};
pub use cas::{hash_bytes, CasStore, FileCas};
pub use item::{Content, ContextItem, Necessity, Source};
pub use luci_verdict_core::Epistemic;
pub use receipt::{ArtifactRecord, ParseError, ResumeBundle, TaskReceipt, TestRecord, VerdictRecord};
