//! Context items: truth x source x necessity.

use luci_verdict_core::Epistemic;

/// The audit input trinity: where did this information originate?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// The system itself records this (ledger, receipts, CAS).
    System,
    /// The user provided this.
    User,
    /// Discovered through investigation / observation.
    Discovered,
}

/// Operational projection of necessity. Not ontology — this is the
/// cache's working judgment about decision-relevance, and it can be
/// wrong, which is why eviction is scored, not binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Necessity {
    Required,
    Optional,
    Irrelevant,
}

/// The item's content: full bytes, or a compressed form that retains
/// a path back to the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Full(String),
    Compressed {
        summary: String,
        cas_hash: String,
        original_len: usize,
    },
}

/// One unit of context under epistemic management.
#[derive(Debug, Clone)]
pub struct ContextItem {
    /// Human key, e.g. "RFC-001.md".
    pub key: String,
    pub content: Content,
    pub truth: Epistemic,
    pub source: Source,
    pub necessity: Necessity,
    /// Where it came from: free text, never trusted as authority.
    pub provenance: String,
}

impl ContextItem {
    pub fn new(
        key: &str,
        content: &str,
        truth: Epistemic,
        source: Source,
        necessity: Necessity,
        provenance: &str,
    ) -> Self {
        ContextItem {
            key: key.to_string(),
            content: Content::Full(content.to_string()),
            truth,
            source,
            necessity,
            provenance: provenance.to_string(),
        }
    }

    /// Approximate visible size in chars (what the model would see).
    pub fn visible_len(&self) -> usize {
        match &self.content {
            Content::Full(s) => s.len(),
            Content::Compressed { summary, .. } => summary.len(),
        }
    }
}
