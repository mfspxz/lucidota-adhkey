//! The epistemic cache: insert, compress, evict, project, dereference.
//!
//! Eviction is scored, not binary, following the projection theorem:
//! an item may be evicted only if its eviction cannot change the next
//! permitted decision. The cache cannot know the consumer's decision
//! function, so it scores eviction safety from truth x source x
//! necessity and reports what it could not prove safe as UNKNOWN.

use crate::cas::CasStore;
use crate::item::{Content, ContextItem, Necessity, Source};
use luci_verdict_core::Epistemic;
use std::collections::BTreeMap;
use std::io;

/// Record of an eviction: what left, why, and how to get it back.
/// Nothing is ever evicted without a reconstruction path.
#[derive(Debug, Clone)]
pub struct EvictedRecord {
    pub key: String,
    pub cas_hash: String,
    pub original_len: usize,
    pub truth: Epistemic,
    pub reason: String,
}

/// A projected view: what the consumer sees, what was removed, and
/// whether the projection introduced UNKNOWN the consumer must handle.
#[derive(Debug)]
pub struct Projection {
    pub kept: Vec<ContextItem>,
    pub evicted: Vec<EvictedRecord>,
    /// True if anything evicted was Optional-or-higher necessity or
    /// Proven/Unknown truth: the projection is LOSSY and the consumer
    /// must treat the missing information as UNKNOWN, retrievable via
    /// the evicted records' CAS hashes.
    pub unknown_introduced: bool,
}

/// Eviction safety score. Higher = safer to evict. None = never evict:
/// Required items are pinned regardless of truth value.
pub fn eviction_score(item: &ContextItem) -> Option<i32> {
    let base: i32 = match item.necessity {
        Necessity::Required => return None,
        Necessity::Optional => 10,
        Necessity::Irrelevant => 20,
    };
    let truth_adj: i32 = match item.truth {
        // Proven facts are load-bearing; keep them visible.
        Epistemic::Proven => -8,
        Epistemic::Unknown => 0,
        // Disproven hypotheses are cheap to drop from view — but their
        // hashes stay recorded, so "don't go there again" survives.
        Epistemic::Disproven => 8,
    };
    let source_adj: i32 = match item.source {
        Source::System => -4,
        Source::User => 0,
        Source::Discovered => 2,
    };
    Some(base + truth_adj + source_adj)
}

pub struct EpistemicCache<S: CasStore> {
    items: BTreeMap<String, ContextItem>,
    pub(crate) cas: S,
}

impl<S: CasStore> EpistemicCache<S> {
    pub fn new(cas: S) -> Self {
        EpistemicCache { items: BTreeMap::new(), cas }
    }

    pub fn insert(&mut self, item: ContextItem) {
        self.items.insert(item.key.clone(), item);
    }

    pub fn get(&self, key: &str) -> Option<&ContextItem> {
        self.items.get(key)
    }

    /// Compress an item: original bytes go to CAS, the item keeps a
    /// summary plus the hash and length needed to reconstruct.
    /// Information is relocated, not destroyed.
    pub fn compress(&mut self, key: &str, summary: &str) -> io::Result<bool> {
        let item = match self.items.get_mut(key) {
            Some(i) => i,
            None => return Ok(false),
        };
        let original = match &item.content {
            Content::Full(s) => s.clone(),
            Content::Compressed { .. } => return Ok(false), // already compressed
        };
        let hash = self.cas.put(original.as_bytes())?;
        let original_len = original.len();
        item.content = Content::Compressed {
            summary: summary.to_string(),
            cas_hash: hash,
            original_len,
        };
        Ok(true)
    }

    /// Dereference: get original bytes (or a byte range) for a key.
    pub fn dereference(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> io::Result<Option<Vec<u8>>> {
        let item = match self.items.get(key) {
            Some(i) => i,
            None => return Ok(None),
        };
        match &item.content {
            Content::Full(s) => {
                let b = s.as_bytes();
                match range {
                    None => Ok(Some(b.to_vec())),
                    Some((a, z)) => {
                        let s_ = (a as usize).min(b.len());
                        let e = (z as usize).min(b.len()).max(s_);
                        Ok(Some(b[s_..e].to_vec()))
                    }
                }
            }
            Content::Compressed { cas_hash, .. } => {
                Ok(Some(self.cas.get(cas_hash, range)?))
            }
        }
    }

    /// Eviction order: keys sorted by safety, safest first.
    /// Required items are absent (never evict).
    pub fn eviction_order(&self) -> Vec<(String, i32)> {
        let mut v: Vec<(String, i32)> = self
            .items
            .iter()
            .filter_map(|(k, i)| eviction_score(i).map(|s| (k.clone(), s)))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// Project the cache under a char budget: evict safest-first until
    /// under budget. Every eviction ensures the original is in CAS first
    /// (compressing on the way out if needed), so the projection is
    /// always reversible through the evicted records.
    pub fn project(&mut self, budget_chars: usize) -> io::Result<Projection> {
        // Ensure every item has a CAS-backed original before evicting.
        let keys: Vec<String> = self.items.keys().cloned().collect();
        for k in &keys {
            let needs = matches!(
                self.items.get(k).map(|i| &i.content),
                Some(Content::Full(_))
            );
            if needs {
                let placeholder = format!("[compressed:{}]", k);
                self.compress(k, &placeholder)?;
            }
        }
        let mut visible: usize = self.items.values().map(|i| i.visible_len()).sum();
        let mut evicted = Vec::new();
        let mut unknown_introduced = false;
        for (key, _score) in self.eviction_order() {
            if visible <= budget_chars {
                break;
            }
            if let Some(item) = self.items.remove(&key) {
                visible = visible.saturating_sub(item.visible_len());
                let (cas_hash, original_len) = match &item.content {
                    Content::Compressed { cas_hash, original_len, .. } => {
                        (cas_hash.clone(), *original_len)
                    }
                    Content::Full(s) => {
                        // Should not happen (pre-compressed above), but
                        // never lose bytes: store now.
                        let h = self.cas.put(s.as_bytes())?;
                        (h, s.len())
                    }
                };
                // Lossy iff the evicted item mattered: Optional+ or
                // Proven/Unknown truth. Disproven+Irrelevant is safe.
                if item.necessity != Necessity::Irrelevant
                    || item.truth != Epistemic::Disproven
                {
                    unknown_introduced = true;
                }
                evicted.push(EvictedRecord {
                    key: item.key.clone(),
                    cas_hash,
                    original_len,
                    truth: item.truth,
                    reason: "budget projection; reversible via CAS".into(),
                });
            }
        }
        let kept = self.items.values().cloned().collect();
        Ok(Projection { kept, evicted, unknown_introduced })
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::FileCas;
    use std::fs;

    fn test_cas(name: &str) -> FileCas {
        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        FileCas::open(&dir).unwrap()
    }

    fn item(key: &str, truth: Epistemic, src: Source, nec: Necessity) -> ContextItem {
        ContextItem::new(key, &format!("content-of-{}", key), truth, src, nec, "test")
    }

    #[test]
    fn required_never_evicts() {
        assert_eq!(
            eviction_score(&item("k", Epistemic::Disproven, Source::Discovered, Necessity::Required)),
            None
        );
    }

    #[test]
    fn eviction_order_safest_first() {
        let cas = test_cas("luci-cache-test-1");
        let mut c = EpistemicCache::new(cas);
        c.insert(item("proven-required", Epistemic::Proven, Source::System, Necessity::Required));
        c.insert(item("proven-optional", Epistemic::Proven, Source::System, Necessity::Optional));
        c.insert(item("disproven-irrelevant", Epistemic::Disproven, Source::Discovered, Necessity::Irrelevant));
        c.insert(item("unknown-optional", Epistemic::Unknown, Source::User, Necessity::Optional));
        let order: Vec<String> = c.eviction_order().into_iter().map(|(k, _)| k).collect();
        // disproven-irrelevant first, proven-required absent entirely.
        assert_eq!(order[0], "disproven-irrelevant");
        assert!(!order.contains(&"proven-required".to_string()));
        // proven-optional outranks unknown-optional (proven is load-bearing).
        let pi = order.iter().position(|k| k == "proven-optional").unwrap();
        let ui = order.iter().position(|k| k == "unknown-optional").unwrap();
        assert!(ui < pi);
    }

    #[test]
    fn compress_relocates_not_destroys() {
        let cas = test_cas("luci-cache-test-2");
        let mut c = EpistemicCache::new(cas);
        c.insert(item("doc", Epistemic::Proven, Source::System, Necessity::Required));
        assert!(c.compress("doc", "short summary").unwrap());
        let it = c.get("doc").unwrap();
        assert!(matches!(it.content, Content::Compressed { .. }));
        // Full bytes recoverable, including by range.
        let full = c.dereference("doc", None).unwrap().unwrap();
        assert_eq!(String::from_utf8(full).unwrap(), "content-of-doc");
        let part = c.dereference("doc", Some((0, 7))).unwrap().unwrap();
        assert_eq!(&part, b"content");
    }

    #[test]
    fn projection_marks_unknown_honestly() {
        let cas = test_cas("luci-cache-test-3");
        let mut c = EpistemicCache::new(cas);
        c.insert(item("big-optional", Epistemic::Unknown, Source::User, Necessity::Optional));
        // pad it large
        if let Some(it) = c.items.get_mut("big-optional") {
            it.content = Content::Full("x".repeat(5000));
        }
        c.insert(item("tiny-required", Epistemic::Proven, Source::System, Necessity::Required));
        let p = c.project(40).unwrap();
        // big-optional evicted (reversible), required kept, unknown flagged.
        assert_eq!(p.evicted.len(), 1);
        assert_eq!(p.evicted[0].key, "big-optional");
        assert!(p.unknown_introduced);
        assert!(c.cas.contains(&p.evicted[0].cas_hash));
        assert_eq!(p.kept.len(), 1);
    }

    #[test]
    fn projection_of_only_trivia_is_not_lossy() {
        let cas = test_cas("luci-cache-test-4");
        let mut c = EpistemicCache::new(cas);
        let mut it = item("trivia", Epistemic::Disproven, Source::Discovered, Necessity::Irrelevant);
        it.content = Content::Full("y".repeat(5000));
        c.insert(it);
        let p = c.project(10).unwrap();
        assert_eq!(p.evicted.len(), 1);
        assert!(!p.unknown_introduced); // safe: disproven + irrelevant
    }
}
