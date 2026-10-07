//! Task receipts: memory as a content-addressed evidence graph.
//!
//! A worker's shift leaves a TaskReceipt, not a transcript. Tomorrow's
//! worker resumes from `receipt:<hash>`: fetch the receipt, dereference
//! its context hashes, and continue with the original bytes — never a
//! lossy summary.
//!
//! The receipt id IS the SHA-256 of the canonical bytes. There is no
//! separate id field to forge or desynchronize: the address is the
//! checksum. `previous_receipt_hash` chains receipts into a chain of
//! custody; "genesis" anchors the chain.
//!
//! A receipt is a system record that the worker *reported* execution —
//! evidence of the decision, not of the underlying fact. Claims inside
//! the receipt carry their own epistemic verdicts.

use crate::cache::EpistemicCache;
use crate::cas::{hash_bytes, CasStore};
use crate::item::{Content, ContextItem, Necessity, Source};
use luci_verdict_core::Epistemic;
use std::fmt;
use std::io;

pub const RECEIPT_DOMAIN: &str = "ADHKEY/1/task-receipt";
pub const RECEIPT_VERSION: &str = "1";
pub const GENESIS: &str = "genesis";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestRecord {
    pub name: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictRecord {
    pub claim: String,
    pub state: Epistemic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub name: String,
    pub cas_hash: String,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskReceipt {
    pub task: String,
    pub input_hash: String,
    pub context_hashes: Vec<String>,
    pub tools_invoked: Vec<String>,
    pub capabilities_granted: Vec<String>,
    pub files_changed: Vec<String>,
    pub tests_executed: Vec<TestRecord>,
    pub observations: Vec<String>,
    pub claims: Vec<String>,
    pub verdicts: Vec<VerdictRecord>,
    pub output_artifacts: Vec<ArtifactRecord>,
    pub at: u64,
    pub previous_receipt_hash: String,
}

fn lp(s: &str) -> String {
    format!("{}:{}", s.len(), s)
}

impl TaskReceipt {
    /// Deterministic canonical bytes. Length-prefixed fields, fixed
    /// order, domain separation. The receipt id is the hash of this.
    pub fn canonical(&self) -> String {
        let mut p = vec![
            RECEIPT_DOMAIN.to_string(),
            lp(RECEIPT_VERSION),
            lp(&self.task),
            lp(&self.input_hash),
        ];
        p.push(self.context_hashes.len().to_string());
        for h in &self.context_hashes {
            p.push(lp(h));
        }
        p.push(self.tools_invoked.len().to_string());
        for t in &self.tools_invoked {
            p.push(lp(t));
        }
        p.push(self.capabilities_granted.len().to_string());
        for c in &self.capabilities_granted {
            p.push(lp(c));
        }
        p.push(self.files_changed.len().to_string());
        for f in &self.files_changed {
            p.push(lp(f));
        }
        p.push(self.tests_executed.len().to_string());
        for t in &self.tests_executed {
            p.push(lp(&t.name));
            p.push(if t.passed { "1".to_string() } else { "0".to_string() });
        }
        p.push(self.observations.len().to_string());
        for o in &self.observations {
            p.push(lp(o));
        }
        p.push(self.claims.len().to_string());
        for c in &self.claims {
            p.push(lp(c));
        }
        p.push(self.verdicts.len().to_string());
        for v in &self.verdicts {
            p.push(lp(&v.claim));
            p.push(format!("{}", v.state as i8));
        }
        p.push(self.output_artifacts.len().to_string());
        for a in &self.output_artifacts {
            p.push(lp(&a.name));
            p.push(lp(&a.cas_hash));
            p.push(a.len.to_string());
        }
        p.push(self.at.to_string());
        p.push(lp(&self.previous_receipt_hash));
        p.join("|")
    }

    /// The receipt's address: SHA-256 hex of the canonical bytes.
    pub fn id(&self) -> String {
        hash_bytes(self.canonical().as_bytes())
    }

    /// Parse canonical bytes back. Rejects wrong domain, wrong version,
    /// truncation, trailing bytes, and malformed hashes.
    pub fn parse(s: &str) -> Result<TaskReceipt, ParseError> {
        let prefix = format!("{}|", RECEIPT_DOMAIN);
        let rest = s
            .strip_prefix(prefix.as_str())
            .ok_or_else(|| ParseError("bad domain".into()))?;
        let mut c = Cursor::new(rest);
        let version = c.field()?;
        if version != RECEIPT_VERSION {
            return Err(ParseError(format!("unsupported version: {}", version)));
        }
        let task = c.field()?;
        let input_hash = c.field()?;
        expect_hash(&input_hash, "input_hash")?;
        let context_hashes = c.vec_field(|c| {
            let h = c.field()?;
            expect_hash(&h, "context_hash")?;
            Ok(h)
        })?;
        let tools_invoked = c.vec_field(|c| c.field())?;
        let capabilities_granted = c.vec_field(|c| c.field())?;
        let files_changed = c.vec_field(|c| c.field())?;
        let tests_executed = c.vec_field(|c| {
            let name = c.field()?;
            let passed = c.flag()?;
            Ok(TestRecord { name, passed })
        })?;
        let observations = c.vec_field(|c| c.field())?;
        let claims = c.vec_field(|c| c.field())?;
        let verdicts = c.vec_field(|c| {
            let claim = c.field()?;
            let state = match c.i8_field()? {
                -1 => Epistemic::Disproven,
                0 => Epistemic::Unknown,
                1 => Epistemic::Proven,
                v => return Err(ParseError(format!("bad epistemic: {}", v))),
            };
            Ok(VerdictRecord { claim, state })
        })?;
        let output_artifacts = c.vec_field(|c| {
            let name = c.field()?;
            let cas_hash = c.field()?;
            expect_hash(&cas_hash, "artifact cas_hash")?;
            let len = c.count()?;
            Ok(ArtifactRecord { name, cas_hash, len })
        })?;
        let at = c.u64_field()?;
        let previous_receipt_hash = c.field()?;
        expect_hash_or_genesis(&previous_receipt_hash)?;
        c.end()?;
        Ok(TaskReceipt {
            task,
            input_hash,
            context_hashes,
            tools_invoked,
            capabilities_granted,
            files_changed,
            tests_executed,
            observations,
            claims,
            verdicts,
            output_artifacts,
            at,
            previous_receipt_hash,
        })
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn expect_hash(s: &str, what: &str) -> Result<(), ParseError> {
    if is_hex64(s) {
        Ok(())
    } else {
        Err(ParseError(format!("{} is not a 64-hex hash", what)))
    }
}

fn expect_hash_or_genesis(s: &str) -> Result<(), ParseError> {
    if s == GENESIS || is_hex64(s) {
        Ok(())
    } else {
        Err(ParseError("previous_receipt_hash must be genesis or 64-hex".into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "receipt parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

struct Cursor<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(s: &'a str) -> Self {
        Cursor { s, pos: 0 }
    }

    /// Take a length-prefixed field "<len>:<bytes>", then '|' or end.
    fn field(&mut self) -> Result<String, ParseError> {
        let rest = &self.s[self.pos..];
        let colon = rest
            .find(':')
            .ok_or_else(|| ParseError("missing ':' in length prefix".into()))?;
        let len: usize = rest[..colon]
            .parse()
            .map_err(|_| ParseError("bad field length".into()))?;
        let start = self.pos + colon + 1;
        let end = start
            .checked_add(len)
            .ok_or_else(|| ParseError("field length overflow".into()))?;
        if end > self.s.len() {
            return Err(ParseError("truncated field".into()));
        }
        if !self.s.is_char_boundary(start) || !self.s.is_char_boundary(end) {
            return Err(ParseError("field splits a char boundary".into()));
        }
        let out = self.s[start..end].to_string();
        self.pos = end;
        self.sep()?;
        Ok(out)
    }

    /// Consume one '|' separator; end-of-input is also fine.
    fn sep(&mut self) -> Result<(), ParseError> {
        if self.pos < self.s.len() {
            if self.s[self.pos..].starts_with('|') {
                self.pos += 1;
            } else {
                return Err(ParseError("expected '|' separator".into()));
            }
        }
        Ok(())
    }

    /// Take a decimal count terminated by '|'.
    fn count(&mut self) -> Result<usize, ParseError> {
        let rest = &self.s[self.pos..];
        let pipe = rest
            .find('|')
            .ok_or_else(|| ParseError("missing '|' after count".into()))?;
        let n: usize = rest[..pipe]
            .parse()
            .map_err(|_| ParseError("bad count".into()))?;
        self.pos += pipe + 1;
        Ok(n)
    }

    fn u64_field(&mut self) -> Result<u64, ParseError> {
        let rest = &self.s[self.pos..];
        let pipe = rest
            .find('|')
            .ok_or_else(|| ParseError("missing '|' after u64".into()))?;
        let n: u64 = rest[..pipe]
            .parse()
            .map_err(|_| ParseError("bad u64".into()))?;
        self.pos += pipe + 1;
        Ok(n)
    }

    fn i8_field(&mut self) -> Result<i8, ParseError> {
        let rest = &self.s[self.pos..];
        let pipe = rest
            .find('|')
            .ok_or_else(|| ParseError("missing '|' after i8".into()))?;
        let n: i8 = rest[..pipe]
            .parse()
            .map_err(|_| ParseError("bad i8".into()))?;
        self.pos += pipe + 1;
        Ok(n)
    }

    /// Take "1"/"0" terminated by '|'.
    fn flag(&mut self) -> Result<bool, ParseError> {
        let rest = &self.s[self.pos..];
        let pipe = rest
            .find('|')
            .ok_or_else(|| ParseError("missing '|' after flag".into()))?;
        match &rest[..pipe] {
            "1" => {
                self.pos += pipe + 1;
                Ok(true)
            }
            "0" => {
                self.pos += pipe + 1;
                Ok(false)
            }
            _ => Err(ParseError("flag must be 0 or 1".into())),
        }
    }

    fn vec_field<T>(
        &mut self,
        mut one: impl FnMut(&mut Self) -> Result<T, ParseError>,
    ) -> Result<Vec<T>, ParseError> {
        let n = self.count()?;
        let mut v = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            v.push(one(self)?);
        }
        Ok(v)
    }

    fn end(&self) -> Result<(), ParseError> {
        if self.pos == self.s.len() {
            Ok(())
        } else {
            Err(ParseError("trailing bytes after receipt".into()))
        }
    }
}

/// What a worker gets when resuming: the receipt plus the original
/// context bytes it references — integrity-verified by the CAS.
#[derive(Debug)]
pub struct ResumeBundle {
    pub receipt: TaskReceipt,
    pub context_blobs: Vec<(String, Vec<u8>)>,
}

impl<S: CasStore> EpistemicCache<S> {
    /// Store a task receipt. Canonical bytes go to CAS; the item is
    /// keyed `receipt:<hash>` as a Required system record and
    /// compressed immediately (the bytes live in CAS; the item keeps a
    /// summary). Returns the receipt hash — the resume address.
    pub fn store_receipt(&mut self, receipt: &TaskReceipt) -> io::Result<String> {
        let bytes = receipt.canonical();
        let hash = self.cas.put(bytes.as_bytes())?;
        debug_assert_eq!(hash, receipt.id());
        let key = format!("receipt:{}", hash);
        let summary = format!(
            "task-receipt '{}': {} tools, {} tests, {} verdicts, {} artifacts, prev={}",
            receipt.task,
            receipt.tools_invoked.len(),
            receipt.tests_executed.len(),
            receipt.verdicts.len(),
            receipt.output_artifacts.len(),
            &receipt.previous_receipt_hash[..receipt.previous_receipt_hash.len().min(12)],
        );
        let item = ContextItem::new(
            &key,
            &bytes,
            Epistemic::Proven,
            Source::System,
            Necessity::Required,
            "task-receipt: system record of worker-reported execution; \
             claims inside carry their own epistemic verdicts",
        );
        self.insert(item);
        // Compress at once: bytes are already CAS-backed, so the item
        // keeps only the summary. Information relocated, not destroyed.
        self.compress(&key, &summary)?;
        // Sanity: the item must reference the same hash we return.
        match self.get(&key).map(|i| &i.content) {
            Some(Content::Compressed { cas_hash, .. }) if cas_hash == &hash => {}
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("receipt item CAS mismatch: {:?}", other.is_some()),
                ))
            }
        }
        Ok(hash)
    }

    /// Fetch a receipt by hash. Verifies the key matches the content
    /// hash (the CAS already verified the bytes against the address).
    /// Unknown hash -> Ok(None). Corrupt content -> Err.
    pub fn fetch_receipt(&self, hash: &str) -> io::Result<Option<TaskReceipt>> {
        if !is_hex64(hash) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receipt hash must be 64 hex chars",
            ));
        }
        let key = format!("receipt:{}", hash);
        let item = match self.get(&key) {
            Some(i) => i,
            None => return Ok(None),
        };
        let bytes: Vec<u8> = match &item.content {
            Content::Full(s) => s.as_bytes().to_vec(),
            Content::Compressed { cas_hash, .. } => self.cas.get(cas_hash, None)?,
        };
        let text = String::from_utf8(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let receipt =
            TaskReceipt::parse(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if receipt.id() != hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "receipt key does not match content hash",
            ));
        }
        Ok(Some(receipt))
    }

    /// Resume from `receipt:<hash>`: the receipt plus every context
    /// blob it references, byte-identical to what the original worker
    /// saw. This is what replaces the transcript.
    pub fn resume_from_receipt(&self, hash: &str) -> io::Result<Option<ResumeBundle>> {
        let receipt = match self.fetch_receipt(hash)? {
            Some(r) => r,
            None => return Ok(None),
        };
        let mut context_blobs = Vec::with_capacity(receipt.context_hashes.len());
        for h in &receipt.context_hashes {
            let bytes = self.cas.get(h, None)?;
            context_blobs.push((h.clone(), bytes));
        }
        Ok(Some(ResumeBundle { receipt, context_blobs }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::FileCas;
    use std::fs;

    fn test_cache(name: &str) -> EpistemicCache<FileCas> {
        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        EpistemicCache::new(FileCas::open(&dir).unwrap())
    }

    fn h(s: &str) -> String {
        hash_bytes(s.as_bytes())
    }

    fn sample_receipt(prev: &str) -> TaskReceipt {
        TaskReceipt {
            task: "harden luci-verdict-core".into(),
            input_hash: h("task input bytes"),
            context_hashes: vec![h("ctx one"), h("ctx two")],
            tools_invoked: vec!["muse.exec".into(), "muse.write".into()],
            capabilities_granted: vec!["fs:write:~/workspace/adhkey".into()],
            files_changed: vec!["crates/luci-verdict-core/src/witness.rs".into()],
            tests_executed: vec![
                TestRecord { name: "transitive_control_collapses".into(), passed: true },
                TestRecord { name: "cycle_does_not_hang".into(), passed: false },
            ],
            observations: vec!["witness count collapsed 2->1".into()],
            claims: vec!["V004 is killed".into()],
            verdicts: vec![
                VerdictRecord { claim: "V004 is killed".into(), state: Epistemic::Proven },
                VerdictRecord { claim: "no regressions".into(), state: Epistemic::Unknown },
            ],
            output_artifacts: vec![ArtifactRecord {
                name: "witness.rs".into(),
                cas_hash: h("artifact bytes"),
                len: 14,
            }],
            at: 1791340000,
            previous_receipt_hash: prev.into(),
        }
    }

    #[test]
    fn canonical_roundtrip() {
        let r = sample_receipt(GENESIS);
        let bytes = r.canonical();
        assert!(bytes.starts_with("ADHKEY/1/task-receipt|"));
        let back = TaskReceipt::parse(&bytes).unwrap();
        assert_eq!(r, back);
        // Deterministic: same receipt -> same bytes -> same id.
        assert_eq!(r.canonical(), back.canonical());
        assert_eq!(r.id(), back.id());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(TaskReceipt::parse("").is_err());
        assert!(TaskReceipt::parse("ADHKEY/1/task-receipt|").is_err());
        let r = sample_receipt(GENESIS);
        let mut bad = r.canonical();
        bad.truncate(bad.len() - 10); // truncation
        assert!(TaskReceipt::parse(&bad).is_err());
        let trailing = format!("{}|EXTRA", r.canonical());
        assert!(TaskReceipt::parse(&trailing).is_err());
        let wrong_domain = r.canonical().replacen("ADHKEY/1/task-receipt", "ADHKEY/1/other", 1);
        assert!(TaskReceipt::parse(&wrong_domain).is_err());
        // Field with pipes and colons inside survives (length-prefixing).
        let mut tricky = sample_receipt(GENESIS);
        tricky.task = "a|b:c::d||".into();
        tricky.observations = vec!["x|1:2".into()];
        assert_eq!(TaskReceipt::parse(&tricky.canonical()).unwrap(), tricky);
    }

    #[test]
    fn store_fetch_roundtrip() {
        let mut cache = test_cache("luci-receipt-test-1");
        let r = sample_receipt(GENESIS);
        let hash = cache.store_receipt(&r).unwrap();
        assert_eq!(hash, r.id());
        // Item is a Required system record, compressed at rest.
        let item = cache.get(&format!("receipt:{}", hash)).unwrap();
        assert_eq!(item.necessity, Necessity::Required);
        assert_eq!(item.source, Source::System);
        assert!(matches!(item.content, Content::Compressed { .. }));
        let back = cache.fetch_receipt(&hash).unwrap().unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn fetch_unknown_hash_is_none_not_error() {
        let cache = test_cache("luci-receipt-test-2");
        let nothing = cache.fetch_receipt(&h("nope")).unwrap();
        assert!(nothing.is_none());
        assert!(cache.fetch_receipt("not-a-hash").is_err());
    }

    #[test]
    fn resume_retrieves_original_bytes() {
        let mut cache = test_cache("luci-receipt-test-3");
        // Seed context blobs into CAS through the public API:
        // insert as items, compress (puts bytes in CAS).
        let blob1 = "original context bytes one — the worker saw exactly this";
        let blob2 = "second blob with unicode: héllo wörld ✓";
        cache.insert(ContextItem::new("ctx1", blob1, Epistemic::Proven, Source::System, Necessity::Required, "t"));
        cache.insert(ContextItem::new("ctx2", blob2, Epistemic::Unknown, Source::User, Necessity::Optional, "t"));
        cache.compress("ctx1", "s1").unwrap();
        cache.compress("ctx2", "s2").unwrap();
        let h1 = h(blob1);
        let h2 = h(blob2);

        let mut r = sample_receipt(GENESIS);
        r.context_hashes = vec![h1.clone(), h2.clone()];
        let hash = cache.store_receipt(&r).unwrap();

        // Simulate a fresh worker: drop nothing (CAS persists), resume.
        let bundle = cache.resume_from_receipt(&hash).unwrap().unwrap();
        assert_eq!(bundle.receipt, r);
        assert_eq!(bundle.context_blobs.len(), 2);
        assert_eq!(bundle.context_blobs[0], (h1, blob1.as_bytes().to_vec()));
        assert_eq!(bundle.context_blobs[1], (h2, blob2.as_bytes().to_vec()));
    }

    #[test]
    fn chain_of_custody_links() {
        let mut cache = test_cache("luci-receipt-test-4");
        let r1 = sample_receipt(GENESIS);
        let h1 = cache.store_receipt(&r1).unwrap();
        let r2 = sample_receipt(&h1);
        let h2 = cache.store_receipt(&r2).unwrap();
        let back2 = cache.fetch_receipt(&h2).unwrap().unwrap();
        assert_eq!(back2.previous_receipt_hash, h1);
        // Walk back one link.
        let back1 = cache.fetch_receipt(&back2.previous_receipt_hash).unwrap().unwrap();
        assert_eq!(back1.id(), h1);
        assert_eq!(back1.previous_receipt_hash, GENESIS);
    }

    #[test]
    fn key_content_mismatch_is_rejected() {
        let mut cache = test_cache("luci-receipt-test-5");
        // Rogue item: key claims one hash, content parses to another.
        let r = sample_receipt(GENESIS);
        let evil_key = format!("receipt:{}", h("different"));
        cache.insert(ContextItem::new(
            &evil_key,
            &r.canonical(),
            Epistemic::Proven,
            Source::System,
            Necessity::Required,
            "t",
        ));
        let res = cache.fetch_receipt(&h("different"));
        assert!(res.is_err());
    }

    #[test]
    fn empty_receipt_roundtrips() {
        let r = TaskReceipt {
            task: "".into(),
            input_hash: h(""),
            context_hashes: vec![],
            tools_invoked: vec![],
            capabilities_granted: vec![],
            files_changed: vec![],
            tests_executed: vec![],
            observations: vec![],
            claims: vec![],
            verdicts: vec![],
            output_artifacts: vec![],
            at: 0,
            previous_receipt_hash: GENESIS.into(),
        };
        assert_eq!(TaskReceipt::parse(&r.canonical()).unwrap(), r);
        let mut cache = test_cache("luci-receipt-test-6");
        let hash = cache.store_receipt(&r).unwrap();
        assert_eq!(cache.fetch_receipt(&hash).unwrap().unwrap(), r);
    }
}
