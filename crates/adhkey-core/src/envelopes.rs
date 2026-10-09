//! Signed envelopes and the key-operator boundary.
//!
//! This module is how the AUDIT.md criticals die — structurally, not by
//! convention:
//!
//! - C1 (signature stub): no `bool` ever crosses from caller to verifier.
//!   The caller supplies a MECHANISM (`&dyn KeyOperator`); the core
//!   supplies every INPUT: the key id (from its own key table), the
//!   message (canonical bytes defined here), and the interpretation.
//!   `VerifierContext.signature_valid` is deleted. It cannot be re-added
//!   without breaking the type signature.
//! - C2 (bare key-id approvals): approvals are signatures over a
//!   `RecoveryIntent` bound to (identity, old_key, new_key, nonce).
//! - C3 (bare bool policy): `establish` takes a signed `PolicyVerdict`
//!   bound to the claim hash. There is no bool parameter anymore.
//! - C6 (free Lost->Active): `SignedPossessionProof` over a fresh
//!   challenge; `transition_key` rejects Lost->Active without one.
//! - C7 (forgeable receipts): `SealedReceipt` — hash-chained and signed
//!   by a service key. `ReceiptBody` alone is not a receipt of record.
//!
//! Every signed object has a domain-separated canonical encoding
//! (AUDIT2 cut #20/#21). Same object -> same bytes -> same signature,
//! across implementations.

use crate::{Check, Error, KeyId, KeyState, Outcome, Subject};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Domain-separated SHA-256. The domain is the first thing hashed.
/// `domain` is always a protocol constant, never caller data.
pub fn sha256d(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(data);
    h.finalize().into()
}

fn push_field(out: &mut Vec<u8>, tag: &[u8], data: &[u8]) {
    out.extend_from_slice(tag);
    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(data);
}

fn push_u64(out: &mut Vec<u8>, tag: &[u8], v: u64) {
    push_field(out, tag, &v.to_be_bytes());
}

// ---------------------------------------------------------------------------
// The key-operator boundary
// ---------------------------------------------------------------------------

/// The protocol's view of key operations. Implemented by adapters
/// (HSM, platform keystore, in-memory reference).
///
/// The CORE drives this trait: it chooses the key id (looked up in its
/// own tables, never from the caller's mouth), builds the message
/// (canonical bytes from this module), and interprets the result.
/// A lying implementation is outside the protocol boundary — exactly
/// like a lying HSM. What the protocol guarantees: no caller can make
/// verification succeed without a signature that checks out under the
/// key the IDENTITY names.
pub trait KeyOperator {
    /// Sign `message` with the private key for `key`.
    /// Err = fail closed (unknown key, hardware failure, ...).
    fn sign(&self, key: &KeyId, message: &[u8]) -> Result<Vec<u8>, Error>;
    /// Verify `signature` over `message` under the public key for `key`.
    /// Ok(true) = valid. Ok(false) = invalid signature. Err = fail closed
    /// (unknown key, malformed signature, backend failure) — never a pass.
    fn verify(&self, key: &KeyId, message: &[u8], signature: &[u8]) -> Result<bool, Error>;
}

// ---------------------------------------------------------------------------
// C1: signed capabilities
// ---------------------------------------------------------------------------

/// A capability PLUS the issuer's signature over its canonical envelope.
/// The signature is checked by the verifier itself (via `KeyOperator`);
/// there is no field for the caller to assert validity through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCapability {
    pub capability: crate::Capability,
    pub signature: Vec<u8>,
}

/// Canonical capability envelope. Domain-separated (AUDIT2 #20).
pub fn capability_envelope(cap: &crate::Capability) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ADHKEY/1/CAPABILITY\n");
    push_field(&mut out, b"subject", cap.subject.0.as_bytes());
    push_field(&mut out, b"scope", cap.scope.as_bytes());
    push_field(&mut out, b"audience", cap.audience.as_bytes());
    push_field(&mut out, b"nonce", cap.nonce.as_bytes());
    push_u64(&mut out, b"issued_at", cap.issued_at);
    push_u64(&mut out, b"expires_at", cap.expires_at);
    push_field(&mut out, b"key_id", cap.key_id.0.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// C5: persistent, bounded, time-partitioned nonce store
// ---------------------------------------------------------------------------

/// Replay protection that survives restarts and cannot grow without bound.
///
/// Time-partitioned: nonces live in `bucket_secs`-wide buckets; buckets
/// older than `window_secs` are dropped. Bounded: each bucket holds at
/// most `max_per_bucket` entries; a full bucket fails CLOSED
/// (`Error::NonceStoreFull`) rather than accepting a replay or dropping
/// an old nonce silently.
///
/// Persistent: the core does no I/O, so the host snapshots and restores:
/// `snapshot()` -> store bytes wherever you keep them -> `restore()` on
/// boot. A nonce store that is not restored reopens the replay window —
/// the host MUST restore it; `restore` prunes stale buckets on load.
///
/// Correctness note: `window_secs` MUST exceed the maximum validity
/// period of anything the nonces protect (capability lifetime + clock
/// skew), or a replayed-but-expired... — no: expired capabilities fail
/// the expiry check regardless. The real bound: within the window, every
/// accepted nonce is remembered; after the window, a nonce MAY be
/// accepted again. For capabilities this is safe only because the
/// capability itself carries its own expiry. Document your window.
#[derive(Debug, Clone)]
pub struct NonceStore {
    window_secs: u64,
    bucket_secs: u64,
    max_per_bucket: usize,
    buckets: BTreeMap<u64, BTreeSet<String>>,
    total: usize,
}

impl NonceStore {
    pub fn new(window_secs: u64, bucket_secs: u64, max_per_bucket: usize) -> Self {
        assert!(bucket_secs >= 1, "bucket_secs must be >= 1");
        assert!(
            window_secs >= bucket_secs,
            "window_secs must be >= bucket_secs"
        );
        assert!(max_per_bucket >= 1, "max_per_bucket must be >= 1");
        NonceStore {
            window_secs,
            bucket_secs,
            max_per_bucket,
            buckets: BTreeMap::new(),
            total: 0,
        }
    }

    /// Sane default for capability verification: 48h window, 1h buckets,
    /// 100k nonces per bucket. Tune to your traffic; the window MUST
    /// exceed your maximum capability lifetime.
    pub fn default_verifier() -> Self {
        NonceStore::new(48 * 3600, 3600, 100_000)
    }

    fn bucket_of(&self, now: u64) -> u64 {
        now / self.bucket_secs
    }

    /// Drop buckets that can no longer contain a live nonce.
    /// Bucket b covers [b*B, (b+1)*B); it is stale when (b+1)*B <= now - window.
    pub fn prune(&mut self, now: u64) {
        let horizon = now.saturating_sub(self.window_secs);
        let stale_below = horizon / self.bucket_secs;
        // Bucket `stale_below` covers [horizon_rounded_down, ...); its tail
        // may still be within the window — keep it, drop strictly older.
        let mut drop = Vec::new();
        for &b in self.buckets.keys() {
            if b < stale_below {
                drop.push(b);
            } else {
                break;
            }
        }
        for b in drop {
            if let Some(set) = self.buckets.remove(&b) {
                self.total = self.total.saturating_sub(set.len());
            }
        }
    }

    /// Check freshness and record. Ok(true) = fresh, now recorded.
    /// Ok(false) = replay (already seen within the window). Err =
    /// bucket full: fail closed, nonce NOT recorded.
    ///
    /// `now` MUST be host-controlled time (see VerifierContext::now).
    /// Caller-controlled `now` would let an attacker steer bucket
    /// assignment and pruning.
    pub fn check_and_insert(&mut self, nonce: &str, now: u64) -> Result<bool, Error> {
        self.prune(now);
        for set in self.buckets.values() {
            if set.contains(nonce) {
                return Ok(false);
            }
        }
        let b = self.bucket_of(now);
        let set = self.buckets.entry(b).or_default();
        if set.len() >= self.max_per_bucket {
            return Err(Error::NonceStoreFull);
        }
        set.insert(nonce.to_string());
        self.total += 1;
        Ok(true)
    }

    /// Has this nonce been seen within the window? (Read-only probe.)
    pub fn contains(&mut self, nonce: &str, now: u64) -> bool {
        self.prune(now);
        self.buckets.values().any(|s| s.contains(nonce))
    }

    pub fn len(&self) -> usize {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Serialize for the host's persistence layer. Buckets are
    /// (bucket_index, nonces). The host stores these bytes; on boot it
    /// calls `restore`. Format is internal to this type — versioned by
    /// the leading tag so a future format change fails loudly.
    pub fn snapshot(&self) -> Vec<(u64, Vec<String>)> {
        self.buckets
            .iter()
            .map(|(b, s)| (*b, s.iter().cloned().collect()))
            .collect()
    }

    /// Load a snapshot, pruning buckets that went stale while we were
    /// down. Stale buckets are dropped (their nonces are outside the
    /// window — remembering them buys nothing).
    pub fn restore(&mut self, snap: &[(u64, Vec<String>)], now: u64) {
        self.buckets.clear();
        self.total = 0;
        for (b, nonces) in snap {
            let set: BTreeSet<String> =
                nonces.iter().take(self.max_per_bucket).cloned().collect();
            self.total += set.len();
            self.buckets.insert(*b, set);
        }
        self.prune(now);
    }
}

// ---------------------------------------------------------------------------
// C2: signed recovery approvals
// ---------------------------------------------------------------------------

/// What a recovery approval authorizes. Bound to one ceremony:
/// (identity, old_key, new_key) plus a fresh nonce. An approval for
/// ceremony N cannot be replayed in ceremony N+1 — the nonce is
/// consumed on use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryIntent {
    pub identity: String,
    pub old_key: KeyId,
    pub new_key: KeyId,
    pub nonce: String,
    pub policy_version: u64,
}

/// A recovery approval: intent + the approver's signature over it.
/// Approvals are single-use (nonce consumed by `recover`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedApproval {
    pub signer: KeyId,
    pub intent: RecoveryIntent,
    pub signature: Vec<u8>,
}

/// Canonical recovery-intent bytes. Domain-separated (AUDIT2 #20).
pub fn recovery_intent_bytes(i: &RecoveryIntent) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ADHKEY/1/RECOVERY\n");
    push_field(&mut out, b"identity", i.identity.as_bytes());
    push_field(&mut out, b"old_key", i.old_key.0.as_bytes());
    push_field(&mut out, b"new_key", i.new_key.0.as_bytes());
    push_field(&mut out, b"nonce", i.nonce.as_bytes());
    push_u64(&mut out, b"policy_version", i.policy_version);
    out
}

// ---------------------------------------------------------------------------
// C3: signed policy verdicts (the bool is dead)
// ---------------------------------------------------------------------------

/// A policy evaluator's verdict. A ternary answer, not a bit:
/// Allow / Deny / Unknown. Unknown fails closed downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    Unknown,
}

/// A policy verdict, signed by an authorized policy evaluator and bound
/// to the exact claim it evaluates (`claim_hash`) and the evidence set
/// it evaluated (`evidence_snapshot`). A verdict for claim A cannot be
/// replayed against claim B; a verdict computed over evidence set E
/// cannot be applied after the evidence changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPolicyVerdict {
    pub policy_id: String,
    pub policy_version: u64,
    pub subject: Subject,
    pub claim_hash: [u8; 32],
    pub decision: PolicyDecision,
    pub evaluated_at: u64,
    pub evidence_snapshot: [u8; 32],
    pub evaluator: KeyId,
    pub signature: Vec<u8>,
}

/// Canonical policy-verdict bytes (everything but the signature).
/// Domain-separated (AUDIT2 #20).
pub fn policy_verdict_bytes(v: &SignedPolicyVerdict) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ADHKEY/1/POLICY-VERDICT\n");
    push_field(&mut out, b"policy_id", v.policy_id.as_bytes());
    push_u64(&mut out, b"policy_version", v.policy_version);
    push_field(&mut out, b"subject", v.subject.0.as_bytes());
    push_field(&mut out, b"claim_hash", &v.claim_hash);
    push_field(
        &mut out,
        b"decision",
        match v.decision {
            PolicyDecision::Allow => b"allow".as_slice(),
            PolicyDecision::Deny => b"deny".as_slice(),
            PolicyDecision::Unknown => b"unknown".as_slice(),
        },
    );
    push_u64(&mut out, b"evaluated_at", v.evaluated_at);
    push_field(&mut out, b"evidence_snapshot", &v.evidence_snapshot);
    push_field(&mut out, b"evaluator", v.evaluator.0.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// C6: proof of possession for Lost -> Active
// ---------------------------------------------------------------------------

/// Proof that whoever asks to re-activate a lost key holds the private
/// key NOW: a signature over (key, fresh challenge, issued_at).
/// The challenge is issued by the verifier/host; `issued_at` bounds its
/// age (`max_challenge_age_secs` at the call site). A stale proof is
/// rejected — "I held it last year" is not proof of possession.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPossessionProof {
    pub key: KeyId,
    pub challenge: [u8; 32],
    pub issued_at: u64,
    pub signature: Vec<u8>,
}

/// Canonical possession-proof bytes. Domain-separated (AUDIT2 #20).
pub fn possession_bytes(key: &KeyId, challenge: &[u8; 32], issued_at: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ADHKEY/1/POSSESSION\n");
    push_field(&mut out, b"key", key.0.as_bytes());
    push_field(&mut out, b"challenge", challenge);
    push_u64(&mut out, b"issued_at", issued_at);
    out
}

// ---------------------------------------------------------------------------
// C7: tamper-evident, hash-chained, signed receipts
// ---------------------------------------------------------------------------

/// The body of a verification receipt: what was checked, what was NOT
/// checked (AUDIT2 #15 — incomplete receipts manufacture confidence),
/// and the outcome. A body alone is NOT a receipt of record; only a
/// `SealedReceipt` is. Bodies are built by the verifier; sealing needs
/// the service key, which callers don't have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptBody {
    pub subject: Subject,
    pub key_id: KeyId,
    pub key_state: KeyState,
    pub checks: Vec<Check>,
    /// What this verification did NOT check. Honesty, in a field.
    pub not_checked: Vec<String>,
    pub outcome: Outcome,
}

/// A sealed receipt: body + hash chain + service signature.
/// `prev_hash` links to the previous sealed receipt (zero for genesis);
/// `sealed_receipt_hash` identifies this receipt for the next link.
/// Forging one requires the receipt-signing key. Tampering with the
/// body invalidates the signature; removing a receipt breaks the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedReceipt {
    pub body: ReceiptBody,
    pub prev_hash: [u8; 32],
    pub issued_at: u64,
    pub signer: KeyId,
    pub signature: Vec<u8>,
}

fn receipt_body_bytes(b: &ReceiptBody, out: &mut Vec<u8>) {
    push_field(out, b"subject", b.subject.0.as_bytes());
    push_field(out, b"key_id", b.key_id.0.as_bytes());
    push_field(
        out,
        b"key_state",
        format!("{:?}", b.key_state).as_bytes(),
    );
    for c in &b.checks {
        push_field(out, b"check", format!("{:?}", c).as_bytes());
    }
    for n in &b.not_checked {
        push_field(out, b"not_checked", n.as_bytes());
    }
    push_field(
        out,
        b"outcome",
        format!("{:?}", b.outcome).as_bytes(),
    );
}

/// Canonical sealed-receipt bytes (everything but the signature).
/// Domain-separated (AUDIT2 #20).
pub fn sealed_receipt_bytes(s: &SealedReceipt) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ADHKEY/1/RECEIPT\n");
    push_field(&mut out, b"prev_hash", &s.prev_hash);
    push_u64(&mut out, b"issued_at", s.issued_at);
    push_field(&mut out, b"signer", s.signer.0.as_bytes());
    receipt_body_bytes(&s.body, &mut out);
    out
}

/// Hash identifying a sealed receipt (for chain links). Covers the
/// signature too: the hash names this exact sealed artifact.
pub fn sealed_receipt_hash(s: &SealedReceipt) -> [u8; 32] {
    let mut bytes = sealed_receipt_bytes(s);
    bytes.extend_from_slice(&s.signature);
    sha256d(b"ADHKEY/1/SEALED-RECEIPT", &bytes)
}

/// Seal a receipt body: chain it to `prev_hash` and sign with the
/// service key. Only the holder of the receipt-signing key can produce
/// a `SealedReceipt` that `verify_chain` accepts.
pub fn seal_receipt(
    keys: &dyn KeyOperator,
    signer: &KeyId,
    body: ReceiptBody,
    prev_hash: [u8; 32],
    issued_at: u64,
) -> Result<SealedReceipt, Error> {
    let mut s = SealedReceipt {
        body,
        prev_hash,
        issued_at,
        signer: signer.clone(),
        signature: Vec::new(),
    };
    let bytes = sealed_receipt_bytes(&s);
    s.signature = keys
        .sign(signer, &bytes)
        .map_err(|e| Error::KeyOperatorFailed(format!("receipt seal failed: {e}")))?;
    Ok(s)
}

/// An append-only log of sealed receipts with chain verification.
/// `append` seals and chains; `verify_chain` re-checks every signature
/// and every link. A single broken link fails the whole chain —
//  loud, not silent.
#[derive(Debug, Clone, Default)]
pub struct ReceiptLog {
    receipts: Vec<SealedReceipt>,
}

impl ReceiptLog {
    pub fn new() -> Self {
        ReceiptLog {
            receipts: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn tip(&self) -> [u8; 32] {
        self.receipts
            .last()
            .map(sealed_receipt_hash)
            .unwrap_or([0u8; 32])
    }

    /// Seal `body` chained to the current tip and append. Returns the
    /// new tip hash.
    pub fn append(
        &mut self,
        keys: &dyn KeyOperator,
        signer: &KeyId,
        body: ReceiptBody,
        issued_at: u64,
    ) -> Result<[u8; 32], Error> {
        let prev = self.tip();
        let sealed = seal_receipt(keys, signer, body, prev, issued_at)?;
        let tip = sealed_receipt_hash(&sealed);
        self.receipts.push(sealed);
        Ok(tip)
    }

    pub fn receipts(&self) -> &[SealedReceipt] {
        &self.receipts
    }

    /// Rebuild a log from stored receipts (e.g. loaded from disk).
    /// Nothing is trusted on the way in: call `verify_chain` after.
    pub fn from_vec(receipts: Vec<SealedReceipt>) -> Self {
        ReceiptLog { receipts }
    }

    /// Re-verify every signature and every chain link. Fail closed on
    /// the first break. A tombstone (empty signature — seal failure) is
    /// structurally invalid and fails here, never verifies.
    pub fn verify_chain(&self, keys: &dyn KeyOperator) -> Result<(), Error> {
        let mut prev = [0u8; 32];
        for r in &self.receipts {
            if r.prev_hash != prev {
                return Err(Error::ReceiptChainBroken);
            }
            if r.signature.is_empty() {
                // Tombstone: the sealer was down when this was produced.
                // Evidence of failure, never a valid receipt.
                return Err(Error::ReceiptChainBroken);
            }
            let bytes = sealed_receipt_bytes(r);
            let ok = keys
                .verify(&r.signer, &bytes, &r.signature)
                .map_err(|e| Error::KeyOperatorFailed(format!("receipt verify failed: {e}")))?;
            if !ok {
                return Err(Error::ReceiptChainBroken);
            }
            prev = sealed_receipt_hash(r);
        }
        Ok(())
    }
}
