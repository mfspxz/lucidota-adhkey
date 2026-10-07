//! muse-exchange: sovereign daemon-less exchange organelle.
//!
//! One Rust binary. Embedded SurrealDB (`SurrealKv`) — no external
//! daemon, zero-latency epistemic graph access, pure local sovereignty.
//!
//! The organelle sits between the model and execution:
//!
//! ```text
//! PreToolUse hook -> authority query -> Authorized | Unknown | Denied
//!   Authorized -> execute, model sees only projected CAS pointers
//!   Unknown    -> DEFER (not a failure): evidence-gathering subtask
//!   Denied     -> block + ledger receipt
//! ```
//!
//! Reuses `luci-verdict-core` (Unknown→Deferred, epistemic ternary) and
//! `luci-context` (projection semantics, eviction ordering) as libraries.
//! The model is never the system of record. Ever.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use surrealdb::engine::local::{Db, SurrealKv};
use surrealdb::Surreal;

use luci_context::cache::eviction_score;
use luci_context::{CasStore, Content, ContextItem, EpistemicCache, Necessity, Source, TaskReceipt};
use luci_verdict_core::pipeline::{
    adjudicate, Attempt, CryptoStatus, Identity, PolicyInput, Verdict as CoreVerdict,
    VerdictInput,
};
use luci_verdict_core::witness::{EvidenceSet, ProvenanceGraph, Witness};
use luci_verdict_core::authority::EstablishmentPolicy;
use luci_verdict_core::{Claimed, Envelope, Epistemic};

// ---------------------------------------------------------------- errors

#[derive(Debug)]
pub enum ExchangeError {
    Db(surrealdb::Error),
    Io(std::io::Error),
    Json(serde_json::Error),
    Schema(String),
    LedgerFull,
}

impl std::fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExchangeError::Db(e) => write!(f, "db: {}", e),
            ExchangeError::Io(e) => write!(f, "io: {}", e),
            ExchangeError::Json(e) => write!(f, "json: {}", e),
            ExchangeError::Schema(e) => write!(f, "schema: {}", e),
            ExchangeError::LedgerFull => write!(f, "ledger at 10GB rotation limit"),
        }
    }
}

impl std::error::Error for ExchangeError {}

impl From<surrealdb::Error> for ExchangeError {
    fn from(e: surrealdb::Error) -> Self {
        ExchangeError::Db(e)
    }
}
impl From<std::io::Error> for ExchangeError {
    fn from(e: std::io::Error) -> Self {
        ExchangeError::Io(e)
    }
}
impl From<serde_json::Error> for ExchangeError {
    fn from(e: serde_json::Error) -> Self {
        ExchangeError::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, ExchangeError>;

// ---------------------------------------------------------------- projection error

/// The lossy-projection check is claimant-aware: when a required edge
/// is still verdict 0 (unknown), the error names the exact claimants
/// that failed to provide evidence, so the evidence-gathering subtask
/// knows who to interrogate or re-run.
#[derive(Debug)]
pub enum ProjectionError {
    LossyProjection { claimants: Vec<String> },
    Exchange(ExchangeError),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectionError::LossyProjection { claimants } => write!(
                f,
                "lossy projection: required evidence still unknown from claimants: {}",
                claimants.join(", ")
            ),
            ProjectionError::Exchange(e) => write!(f, "exchange: {}", e),
        }
    }
}

impl std::error::Error for ProjectionError {}

impl From<ExchangeError> for ProjectionError {
    fn from(e: ExchangeError) -> Self {
        ProjectionError::Exchange(e)
    }
}

impl From<surrealdb::Error> for ProjectionError {
    fn from(e: surrealdb::Error) -> Self {
        ProjectionError::Exchange(ExchangeError::Db(e))
    }
}

// ---------------------------------------------------------------- verdict

/// The ternary authority verdict. Maps 1:1 onto `Epistemic`:
/// Authorized=Proven(+1), Unknown=Unknown(0), Denied=Disproven(-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityVerdict {
    Authorized,
    Unknown,
    Denied,
}

impl AuthorityVerdict {
    pub fn epistemic(self) -> Epistemic {
        match self {
            AuthorityVerdict::Authorized => Epistemic::Proven,
            AuthorityVerdict::Unknown => Epistemic::Unknown,
            AuthorityVerdict::Denied => Epistemic::Disproven,
        }
    }

    /// Verdict mapping: 1 -> Authorized, -1 -> Denied, anything else
    /// (0, missing, malformed) -> Unknown. Absence of evidence is not
    /// evidence of authority.
    pub fn from_verdict(v: i8) -> Self {
        match v {
            1 => AuthorityVerdict::Authorized,
            -1 => AuthorityVerdict::Denied,
            _ => AuthorityVerdict::Unknown,
        }
    }
}

/// One row of the context budget: a CAS pointer with epistemic tags.
///
/// `claimant` is a first-class epistemic property: the exact actor
/// identity ("zackary", "lucidota", "subagent:g1-a",
/// "worker:nim-claimant-01"). It is NEVER collapsed into `source`,
/// which stays the broad trust domain (system|user|discovered|external).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPointer {
    pub hash: String,
    pub claimant: String,
    pub source: String,
    pub necessity: String,
    pub verdict: i8,
}

/// One `authorizes` edge from the epistemic graph: the raw material
/// for structural adjudication. The graph's verdict is an *input* to the
/// verdict-core pipeline — never a direct authorization.
#[derive(Debug, Clone)]
pub struct AuthorityEdge {
    pub tool: String,
    pub verdict: i8,
    pub claimant: String,
    pub source: String,
    pub hash: String,
    pub receipt_id: String,
    /// Validity window as unix seconds (from valid_from / valid_to).
    pub valid_from: u64,
    pub valid_to: u64,
}

/// Structural authority adjudication through luci-verdict-core.
///
/// The graph edge becomes a `VerdictInput`: the tool is a `Claimed`
/// identity, the edge's claimant is the witness, the edge's receipt
/// chain is the envelope's previous-receipt binding. The pipeline —
/// never a raw verdict mapping — decides:
///
/// - graph +1, fresh envelope, bound request, sufficient witness,
///   policy satisfied, activation proven -> Authorized
/// - graph -1 -> policy rejects -> Denied (terminal)
/// - graph 0 / missing / insufficient evidence -> Deferred -> Unknown
///
/// Returns the stage results (auditable), the authority verdict, and a
/// human-readable reason naming the terminal stage.
pub fn adjudicate_tool_authority(
    tool: &str,
    tool_input_hash: &str,
    edge: Option<&AuthorityEdge>,
    now_secs: u64,
) -> (
    luci_verdict_core::pipeline::StageResults,
    AuthorityVerdict,
    String,
) {
    // No edge: absence of evidence is not evidence of authority.
    // A minimal Deferred input keeps the pipeline as the single
    // decision point rather than branching around it.
    let edge = match edge {
        Some(e) => e,
        None => {
            let input = minimal_deferred_input(tool, tool_input_hash, now_secs);
            let (stages, verdict) = adjudicate(input);
            return (stages, map_core_verdict(&verdict), core_reason(&verdict));
        }
    };

    let policy_satisfied = match edge.verdict {
        1 => Epistemic::Proven,
        -1 => Epistemic::Disproven,
        _ => Epistemic::Unknown,
    };
    let activation = policy_satisfied; // the graph verdict drives activation too

    let envelope = Envelope {
        envelope_id: format!("env-{}-{}", tool, edge.receipt_id),
        subject_id: tool.to_string(),
        audience_id: "muse-exchange".to_string(),
        operation_id: "execute".to_string(),
        request_hash: tool_input_hash.to_string(),
        evidence_hash: edge.hash.clone(),
        policy_hash: "exchange-policy-v1".to_string(),
        policy_version: 1,
        nonce: format!("n-{}-{}", now_secs, edge.receipt_id),
        issued_at: edge.valid_from,
        expires_at: edge.valid_to,
        previous_receipt_hash: edge.receipt_id.clone(),
    };
    let input = VerdictInput {
        claimed_identity: Claimed::new(Identity { subject_id: tool.to_string() }),
        envelope,
        attempt: Attempt {
            subject_id: tool.to_string(),
            audience_id: "muse-exchange".to_string(),
            operation_id: "execute".to_string(),
            request_hash: tool_input_hash.to_string(),
            policy_hash: "exchange-policy-v1".to_string(),
            now: now_secs,
            max_skew_secs: 300,
        },
        evidence: EvidenceSet {
            witnesses: vec![Witness {
                id: format!("witness:{}", edge.claimant),
                trust_root: edge.source.clone(),
            }],
        },
        provenance: ProvenanceGraph::default(),
        policy: PolicyInput {
            establishment: EstablishmentPolicy { required_independent_witnesses: 1 },
            policy_satisfied,
        },
        // The local embedded graph IS the system of record; there is no
        // external signature to check on a locally-read edge.
        crypto: CryptoStatus::Valid,
        activation,
    };
    let (stages, verdict) = adjudicate(input);
    (stages, map_core_verdict(&verdict), core_reason(&verdict))
}

/// Minimal input for the no-edge case: crypto valid, envelope fresh and
/// bound, but zero witnesses and undecided policy -> Deferred at the
/// evidence stage. Unknown propagates; it never authorizes.
fn minimal_deferred_input(
    tool: &str,
    tool_input_hash: &str,
    now_secs: u64,
) -> VerdictInput {
    VerdictInput {
        claimed_identity: Claimed::new(Identity { subject_id: tool.to_string() }),
        envelope: Envelope {
            envelope_id: format!("env-{}-noedge", tool),
            subject_id: tool.to_string(),
            audience_id: "muse-exchange".to_string(),
            operation_id: "execute".to_string(),
            request_hash: tool_input_hash.to_string(),
            evidence_hash: "no-edge".to_string(),
            policy_hash: "exchange-policy-v1".to_string(),
            policy_version: 1,
            nonce: format!("n-{}", now_secs),
            issued_at: now_secs.saturating_sub(60),
            expires_at: now_secs + 3600,
            previous_receipt_hash: "genesis".to_string(),
        },
        attempt: Attempt {
            subject_id: tool.to_string(),
            audience_id: "muse-exchange".to_string(),
            operation_id: "execute".to_string(),
            request_hash: tool_input_hash.to_string(),
            policy_hash: "exchange-policy-v1".to_string(),
            now: now_secs,
            max_skew_secs: 300,
        },
        evidence: EvidenceSet { witnesses: vec![] },
        provenance: ProvenanceGraph::default(),
        policy: PolicyInput {
            establishment: EstablishmentPolicy { required_independent_witnesses: 1 },
            policy_satisfied: Epistemic::Unknown,
        },
        crypto: CryptoStatus::Valid,
        activation: Epistemic::Unknown,
    }
}

fn map_core_verdict(v: &CoreVerdict) -> AuthorityVerdict {
    match v {
        CoreVerdict::Authorized { .. } => AuthorityVerdict::Authorized,
        CoreVerdict::Denied { .. } => AuthorityVerdict::Denied,
        CoreVerdict::Deferred { .. } => AuthorityVerdict::Unknown,
    }
}

fn core_reason(v: &CoreVerdict) -> String {
    match v {
        CoreVerdict::Authorized { receipt } => {
            format!("pipeline AUTHORIZED at {:?} (receipt {})", receipt.terminal_stage, receipt.receipt_id)
        }
        CoreVerdict::Denied { stage, reason } => {
            format!("pipeline DENIED at {:?}: {}", stage, reason)
        }
        CoreVerdict::Deferred { stage, reason } => {
            format!("pipeline DEFERRED at {:?}: {}", stage, reason)
        }
    }
}

// ---------------------------------------------------------------- schema

/// Idempotent DDL for the epistemic graph. The canonical schema lives in
/// `graph-recalibration/lifelog-epistemic-schema.surql`; this is the
/// `IF NOT EXISTS` operational form applied at init.
const SCHEMA_DDL: &str = r#"
DEFINE TABLE IF NOT EXISTS lifelog_edge SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS in         ON lifelog_edge TYPE record;
DEFINE FIELD IF NOT EXISTS out        ON lifelog_edge TYPE record;
DEFINE FIELD IF NOT EXISTS edge_kind  ON lifelog_edge TYPE string
    ASSERT $value IN ['claims','observes','verifies','authorizes','executes'];
DEFINE FIELD IF NOT EXISTS hash       ON lifelog_edge TYPE string;
DEFINE FIELD IF NOT EXISTS source     ON lifelog_edge TYPE string
    ASSERT $value IN ['system','user','discovered','external'];
DEFINE FIELD IF NOT EXISTS claimant   ON lifelog_edge TYPE string
    ASSERT $value != NONE;
DEFINE FIELD IF NOT EXISTS necessity  ON lifelog_edge TYPE string
    ASSERT $value IN ['required','optional','irrelevant'];
DEFINE FIELD IF NOT EXISTS verdict    ON lifelog_edge TYPE int
    ASSERT $value IN [-1, 0, 1];
DEFINE FIELD IF NOT EXISTS receipt_id ON lifelog_edge TYPE string;
DEFINE FIELD IF NOT EXISTS valid_from ON lifelog_edge TYPE datetime;
DEFINE FIELD IF NOT EXISTS valid_to   ON lifelog_edge TYPE datetime;
DEFINE INDEX IF NOT EXISTS idx_edge_kind    ON lifelog_edge FIELDS edge_kind;
DEFINE INDEX IF NOT EXISTS idx_edge_verdict ON lifelog_edge FIELDS verdict;
DEFINE INDEX IF NOT EXISTS idx_claimant     ON lifelog_edge FIELDS claimant;
"#;

// ---------------------------------------------------------------- organelle

pub struct MuseExchange {
    db: Arc<Surreal<Db>>,
    ledger_path: PathBuf,
    evidence_queue: PathBuf,
}

impl MuseExchange {
    /// Sovereign init: embedded SurrealKv at `db_path`, namespace
    /// `lucidota`, database `epistemic_graph`. No daemon, no network.
    pub async fn init(
        db_path: &Path,
        ledger_path: PathBuf,
        evidence_queue: PathBuf,
    ) -> Result<Self> {
        let db = Surreal::new::<SurrealKv>(db_path).await?;
        db.use_ns("lucidota").use_db("epistemic_graph").await?;
        std::fs::create_dir_all(&evidence_queue)?;
        Ok(Self { db: Arc::new(db), ledger_path, evidence_queue })
    }

    pub fn db(&self) -> &Surreal<Db> {
        &self.db
    }

    /// Apply the epistemic schema. Idempotent: safe to run on every init.
    pub async fn apply_schema(&self) -> Result<()> {
        self.db.query(SCHEMA_DDL).await?.check()?;
        Ok(())
    }

    /// PreToolUse interception: fetch the latest `authorizes` edge for
    /// this tool and run it through luci-verdict-core's staged pipeline.
    /// The graph verdict is an input, never a direct authorization:
    /// Claimed(tool) -> Established(witness evidence) -> Authorized(policy).
    /// Unknown (or no edge) triggers the evidence-gathering path, never a
    /// hard failure.
    pub async fn handle_pre_tool_use(&self, tool: &str) -> Result<AuthorityVerdict> {
        let (_, verdict, _) = self.adjudicate_pre_tool_use(tool, "").await?;
        Ok(verdict)
    }

    /// Full structural adjudication for a tool call: returns the pipeline
    /// stage results, the authority verdict, and the terminal-stage reason.
    /// This is the integration joint between the embedded graph and
    /// luci-verdict-core — the mapping is structural, not nominal.
    pub async fn adjudicate_pre_tool_use(
        &self,
        tool: &str,
        tool_input: &str,
    ) -> Result<(
        luci_verdict_core::pipeline::StageResults,
        AuthorityVerdict,
        String,
    )> {
        #[derive(Deserialize)]
        struct EdgeRow {
            verdict: i8,
            claimant: String,
            source: String,
            hash: String,
            receipt_id: String,
            vf: u64,
            vt: u64,
        }
        let mut res = self
            .db
            .query(
                "SELECT verdict, claimant, source, hash, receipt_id, \
                        time::unix(valid_from) AS vf, time::unix(valid_to) AS vt \
                 FROM lifelog_edge \
                 WHERE edge_kind = 'authorizes' \
                   AND out = type::thing('tool', $tool) \
                 ORDER BY vf DESC LIMIT 1;",
            )
            .bind(("tool", tool.to_string()))
            .await?;
        let row: Option<EdgeRow> = res.take(0)?;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let input_hash = luci_context::cas::hash_bytes(
            format!("{}:{}", tool, tool_input).as_bytes(),
        );
        let edge = row.map(|r| AuthorityEdge {
            tool: tool.to_string(),
            verdict: r.verdict,
            claimant: r.claimant,
            source: r.source,
            hash: r.hash,
            receipt_id: r.receipt_id,
            valid_from: r.vf,
            valid_to: r.vt,
        });
        Ok(adjudicate_tool_authority(tool, &input_hash, edge.as_ref(), now_secs))
    }

    /// Close the execution loop: store the `TaskReceipt` in the epistemic
    /// cache (canonical bytes to CAS, Required/system record) and append
    /// a ledger entry binding the receipt hash to the verdict chain.
    /// Returns the receipt hash — the resume address.
    pub async fn record_execution<S: CasStore>(
        &self,
        engine: &mut EpistemicCache<S>,
        receipt: &TaskReceipt,
    ) -> Result<String> {
        let hash = engine
            .store_receipt(receipt)
            .map_err(ExchangeError::Io)?;
        let ledger_id = self
            .append_ledger(
                "execution",
                &format!(
                    "EXECUTED task '{}': receipt {} stored ({} tools, {} verdicts, prev={}); task chain closed",
                    receipt.task,
                    hash,
                    receipt.tools_invoked.len(),
                    receipt.verdicts.len(),
                    receipt.previous_receipt_hash,
                ),
                "executed",
            )
            .await?;
        let _ = ledger_id;
        Ok(hash)
    }

    /// The lossy projection theorem as a graph query: evict `irrelevant`
    /// necessity and disproven (`verdict = -1`) rows; return only safe
    /// CAS pointers, ordered most-relevant-first via luci-context's
    /// eviction scoring (least safe to evict = most relevant).
    ///
    /// Claimant-aware: if a `required` edge is still verdict 0
    /// (unknown), the projection is lossy and the error names the exact
    /// claimants that failed to provide evidence.
    pub async fn resolve_context_budget(
        &self,
        task_hash: &str,
    ) -> std::result::Result<Vec<ContextPointer>, ProjectionError> {
        let mut res = self
            .db
            .query(
                "SELECT hash, claimant, source, necessity, verdict FROM lifelog_edge \
                 WHERE in = type::thing('task', $task_hash) \
                   AND necessity != 'irrelevant' \
                   AND verdict != -1;",
            )
            .bind(("task_hash", task_hash.to_string()))
            .await?;
        let mut pointers: Vec<ContextPointer> = res.take(0)?;
        // Lossy-projection check: required evidence still unknown.
        let mut claimants: Vec<String> = pointers
            .iter()
            .filter(|p| p.necessity == "required" && p.verdict == 0)
            .map(|p| p.claimant.clone())
            .collect();
        claimants.sort();
        claimants.dedup();
        if !claimants.is_empty() {
            return Err(ProjectionError::LossyProjection { claimants });
        }
        // Relevance ordering through luci-context projection semantics:
        // items that must never be evicted (Required) surface first.
        pointers.sort_by_key(|p| relevance_rank(p));
        Ok(pointers)
    }

    /// Full routing: verdict -> hook decision, with ledger receipts on
    /// Denied and evidence-subtask dispatch on Unknown (Defer).
    pub async fn route(&self, req: &HookRequest) -> Result<HookDecision> {
        let verdict = self.handle_pre_tool_use(&req.tool_name).await?;
        match verdict {
            AuthorityVerdict::Authorized => {
                let task_hash = req.task_hash.clone().unwrap_or_else(|| {
                    luci_context::cas::hash_bytes(
                        format!("{}:{}", req.tool_name, req.tool_input).as_bytes(),
                    )
                });
                let pointers = match self.resolve_context_budget(&task_hash).await {
                    Ok(p) => p,
                    Err(ProjectionError::LossyProjection { claimants }) => {
                        // Authorized tool, but required context is still
                        // unknown: defer with a claimant-targeted evidence
                        // subtask naming who to interrogate or re-run.
                        let sub_path = self.dispatch_evidence_subtask_claimants(
                            &req.tool_name,
                            &format!(
                                "lossy projection: required evidence still unknown from claimants: {}",
                                claimants.join(", ")
                            ),
                            &claimants,
                        )?;
                        let _ = self
                            .append_ledger(
                                "verdict",
                                &format!(
                                    "DEFERRED tool '{}': lossy projection; claimants failing evidence: {}; subtask {}",
                                    req.tool_name,
                                    claimants.join(", "),
                                    sub_path.display()
                                ),
                                "deferred",
                            )
                            .await;
                        return Ok(HookDecision {
                            decision: "block",
                            reason: format!(
                                "DEFERRED (lossy projection): required evidence still unknown \
                                 from claimants: {}. Evidence-gathering subtask dispatched to {}. \
                                 Retry after the graph carries proven evidence.",
                                claimants.join(", "),
                                sub_path.display()
                            ),
                            additional_context: None,
                        });
                    }
                    Err(ProjectionError::Exchange(e)) => return Err(e),
                };
                let lines: Vec<String> = pointers
                    .iter()
                    .map(|p| {
                        format!(
                            "- {} [{}|{}|{:+}] by {}",
                            p.hash, p.source, p.necessity, p.verdict, p.claimant
                        )
                    })
                    .collect();
                let context = if lines.is_empty() {
                    "no context pointers for this task".to_string()
                } else {
                    format!("verified CAS pointers:\n{}", lines.join("\n"))
                };
                Ok(HookDecision {
                    decision: "approve",
                    reason: format!(
                        "AUTHORIZED: tool '{}' carries verdict +1 (epistemic: proven)",
                        req.tool_name
                    ),
                    additional_context: Some(context),
                })
            }
            AuthorityVerdict::Denied => {
                let receipt_id = self
                    .append_ledger(
                        "verdict",
                        &format!(
                            "DENIED tool '{}': lifelog_edge authorizes verdict -1 (disproven)",
                            req.tool_name
                        ),
                        "denied",
                    )
                    .await?;
                Ok(HookDecision {
                    decision: "block",
                    reason: format!(
                        "DENIED: tool '{}' is disproven/unauthorized. Receipt {} appended to ledger.",
                        req.tool_name, receipt_id
                    ),
                    additional_context: None,
                })
            }
            AuthorityVerdict::Unknown => {
                let sub_path = self.dispatch_evidence_subtask(
                    &req.tool_name,
                    "authority UNKNOWN: no authorizes edge with verdict +1/-1",
                )?;
                let _ = self
                    .append_ledger(
                        "verdict",
                        &format!(
                            "DEFERRED tool '{}': authority UNKNOWN; evidence subtask dispatched to {}",
                            req.tool_name,
                            sub_path.display()
                        ),
                        "deferred",
                    )
                    .await;
                Ok(HookDecision {
                    decision: "block",
                    reason: format!(
                        "DEFERRED (not denied): authority UNKNOWN for tool '{}'. \
                         Evidence-gathering subtask dispatched to {}. \
                         Retry after the graph carries an authorizes edge.",
                        req.tool_name,
                        sub_path.display()
                    ),
                    additional_context: None,
                })
            }
        }
    }

    /// Dispatch an evidence-gathering subtask for the DAG orchestrator.
    /// Returns the subtask file path.
    pub fn dispatch_evidence_subtask(
        &self,
        tool: &str,
        reason: &str,
    ) -> Result<PathBuf> {
        self.dispatch_evidence_subtask_claimants(tool, reason, &[])
    }

    /// Claimant-targeted variant: `target_claimants` names the exact
    /// actors to interrogate or re-run (from a lossy-projection error).
    pub fn dispatch_evidence_subtask_claimants(
        &self,
        tool: &str,
        reason: &str,
        claimants: &[String],
    ) -> Result<PathBuf> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let id_input = format!("{}:{}:{}:{:?}", tool, reason, now, claimants);
        let full = luci_context::cas::hash_bytes(id_input.as_bytes());
        let id = format!("ev-{}", &full[..16]);
        let instructions = if claimants.is_empty() {
            format!(
                "Establish a lifelog_edge with edge_kind='authorizes', \
                 out=type::thing('tool','{tool}'), verdict=+1 or -1, \
                 claimant, necessity, source, and a receipt_id. The deferred \
                 tool call may then be retried."
            )
        } else {
            format!(
                "Interrogate or re-run the failing claimants ({}) to produce \
                 proven evidence. Then establish lifelog_edge rows with \
                 edge_kind='authorizes', out=type::thing('tool','{tool}'), \
                 verdict=+1, claimant set to the providing actor, necessity, \
                 source, and a receipt_id. The deferred tool call may then \
                 be retried.",
                claimants.join(", ")
            )
        };
        let subtask = serde_json::json!({
            "subtask_id": id,
            "tool": tool,
            "missing": "authority verdict for tool",
            "target_claimants": claimants,
            "dispatched_at": unix_to_rfc3339((now / 1_000_000_000) as u64),
            "status": "pending_evidence",
            "reason": reason,
            "instructions": instructions,
        });
        let path = self.evidence_queue.join(format!("{}.json", id));
        std::fs::write(&path, serde_json::to_string_pretty(&subtask)?)?;
        Ok(path)
    }

    /// Append a verdict receipt to the ledger (JSONL, same schema as
    /// ~/ledger/ledger.py). Refuses at the 10GB rotation limit.
    pub async fn append_ledger(
        &self,
        kind: &str,
        summary: &str,
        verdict: &str,
    ) -> Result<String> {
        const TEN_GB: u64 = 10 * 1024 * 1024 * 1024;
        if let Ok(md) = std::fs::metadata(&self.ledger_path) {
            if md.len() >= TEN_GB {
                return Err(ExchangeError::LedgerFull);
            }
        }
        let seq = next_seq(&self.ledger_path)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let receipt_id = format!("rcpt-mex-{}", seq);
        let entry = serde_json::json!({
            "actor": "muse-exchange",
            "device": "vm",
            "chat": "side_chat:450312ef",
            "type": kind,
            "summary": summary,
            "detail": "sovereign organelle verdict; see receipt chain",
            "verdict": verdict,
            "ts": unix_to_rfc3339(now),
            "seq": seq,
            "receipt_id": receipt_id,
        });
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ledger_path)?;
        writeln!(f, "{}", serde_json::to_string(&entry)?)?;
        Ok(receipt_id)
    }
}

/// Relevance rank for budget ordering, via luci-context projection
/// semantics: Required items (never evictable) rank first, then by
/// ascending eviction safety score.
fn relevance_rank(p: &ContextPointer) -> i32 {
    let item = to_context_item(p);
    match eviction_score(&item) {
        None => i32::MIN, // Required: most relevant
        Some(s) => s,
    }
}

/// Bridge a graph row into luci-context's epistemic item model.
fn to_context_item(p: &ContextPointer) -> ContextItem {
    let truth = match p.verdict {
        1 => Epistemic::Proven,
        -1 => Epistemic::Disproven,
        _ => Epistemic::Unknown,
    };
    let source = match p.source.as_str() {
        "system" => Source::System,
        "user" => Source::User,
        _ => Source::Discovered,
    };
    let necessity = match p.necessity.as_str() {
        "required" => Necessity::Required,
        "optional" => Necessity::Optional,
        _ => Necessity::Irrelevant,
    };
    ContextItem::new(
        &format!("cas:{}", p.hash),
        &format!("CAS pointer {}", p.hash),
        truth,
        source,
        necessity,
        &format!("lifelog_edge claimant={}", p.claimant),
    )
}

// ---------------------------------------------------------------- hook io

/// What the PreToolUse hook delivers (stdin JSON).
#[derive(Debug, Clone, Deserialize)]
pub struct HookRequest {
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub task_hash: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
}

/// What the hook prints (stdout JSON). Muse's hook protocol speaks
/// approve/block; our ternary maps Unknown -> block-with-DEFERRED-reason
/// (the tool does not run now, but the evidence path re-enables it —
/// never a hard systemic failure).
#[derive(Debug, Clone, Serialize)]
pub struct HookDecision {
    pub decision: &'static str,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl HookDecision {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "decision": self.decision,
            "reason": self.reason,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": self.additional_context,
            },
        })
    }
}

// ---------------------------------------------------------------- helpers

fn next_seq(path: &Path) -> Result<u64> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut seq = 0u64;
    for line in content.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(s) = v.get("seq").and_then(|s| s.as_u64()) {
                seq = s;
            }
        }
        break;
    }
    Ok(seq + 1)
}

/// Unix seconds -> RFC3339 UTC. No chrono: Howard Hinnant's civil date.
fn unix_to_rfc3339(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// Silence unused-import warning if Content ends up unused in future edits.
#[allow(dead_code)]
fn _use_content(c: &Content) -> bool {
    matches!(c, Content::Full(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_mapping_ternary() {
        assert_eq!(AuthorityVerdict::from_verdict(1), AuthorityVerdict::Authorized);
        assert_eq!(AuthorityVerdict::from_verdict(0), AuthorityVerdict::Unknown);
        assert_eq!(AuthorityVerdict::from_verdict(-1), AuthorityVerdict::Denied);
        assert_eq!(AuthorityVerdict::from_verdict(42), AuthorityVerdict::Unknown);
        assert_eq!(AuthorityVerdict::Authorized.epistemic(), Epistemic::Proven);
        assert_eq!(AuthorityVerdict::Unknown.epistemic(), Epistemic::Unknown);
        assert_eq!(AuthorityVerdict::Denied.epistemic(), Epistemic::Disproven);
    }

    #[test]
    fn rfc3339_epoch() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00+00:00");
        // 2026-10-06T00:00:00Z = 1791244800
        assert_eq!(unix_to_rfc3339(1791244800), "2026-10-06T00:00:00+00:00");
    }

    #[test]
    fn relevance_required_first() {
        let req = ContextPointer {
            hash: "a".into(),
            claimant: "zackary".into(),
            source: "system".into(),
            necessity: "required".into(),
            verdict: 1,
        };
        let opt = ContextPointer {
            hash: "b".into(),
            claimant: "lucidota".into(),
            source: "user".into(),
            necessity: "optional".into(),
            verdict: 0,
        };
        let mut v = vec![opt, req];
        v.sort_by_key(relevance_rank);
        assert_eq!(v[0].hash, "a");
    }

    #[test]
    fn claimant_never_collapses_into_source() {
        // The struct keeps claimant and source as independent fields:
        // exact actor identity vs broad trust domain.
        let p = ContextPointer {
            hash: "h".into(),
            claimant: "subagent:g1-a".into(),
            source: "system".into(),
            necessity: "required".into(),
            verdict: 1,
        };
        assert_ne!(p.claimant, p.source);
        let item = to_context_item(&p);
        assert!(item.provenance.contains("subagent:g1-a"));
    }
}
