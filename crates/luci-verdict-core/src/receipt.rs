//! Receipts: what was decided, chained to what came before.
//!
//! A receipt records the verdict and the typed stage results that
//! produced it. `previous_receipt_hash` chains receipts; "genesis"
//! anchors the chain. A receipt is evidence of the *decision*, not of
//! the underlying fact — it never upgrades CLAIMED to ESTABLISHED.

/// Which stage of the pipeline produced a terminal result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Crypto,
    Freshness,
    Binding,
    Identity,
    Evidence,
    Relationship,
    Policy,
    Activation,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Crypto => "crypto",
            Stage::Freshness => "freshness",
            Stage::Binding => "binding",
            Stage::Identity => "identity",
            Stage::Evidence => "evidence",
            Stage::Relationship => "relationship",
            Stage::Policy => "policy",
            Stage::Activation => "activation",
        }
    }
}

/// The recorded outcome of one adjudication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub receipt_id: String,
    pub envelope_id: String,
    /// "authorized" | "denied" | "deferred"
    pub outcome: String,
    pub terminal_stage: Stage,
    pub reason: String,
    pub at: u64,
    pub previous_receipt_hash: String,
    /// Hash of this receipt's canonical encoding. Computed by the
    /// caller (crypto layer); stored here so the chain is checkable.
    pub receipt_hash: String,
}

impl Receipt {
    /// The canonical string the crypto layer hashes. Length-prefixed
    /// fields, fixed order, ADHKEY/1/ domain separation.
    pub fn canonical(&self) -> String {
        fn lp(s: &str) -> String {
            format!("{}:{}", s.len(), s)
        }
        ["ADHKEY/1/receipt",
            &lp(&self.receipt_id),
            &lp(&self.envelope_id),
            &lp(&self.outcome),
            &lp(self.terminal_stage.as_str()),
            &lp(&self.reason),
            &self.at.to_string(),
            &lp(&self.previous_receipt_hash),
        ]
        .join("|")
    }
}
