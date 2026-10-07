//! luci-verdict-core: the staged epistemic verdict pipeline.
//!
//! Not a "verifier." It performs CLAIM -> ESTABLISHED -> AUTHORIZED as
//! structurally separated transitions, and makes it *impossible* —
//! by type, not by discipline — for a caller-controlled field to move
//! a proposition from CLAIMED/UNKNOWN to ESTABLISHED/AUTHORIZED.
//!
//! Sacred invariant: no attacker-controlled field may directly cause a
//! transition from CLAIMED/UNKNOWN to ESTABLISHED/AUTHORIZED.
//!
//! UNKNOWN propagates. It never becomes TRUE through convenience.
//!
//! No cryptography here. No I/O. No clock. Pure types + transitions.
//! The crypto layer supplies a `CryptoReport`; this crate reasons about
//! statuses, never about bytes.

pub mod authority;
pub mod envelope;
pub mod execution;
pub mod pipeline;
pub mod receipt;
pub mod ternary;
pub mod witness;

pub use authority::{Authorized, Claimed, Established};
pub use envelope::Envelope;
pub use pipeline::{adjudicate, StageResults, Verdict, VerdictInput};
pub use ternary::Epistemic;
