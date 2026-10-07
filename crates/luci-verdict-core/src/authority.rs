//! Authority as types, not strings.
//!
//! V001 killer: the caller may assert `claimed_authority` all day.
//! The policy engine can only consume `Established<T>` / `Authorized<T>`,
//! and those can only be constructed through evidence and policy.
//! `authorize(x: Established<Identity>)` cannot accept `Claimed<Identity>`
//! — the compiler rejects it. No runtime check to forget.

use crate::ternary::Epistemic;
use crate::witness::{independent_witnesses, EvidenceSet, ProvenanceGraph};

/// A caller assertion. Anyone can construct this. It authorizes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed<T>(T);

/// Evidence has been evaluated and the claim is established.
/// Constructible only through `establish()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Established<T>(T);

/// Policy has been applied to an established fact.
/// Constructible only through `authorize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized<T>(T);

impl<T> Claimed<T> {
    /// The only constructor. Claims are cheap; that is the point.
    pub fn new(inner: T) -> Self {
        Claimed(inner)
    }
    pub fn into_inner(self) -> T {
        self.0
    }
    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<T> Established<T> {
    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<T> Authorized<T> {
    pub fn inner(&self) -> &T {
        &self.0
    }
}

/// What the policy demands before a claim may be established.
#[derive(Debug, Clone)]
pub struct EstablishmentPolicy {
    /// Minimum count of *independent* witnesses (trust-root distinct).
    pub required_independent_witnesses: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstablishError {
    /// Not enough *independent* witnesses. Correlated witnesses from one
    /// trust root count once (V004).
    InsufficientIndependentWitnesses { have: usize, need: usize },
}

/// The ONLY path from Claimed to Established: evidence evaluation.
/// There is no `Established::from_claimed`, no `unsafe`, no backdoor.
pub fn establish<T: Clone>(
    claimed: &Claimed<T>,
    evidence: &EvidenceSet,
    provenance: &ProvenanceGraph,
    policy: &EstablishmentPolicy,
) -> Result<Established<T>, EstablishError> {
    let n = independent_witnesses(&evidence.witnesses, provenance);
    if n >= policy.required_independent_witnesses {
        Ok(Established(claimed.inner().clone()))
    } else {
        Err(EstablishError::InsufficientIndependentWitnesses {
            have: n,
            need: policy.required_independent_witnesses,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    PolicyRejects,
    EvidenceUnknown,
}

/// The ONLY path from Established to Authorized: policy application.
/// Takes `Established<T>` — never `Claimed<T>`. The type system is the
/// enforcement; a caller cannot smuggle a claim across this boundary.
pub fn authorize<T>(
    established: Established<T>,
    policy_satisfied: Epistemic,
) -> Result<Authorized<T>, Denial> {
    match policy_satisfied {
        Epistemic::Proven => Ok(Authorized(established.0)),
        Epistemic::Disproven => Err(Denial::PolicyRejects),
        // UNKNOWN propagates: not denied-forever, not authorized.
        // The caller must handle Defer, not assume success.
        Epistemic::Unknown => Err(Denial::EvidenceUnknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::Witness;

    fn witness(id: &str, root: &str) -> Witness {
        Witness { id: id.into(), trust_root: root.into() }
    }

    #[test]
    fn v001_claimed_cannot_become_authorized_without_evidence() {
        let claimed = Claimed::new("governor");
        let evidence = EvidenceSet { witnesses: vec![] };
        let provenance = ProvenanceGraph { controlled_by: vec![] };
        let policy = EstablishmentPolicy { required_independent_witnesses: 1 };
        // No evidence at all: establishment must fail.
        assert!(establish(&claimed, &evidence, &provenance, &policy).is_err());
        // And there is simply no function that turns Claimed into
        // Authorized: the only route is establish() then authorize().
        // (Compile-time: authorize() takes Established<T>, not Claimed<T>.)
    }

    #[test]
    fn v004_correlated_witnesses_count_once() {
        let claimed = Claimed::new("x");
        // Two witnesses, one trust root: independence = 1.
        let evidence = EvidenceSet {
            witnesses: vec![witness("a", "root-c"), witness("b", "root-c")],
        };
        let provenance = ProvenanceGraph { controlled_by: vec![] };
        let policy = EstablishmentPolicy { required_independent_witnesses: 2 };
        let r = establish(&claimed, &evidence, &provenance, &policy);
        assert_eq!(
            r.unwrap_err(),
            EstablishError::InsufficientIndependentWitnesses { have: 1, need: 2 }
        );
    }

    #[test]
    fn unknown_policy_never_authorizes() {
        let claimed = Claimed::new("x");
        let evidence = EvidenceSet { witnesses: vec![witness("a", "r1")] };
        let provenance = ProvenanceGraph { controlled_by: vec![] };
        let policy = EstablishmentPolicy { required_independent_witnesses: 1 };
        let est = establish(&claimed, &evidence, &provenance, &policy).unwrap();
        // Policy undecided: not authorized, not permanently rejected.
        assert_eq!(authorize(est, Epistemic::Unknown), Err(Denial::EvidenceUnknown));
    }
}
