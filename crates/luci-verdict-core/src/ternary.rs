//! Epistemic ternary: PROVEN / UNKNOWN / DISPROVEN (+1 / 0 / -1).
//!
//! UNKNOWN is not FALSE. UNKNOWN propagates through every combinator.
//! There is no path from UNKNOWN to PROVEN except through evidence.

/// The epistemic state of a proposition. Discriminants are the
/// canonical +1/0/-1 so the values are meaningful across serializations.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i8)]
pub enum Epistemic {
    Disproven = -1,
    Unknown = 0,
    Proven = 1,
}

impl Epistemic {
    /// Conjunction. Proven requires both proven. Disproven dominates.
    /// Unknown propagates: (Unknown, Proven) -> Unknown, never Proven.
    pub fn and(self, other: Epistemic) -> Epistemic {
        use Epistemic::*;
        match (self, other) {
            (Proven, Proven) => Proven,
            (Disproven, _) | (_, Disproven) => Disproven,
            _ => Unknown,
        }
    }

    /// Disjunction. Proven if either proven. Unknown only if both unknown.
    /// (Unknown, Unknown) -> Unknown: convenience never manufactures truth.
    pub fn or(self, other: Epistemic) -> Epistemic {
        use Epistemic::*;
        match (self, other) {
            (Proven, _) | (_, Proven) => Proven,
            (Disproven, Disproven) => Disproven,
            _ => Unknown,
        }
    }

    /// Negation flips the axis; Unknown stays Unknown.
    pub fn not(self) -> Epistemic {
        use Epistemic::*;
        match self {
            Proven => Disproven,
            Disproven => Proven,
            Unknown => Unknown,
        }
    }

    /// Fold a set of epistemic states with conjunction.
    /// Empty set -> Unknown: no evidence is not evidence.
    pub fn all<I: IntoIterator<Item = Epistemic>>(it: I) -> Epistemic {
        let mut it = it.into_iter();
        match it.next() {
            None => Epistemic::Unknown,
            Some(first) => it.fold(first, Epistemic::and),
        }
    }

    /// Fold with disjunction. Empty set -> Disproven (nothing supports).
    pub fn any<I: IntoIterator<Item = Epistemic>>(it: I) -> Epistemic {
        let mut it = it.into_iter();
        match it.next() {
            None => Epistemic::Disproven,
            Some(first) => it.fold(first, Epistemic::or),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Epistemic;
    use super::Epistemic::*;

    #[test]
    fn unknown_never_becomes_proven_by_convenience() {
        assert_eq!(Unknown.and(Proven), Unknown);
        assert_eq!(Proven.and(Unknown), Unknown);
        assert_eq!(Unknown.or(Unknown), Unknown);
        assert_eq!(Unknown.not(), Unknown);
        assert_eq!(Epistemic::all([Proven, Unknown]), Unknown);
    }

    #[test]
    fn disproven_dominates() {
        assert_eq!(Disproven.and(Proven), Disproven);
        assert_eq!(Disproven.or(Unknown), Unknown);
        assert_eq!(Epistemic::any([Disproven, Disproven]), Disproven);
    }

    #[test]
    fn empty_evidence_is_not_evidence() {
        let empty: [Epistemic; 0] = [];
        assert_eq!(Epistemic::all(empty), Unknown);
        assert_eq!(Epistemic::any(empty), Disproven);
    }
}
