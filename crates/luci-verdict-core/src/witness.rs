//! Witness independence: corroboration must be graph-aware.
//!
//! V004 killer: A says X, B says X is not two witnesses when A and B
//! share a trust root. `independent_witnesses()` counts distinct
//! *ultimate* trust roots through the `controlled_by` relation.

use std::collections::{BTreeMap, BTreeSet};

/// A single attestation offered as evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub id: String,
    /// The trust root this witness speaks for (may itself be controlled).
    pub trust_root: String,
}

/// The set of evidence offered for one claim.
#[derive(Debug, Clone, Default)]
pub struct EvidenceSet {
    pub witnesses: Vec<Witness>,
}

/// Provenance edges: (entity, controller). Ultimate roots are entities
/// that appear as trust roots but are not controlled by anyone listed.
#[derive(Debug, Clone, Default)]
pub struct ProvenanceGraph {
    pub controlled_by: Vec<(String, String)>,
}

fn ultimate_root(start: &str, controlled: &BTreeMap<&str, &str>) -> String {
    let mut cur = start;
    let mut seen = BTreeSet::new();
    while let Some(next) = controlled.get(cur) {
        if !seen.insert(cur) {
            // Control cycle: resolve deterministically to the
            // lexicographically smallest member rather than hanging
            // or double-counting.
            seen.insert(cur);
            return seen.into_iter().min().unwrap_or(start).to_string();
        }
        cur = next;
    }
    // Walk terminated naturally: cur has no controller — it is the root.
    cur.to_string()
}

/// Count distinct ultimate trust roots. Two witnesses under one root
/// contribute 1, not 2.
pub fn independent_witnesses(
    witnesses: &[Witness],
    graph: &ProvenanceGraph,
) -> usize {
    let controlled: BTreeMap<&str, &str> = graph
        .controlled_by
        .iter()
        .map(|(e, c)| (e.as_str(), c.as_str()))
        .collect();
    witnesses
        .iter()
        .map(|w| ultimate_root(&w.trust_root, &controlled))
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(id: &str, root: &str) -> Witness {
        Witness { id: id.into(), trust_root: root.into() }
    }

    #[test]
    fn distinct_roots_count_distinctly() {
        let ws = vec![w("a", "r1"), w("b", "r2")];
        assert_eq!(independent_witnesses(&ws, &ProvenanceGraph::default()), 2);
    }

    #[test]
    fn shared_root_counts_once() {
        let ws = vec![w("a", "r1"), w("b", "r1"), w("c", "r1")];
        assert_eq!(independent_witnesses(&ws, &ProvenanceGraph::default()), 1);
    }

    #[test]
    fn transitive_control_collapses() {
        // a -> b -> c: a's witness and c's witness share ultimate root.
        let ws = vec![w("wa", "a"), w("wc", "c")];
        let g = ProvenanceGraph {
            controlled_by: vec![
                ("a".into(), "b".into()),
                ("b".into(), "c".into()),
            ],
        };
        assert_eq!(independent_witnesses(&ws, &g), 1);
    }

    #[test]
    fn control_cycle_does_not_double_count_or_hang() {
        let ws = vec![w("wa", "a"), w("wb", "b")];
        let g = ProvenanceGraph {
            controlled_by: vec![
                ("a".into(), "b".into()),
                ("b".into(), "a".into()),
            ],
        };
        assert_eq!(independent_witnesses(&ws, &g), 1);
    }
}
