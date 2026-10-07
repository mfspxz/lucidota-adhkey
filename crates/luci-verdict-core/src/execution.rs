//! Execution is a claim until independently observed.
//!
//! V005 killer: "I executed X" is CLAIM. The agent's own receipt is
//! evidence of the claim, not evidence of the execution.
//!
//! EXECUTION_CLAIMED -> EXECUTION_OBSERVED -> EXECUTION_VERIFIED
//!
//! A process cannot manufacture its own independent observation:
//! observations whose observer == claimant are discarded before
//! evaluation.

/// What an agent says it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaim {
    pub claimant: String,
    pub command: String,
    pub claimed_at: u64,
}

/// What an independent party observed (kernel, filesystem, network...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub observer: String,
    pub observed: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Only the claimant's word. Not evidence of execution.
    Claimed,
    /// >=1 external observation corroborates.
    Observed { corroborated_by: Vec<String> },
    /// >=2 *independent* external observers corroborate.
    Verified { corroborated_by: Vec<String> },
}

/// Evaluate an execution claim. `covers` decides whether an observation
/// corroborates this specific claim (e.g. pid-existed + artifact-hash
/// match the claimed command). Self-observations are discarded first.
pub fn verify_execution(
    claim: &ExecutionClaim,
    observations: &[Observation],
    covers: impl Fn(&Observation) -> bool,
) -> ExecutionStatus {
    use std::collections::BTreeSet;
    let corroborators: BTreeSet<String> = observations
        .iter()
        .filter(|o| o.observer != claim.claimant) // V005: self != witness
        .filter(|o| covers(o))
        .map(|o| o.observer.clone())
        .collect();
    let list: Vec<String> = corroborators.into_iter().collect();
    match list.len() {
        0 => ExecutionStatus::Claimed,
        1 => ExecutionStatus::Observed { corroborated_by: list },
        _ => ExecutionStatus::Verified { corroborated_by: list },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> ExecutionClaim {
        ExecutionClaim { claimant: "agent-1".into(), command: "deploy".into(), claimed_at: 100 }
    }

    #[test]
    fn v005_self_report_is_not_observation() {
        // The agent's own "receipt" of its execution: discarded.
        let obs = vec![Observation {
            observer: "agent-1".into(),
            observed: "pid 123 ran deploy".into(),
        }];
        assert_eq!(verify_execution(&claim(), &obs, |_| true), ExecutionStatus::Claimed);
    }

    #[test]
    fn v005_one_external_observer_is_observed_not_verified() {
        let obs = vec![Observation {
            observer: "kernel".into(),
            observed: "pid 123 existed".into(),
        }];
        assert_eq!(
            verify_execution(&claim(), &obs, |_| true),
            ExecutionStatus::Observed { corroborated_by: vec!["kernel".into()] }
        );
    }

    #[test]
    fn v005_two_independent_observers_verify() {
        let obs = vec![
            Observation { observer: "kernel".into(), observed: "pid 123".into() },
            Observation { observer: "filesystem".into(), observed: "artifact H".into() },
        ];
        assert!(matches!(
            verify_execution(&claim(), &obs, |_| true),
            ExecutionStatus::Verified { .. }
        ));
    }

    #[test]
    fn v005_non_corroborating_observations_do_not_count() {
        let obs = vec![Observation {
            observer: "kernel".into(),
            observed: "unrelated pid 999".into(),
        }];
        // covers() says this observation is about something else.
        assert_eq!(
            verify_execution(&claim(), &obs, |o| o.observed.contains("deploy")),
            ExecutionStatus::Claimed
        );
    }
}
