//! Challenge generation: randomized, stratified sampling (P0/D5).
//!
//! Facts are shuffled within each category (CSPRNG), then sampled
//! round-robin across categories so the challenge set is unpredictable
//! and balanced. Deterministic first-n selection is gone.

use crate::{commitments::VaultFact, Error};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// A challenge presented during recovery. Carries the salted commitment —
/// safe to show to humans (offline guessing is infeasible per T-C15).
#[derive(Serialize, Deserialize, Clone)]
pub struct Challenge {
    pub fact_id: String,
    pub question: String,
    pub commitment: crate::commitments::AnswerCommit,
    pub options: Option<Vec<String>>,
}

fn category_rank(f: &VaultFact) -> usize {
    match f.category {
        crate::commitments::FactCategory::Timeline => 0,
        crate::commitments::FactCategory::Transaction => 1,
        crate::commitments::FactCategory::Personal => 2,
        crate::commitments::FactCategory::Negative => 3,
    }
}

/// Generate up to `n` challenges, stratified across categories and shuffled.
/// The caller supplies the RNG (seed it in tests for determinism).
pub fn generate_challenges<R: Rng>(
    facts: &[VaultFact],
    n: usize,
    rng: &mut R,
) -> Result<Vec<Challenge>, Error> {
    if facts.is_empty() || n == 0 {
        return Ok(Vec::new());
    }
    // Bucket by category, preserving a fixed category order.
    let mut buckets: [Vec<&VaultFact>; 4] = Default::default();
    for f in facts {
        buckets[category_rank(f)].push(f);
    }
    for bucket in buckets.iter_mut() {
        bucket.shuffle(rng);
    }
    // Round-robin across non-empty buckets.
    let mut challenges = Vec::new();
    let mut progress = true;
    while challenges.len() < n && progress {
        progress = false;
        for bucket in buckets.iter_mut() {
            if challenges.len() >= n {
                break;
            }
            if let Some(f) = bucket.pop() {
                progress = true;
                challenges.push(Challenge {
                    fact_id: f.id.clone(),
                    question: f.question.clone(),
                    commitment: f.commitment.clone(),
                    options: None,
                });
            }
        }
    }
    Ok(challenges)
}

/// Verify a challenge answer against its commitment.
pub fn verify_challenge(challenge: &Challenge, answer: &str) -> Result<bool, Error> {
    crate::verify_answer(&challenge.commitment, answer)
}
