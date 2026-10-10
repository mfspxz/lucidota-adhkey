//! PROPERTY TESTS (R-7) — T-CRYPTO: cryptographic property tests (RFC §9.1).
//! Adversarial properties, not happy paths.
//! Expectations here may never be rewritten to match a behavior change
//! without adversarial sign-off.

use adhkey_flailer::*;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashSet;

fn test_set() -> ([u8; 16], u64) {
    ([0x11u8; 16], 7)
}

fn test_facts() -> Vec<VaultFact> {
    vec![
        VaultFact::new("t1", "Where were you Oct 4 2026 at 20:00?", "Gastown", FactCategory::Timeline).unwrap(),
        VaultFact::new("t2", "What did you buy for $12 on Oct 3?", "coffee", FactCategory::Transaction).unwrap(),
        VaultFact::new("p1", "What is the dog's name?", "Biscuit", FactCategory::Personal).unwrap(),
        VaultFact::new("n1", "Which did you NOT do on Oct 2?", "went sailing", FactCategory::Negative).unwrap(),
    ]
}

fn full_setup() -> (RootSecret, [u8; 32], [VerifiedShare; 5], [u8; 16], u64) {
    let (set_id, epoch) = test_set();
    let root = generate_root().unwrap();
    let vault_key = derive_vault_key(&root, &set_id, epoch).unwrap();
    let shares = split_root(&root).unwrap();
    let wrapping_key = [0xABu8; 32];
    let mut verified: [VerifiedShare; 5] = [
        unwrap_share(&wrap_share(&shares[0], &wrapping_key, set_id, epoch, 0).unwrap(), &wrapping_key, &set_id, epoch).unwrap(),
        unwrap_share(&wrap_share(&shares[1], &wrapping_key, set_id, epoch, 1).unwrap(), &wrapping_key, &set_id, epoch).unwrap(),
        unwrap_share(&wrap_share(&shares[2], &wrapping_key, set_id, epoch, 2).unwrap(), &wrapping_key, &set_id, epoch).unwrap(),
        unwrap_share(&wrap_share(&shares[3], &wrapping_key, set_id, epoch, 3).unwrap(), &wrapping_key, &set_id, epoch).unwrap(),
        unwrap_share(&wrap_share(&shares[4], &wrapping_key, set_id, epoch, 4).unwrap(), &wrapping_key, &set_id, epoch).unwrap(),
    ];
    // silence unused-mut warning pattern by rebuilding; keep simple
    let _ = &mut verified;
    (root, vault_key, verified, set_id, epoch)
}

#[test]
fn t_c1_vault_roundtrip() {
    let (_root, vault_key, _v, set_id, epoch) = full_setup();
    let facts = test_facts();
    let vault = seal_vault(&facts, &vault_key, set_id, epoch).unwrap();
    let opened = open_vault(&vault, &vault_key, &set_id, epoch).unwrap();
    assert_eq!(opened.len(), 4);
    assert!(opened[0].verify("Gastown").unwrap());
    assert!(!opened[0].verify("Downtown").unwrap());
}

#[test]
fn t_c2_ciphertext_bitflip_rejected() {
    let (_root, vault_key, _v, set_id, epoch) = full_setup();
    let mut vault = seal_vault(&test_facts(), &vault_key, set_id, epoch).unwrap();
    vault.ciphertext[0] ^= 1;
    assert!(open_vault(&vault, &vault_key, &set_id, epoch).is_err());
}

#[test]
fn t_c3_nonce_flip_rejected() {
    let (_root, vault_key, _v, set_id, epoch) = full_setup();
    let mut vault = seal_vault(&test_facts(), &vault_key, set_id, epoch).unwrap();
    vault.nonce[0] ^= 1;
    assert!(open_vault(&vault, &vault_key, &set_id, epoch).is_err());
}

#[test]
fn t_c4_nonce_uniqueness() {
    let (_root, vault_key, _v, set_id, epoch) = full_setup();
    // NOTE: facts built ONCE — test_facts() runs Argon2id per fact; building
    // them inside the loop would mean 4000 KDF ops instead of 4.
    let facts = test_facts();
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let vault = seal_vault(&facts, &vault_key, set_id, epoch).unwrap();
        assert!(nonces.insert(vault.nonce), "nonce reused!");
    }
}

#[test]
fn t_c5_aad_binding() {
    let (_root, vault_key, _v, set_id, epoch) = full_setup();
    let vault = seal_vault(&test_facts(), &vault_key, set_id, epoch).unwrap();
    // Wrong epoch: AAD mismatch must fail even with the right key.
    assert!(open_vault(&vault, &vault_key, &set_id, epoch + 1).is_err());
    // Wrong set id.
    assert!(open_vault(&vault, &vault_key, &[0x22u8; 16], epoch).is_err());
    // Vault key derived for a different epoch cannot open either (key separation).
    let other_key = derive_vault_key(&generate_root().unwrap(), &set_id, epoch + 1).unwrap();
    assert!(open_vault(&vault, &other_key, &set_id, epoch).is_err());
}

#[test]
fn t_c6_wrong_passphrase_envelope_sealed() {
    let (_root, _vk, verified, set_id, epoch) = full_setup();
    // Re-split to get raw share bytes for the envelope test.
    let root = generate_root().unwrap();
    let shares = split_root(&root).unwrap();
    let wrapping_key = [0xABu8; 32];
    let env0 = wrap_share(&shares[0], &wrapping_key, set_id, epoch, 0).unwrap();
    let verified0 = unwrap_share(&env0, &wrapping_key, &set_id, epoch).unwrap();
    let _ = verified;
    // Envelope round trip needs raw bytes; exercise via passphrase envelope on dummy bytes.
    let env = seal_share_envelope(b"dummy-share-bytes-32-bytes-long!!!", "correct horse", set_id, epoch).unwrap();
    assert!(open_share_envelope(&env, "correct horse").is_ok());
    assert!(open_share_envelope(&env, "wrong horse").is_err());
    assert!(open_share_envelope(&env, "").is_err());
    let _ = verified0;
}

#[test]
fn t_c8_all_subsets_reconstruct() {
    let (root, _vk, verified, set_id, epoch) = full_setup();
    let reference_key = derive_vault_key(&root, &set_id, epoch).unwrap();
    // All C(5,3) = 10 subsets.
    let mut count = 0;
    for i in 0..5 {
        for j in (i + 1)..5 {
            for k in (j + 1)..5 {
                let subset = vec![verified[i].clone(), verified[j].clone(), verified[k].clone()];
                let recovered = recover_root(&subset).unwrap();
                let key = derive_vault_key(&recovered, &set_id, epoch).unwrap();
                assert_eq!(key, reference_key, "subset ({i},{j},{k}) diverged");
                count += 1;
            }
        }
    }
    assert_eq!(count, 10);
}

#[test]
fn t_c9_two_shares_insufficient() {
    let (_root, _vk, verified, _set_id, _epoch) = full_setup();
    assert!(recover_root(&verified[0..2]).is_err());
    assert!(recover_root(&verified[0..1]).is_err());
    assert!(recover_root(&[]).is_err());
}

#[test]
fn t_c10_corrupted_share_envelope_rejected() {
    let (_root, _vk, _v, set_id, epoch) = full_setup();
    let root = generate_root().unwrap();
    let shares = split_root(&root).unwrap();
    let wrapping_key = [0xABu8; 32];
    let mut env = wrap_share(&shares[0], &wrapping_key, set_id, epoch, 0).unwrap();
    env.ciphertext[3] ^= 0xFF;
    assert!(unwrap_share(&env, &wrapping_key, &set_id, epoch).is_err());
    // Wrong wrapping key.
    let env2 = wrap_share(&shares[1], &wrapping_key, set_id, epoch, 1).unwrap();
    assert!(unwrap_share(&env2, &[0xCDu8; 32], &set_id, epoch).is_err());
}

#[test]
fn t_c11_old_epoch_rejected() {
    let (_root, _vk, _v, set_id, epoch) = full_setup();
    let root = generate_root().unwrap();
    let shares = split_root(&root).unwrap();
    let wrapping_key = [0xABu8; 32];
    let env = wrap_share(&shares[0], &wrapping_key, set_id, epoch, 0).unwrap();
    assert!(unwrap_share(&env, &wrapping_key, &set_id, epoch + 1).is_err());
}

#[test]
fn t_c12_duplicate_share_index_no_double_count() {
    let (_root, _vk, verified, _set_id, _epoch) = full_setup();
    // Same share twice + one other = only 2 distinct → must fail.
    let dup = vec![verified[0].clone(), verified[0].clone(), verified[1].clone()];
    assert!(recover_root(&dup).is_err());
    // Same share three times = 1 distinct → must fail.
    let triple = vec![verified[2].clone(), verified[2].clone(), verified[2].clone()];
    assert!(recover_root(&triple).is_err());
}

#[test]
fn t_c13_share_substitution_detected() {
    let (_root, _vk, _v, set_id, epoch) = full_setup();
    let root = generate_root().unwrap();
    let shares = split_root(&root).unwrap();
    let wrapping_key = [0xABu8; 32];
    // Envelope minted for a DIFFERENT set id must not verify here.
    let foreign = wrap_share(&shares[0], &wrapping_key, [0x99u8; 16], epoch, 0).unwrap();
    assert!(unwrap_share(&foreign, &wrapping_key, &set_id, epoch).is_err());
}

#[test]
fn t_c14_key_purpose_confusion() {
    let (set_id, epoch) = test_set();
    let root = generate_root().unwrap();
    let vault_key = derive_vault_key(&root, &set_id, epoch).unwrap();
    let other_epoch_key = derive_vault_key(&root, &set_id, epoch + 1).unwrap();
    let other_set_key = derive_vault_key(&root, &[0x55u8; 16], epoch).unwrap();
    assert_ne!(vault_key, other_epoch_key);
    assert_ne!(vault_key, other_set_key);
    // Same inputs → same key (deterministic derivation).
    let again = derive_vault_key(&root, &set_id, epoch).unwrap();
    assert_eq!(vault_key, again);
}

#[test]
fn t_c15_answer_commitments_verify() {
    // Same answer committed twice → different salts/hashes (no rainbow tables).
    let c1 = commit_answer("Gastown").unwrap();
    let c2 = commit_answer("Gastown").unwrap();
    assert_ne!(c1.salt, c2.salt);
    assert_ne!(c1.hash, c2.hash);
    // Correct verifies, wrong does not.
    assert!(verify_answer(&c1, "Gastown").unwrap());
    assert!(!verify_answer(&c1, "gastown").unwrap());
    assert!(!verify_answer(&c1, "").unwrap());
    // Cross-commitment: c1's answer does not verify against c2's salt... it SHOULD
    // verify (same answer) — what must NOT happen is a wrong answer verifying.
    assert!(verify_answer(&c2, "Gastown").unwrap());
    assert!(!verify_answer(&c2, "Downtown").unwrap());
}

#[test]
fn t_c16_challenge_sampling() {
    // 3 facts per category: single-fact buckets would make shuffle order
    // deterministic and the randomness assertion vacuous.
    let mut facts = Vec::new();
    for i in 0..3 {
        facts.push(VaultFact::new(&format!("t{i}"), &format!("Q t{i}"), &format!("A t{i}"), FactCategory::Timeline).unwrap());
        facts.push(VaultFact::new(&format!("x{i}"), &format!("Q x{i}"), &format!("A x{i}"), FactCategory::Transaction).unwrap());
        facts.push(VaultFact::new(&format!("p{i}"), &format!("Q p{i}"), &format!("A p{i}"), FactCategory::Personal).unwrap());
        facts.push(VaultFact::new(&format!("n{i}"), &format!("Q n{i}"), &format!("A n{i}"), FactCategory::Negative).unwrap());
    }
    let mut rng1 = StdRng::seed_from_u64(1);
    let mut rng2 = StdRng::seed_from_u64(2);
    let ch1 = generate_challenges(&facts, 8, &mut rng1).unwrap();
    let ch2 = generate_challenges(&facts, 8, &mut rng2).unwrap();
    assert_eq!(ch1.len(), 8);
    // Stratified: the first round-robin pass covers all four categories.
    let first4: HashSet<char> =
        ch1.iter().take(4).map(|c| c.fact_id.chars().next().unwrap()).collect();
    assert_eq!(first4.len(), 4, "first pass spans all categories");
    // No duplicates.
    let ids: HashSet<&str> = ch1.iter().map(|c| c.fact_id.as_str()).collect();
    assert_eq!(ids.len(), 8);
    // Random: different seeds give different orders (not deterministic first-n).
    let order1: Vec<&str> = ch1.iter().map(|c| c.fact_id.as_str()).collect();
    let order2: Vec<&str> = ch2.iter().map(|c| c.fact_id.as_str()).collect();
    assert_ne!(order1, order2);
    // Challenge verify still works (answer "A <id>" by construction).
    let g = &ch1[0];
    let expected = format!("A {}", g.fact_id);
    assert!(verify_challenge(g, &expected).unwrap());
    assert!(!verify_challenge(g, "wrong answer").unwrap());
    // n larger than facts → all facts, no panic, no duplicates.
    let mut rng3 = StdRng::seed_from_u64(3);
    let chall = generate_challenges(&facts, 99, &mut rng3).unwrap();
    assert_eq!(chall.len(), 12);
}

/// T-LOG: secret-holding types must not derive leaky traits.
/// Stable-Rust substitute for negative trait bounds: scan the crate's own source.
#[test]
fn t_log_secret_types_have_no_leaky_derives() {
    // (file, type, forbid_serialize_too)
    const SECRET_TYPES: &[(&str, &str, bool)] = &[
        ("key_hierarchy.rs", "RootSecret", true),
        ("secret_sharing.rs", "UnverifiedShare", true),
        ("secret_sharing.rs", "VerifiedShare", true),
        ("secret_sharing.rs", "ShareEnvelope", false), // ciphertext-only container: Serialize OK
        ("key_hierarchy.rs", "PassphraseEnvelope", false), // ciphertext-only: Serialize OK
        ("vault.rs", "Vault", false), // ciphertext-only: Serialize OK
    ];
    for (file, ty, forbid_ser) in SECRET_TYPES {
        let path = format!("{}/src/{}", env!("CARGO_MANIFEST_DIR"), file);
        let src = std::fs::read_to_string(&path).unwrap();
        let struct_pos = src.find(&format!("struct {}", ty)).unwrap_or_else(|| panic!("type {ty} missing"));
        let above = &src[..struct_pos];
        let mut attrs = String::new();
        for line in above.lines().rev() {
            let t = line.trim();
            if t.starts_with("#[") {
                attrs.push_str(t);
            } else if t.is_empty() || t.starts_with("///") || t.starts_with("//!") {
                continue;
            } else {
                break;
            }
        }
        for leaky in ["Debug", "Display"] {
            assert!(!attrs.contains(leaky), "T-LOG FAIL: {ty} derives {leaky}");
        }
        if *forbid_ser {
            assert!(!attrs.contains("Serialize"), "T-LOG FAIL: {ty} derives Serialize");
        }
    }
}

#[test]
fn t_paper_backup_roundtrip() {
    let (set_id, epoch) = test_set();
    let root = generate_root().unwrap();
    let shares = split_root(&root).unwrap();
    let wrapping_key = [0xABu8; 32];
    // Wrap index 4 as the paper share, then encode/decode.
    let encoded = adhkey_flailer::secret_sharing::encode_paper_share(&shares[4], set_id, epoch, 4).unwrap();
    assert!(encoded.starts_with("FL1"));
    let (raw, dec_set, dec_epoch, dec_idx) =
        adhkey_flailer::secret_sharing::decode_paper_share(&encoded).unwrap();
    assert_eq!(dec_set, set_id);
    assert_eq!(dec_epoch, epoch);
    assert_eq!(dec_idx, 4);
    // The decoded share must combine with two others to recover.
    let env0 = wrap_share(&shares[0], &wrapping_key, set_id, epoch, 0).unwrap();
    let env1 = wrap_share(&shares[1], &wrapping_key, set_id, epoch, 1).unwrap();
    let v0 = unwrap_share(&env0, &wrapping_key, &set_id, epoch).unwrap();
    let v1 = unwrap_share(&env1, &wrapping_key, &set_id, epoch).unwrap();
    // Re-wrap the paper share through a fresh envelope to get a VerifiedShare.
    let penv = wrap_share(&raw, &wrapping_key, dec_set, dec_epoch, dec_idx).unwrap();
    let v4 = unwrap_share(&penv, &wrapping_key, &set_id, epoch).unwrap();
    let recovered = recover_root(&[v0, v1, v4]).unwrap();
    let k1 = derive_vault_key(&root, &set_id, epoch).unwrap();
    let k2 = derive_vault_key(&recovered, &set_id, epoch).unwrap();
    assert_eq!(k1, k2);
    // Tampered paper → checksum failure (flip to a guaranteed-different nibble).
    let mut bad = encoded.clone();
    let cur = bad.chars().nth(10).unwrap();
    let rep = if cur == 'f' { "0" } else { "f" };
    bad.replace_range(10..11, rep);
    assert!(adhkey_flailer::secret_sharing::decode_paper_share(&bad).is_err());
}
