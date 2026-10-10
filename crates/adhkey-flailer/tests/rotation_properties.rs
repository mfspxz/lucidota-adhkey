//! P3: rotation and enrollment tests.

use adhkey_flailer::*;
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x9074)
}

fn authority(rng: &mut StdRng) -> SigningKey {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn setup_epoch7() -> (RootSecret, [VerifiedShare; 5], [[u8; 32]; 5], [u8; 16]) {
    let mut r = rng();
    let set_id = [0x11u8; 16];
    let root = generate_root().unwrap();
    let shares = split_root(&root).unwrap();
    let mut keys = [[0u8; 32]; 5];
    let mut verified: Vec<VerifiedShare> = Vec::new();
    for i in 0..5 {
        r.fill_bytes(&mut keys[i]);
        let env = wrap_share(&shares[i], &keys[i], set_id, 7, i as u8).unwrap();
        verified.push(unwrap_share(&env, &keys[i], &set_id, 7).unwrap());
    }
    // NOTE: no unwrap()/expect() on the conversion — VerifiedShare has no
    // Debug by design (T-LOG), and Result::unwrap requires E: Debug.
    let mut it = verified.into_iter();
    let arr = [
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap(),
    ];
    (root, arr, keys, set_id)
}

#[test]
fn t_enroll_guardian_receipt() {
    let mut r = rng();
    let auth = authority(&mut r);
    let mut gid = [0u8; 16];
    r.fill_bytes(&mut gid);
    let gk = authority(&mut r);
    let vk = gk.verifying_key().to_bytes();
    let receipt = enroll_guardian(gid, 2, &vk, [0x11u8; 16], 7, &auth, 1_800_000_000).unwrap();
    assert!(verify_enrollment_receipt(&receipt, &vk).is_ok());
    // Wrong pubkey → rejected.
    let other_vk = authority(&mut r).verifying_key().to_bytes();
    assert!(verify_enrollment_receipt(&receipt, &other_vk).is_err());
    // Tampered signature → rejected.
    let mut bad = receipt.clone();
    bad.signature[0] ^= 1;
    assert!(verify_enrollment_receipt(&bad, &vk).is_err());
    // Bad share index → rejected at enrollment.
    assert!(enroll_guardian(gid, 9, &vk, [0x11u8; 16], 7, &auth, 1_800_000_000).is_err());
}

#[test]
fn t_rotate_epoch() {
    let mut r = rng();
    let auth = authority(&mut r);
    let (root, verified, _keys, set_id) = setup_epoch7();
    let mut new_keys = [[0u8; 32]; 5];
    for k in new_keys.iter_mut() {
        r.fill_bytes(k);
    }
    let (envelopes, receipt) = rotate_epoch(
        &verified[0..3],
        7,
        8,
        set_id,
        &new_keys,
        &auth,
        1_800_000_000,
        "guardian C replaced",
    )
    .unwrap();
    assert_eq!(envelopes.len(), 5);
    assert!(verify_rotation_receipt(&receipt).is_ok());
    assert!(!receipt.root_rotated);
    // New envelopes verify at epoch 8 and reconstruct the SAME root.
    let mut new_verified = Vec::new();
    for (i, env) in envelopes.iter().enumerate() {
        new_verified.push(unwrap_share(env, &new_keys[i], &set_id, 8).unwrap());
    }
    let recovered = recover_root(&new_verified[0..3]).unwrap();
    let k1 = derive_vault_key(&root, &set_id, 7).unwrap();
    let k2 = derive_vault_key(&recovered, &set_id, 7).unwrap();
    assert_eq!(k1, k2);
    // Old envelopes do NOT verify as epoch 8 (epoch binding).
    assert!(unwrap_share(&envelopes[0], &new_keys[0], &set_id, 7).is_err());
    // Non-advancing epoch → rejected.
    assert!(rotate_epoch(&verified[0..3], 7, 7, set_id, &new_keys, &auth, 1_800_000_000, "x").is_err());
    assert!(rotate_epoch(&verified[0..3], 7, 6, set_id, &new_keys, &auth, 1_800_000_000, "x").is_err());
    // Tampered receipt → rejected.
    let mut bad = receipt.clone();
    bad.new_epoch = 9;
    assert!(verify_rotation_receipt(&bad).is_err());
}

#[test]
fn t_rotate_root() {
    let mut r = rng();
    let auth = authority(&mut r);
    let (_root, _verified, _keys, _set_id) = setup_epoch7();
    let facts = vec![
        VaultFact::new("p1", "dog name?", "Biscuit", FactCategory::Personal).unwrap(),
    ];
    let mut new_keys = [[0u8; 32]; 5];
    for k in new_keys.iter_mut() {
        r.fill_bytes(k);
    }
    let rot = rotate_root(
        &facts,
        [0x11u8; 16],
        7,
        [0x22u8; 16],
        8,
        &new_keys,
        &auth,
        1_800_000_000,
        "suspected share exposure",
    )
    .unwrap();
    assert!(rot.receipt.root_rotated);
    assert!(verify_rotation_receipt(&rot.receipt).is_ok());
    // New vault opens with the new root's key; facts intact.
    let new_key = derive_vault_key(&rot.new_root, &[0x22u8; 16], 8).unwrap();
    let opened = open_vault(&rot.new_vault, &new_key, &[0x22u8; 16], 8).unwrap();
    assert_eq!(opened.len(), 1);
    assert!(opened[0].verify("Biscuit").unwrap());
    // New shares reconstruct the new root.
    let mut nv = Vec::new();
    for (i, env) in rot.new_envelopes.iter().enumerate() {
        nv.push(unwrap_share(env, &new_keys[i], &[0x22u8; 16], 8).unwrap());
    }
    let rec = recover_root(&nv).unwrap();
    let k1 = derive_vault_key(&rot.new_root, &[0x22u8; 16], 8).unwrap();
    let k2 = derive_vault_key(&rec, &[0x22u8; 16], 8).unwrap();
    assert_eq!(k1, k2);
}
