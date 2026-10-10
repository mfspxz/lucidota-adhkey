//! flailer-cli: stateless ceremony tool for the P3 guardian machinery.
//!
//! No persistence here — sessions, chains, and stores belong to P4. Every
//! command reads explicit arguments and prints JSON. Pipe JSON between
//! commands or store it wherever the operator keeps ceremony material.
//!
//! Commands:
//!   keygen                                            fresh Ed25519 keypair (hex)
//!   enroll --authority-key <hex> --guardian-id <hex16> --index <n>
//!          --guardian-pubkey <hex32> --set <hex16> --epoch <n>
//!   approve --signing-key <hex32> --guardian-id <hex16> --session-id <hex16>
//!           --nonce <hex16> --epoch <n> --expires <unix> --policy-version <n>
//!           --decision approve|deny
//!   paper --share <hex33> --set <hex16> --epoch <n> --index <n>
//!   paper-verify <FL1-...>

use adhkey_flailer::{
    enroll_guardian, sign_approval, verify_enrollment_receipt, Decision,
};
use adhkey_flailer::secret_sharing::{decode_paper_share, encode_paper_share};
use adhkey_flailer::secret_sharing::UnverifiedShare;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  flailer keygen");
    eprintln!("  flailer enroll --authority-key <hex32> --guardian-id <hex16> --index <n> --guardian-pubkey <hex32> --set <hex16> --epoch <n>");
    eprintln!("  flailer approve --signing-key <hex32> --guardian-id <hex16> --session-id <hex16> --nonce <hex16> --epoch <n> --expires <unix> --policy-version <n> --decision approve|deny");
    eprintln!("  flailer paper --share <hex33> --set <hex16> --epoch <n> --index <n>");
    eprintln!("  flailer paper-verify <FL1-...>");
    std::process::exit(2);
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or("bad hex")?;
        let lo = (pair[1] as char).to_digit(16).ok_or("bad hex")?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn parse_args() -> (String, HashMap<String, String>, Vec<String>) {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| usage());
    let mut flags = HashMap::new();
    let mut positionals = Vec::new();
    while let Some(a) = it.next() {
        if let Some(k) = a.strip_prefix("--") {
            let v = it.next().unwrap_or_else(|| usage());
            flags.insert(k.to_string(), v);
        } else {
            positionals.push(a);
        }
    }
    (cmd, flags, positionals)
}

fn get_flag(flags: &HashMap<String, String>, name: &str) -> Result<String, String> {
    flags.get(name).cloned().ok_or_else(|| format!("missing --{name}"))
}

fn get_bytes(flags: &HashMap<String, String>, name: &str, len: usize) -> Result<Vec<u8>, String> {
    let b = hex_decode(&get_flag(flags, name)?)?;
    if b.len() != len {
        return Err(format!("--{name} must be {len} bytes"));
    }
    Ok(b)
}

fn get_u64(flags: &HashMap<String, String>, name: &str) -> Result<u64, String> {
    get_flag(flags, name)?.parse::<u64>().map_err(|_| format!("bad --{name}"))
}

fn get_u8(flags: &HashMap<String, String>, name: &str) -> Result<u8, String> {
    get_flag(flags, name)?.parse::<u8>().map_err(|_| format!("bad --{name}"))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("flailer: error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (cmd, flags, positionals) = parse_args();
    match cmd.as_str() {
        "keygen" => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|_| "rng failed".to_string())?;
            let sk = SigningKey::from_bytes(&seed);
            let out = serde_json::json!({
                "signing_key_seed": hex_encode(&seed),
                "verifying_key": hex_encode(&sk.verifying_key().to_bytes()),
                "warning": "store the seed offline; anyone with it can sign as this key",
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
            Ok(())
        }
        "enroll" => {
            let seed = get_bytes(&flags, "authority-key", 32)?;
            let mut gid = [0u8; 16];
            gid.copy_from_slice(&get_bytes(&flags, "guardian-id", 16)?);
            let index = get_u8(&flags, "index")?;
            let mut gpk = [0u8; 32];
            gpk.copy_from_slice(&get_bytes(&flags, "guardian-pubkey", 32)?);
            let mut set = [0u8; 16];
            set.copy_from_slice(&get_bytes(&flags, "set", 16)?);
            let epoch = get_u64(&flags, "epoch")?;
            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(&seed);
            let auth = SigningKey::from_bytes(&seed_arr);
            let receipt = enroll_guardian(gid, index, &gpk, set, epoch, &auth, now_unix())
                .map_err(|e| e.to_string())?;
            // Self-verify before printing: never emit a receipt we can't verify.
            verify_enrollment_receipt(&receipt, &gpk).map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            Ok(())
        }
        "approve" => {
            let seed = get_bytes(&flags, "signing-key", 32)?;
            let mut gid = [0u8; 16];
            gid.copy_from_slice(&get_bytes(&flags, "guardian-id", 16)?);
            let mut sid = [0u8; 16];
            sid.copy_from_slice(&get_bytes(&flags, "session-id", 16)?);
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&get_bytes(&flags, "nonce", 16)?);
            let epoch = get_u64(&flags, "epoch")?;
            let expires = get_u64(&flags, "expires")?;
            let pv = get_flag(&flags, "policy-version")?.parse::<u32>().map_err(|_| "bad --policy-version")?;
            let decision = match get_flag(&flags, "decision")?.as_str() {
                "approve" => Decision::Approve,
                "deny" => Decision::Deny,
                _ => return Err("--decision must be approve|deny".to_string()),
            };
            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(&seed);
            let sk = SigningKey::from_bytes(&seed_arr);
            let approval = sign_approval(&sk, gid, sid, &nonce, epoch, expires, pv, decision);
            // Show the guardian exactly what they are signing.
            eprintln!("signing approval for session {} decision {:?} (statement {} bytes)",
                hex_encode(&sid), decision, approval.statement.len());
            println!("{}", serde_json::to_string_pretty(&approval).unwrap());
            Ok(())
        }
        "paper" => {
            let share_bytes = get_bytes(&flags, "share", 33)?;
            let mut set = [0u8; 16];
            set.copy_from_slice(&get_bytes(&flags, "set", 16)?);
            let epoch = get_u64(&flags, "epoch")?;
            let index = get_u8(&flags, "index")?;
            let share = UnverifiedShare::from_bytes(share_bytes).map_err(|e| e.to_string())?;
            let encoded = encode_paper_share(&share, set, epoch, index)
                .map_err(|e| e.to_string())?;
            println!("{encoded}");
            eprintln!("store on paper, separately from all other recovery material. never photograph.");
            Ok(())
        }
        "paper-verify" => {
            let enc = positionals.first().ok_or("missing encoding argument")?;
            let (_share, set_id, epoch, index) =
                decode_paper_share(enc).map_err(|e| e.to_string())?;
            let out = serde_json::json!({
                "valid": true,
                "set_id": hex_encode(&set_id),
                "epoch": epoch,
                "index": index,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
            Ok(())
        }
        _ => usage(),
    }
}

