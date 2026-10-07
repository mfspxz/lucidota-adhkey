//! muse-exchange binary: the PreToolUse hook endpoint.
//!
//! Usage:
//!   echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' \
//!     | muse-exchange [--db PATH] [--ledger PATH] [--evidence-queue DIR]
//!
//! Reads the hook request JSON from stdin, queries the embedded
//! epistemic graph, prints the hook decision JSON to stdout.
//! Exit 0 always on a produced decision; exit 1 only on organelle
//! failure (which the hook layer treats as its own problem).

use muse_exchange::{HookRequest, MuseExchange};
use std::path::PathBuf;

fn home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("muse-exchange: organelle failure: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> muse_exchange::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut db_path = home().join(".muse-exchange/epistemic.db");
    let mut ledger = home().join("ledger/ledger-0001.jsonl");
    let mut queue = home().join("workspace/exchange/evidence-queue");

    let mut it = args.iter().skip(1).peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--db" => {
                db_path = it.next().map(PathBuf::from).unwrap_or(db_path);
            }
            "--ledger" => {
                ledger = it.next().map(PathBuf::from).unwrap_or(ledger);
            }
            "--evidence-queue" => {
                queue = it.next().map(PathBuf::from).unwrap_or(queue);
            }
            "--help" | "-h" => {
                println!(
                    "muse-exchange: sovereign PreToolUse authority gateway\n\
                     \n\
                     Reads hook JSON on stdin: \
                     {{\"tool_name\":\"Bash\",\"tool_input\":{{...}},\"task_hash\":\"...\"}}\n\
                     Prints hook decision JSON on stdout.\n\
                     \n\
                     Flags: --db PATH  --ledger PATH  --evidence-queue DIR"
                );
                return Ok(());
            }
            other => {
                eprintln!("muse-exchange: unknown flag '{}', see --help", other);
                std::process::exit(2);
            }
        }
    }

    // Read the whole hook request from stdin.
    let mut input = String::new();
    use std::io::Read;
    std::io::stdin().read_to_string(&mut input)?;
    if input.trim().is_empty() {
        eprintln!("muse-exchange: empty stdin; expected hook request JSON");
        std::process::exit(2);
    }
    let req: HookRequest = serde_json::from_str(&input)?;

    let ex = MuseExchange::init(&db_path, ledger, queue).await?;
    ex.apply_schema().await?;
    let decision = ex.route(&req).await?;
    println!("{}", serde_json::to_string(&decision.to_json())?);
    Ok(())
}
