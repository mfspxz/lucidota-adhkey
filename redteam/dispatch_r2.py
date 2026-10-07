#!/usr/bin/env python3
"""REDTEAM-002: attack the Statement model with Zackary's 8 kill-targets.
Lanes: deepseek, nemotron-550b (direct). NIM gets a separate queued job.
Target: crates/adhkey-statement/src/lib.rs + DOCTRINE.md + KILLLIST-STATEMENT.md
"""
import json
import os
import sys
import threading
import urllib.request

sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
from dynamic_credentials import add_surrogate_to_request, read_json_response

BASE = "/home/hatch/workspace/adhkey"
OUT = os.path.join(BASE, "redteam")
os.makedirs(OUT, exist_ok=True)

STMT = open(os.path.join(BASE, "crates/adhkey-statement/src/lib.rs")).read()
DOCTRINE = open(os.path.join(BASE, "DOCTRINE.md")).read()
KILL = open(os.path.join(BASE, "KILLLIST-STATEMENT.md")).read()

MISSION = """You are an adversarial protocol analyst. The target is a NEW
Statement-primitive identity model (Rust, ~400 lines). An earlier 22-point
critique killed the previous architecture; this is its replacement. Your
job is to try to MURDER this model.

You are given: the Statement model source, four permanent doctrines
(rejection criteria), and 8 specific kill-targets from the lead designer.

For EACH of the 8 kill-targets: either (a) break it with a concrete
exploit, failing test case, or constructed counterexample, or (b) state
explicitly that it HOLDS and why — with the exact mechanism in the code
that prevents the attack. Do not hedge; commit.

Then hunt for anything the 8 missed: read the actual code for logic bugs,
TOCTOU, encoding edge cases, type-system gaps where a claimed invariant is
actually just a comment.

OUTPUT: numbered sections per kill-target (BROKEN/HOLDS + evidence), then
"NEW:" findings. Terse. No praise, no summary of the brief.
"""

FULL = MISSION + "\n\n===== DOCTRINE =====\n" + DOCTRINE + \
    "\n\n===== KILL-LIST (8 targets) =====\n" + KILL + \
    "\n\n===== STATEMENT MODEL SOURCE =====\n" + STMT


def call(tag, cred, entry, host, url, model, max_tokens):
    try:
        body = json.dumps({"model": model,
                           "messages": [{"role": "user", "content": FULL}],
                           "max_tokens": max_tokens}).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        kw = {"allowed_hosts": [host]}
        if entry:
            kw["entry_name"] = entry
        add_surrogate_to_request(req, cred, **kw)
        with urllib.request.urlopen(req, timeout=600) as r:
            out = read_json_response(r)
        text = out["choices"][0]["message"]["content"]
        open(os.path.join(OUT, f"r2-{tag}.txt"), "w").write(text)
        print(f"r2-{tag}: OK {len(text)} chars")
    except Exception as e:
        print(f"r2-{tag}: FAIL {type(e).__name__}: {str(e)[:150]}")


ts = [
    threading.Thread(target=call, args=(
        "deepseek", "custom.deepseek", "access_token", "api.deepseek.com",
        "https://api.deepseek.com/v1/chat/completions", "deepseek-chat", 5000)),
    threading.Thread(target=call, args=(
        "nemotron", "custom.openrouter", "acccess_token", "openrouter.ai",
        "https://openrouter.ai/api/v1/chat/completions",
        "nvidia/nemotron-3-ultra-550b-a55b:free", 5000)),
]
for t in ts:
    t.start()
for t in ts:
    t.join()
print("round 2 direct lanes done")
