#!/usr/bin/env python3
"""REDTEAM-003: attack the TIG operational design (5 ideas + kill-targets 9-14).
Lanes: deepseek, nemotron-550b (direct). NIM queued separately.
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

TIGOP = open(os.path.join(BASE, "TIG-OPERATIONAL.md")).read()
TIG = open(os.path.join(BASE, "TIG-DESIGN.md")).read()
KILL = open(os.path.join(BASE, "KILLLIST-STATEMENT.md")).read()
DOC = open(os.path.join(BASE, "DOCTRINE.md")).read()
CONSOL = open(os.path.join(BASE, "CONSOLIDATION-002.md")).read()

MISSION = """You are an adversarial systems analyst. Target: a DESIGN (not
code) for the Ternary Identity Graph (TIG) operational engine — five
structural ideas for turning an epistemically-typed identity graph into a
working system. A previous red-team round converged on breaks in the
underlying Statement model (summary provided); this round attacks the
operational layer ABOVE it.

You are given: the 5 operational ideas, the TIG design, kill-targets 9-14
(aimed at this layer), five permanent doctrines, and the round-2
consolidation (context on what already broke below).

For EACH kill-target 9-14: (a) break it with a concrete attack scenario —
who attacks, what they control, the exact steps, what the system does
wrong — or (b) state it HOLDS and name the mechanism that prevents it.
Commit.

Then: attack the five ideas directly. Best targets: the "O(1) retraction"
claim, the "same clock cycle" lease termination, the epistemic firewall
under adversarial scheduling, EQL as a trust boundary, the 15-primitive
seams. Find what the kill-targets missed.

OUTPUT: numbered sections per kill-target (BROKEN/HOLDS + scenario), then
"NEW:" findings. Terse. No praise. End with: VERDICT: <one sentence>."""

FULL = MISSION + "\n\n===== DOCTRINE =====\n" + DOC + \
    "\n\n===== TIG DESIGN =====\n" + TIG + \
    "\n\n===== 5 OPERATIONAL IDEAS (TARGET) =====\n" + TIGOP + \
    "\n\n===== KILL-TARGETS 9-14 =====\n" + KILL + \
    "\n\n===== ROUND-2 CONTEXT =====\n" + CONSOL


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
        open(os.path.join(OUT, f"r3-{tag}.txt"), "w").write(text)
        print(f"r3-{tag}: OK {len(text)} chars")
    except Exception as e:
        print(f"r3-{tag}: FAIL {type(e).__name__}: {str(e)[:150]}")


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
print("round 3 direct lanes done")
