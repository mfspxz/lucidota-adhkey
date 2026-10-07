#!/usr/bin/env python3
"""Dispatch 4 LLM attackers against AdhKey 0.2.0 code.
Lanes: deepseek (vault), nemotron-550b (openrouter vault), mistral (vault), nim (Exchange).
Each gets: the code + the 22-point ontological critique + the attack mission.
Receipts -> ~/workspace/adhkey/redteam/
"""
import json
import os
import sys
import threading
import urllib.request
import urllib.error

sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
from dynamic_credentials import add_surrogate_to_request, read_json_response

BASE = "/home/hatch/workspace/adhkey"
OUT = os.path.join(BASE, "redteam")
os.makedirs(OUT, exist_ok=True)

CODE = open(os.path.join(BASE, "ADHKEY-CODE.txt")).read()
CRITIQUE = open(os.path.join(BASE, "AUDIT2-ONTOLOGY.md")).read()
DOCTRINE = open(os.path.join(BASE, "DOCTRINE.md")).read()

MISSION = """You are an adversarial security auditor. You are given:

1. ADHKEY-CODE: a Rust identity/key-lifecycle protocol (0.2.0), ~1300 LOC.
2. CRITIQUE: a 22-point ontological teardown of this code (assume it is CORRECT — do not re-litigate it).
3. DOCTRINE: four permanent rejection criteria.

YOUR MISSION — three tasks:

TASK A: Find security bugs the 22-point critique MISSED. Read the actual
code, not the critique's description of it. Look for: integer/logic bugs
in the state machine, TOCTOU windows, confused-deputy paths, places where
a test asserts less than its name promises, error paths that leak
authority, any `unwrap()`/panic on adversarial input, boundary conditions
in split/combine-style math. Each finding needs: severity (CRITICAL/HIGH/
MED), the exact function/line pattern, and a concrete exploit or failing
test case. If you find nothing new, say so explicitly — do not invent.

TASK B: Attack the recovery path specifically. The critique says approvals
are IDs not signatures and the transition isn't atomic. Assume those get
fixed naively (signatures added, validate-then-commit). Break the FIXED
version: what still goes wrong? Think about: replayed recovery statements,
competing recoveries, recovery of a revoked identity, policy version
confusion, witness equivocation.

TASK C: The critique demands a Statement-primitive redesign (subject/
predicate/object + issuer/evidence/policy/timestamp/state/signature, with
hash-chained authenticated events and reduce() -> derived state). Sketch
the MINIMAL core types for this in Rust (under 150 lines) that (1) makes
cuts #1, #2, #7, #15, #22 structurally impossible, and (2) preserves the
four doctrines as type-level or constructor-level guarantees.

OUTPUT FORMAT: numbered findings, terse. No praise, no summary of the
critique, no motivational language. If a task yields nothing, write
"NONE FOUND" for it and move on.
"""

FULL_PROMPT = MISSION + "\n\n===== DOCTRINE =====\n" + DOCTRINE + \
    "\n\n===== CRITIQUE (22 points, condensed) =====\n" + CRITIQUE + \
    "\n\n===== ADHKEY-CODE =====\n" + CODE


def call_direct(tag, cred, entry, host, url, model, max_tokens, body_fn):
    try:
        body = body_fn(FULL_PROMPT, model, max_tokens)
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        kwargs = {"allowed_hosts": [host]}
        if entry:
            kwargs["entry_name"] = entry
        add_surrogate_to_request(req, cred, **kwargs)
        with urllib.request.urlopen(req, timeout=600) as r:
            out = read_json_response(r)
        text = out["choices"][0]["message"]["content"]
        open(os.path.join(OUT, f"attacker-{tag}.txt"), "w").write(text)
        print(f"{tag}: OK {len(text)} chars")
    except Exception as e:
        print(f"{tag}: FAIL {type(e).__name__}: {str(e)[:150]}")


def deepseek_body(prompt, model, max_tokens):
    return json.dumps({"model": "deepseek-chat",
                       "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens}).encode()


def openrouter_body(prompt, model, max_tokens):
    return json.dumps({"model": model,
                       "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens}).encode()


def mistral_body(prompt, model, max_tokens):
    return json.dumps({"model": "mistral-large-latest",
                       "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens}).encode()


threads = [
    threading.Thread(target=call_direct, args=(
        "deepseek", "custom.deepseek", "acccess_token", "api.deepseek.com",
        "https://api.deepseek.com/v1/chat/completions", None, 4000, deepseek_body)),
    threading.Thread(target=call_direct, args=(
        "nemotron", "custom.openrouter", "acccess_token", "openrouter.ai",
        "https://openrouter.ai/api/v1/chat/completions",
        "nvidia/nemotron-3-ultra-550b-a55b:free", 4000, openrouter_body)),
    threading.Thread(target=call_direct, args=(
        "mistral", "custom.mistral", None, "api.mistral.ai",
        "https://api.mistral.ai/v1/chat/completions", None, 4000, mistral_body)),
]
for t in threads:
    t.start()
for t in threads:
    t.join()
print("direct lanes done")
