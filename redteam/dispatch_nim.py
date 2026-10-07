#!/usr/bin/env python3
"""Submit the 4th attacker (NIM gpt-oss-20b) as an Exchange job."""
import json
import os
import urllib.request

EXCHANGE = "https://lucidota-exchange.cutecity.workers.dev"
KEY = open(os.path.expanduser("~/.exchange_key")).read().strip()
BASE = "/home/hatch/workspace/adhkey"

# Trimmed package for the fast lane: core source (no court tests) + critique
code_parts = []
for f in ["crates/adhkey-core/src/lib.rs", "crates/adhkey-core/src/lifecycle.rs",
          "crates/adhkey-core/src/verifier.rs",
          "crates/adhkey-core/src/evidence.rs"]:
    code_parts.append(f"===== {f} =====\n" + open(os.path.join(BASE, f)).read())
CODE = "\n\n".join(code_parts)
CRITIQUE = open(os.path.join(BASE, "AUDIT2-ONTOLOGY.md")).read()

PROMPT = """You are an adversarial security auditor. Given (1) Rust identity-protocol source below and (2) a 22-point critique (assume correct), do three tasks:

TASK A: Find security bugs the critique MISSED. Read the code itself. Each finding: severity, exact location, concrete exploit or failing test. If none, say NONE FOUND.
TASK B: Assume the critique's recovery flaws (IDs-not-signatures, non-atomic) get fixed naively. Break the FIXED version: replayed recoveries, competing recoveries, policy version confusion.
TASK C: Sketch minimal Rust types (<100 lines) for a Statement primitive (subject/predicate/object + issuer/evidence/policy/timestamp/state/signature, hash-chained events, reduce() -> derived state) making the critique's cuts #1, #2, #7, #15, #22 structurally impossible.

Terse numbered findings. No praise.

===== CRITIQUE =====
""" + CRITIQUE + "\n\n===== CODE =====\n" + CODE + \
    '\n\nEnd with a final line: VERDICT: <one sentence>.'


def gov(method, path, body=None):
    req = urllib.request.Request(
        EXCHANGE + path, data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {KEY}",
                 "User-Agent": "lucidota-research/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


spec = {"capability": "inference",
        "input": {"model": "openai/gpt-oss-20b",
                  "messages": [{"role": "user", "content": PROMPT}],
                  "max_tokens": 4000},
        "data_class": "public", "max_cost": 0,
        "idempotency_key": "adhkey-redteam-nim"}
d = gov("POST", "/v1/job", spec)
print("nim attacker ->", d.get("job_id"), d.get("state"))
json.dump({"nim": d.get("job_id")},
          open(os.path.join(BASE, "redteam", "nim_job.json"), "w"))
