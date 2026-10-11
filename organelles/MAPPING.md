# adhkey — organelle mapping decisions

Decomposition reviewed 2026-10-10 under the corrected doctrine
(decompose ACTUAL capabilities; map-or-design per unit, justified).

## What the code actually does

`adhkey` is a portable identity/key-lifecycle protocol plus its epistemic
machinery: identities with explicit key-state machines and recovery
ceremonies (`adhkey-core`), the atomic Statement object with cross-
implementation canonical bytes (`adhkey-statement`), a staged epistemic
verdict pipeline CLAIMED -> ESTABLISHED -> AUTHORIZED (`luci-verdict-core`),
a CAS-backed epistemic context cache (`luci-context`), and the sovereign
PreToolUse authority gateway over an embedded SurrealDB graph
(`muse-exchange`). Key management: passphrase -> Argon2id -> master key ->
domain subkeys (same shape as noter, separate codebase).

## Capability units -> organelles

| Unit | Source | Organelle / ops | Decision |
|---|---|---|---|
| Portable identity/key-lifecycle state machine | `adhkey-core` (lifecycle.rs: activate/transition/refound/recover; lib.rs: Identity/KeyId/KeyState/Event) | **adhkey-lifecycle** (`ak`): `create_identity`, `activate_key`, `transition_key`, `can_transition`, `key_state`, `active_keys` — all ReadOnly/Proven, by-value | **Bespoke** (`ak`). Justification: the computation is a domain key-state machine with recorded history (Lost->Active rejected without proof of possession). No ref organelle models key lifecycles. `ref-ledger-append` would record events but not ENFORCE the transition table — the wrong half. |
| Statement canonicalization | `adhkey-statement` (canonical_bytes, statement_hash) | **adhkey-statement** (`as`): `canonical_bytes`, `statement_hash` — ReadOnly/Proven, pure | **Bespoke** (`as`). Justification: domain-separated canonical encoding of the atomic object (evidence sorted by digest; same statement -> same bytes across implementations). `ref-hash-seal` seals blobs; this defines WHAT bytes get signed. Different computation. |
| Epistemic context cache | `luci-context` (EpistemicCache, FileCas) | **luci-context** (`lx`): `insert`/`compress`/`project` (Write, `lx.write`), `get`/`dereference`/`eviction_order`/`len` (ReadOnly) — Proven | **Bespoke** (`lx`). Justification: truth/provenance/necessity-scored cache with CAS-backed lossless compression and lossy-safe projection (UNKNOWN-marked, never silent). `ref-kv-store` is a blind KV; this is an epistemic cache with a projection theorem. Different computation. |
| Sovereign authority gateway | `muse-exchange` (MuseExchange::route, embedded SurrealKv) | **muse-exchange** (`mx`): `route` (Write, `mx.route`), `apply_schema` (Write, `mx.admin`) — Candidate | **Bespoke** (`mx`). Justification: PreToolUse adjudication over an embedded authority graph through the staged verdict pipeline. No ref organelle adjudicates tool calls. Transports native + unix-socket only (embedded DB, no MCP/REST surface). |

## Deliberate exclusions

- `luci-verdict-core` standalone (`adjudicate`): the pipeline's input
  types are not JSON-serializable and the crate has no serde; adding
  derives across 7 modules would churn the epistemic core for an
  artificial surface. The pipeline IS reachable — through `mx route`,
  which is its real invocation surface (the binary's stdin hook JSON
  maps 1:1 to the `route` op).
- `adhkey-crypto`: primitive library (audited FOSS only, no custom
  crypto) — supporting, not independently callable.
- `adhkey-store`: the KeyStore trait — adapters interface, no concrete
  in-repo surface to expose.
- `adhkey-statement::authenticate`: needs a signature-verification
  closure over real keys; exercised by the crate's own tests.
- `adhkey-core::refound_key` / `recover`: need a KeyOperator (real
  signature verification); exercised by the crate's own tests.
- `adhkey-flailer`: IN ACTIVE DEVELOPMENT (uncommitted recovery-
  protocol expansion as of 2026-10-10). Its API is moving; an organelle
  contract against it would be wrong on arrival. Migration follows when
  the API stabilizes. Documented, not hidden.

## Reference-organelle check (all 12 considered)

- `ref-ledger-append`: records; the lifecycle ENFORCES transitions.
  Wrong half (same argument as wreck).
- `ref-hash-seal`: seals blobs; `as` defines the canonical bytes that
  get signed. Adjacent, not overlapping.
- `ref-kv-store`: blind KV; `lx` is an epistemic cache with scored
  eviction and CAS reconstruction. Different computation.
- `ref-file-cas`: content-addressed files; `lx`'s CAS is an internal
  detail of the cache, not the exposed capability.
- Others: no overlap.
- Verdict: genuinely bespoke. Nothing reinvented that already existed.

## Execution facts

- `ak`, `as`: Proven, pure by-value; no fs, no network, no secrets
  (KeyId is an opaque identifier; no key material flows).
- `lx`: Proven; fs read-write on the CAS dir only; state is the
  in-memory item map + file CAS.
- `mx`: Candidate; async (tokio runtime owned by the organelle);
  embedded SurrealKv at the supplied path; writes ledger + evidence
  queue on route. No network.
- Envelopes: ak/as 1 cpu / 64 MB / 10 s; lx 1 cpu / 256 MB / 60 s;
  mx 2 cpu / 1 GB / 120 s.
- Receipts: content-addressed sha256, chained; `verify_chain` green
  in tests.
- Serde derives added (additive, behavior-preserving): adhkey-core
  lib.rs types, adhkey-statement types, luci-context item/cache
  types, luci-verdict-core Epistemic. No logic touched.
