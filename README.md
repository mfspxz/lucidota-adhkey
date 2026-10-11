[Active R&D Lab] — no CI runs on record; active development, expect rough edges.

# AdhKey

A portable identity/key-lifecycle protocol that sits above any vault,
wallet, authenticator, OS keystore, HSM, or password manager.

**Not** a password manager. **Not** a blockchain. **Not** a wallet.
**Not** a DID chain. Adapters, not allegiance.

## The core question

> "Can this key sign this thing?"

```rust
trait KeyStore {
    fn public_key(&self, id: KeyId) -> Result<PublicKey>;
    fn sign(&self, id: KeyId, message: &[u8]) -> Result<Signature>;
}
```

## The product

**Identity persistence without credential persistence.** Key loss becomes
a normal state transition:

```
KEY-01 ACTIVE → LOST → recovery threshold → KEY-02 ACTIVE → KEY-01 REVOKED
IDENTITY-001 persists throughout.
```

## Crates

- `adhkey-core` — types, lifecycle state machine, verifier, the tiny Court.
  No crypto, no I/O. The auditable core.
- `adhkey-crypto` — audited FOSS primitives only (ed25519-dalek, sha2).
- `adhkey-store` — the `KeyStore` trait.

## The tiny Court

`cargo test -p adhkey-core` runs the adversarial suite: wrong/unknown/
revoked/expired key, wrong subject/scope/audience/nonce, replay, wrong
purpose, bad signature, unauthorized/partial/stale recovery, key
substitution — and the trichotomy test proving CLAIMED / ESTABLISHED /
AUTHORIZED never collapse into one boolean.

## Rules (MUST)

No particular key manager. No blockchain. No account. No private-key
transmission. Offline-capable. Fail closed. Identity, authentication,
authorization, and recovery stay distinct.

## Status

0.1.0 — core types, lifecycle, verifier, Court tests. Adapters and
conformance vectors next. Design: `docs/architecture/ADHKEY-DESIGN.md`.
