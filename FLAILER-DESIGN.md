# AdhKey Flailer Recovery — Design v1

**Problem:** AdhKey's k-of-n cryptographic recovery assumes you pre-designated recovery keys and still have access to them. If Zack loses ALL devices and can't reach his recovery keys, he's locked out. No heuristics exist.

**Solution:** A "flailer" protocol — layered self-vouching that lets a device-less Zack prove identity through knowledge, behavior, and social trust, then bootstrap a new key.

## Threat Model

**Defender:** Zack, zero devices, on a borrowed/new device, needs to recover AdhKey identity.
**Attacker:** Someone who knows Zack is locked out and tries to impersonate him during recovery. Has public info (social media, etc.) but NOT: his hypertimeline details, his writing style nuance, his personal vault secrets, or his trusted humans' cooperation.

**Non-goals:** Protecting against a nation-state who has compromised his trusted humans AND scraped his entire digital life. The protocol raises the bar to "must compromise multiple humans + know non-public details."

## Layers

### Layer 1: Knowledge Vault (encrypted, Shamir-split)

A vault of facts ONLY Zack knows:
- **Hypertimeline-derived:** "Where were you Oct 4 2026 at 20:00?" (GPS), "What did you spend $X on [date]?" (transactions), "Who did you message at [time]?"
- **Manual secrets:** passwords, PINs, answers to personal questions, "what did mom say when..."
- **Negative facts:** "What did you NOT do on [date]?" (harder to guess)

**Encryption:** XChaCha20-Poly1305. Key is Shamir-split (3-of-5):
- Share A: derived from Zack's memorized passphrase (Argon2id)
- Share B: mom
- Share C: cousin / best friend
- Share D: boss / trusted colleague
- Share E: paper backup in a safe place

**Recovery:** Zack provides passphrase → reconstructs Share A. Contacts 2 of the 4 humans → 3 shares → decrypt vault.

### Layer 2: Challenge-Response (before humans release shares)

Trusted humans don't hand over shares blindly. The protocol:
1. Zack initiates recovery, proves Share A (passphrase).
2. System generates challenges from the vault (which the human can verify without decrypting — challenges are pre-committed hashes).
3. Human asks Zack the challenges (via phone, in person, etc.).
4. Zack answers. Human verifies (they know enough context, or the system verifies against vault once decrypted).

**Challenge types:**
- **Timeline:** "Where were you on [date]?" (from hypertimeline GPS)
- **Transaction:** "What did you buy for $[amount] on [date]?"
- **Personal:** "What's the name of [personal detail]?"
- **Negative:** "Which of these did you NOT do?" (multiple choice, 1 correct)

### Layer 3: Behavioral (soft signals, not gates)

- **Stylometry:** Analyze the recovery conversation against Zack's writing baseline (from chats, emails). Scores similarity. A sudden style shift is a red flag.
- **Web fingerprinting:** Browser, OS, screen, timezone, fonts. Not identifying alone, but a mismatch (e.g., recovery from a device in a different country with no travel history) raises the threshold.

These adjust the required threshold: strong behavioral match → fewer challenges needed; mismatch → more challenges + human verification.

### Layer 4: Social Vouching (hard requirement)

At least 2 trusted humans must independently confirm "yes, this is Zack" via their own authenticated channels (phone call, in-person, etc.). This is the ultimate backstop — humans are good at detecting impersonators.

## Protocol Flow

```
1. INITIATE: Zack on new device → claims identity "I am Zack, I lost everything"
   → provides passphrase → Share A reconstructed

2. CONTACT: System notifies trusted humans (pre-configured: SMS, email, etc.)
   "Zack is attempting flailer recovery. Do NOT release your share until he passes challenges."

3. CHALLENGE: System generates 5 challenges from vault.
   Human asks Zack (or system asks via secure channel).
   Zack answers.

4. VERIFY: 
   - If 2+ humans provide shares → vault decrypted → answers checked cryptographically.
   - OR humans verify manually ("yeah, that's right").
   - Stylometry + fingerprinting score the session.

5. THRESHOLD: 
   - 3 shares (incl. Zack's) + 4/5 challenges correct + 2 human vouches = RECOVER
   - Anything less = FAIL, lockout timer, humans alerted.

6. RECOVER: New key generated → AdhKey recovery ceremony (k-of-n with the flailer evidence as the "k") → old keys revoked.
```

## Security Properties

- **No single point of failure:** Attacker needs Zack's passphrase AND 2 humans' shares AND to pass challenges.
- **Humans can't go rogue alone:** A single malicious human can't recover (needs 3 shares).
- **Zack can't be coerced easily:** He needs the humans; they verify it's really him.
- **Forward secrecy:** After recovery, vault is re-encrypted with a new key, shares re-split.

## What's NOT Here (v2)

- Automated challenge generation from live hypertimeline (currently manual vault population)
- Stylometry model training (needs baseline corpus)
- Secure human communication channel (currently assumes phone/in-person)

## Implementation Plan

1. `adhkey-flailer` crate: vault (encrypt/decrypt), Shamir split/recombine, challenge generation/verification.
2. Vault population tool: import from hypertimeline + manual entry.
3. Challenge protocol: interactive CLI for testing.
4. Stylometry baseline: extract from existing chats (future).
5. Integration with AdhKey core recovery.

---

**Status:** Design v1. Building now.
