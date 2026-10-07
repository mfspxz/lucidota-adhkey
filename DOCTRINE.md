# AdhKey Court Doctrine — permanent

Every design, implementation, and adapter answers to these. They are not
aspirations; they are rejection criteria. A change that violates one is
rejected regardless of what it fixes.

1. **NO CLAIM MAY DERIVE AUTHORITY FROM ITS OWN EXISTENCE.**
   Existence in a struct, a log, or a receipt confers nothing.

2. **NO LOCAL STATE MAY CLAIM TO KNOW A REMOTE FACT WITHOUT A WITNESS,
   VERSION, AND FRESHNESS BOUND.**
   Offline honesty: CURRENT vs AS_OF(V) vs UNKNOWN. Never pretend.

3. **CONTROL OF A KEY ≠ IDENTITY OF A HUMAN.**
   Keys establish control of keys. Human identity requires evidence.

4. **MULTIPLE ATTESTATIONS ≠ INDEPENDENT ATTESTATIONS.**
   Count witnesses × trust-domain diversity × independence, not attestations.

5. **INFERENCE MAY DISCOVER IDENTITY RELATIONSHIPS. EVIDENCE MAY SUPPORT
   THEM. ONLY POLICY-GOVERNED ESTABLISHMENT MAY AUTHORIZE THEM.**
   No arrow goes backward. A heuristic score of 0.97 is a candidate
   relationship, never evidence.

6. **IMMUTABLE HISTORY, NOT IMMUTABLE SENTENCING.**
   Violation statements are permanent; authority decisions are revisable.
   Preserve "this event was established under policy P at version V" —
   never hard-code "this subject is condemned forever."

Filed 2026-10-06. Source: ontological audit (AUDIT2-ONTOLOGY.md), TIG
design (TIG-DESIGN.md), immune-system design (IMMUNE-SYSTEM-DESIGN.md).
