    use super::*;

    fn subj(ns: &str, id: &str) -> SubjectRef {
        SubjectRef {
            namespace: ns.into(),
            id: id.into(),
        }
    }

    fn stmt(seq: u64, prev: [u8; 32]) -> Statement {
        Statement {
            subject: subj("test", "S1"),
            predicate: Predicate::Controls,
            object: Object::Key(KeyRef([1u8; 32])),
            issuer: subj("test", "S1"),
            issuer_key: KeyRef([1u8; 32]),
            evidence: vec![],
            policy: "P".into(),
            policy_version: 1,
            timestamp: 1000,
            sequence: seq,
            previous: prev,
            signature: vec![0xAA],
            suite: "test".into(),
        }
    }

    fn cfg() -> AuthConfig {
        AuthConfig::strict(vec!["test".into()])
    }

    /// Trust roots for the "test" namespace: keys [1u8;32] and [2u8;32].
    fn roots() -> TrustRoots {
        let mut r = TrustRoots::default();
        r.roots.insert(("test".into(), KeyRef([1u8; 32])));
        r.roots.insert(("test".into(), KeyRef([2u8; 32])));
        r
    }

    fn auth(s: Statement, prev: Option<&AuthenticatedStatement>) -> Claimed<AuthenticatedStatement> {
        authenticate(s, prev, |_, _, _, _| true, &cfg()).unwrap()
    }

    // ---------- existing tests, updated to the two-phase API ----------

    #[test]
    fn chain_enforced() {
        let g = auth(stmt(0, [0u8; 32]), None);
        // Gap: seq 2 after 0 -> rejected.
        assert_eq!(
            authenticate(stmt(2, g.inner().hash()), Some(g.inner()), |_, _, _, _| true, &cfg()),
            Err(AuthError::SequenceGap)
        );
        // Wrong prev hash -> rejected.
        assert_eq!(
            authenticate(stmt(1, [9u8; 32]), Some(g.inner()), |_, _, _, _| true, &cfg()),
            Err(AuthError::ChainBreak)
        );
        // Correct -> accepted (as a CLAIM).
        let s1 = auth(stmt(1, g.inner().hash()), Some(g.inner()));
        assert_eq!(s1.inner().statement().sequence, 1);
    }

    #[test]
    fn bad_signature_rejected() {
        let r = authenticate(stmt(0, [0u8; 32]), None, |_, _, _, _| false, &cfg());
        assert_eq!(r, Err(AuthError::BadSignature));
    }

    #[test]
    fn canonical_deterministic() {
        let a = stmt(0, [0u8; 32]);
        let b = stmt(0, [0u8; 32]);
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
        assert_eq!(statement_hash(&a), statement_hash(&b));
    }

    #[test]
    fn reduce_derives_controls() {
        let g = auth(stmt(0, [0u8; 32]), None);
        let st = reduce(&[g], &roots(), &AcceptAll);
        let keys = &st.controls[&subj("test", "S1")];
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], KeyRef([1u8; 32]));
    }

    #[test]
    fn no_identity_struct_to_construct() {
        let st = DerivedState::default();
        assert!(st.controls.is_empty());
    }

    #[test]
    fn equivocation_is_conflict_not_tiebreak() {
        let g = auth(stmt(0, [0u8; 32]), None);
        let s1 = stmt(1, g.inner().hash());
        let mut s2 = stmt(1, g.inner().hash());
        s2.object = Object::Key(KeyRef([2u8; 32])); // different content
        let a1 = auth(s1, Some(g.inner()));
        let a2 = auth(s2, Some(g.inner()));
        assert_ne!(a1.inner().hash(), a2.inner().hash());
        let st = reduce(&[a1, a2, g], &roots(), &AcceptAll);
        assert_eq!(st.conflicts.len(), 1);
        let keys = &st.controls[&subj("test", "S1")];
        assert_eq!(keys.len(), 1, "only genesis controls survived");
        assert_eq!(keys[0], KeyRef([1u8; 32]));
    }

    // ---------- regression tests per finding ----------

    /// T1 (nim-resub #1, deepseek #1, nemotron #1): self-authority.
    /// Alice mints a genesis for Bob's subject. Signed, chained — but
    /// Alice's key is not a trust root: UntrustedGenesis, never applied.
    #[test]
    fn t1_self_authority_rejected() {
        let mut roots = TrustRoots::default();
        roots.roots.insert(("test".into(), KeyRef([0xBB; 32])));
        let mut gb = stmt(0, [0u8; 32]);
        gb.subject = subj("test", "Bob");
        gb.issuer = subj("test", "Bob");
        gb.issuer_key = KeyRef([0xBB; 32]);
        gb.object = Object::Key(KeyRef([0xBB; 32]));
        let gb = auth(gb, None);
        let mut evil = stmt(0, [0u8; 32]);
        evil.subject = subj("test", "Bob");
        evil.issuer = subj("test", "Alice");
        evil.issuer_key = KeyRef([0xAA; 32]);
        evil.object = Object::Key(KeyRef([0xAA; 32]));
        let evil = auth(evil, None);
        assert_eq!(
            authorize_issuance(&evil, &DerivedState::default(), &roots, &AcceptAll),
            Err(AuthError::UntrustedGenesis)
        );
        let st = reduce(&[gb, evil], &roots, &AcceptAll);
        assert_eq!(st.controls[&subj("test", "Bob")], vec![KeyRef([0xBB; 32])]);
        assert!(st
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::UntrustedGenesis));
    }

    /// T1b (nim-resub #6): issuer_key binding. A statement that claims
    /// issuer Bob but is signed by Alice's key is rejected even though the
    /// (caller-supplied) signature closure returns true.
    #[test]
    fn t1b_wrong_issuer_key_rejected() {
        let g = auth(stmt(0, [0u8; 32]), None);
        let mut s1 = stmt(1, g.inner().hash());
        s1.issuer_key = KeyRef([0xAA; 32]); // not Bob's/S1's key
        let s1 = auth(s1, Some(g.inner()));
        let mut st = DerivedState::default();
        st.controls
            .insert(subj("test", "S1"), vec![KeyRef([1u8; 32])]);
        assert_eq!(
            authorize_issuance(&s1, &st, &roots(), &AcceptAll),
            Err(AuthError::UnauthorizedIssuer)
        );
    }

    /// T1c: the verifier actually receives the issuing key.
    #[test]
    fn t1c_verifier_receives_issuer_key() {
        use std::cell::Cell;
        let seen = Cell::new(KeyRef([0u8; 32]));
        let r = authenticate(
            stmt(0, [0u8; 32]),
            None,
            |key, _, _, _| {
                seen.set(*key);
                true
            },
            &cfg(),
        );
        assert!(r.is_ok());
        assert_eq!(seen.get(), KeyRef([1u8; 32]));
    }

    /// T1d (positive): delegation works. Bob roots, grants Alice's key via
    /// Controls, Alice then rotates to Carol's key. Each step authorized.
    #[test]
    fn t1d_delegation_through_controls() {
        let mut roots = TrustRoots::default();
        roots.roots.insert(("test".into(), KeyRef([0xBB; 32])));
        let mut gb = stmt(0, [0u8; 32]);
        gb.subject = subj("test", "Bob");
        gb.issuer = subj("test", "Bob");
        gb.issuer_key = KeyRef([0xBB; 32]);
        gb.object = Object::Key(KeyRef([0xBB; 32]));
        let gb = auth(gb, None);
        // Bob grants Alice's key.
        let mut g1 = stmt(1, gb.inner().hash());
        g1.subject = subj("test", "Bob");
        g1.issuer = subj("test", "Bob");
        g1.issuer_key = KeyRef([0xBB; 32]);
        g1.object = Object::Key(KeyRef([0xAA; 32]));
        let g1 = auth(g1, Some(gb.inner()));
        // Alice rotates Bob's key to Carol's (Replaces must name live old).
        // Alice's own genesis about Bob: sequence 0 in the (Alice, Bob)
        // chain, zero previous. It cannot authorize until Bob's grant of
        // her key is applied — the fixpoint in reduce handles the ordering.
        let mut g2 = stmt(0, [0u8; 32]);
        g2.subject = subj("test", "Bob");
        g2.issuer = subj("test", "Alice");
        g2.issuer_key = KeyRef([0xAA; 32]);
        g2.predicate = Predicate::Replaces {
            old: KeyRef([0xBB; 32]),
            new: KeyRef([0xCC; 32]),
        };
        g2.object = Object::Key(KeyRef([0xCC; 32]));
        let g2 = auth(g2, None);
        let st = reduce(&[gb, g1, g2], &roots, &AcceptAll);
        assert!(st.rejected.is_empty(), "{:?}", st.rejected);
        let mut keys = st.controls[&subj("test", "Bob")].clone();
        keys.sort();
        let mut expected = vec![KeyRef([0xAA; 32]), KeyRef([0xCC; 32])];
        expected.sort();
        assert_eq!(keys, expected);
    }

    /// T2 (nim-resub #2, deepseek #2): genesis without trust-root anchor.
    /// Covered by t1 (UntrustedGenesis). Positive case: registered root's
    /// genesis authorizes.
    #[test]
    fn t2_trusted_genesis_authorizes() {
        let g = auth(stmt(0, [0u8; 32]), None);
        let r = authorize_issuance(&g, &DerivedState::default(), &roots(), &AcceptAll);
        assert!(r.is_ok());
        // Wrong namespace: same key, unregistered namespace -> rejected.
        let mut s = stmt(0, [0u8; 32]);
        s.subject = subj("other", "S1");
        let s = auth(s, None);
        assert_eq!(
            authorize_issuance(&s, &DerivedState::default(), &roots(), &AcceptAll),
            Err(AuthError::UntrustedGenesis)
        );
    }

    /// T3 (deepseek 3d): sequence overflow uses checked_add. A genesis
    /// claiming u64::MAX is a gap (genesis must be 0), not a wrap.
    #[test]
    fn t3_sequence_overflow_checked() {
        let s = stmt(u64::MAX, [0u8; 32]);
        let r = authenticate(s, None, |_, _, _, _| true, &cfg());
        assert_eq!(r, Err(AuthError::SequenceGap));
        // And a normal increment path is unaffected.
        let g = auth(stmt(0, [0u8; 32]), None);
        assert!(auth(stmt(1, g.inner().hash()), Some(g.inner()))
            .inner()
            .statement()
            .sequence
            == 1);
    }

    /// T4 (nim-resub #12): suite allowlist, exact match.
    #[test]
    fn t4_suite_allowlist() {
        let mut s = stmt(0, [0u8; 32]);
        s.suite = "ed25519".into();
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::UnknownSuite)
        );
        let mut s = stmt(0, [0u8; 32]);
        s.suite = "".into();
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::UnknownSuite)
        );
        // Exact match passes.
        assert!(auth(stmt(0, [0u8; 32]), None).inner().hash() != [0u8; 32]);
    }

    /// T6 (nim-resub #7, #9): evidence validation.
    fn ev(digest: [u8; 32], from: u64, until: Option<u64>, revoked: bool) -> EvidenceRef {
        EvidenceRef {
            digest,
            issuer: subj("test", "W"),
            predicate: Predicate::Attests,
            valid_from: from,
            valid_until: until,
            revoked,
        }
    }

    #[test]
    fn t6_evidence_windows_enforced() {
        // valid_from > valid_until
        let mut s = stmt(0, [0u8; 32]);
        s.evidence = vec![ev([7u8; 32], 2000, Some(1000), false)];
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::InvalidEvidence)
        );
        // statement timestamp after valid_until (ts=1000, until=500)
        let mut s = stmt(0, [0u8; 32]);
        s.evidence = vec![ev([7u8; 32], 0, Some(500), false)];
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::InvalidEvidence)
        );
        // statement timestamp before valid_from (ts=1000, from=2000)
        let mut s = stmt(0, [0u8; 32]);
        s.evidence = vec![ev([7u8; 32], 2000, None, false)];
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::InvalidEvidence)
        );
        // revoked evidence
        let mut s = stmt(0, [0u8; 32]);
        s.evidence = vec![ev([7u8; 32], 0, None, true)];
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::InvalidEvidence)
        );
        // self-reference (cycle of length 1): UNCONSTRUCTIBLE with a
        // preimage-resistant hash. The statement hash commits to the evidence
        // list, so citing your own final hash requires a SHA-256 fixed
        // point. The check in authenticate() stays as defense-in-depth
        // (hash agility), but no test can trigger it honestly — asserting
        // the near-miss instead: a digest of the PRE-evidence hash is not
        // a self-reference and must not trip the cycle check.
        let mut s = stmt(0, [0u8; 32]);
        let h = statement_hash(&s);
        s.evidence = vec![ev(h, 0, None, false)];
        assert!(authenticate(s, None, |_, _, _, _| true, &cfg()).is_ok());
        // fan-out bound
        let mut s = stmt(0, [0u8; 32]);
        s.evidence = (0..17).map(|i| ev([i as u8; 32], 0, None, false)).collect();
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::InvalidEvidence)
        );
        // valid evidence passes
        let mut s = stmt(0, [0u8; 32]);
        s.evidence = vec![ev([7u8; 32], 0, Some(2000), false)];
        assert!(auth(s, None).inner().hash() != [0u8; 32]);
    }

    /// T7 (nim-resub #13, deepseek N2): predicate/object compatibility.
    /// Replaces' object MUST be Key(new): one semantic, one channel.
    #[test]
    fn t7_predicate_object_compatibility() {
        let mut s = stmt(0, [0u8; 32]);
        s.object = Object::Text("not a key".into());
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::PredicateObjectMismatch)
        );
        let mut s = stmt(0, [0u8; 32]);
        s.predicate = Predicate::Withdraws;
        s.object = Object::Key(KeyRef([9u8; 32]));
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::PredicateObjectMismatch)
        );
        let mut s = stmt(0, [0u8; 32]);
        s.predicate = Predicate::Replaces {
            old: KeyRef([1u8; 32]),
            new: KeyRef([2u8; 32]),
        };
        s.object = Object::Key(KeyRef([1u8; 32])); // old, not new
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::PredicateObjectMismatch)
        );
        // Correct Replaces passes authenticate...
        let mut s = stmt(0, [0u8; 32]);
        s.predicate = Predicate::Replaces {
            old: KeyRef([1u8; 32]),
            new: KeyRef([2u8; 32]),
        };
        s.object = Object::Key(KeyRef([2u8; 32]));
        let _ = auth(s, None);
        // ...but reduce rejects rotation of a non-controlled key.
        // (covered in t7b below)
    }

    /// T7b (deepseek 3c): Replaces naming an unrelated old key is rejected
    /// at reduce, not silently applied.
    #[test]
    fn t7b_replaces_unknown_old_key_rejected() {
        let g = auth(stmt(0, [0u8; 32]), None);
        let mut r = stmt(1, g.inner().hash());
        r.predicate = Predicate::Replaces {
            old: KeyRef([0xFF; 32]), // never controlled
            new: KeyRef([0xCC; 32]),
        };
        r.object = Object::Key(KeyRef([0xCC; 32]));
        let r = auth(r, Some(g.inner()));
        let st = reduce(&[g, r], &roots(), &AcceptAll);
        // The unrelated key was NOT added.
        assert_eq!(st.controls[&subj("test", "S1")], vec![KeyRef([1u8; 32])]);
        assert!(st
            .rejected
            .iter()
            .any(|x| x.reason == RejectReason::UnknownOldKey));
    }

    /// T8 (deepseek N3): withdrawals are APPLIED. This was a live bug:
    /// withdrawn Controls keys stayed in `controls` forever.
    #[test]
    fn t8_withdrawals_applied() {
        let g = auth(stmt(0, [0u8; 32]), None);
        let gh = g.inner().hash();
        let mut w = stmt(1, gh);
        w.predicate = Predicate::Withdraws;
        w.object = Object::StatementHash(gh);
        let w = auth(w, Some(g.inner()));
        let st = reduce(&[g, w], &roots(), &AcceptAll);
        assert_eq!(st.withdrawn, vec![gh]);
        assert!(
            st.controls.get(&subj("test", "S1")).map_or(true, |v| v.is_empty()),
            "withdrawn key must be removed: {:?}",
            st.controls
        );
    }

    /// T9 (deepseek N1, N9): reduce is order-independent. A fork with a
    /// descendant on one branch yields identical state regardless of log
    /// order, and post-fork effects never survive.
    #[test]
    fn t9_reduce_order_independent() {
        let g = auth(stmt(0, [0u8; 32]), None);
        let gh = g.inner().hash();
        let a1 = stmt(1, gh);
        let mut a2 = stmt(1, gh);
        a2.object = Object::Key(KeyRef([2u8; 32]));
        let a1 = auth(a1, Some(g.inner()));
        let a2 = auth(a2, Some(g.inner()));
        // child of a1 (would apply effects if order leaked)
        let mut ch = stmt(2, a1.inner().hash());
        ch.object = Object::Key(KeyRef([3u8; 32]));
        let ch = auth(ch, Some(a1.inner()));
        let st1 = reduce(
            &[g.clone(), a1.clone(), ch.clone(), a2.clone()],
            &roots(),
            &AcceptAll,
        );
        let st2 = reduce(
            &[g.clone(), a1.clone(), a2.clone(), ch.clone()],
            &roots(),
            &AcceptAll,
        );
        assert_eq!(st1, st2, "reduce must be order-independent");
        assert_eq!(st1.conflicts.len(), 1);
        // Only genesis effects survived: no fork-branch keys, no child key.
        assert_eq!(
            st1.controls[&subj("test", "S1")],
            vec![KeyRef([1u8; 32])]
        );
    }

    /// T9b: independent rooted chains (a forest of legitimate chains)
    /// reduce independently in one log.
    #[test]
    fn t9b_forest_fragment_rejected() {
        let g = auth(stmt(0, [0u8; 32]), None);
        let mut g2 = stmt(0, [0u8; 32]);
        g2.subject = subj("test", "S2");
        g2.issuer = subj("test", "S2");
        g2.issuer_key = KeyRef([2u8; 32]);
        g2.object = Object::Key(KeyRef([2u8; 32]));
        let g2 = auth(g2, None);
        let st = reduce(&[g, g2], &roots(), &AcceptAll);
        assert_eq!(st.controls[&subj("test", "S1")], vec![KeyRef([1u8; 32])]);
        assert_eq!(st.controls[&subj("test", "S2")], vec![KeyRef([2u8; 32])]);
        assert!(st.rejected.is_empty());
    }

    /// T10 (nim-resub #11): empty subject/issuer fields rejected.
    #[test]
    fn t10_empty_subject_rejected() {
        let mut s = stmt(0, [0u8; 32]);
        s.subject.namespace = "".into();
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::EmptySubject)
        );
        let mut s = stmt(0, [0u8; 32]);
        s.issuer.id = "".into();
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::EmptySubject)
        );
    }

    /// T11 (nim-resub #8): policy is enforced, not decorative.
    /// Empty policy id rejected; Disproven policy blocks application and is
    /// recorded; Unknown fails closed.
    #[test]
    fn t11_policy_enforced() {
        let mut s = stmt(0, [0u8; 32]);
        s.policy = "".into();
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::EmptyPolicy)
        );
        struct DenyAll;
        impl IssuancePolicy for DenyAll {
            fn evaluate(&self, _s: &Statement, _st: &DerivedState) -> Epistemic {
                Epistemic::Disproven
            }
        }
        struct Shrug;
        impl IssuancePolicy for Shrug {
            fn evaluate(&self, _s: &Statement, _st: &DerivedState) -> Epistemic {
                Epistemic::Unknown
            }
        }
        let g = auth(stmt(0, [0u8; 32]), None);
        let st = reduce(&[g.clone()], &roots(), &DenyAll);
        assert!(st.controls.get(&subj("test", "S1")).map_or(true, |v| v.is_empty()));
        assert!(st
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::PolicyRejected));
        let st = reduce(&[g], &roots(), &Shrug);
        assert!(st
            .rejected
            .iter()
            .any(|r| r.reason == RejectReason::PolicyUnknown));
    }

    /// T12 (deepseek 4e): evidence order does not affect canonical bytes.
    #[test]
    fn t12_evidence_order_canonical() {
        let mut a = stmt(0, [0u8; 32]);
        let mut b = stmt(0, [0u8; 32]);
        a.evidence = vec![ev([1u8; 32], 0, None, false), ev([2u8; 32], 0, None, false)];
        b.evidence = vec![ev([2u8; 32], 0, None, false), ev([1u8; 32], 0, None, false)];
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
        assert_eq!(statement_hash(&a), statement_hash(&b));
    }

    /// T13 (deepseek 4d): field length caps enforced.
    #[test]
    fn t13_field_length_cap() {
        let mut s = stmt(0, [0u8; 32]);
        s.object = Object::Bytes(vec![0u8; (1 << 20) + 1]);
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::FieldTooLarge)
        );
        let mut s = stmt(0, [0u8; 32]);
        s.subject.id = "x".repeat((1 << 20) + 1);
        assert_eq!(
            authenticate(s, None, |_, _, _, _| true, &cfg()),
            Err(AuthError::FieldTooLarge)
        );
    }