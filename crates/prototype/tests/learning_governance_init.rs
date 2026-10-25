//! The actual typed pool initializer, exercised on uninitialized host storage.
//! No native stack or replay-data claim follows from this host-only test.
#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::learning::{Error, governance::*};
use cyxia_prototype::policy::ModelBinding;

#[test]
fn governance_is_initialized_in_place_without_a_large_return_value() {
    support::with_candidate(|candidate, old| {
        let active = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let gate = CommitGate::new(11, active).unwrap();
        let mut init = GovernanceInit::new(&gate, candidate, old, 0).unwrap();
        let mut memory = Box::<Governance<'_, '_>>::new_uninit();
        let base = memory.as_mut_ptr().cast::<u8>();
        let mut occupied = vec![false; init.bytes()];
        assert_eq!(base as usize % init.alignment(), 0);
        assert_eq!(init.total_pieces(), 381);
        while let Some(piece) = init.peek() {
            assert!(piece.value.byte_len() <= 512);
            assert_eq!(piece.offset % piece.value.alignment(), 0);
            for bit in &mut occupied[piece.offset..piece.offset + piece.value.byte_len()] {
                assert!(!*bit);
                *bit = true;
            }
            unsafe {
                let p = base.add(piece.offset);
                macro_rules! write {
                    ($v:expr) => {
                        core::ptr::write(p.cast(), $v)
                    };
                }
                match piece.value {
                    InitValue::Candidate(v) => write!(v),
                    InitValue::Old(v) => write!(v),
                    InitValue::Binding(v) => write!(v),
                    InitValue::OptionalBinding(v) => write!(v),
                    InitValue::Stage(v) => write!(v),
                    InitValue::U64(v) => write!(v),
                    InitValue::U16(v) => write!(v),
                    InitValue::Bool(v) => write!(v),
                    InitValue::U32(v) => write!(v),
                    InitValue::Target(v) => write!(v),
                    InitValue::Permit(v) => write!(v),
                    InitValue::Restoration(v) => write!(v),
                    InitValue::OptionalU64(v) => write!(v),
                    InitValue::Usize(v) => write!(v),
                    InitValue::OptionalUsize(v) => write!(v),
                    InitValue::U8(v) => write!(v),
                    InitValue::Fault(v) => write!(v),
                    InitValue::Submission(v) => write!(v),
                    InitValue::Second(v) => write!(v),
                    InitValue::Incomplete(v) => write!(v),
                }
            }
            init.commit(piece.sequence).unwrap();
        }
        // A Busy finish may miss the reserved future window. Rebase only the
        // final typed field, before any Governance reference is formed.
        assert_eq!(init.check_finish(&gate), Ok(()));
        init.set_start_window(4).unwrap();
        assert_eq!(init.completed_pieces(), 380);
        assert_eq!(init.check_finish(&gate), Err(Error::State));
        let last = init.peek().unwrap();
        assert_eq!(last.sequence, 380);
        match last.value {
            InitValue::U64(v) => {
                assert_eq!(v, 4);
                unsafe {
                    core::ptr::write(base.add(last.offset).cast::<u64>(), v);
                }
            }
            _ => panic!("shadow start must be the last typed write"),
        }
        init.commit(last.sequence).unwrap();
        assert_eq!(init.check_finish(&gate), Ok(()));
        assert_eq!(init.set_start_window(3), Err(Error::Stale));
        assert_eq!(init.start_window(), 4);
        assert_eq!(init.completed_pieces(), 381);
        let complete = init.finish(&gate).unwrap();
        assert_eq!(complete.pieces(), 381);
        assert_eq!(complete.original_binding(), active);
        assert_eq!(complete.boot_epoch(), 11);
        println!(
            "Governance bytes={}, max typed piece={}",
            complete.bytes(),
            core::mem::size_of::<InitValue<'_, '_>>()
        );
        let mut governance = unsafe { memory.assume_init() };
        assert_eq!(governance.stage(), Stage::Shadow);
        assert_eq!(governance.original_binding(), active);
        assert_eq!(
            governance.candidate_hash(),
            candidate.model().manifest().parameters_hash
        );
        assert_eq!(governance.reason(), None);
        assert_eq!(governance.submissions().count(), 0);
        for i in 0..30 {
            assert_eq!(governance.second(i), None);
            assert_eq!(governance.incomplete_second(i), None);
        }
        assert_eq!(
            governance.close_shadow_window(WINDOW_NS),
            Err(Error::DataIncomplete)
        );
        assert_eq!(
            governance.close_shadow_window(5 * WINDOW_NS),
            Err(Error::DataIncomplete)
        );
    });
}
#[test]
fn initialization_requires_every_write_and_rechecks_current_commit_gate() {
    support::with_candidate(|candidate, old| {
        let active = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let gate = CommitGate::new(11, active).unwrap();
        assert_eq!(
            GovernanceInit::new(&gate, candidate, old, u64::MAX)
                .err()
                .map(|_| ()),
            Some(())
        );
        assert_eq!(
            GovernanceInit::new(&gate, candidate, old, 0)
                .unwrap()
                .finish(&gate)
                .err(),
            Some(Error::State)
        );
        let mut init = GovernanceInit::new(&gate, candidate, old, 0).unwrap();
        assert_eq!(init.commit(1), Err(Error::Order));
        assert_eq!(init.completed_pieces(), 0);
        init.commit(0).unwrap();
        assert_eq!(init.commit(0), Err(Error::Order));
        // This tests recipe progression, not a claim that external writes took
        // place. The real owner must bind the completion token to its loan.
        while let Some(piece) = init.peek() {
            init.commit(piece.sequence).unwrap();
        }
        let changed = CommitGate::new(
            11,
            ModelBinding {
                generation: 8,
                ..active
            },
        )
        .unwrap();
        assert_eq!(init.check_finish(&changed), Err(Error::Stale));
        // A preflight failure leaves the exact recipe available for its
        // original gate; the native owner does not take Option on failure.
        assert_eq!(init.check_finish(&gate), Ok(()));
        assert!(init.finish(&gate).is_ok());
    });
}
