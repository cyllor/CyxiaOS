//! Real recorder and Cores/Handoff, controlled host stop producers only.
//! These tests never establish native execution or generate acceptance labels.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    cores::{CoreSet, Cores, ThreadSpec},
    domains::{ApplyId, Error, ObjectKey, PolicyStamp},
};
#[allow(dead_code)]
#[path = "../../../user/prototype-runtime/dynamic.rs"]
mod dynamic;
#[allow(dead_code)]
#[path = "../../../kernel/src/diagnostics/ownership_evidence.rs"]
mod evidence;
mod domain_evidence {
    use super::*;
    pub fn ownership_snapshot(
        slot: usize,
        sequence: u64,
        mut copy: impl FnMut(usize, u64),
    ) -> Result<(), Error> {
        assert!(slot < 64);
        assert!(sequence > 0);
        for i in 0..672 {
            copy(i, sequence * 1000 + i as u64)
        }
        Ok(())
    }
}
unsafe extern "C" {
    #[link_name = "OWNERSHIP_V15_EVIDENCE"]
    static BANK: [AtomicU64; 128 + 8 * 896];
}
fn word(i: usize) -> u64 {
    unsafe { BANK[i].load(Ordering::Acquire) }
}
fn apply(sequence: u64) -> ApplyId {
    ApplyId {
        boot_epoch: 7,
        controller_epoch: 1,
        plan_seq: sequence,
        action_index: 0,
        target: ObjectKey {
            id: 50,
            generation: 1,
        },
    }
}
#[test]
fn actual_recorder_links_distinct_applies_to_both_real_owner_publications_and_preserves_failure() {
    let mut config = [0; 64];
    for (i, v) in config[4..18].iter_mut().enumerate() {
        *v = i as u64 + 1;
    }
    evidence::initialize(&config, 0);
    let mut owner = Cores::new(CoreSet::from_bits(15), CoreSet::from_bits(2)).unwrap();
    owner.advance_window(1).unwrap();
    let mut thread = Some(
        owner
            .admit(ThreadSpec {
                thread_id: 2,
                budget_milli: 900,
                allowed_mask: CoreSet::from_bits(4),
                assigned_cpu: 2,
            })
            .unwrap(),
    );
    owner.charge(thread.unwrap(), 300).unwrap();
    let complete = dynamic::NativeStop {
        dispatch: true,
        tasks: true,
        irq: true,
        dma: true,
        tlb: true,
        references: true,
    };
    for (i, target) in [6, 2].into_iter().enumerate() {
        let now = 1000 + i as u64 * 1100;
        let key = apply(20 + i as u64);
        let stamp = PolicyStamp {
            version: i as u64 + 1,
            snapshot_ns: now * 1_000_000,
            installed_until_ns: 0,
        };
        evidence::accepted(
            key,
            stamp,
            target,
            [owner.snapshot().core_generation, 9],
            &owner,
            now * 1_000_000,
        );
        evidence::accepted(
            key,
            stamp,
            target,
            [owner.snapshot().core_generation, 9],
            &owner,
            now * 1_000_000,
        );
        let mut handoff = dynamic::Handoff::new(&owner.snapshot(), target, now).unwrap();
        assert_eq!(
            handoff.poll_with_thread(
                &mut owner,
                dynamic::NativeStop::default(),
                now + 1,
                &mut thread
            ),
            Ok(false)
        );
        evidence::draining(key, i as u64 + 1, &owner, (now + 1) * 1_000_000);
        assert_eq!(owner.snapshot().control.bits(), if i == 0 { 2 } else { 6 });
        assert_eq!(
            handoff.poll_with_thread(&mut owner, complete, now + 2, &mut thread),
            Ok(true)
        );
        evidence::published(
            key,
            i as u64 + 1,
            &owner,
            (now + 2) * 1_000_000,
            63,
            i as u64 + 1,
        );
        evidence::completed(key, &owner, (now + 3) * 1_000_000);
        evidence::model_witness(key, 3 + i, 20 + i as u64).unwrap();
        evidence::model_witness(key, 3 + i, 20 + i as u64).unwrap();
        let r = 128 + i * 896;
        assert_eq!(word(r) & 1, 0);
        assert_eq!(word(r + 1), 31);
        assert_eq!(word(r + 4), 20 + i as u64);
        assert_eq!(word(r + 8), target);
        assert_eq!(word(r + 11), i as u64 + 1);
        assert_eq!(word(r + 48 + 6), 4);
        assert_eq!(word(r + 64 + 2), target);
        assert_eq!(
            word(r + 64 + 12),
            300,
            "publication refunded source spending"
        );
        assert_eq!(word(r + 128), (20 + i as u64) * 1000);
        assert_eq!(word(r + 192), (20 + i as u64) * 1000 + 32);
        assert_eq!(word(r + 831), (20 + i as u64) * 1000 + 671);
    }
    assert_eq!(
        (word(4), word(10), word(11)),
        (2, 2, 2),
        "retry duplicated append or witness"
    );
    let key = apply(22);
    let stamp = PolicyStamp {
        version: 3,
        snapshot_ns: 3_300_000_000,
        installed_until_ns: 0,
    };
    evidence::accepted(
        key,
        stamp,
        6,
        [owner.snapshot().core_generation, 9],
        &owner,
        3_300_000_000,
    );
    let original = owner.snapshot();
    let mut handoff = dynamic::Handoff::new(&original, 6, 3300).unwrap();
    assert_eq!(
        handoff.poll(&mut owner, dynamic::NativeStop::default(), 3301),
        Ok(false)
    );
    evidence::draining(key, 3, &owner, 3_301_000_000);
    assert!(
        handoff
            .poll(&mut owner, dynamic::NativeStop::default(), 3500)
            .is_err()
    );
    evidence::failed(key, &owner, 3_500_000_000, 3, 0);
    let r = 128 + 2 * 896;
    assert_eq!(word(r + 1), 67);
    assert_eq!(word(r + 96 + 2), original.control.bits());
    assert_eq!(word(r + 96 + 3), original.business.bits());
    assert_eq!(word(r + 96 + 5), 0);
    assert_eq!(word(r + 96 + 7), 4);
    assert_eq!(word(r + 96 + 12), 300, "missing ACK refunded source debt");
    assert_eq!(word(r + 15), 0, "a timeout manufactured model completion");
}
