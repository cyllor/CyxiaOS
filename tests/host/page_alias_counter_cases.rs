#[test]
fn runtime_batch_alias_counts_match_independent_lane_arithmetic_at_boundaries() {
    let _lock = runtime::TEST.lock().unwrap();
    runtime::reset();
    for phase in [Phase::StableWritable, Phase::Transition, Phase::StableSealed] {
        runtime::phase(PA, phase);
        for total in [0u64, 1, 2, 0xffffe, 0xfffff] {
            for writable in [0u64, 1, 2, 0xffffe, 0xfffff] {
                for executable in [0u64, 1, 2, 0xffffe, 0xfffff] {
                    for old in 0u64..8 {
                        for new in [0u64, 1, 2, 3, 4, 5, 6, 7, 8, 15] {
                            let lanes = [total, writable, executable];
                            let value = total | writable << 20 | executable << 40;
                            // Reserved high bits are discarded by the original
                            // writer only on success; a failure preserves them.
                            for high in [0, 0xf000_0000_0000_0000] {
                                let original = value | high;
                                runtime::set_count(PA, original);
                                let mut expected = 0u64;
                                let mut allowed = new == 0 || match phase {
                                    Phase::StableWritable => new == 1 || new == 3,
                                    Phase::StableSealed => new == 1 || new == 5,
                                    Phase::Transition => false,
                                };
                                for (index, count) in lanes.into_iter().enumerate() {
                                    let remove = i64::from(old & (1 << index) != 0);
                                    let add = i64::from(new & (1 << index) != 0);
                                    // Removal must succeed before addition, even
                                    // when both bits request no net change.
                                    let after_remove = count as i64 - remove;
                                    let after_add = after_remove + add;
                                    allowed &= after_remove >= 0 && after_add <= 0xfffff;
                                    if after_add >= 0 {
                                        expected |= (after_add as u64) << (index * 20);
                                    }
                                }
                                assert_eq!(runtime::single_change(PA, old, new), allowed,
                                    "phase={phase:?} value={original:#x} old={old} new={new}");
                                assert_eq!(runtime::count(PA), if allowed { expected } else { original });
                                assert!(!runtime::gate());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn runtime_batch_alias_zero_one_shared_and_transition_lifecycles() {
    let _lock = runtime::TEST.lock().unwrap();
    for (phase, flags, single) in [(Phase::StableWritable, 1, 1),
            (Phase::StableWritable, 3, 1 | 1 << 20),
            (Phase::StableSealed, 5, 1 | 1 << 40)] {
        runtime::reset();
        runtime::phase(PA, phase);
        for expected in [single, single * 2, single * 3] {
            assert!(runtime::single_change(PA, 0, flags));
            assert_eq!(runtime::count(PA), expected);
        }
        runtime::phase(PA, Phase::Transition);
        assert!(!runtime::single_change(PA, 0, flags));
        for expected in [single * 2, single, 0] {
            assert!(runtime::single_change(PA, flags, 0));
            assert_eq!(runtime::count(PA), expected);
        }
        assert!(!runtime::single_change(PA, flags, 0));
        assert_eq!(runtime::count(PA), 0);
    }
}
