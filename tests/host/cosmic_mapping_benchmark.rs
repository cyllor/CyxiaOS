// Included inside the real AddressSpace test module. No hardware timing claim.
#[test]
fn ecc_mapping_benchmark() {
    use crate::staging::{PageTable, ProcessSpace};
    use std::time::Instant;
    let _lock = runtime::TEST.lock().unwrap();
    #[repr(C, align(4096))]
    struct EccTables([u8; 128 * 4096]);
    for (name, count, protection, stride) in [
        ("small_rw", 8usize, 3u8, 4096u64),
        ("cosmic_rx", 8818, 5, 4096),
        ("dense_rw", 16384, 3, 4096),
        ("fragmented_rw", 4096, 3, 8192),
    ] {
        runtime::reset();
        for i in 0..count {
            runtime::phase(PA + i as u64 * stride,
                if protection == 5 { Phase::StableSealed } else { Phase::StableWritable });
            runtime::set_count(PA + i as u64 * stride, 0);
        }
        let tables: Vec<_> = (0..count.div_ceil(512)).map(|table| {
            let mut desired = PageTable::empty();
            for page in 0..(count - table * 512).min(512) {
                desired.set(page, PA + (table * 512 + page) as u64 * stride, protection).unwrap();
            }
            desired
        }).collect();
        let mut map_samples = Vec::new();
        let mut retire_samples = Vec::new();
        let mut observed_map = 0;
        let mut observed_retire = 0;
        let mut map_arithmetic = 0;
        let mut retire_arithmetic = 0;
        let samples = if cfg!(ecc_owner_observation) { 1 } else { 9 };
        let repeats = if cfg!(ecc_owner_observation) { 1 } else { 8 };
        for sample in 0..samples + 1 {
            let mut map_ns = 0u128;
            let mut retire_ns = 0u128;
            for _ in 0..repeats {
                let mut memory = Box::new(EccTables([0; 128 * 4096]));
                let kernel = KernelMappings::new([0; 256], runtime::RAM).unwrap();
                let arena = unsafe { TableArena::from_raw(memory.0.as_mut_ptr(), 0x00200000, 128) }.unwrap();
                let space = unsafe { AddressSpace::new(arena, &kernel, SpaceId { id: 1, generation: 1 }) }.unwrap();
                let mut owner = ProcessSpace::test_owner(Some(space));
                let before = runtime::owner_reads();
                let before_arithmetic = runtime::alias_arithmetic_pages();
                let start = Instant::now();
                for (i, desired) in tables.iter().enumerate() {
                    desired.publish(&mut owner, VA + i as u64 * 0x200000).unwrap();
                }
                map_ns += start.elapsed().as_nanos();
                observed_map = runtime::owner_reads() - before;
                map_arithmetic = runtime::alias_arithmetic_pages() - before_arithmetic;
                let space = owner.current.as_ref().unwrap();
                for i in 0..count {
                    let translation = space.translate(VA + i as u64 * 4096 + 17).unwrap();
                    assert_eq!(translation.physical, PA + i as u64 * stride + 17);
                    assert_eq!(translation.permissions.writable, protection == 3);
                    assert_eq!(translation.permissions.executable, protection == 5);
                    assert_eq!(runtime::count(PA + i as u64 * stride),
                        1 | if protection == 3 { 1 << 20 } else { 1 << 40 });
                    if cfg!(ecc_owner_observation) {
                        // Real CPUs vary A/D bits without changing permissions.
                        // Exercise that boundary only in the untimed observer.
                        let leaf = space.leaf(VA + i as u64 * 4096).unwrap();
                        unsafe { leaf.write_volatile(leaf.read_volatile() | ((i as u64 & 3) << 5)) };
                    }
                }
                let before = runtime::owner_reads();
                let before_arithmetic = runtime::alias_arithmetic_pages();
                let start = Instant::now();
                drop(owner);
                retire_ns += start.elapsed().as_nanos();
                observed_retire = runtime::owner_reads() - before;
                retire_arithmetic = runtime::alias_arithmetic_pages() - before_arithmetic;
                for i in 0..count { assert_eq!(runtime::count(PA + i as u64 * stride), 0); }
                drop(memory);
            }
            if sample != 0 {
                map_samples.push(map_ns / repeats);
                retire_samples.push(retire_ns / repeats);
            }
        }
        map_samples.sort();
        retire_samples.sort();
        println!("ECC_MAPPING_BENCH {{\"shape\":\"{name}\",\"pages\":{count},\"observed\":{},\"map_median_ns\":{},\"map_p95_ns\":{},\"retire_median_ns\":{},\"retire_p95_ns\":{},\"map_owner_reads\":{observed_map},\"retire_owner_reads\":{observed_retire},\"map_arithmetic_pages\":{map_arithmetic},\"retire_arithmetic_pages\":{retire_arithmetic}}}",
            cfg!(ecc_owner_observation), map_samples[map_samples.len()/2], map_samples[map_samples.len()-1],
            retire_samples[retire_samples.len()/2], retire_samples[retire_samples.len()-1]);
        if cfg!(ecc_owner_observation) && stride == 4096
            && std::env::var_os("ECC_REQUIRE_COALESCED").is_some()
        {
            assert!(observed_map <= (count.div_ceil(512) * 3 + 4) as u64,
                "contiguous mappings still authenticate ownership per page");
        }
        if cfg!(ecc_owner_observation) && stride == 4096
            && std::env::var_os("SUPERPOWERS_REQUIRE_COALESCED_RETIRE").is_some()
        {
            assert!(observed_retire <= (count.div_ceil(512) * 2 + 4) as u64,
                "contiguous retirement still authenticates ownership per page: {observed_retire}");
        }
        if cfg!(ecc_owner_observation)
            && std::env::var_os("MATT_REQUIRE_DIRECT_ALIAS_COUNTS").is_some()
        {
            assert_eq!((map_arithmetic, retire_arithmetic), (0, 0),
                "zero/one aliases still execute general lane arithmetic");
        }
    }
}
