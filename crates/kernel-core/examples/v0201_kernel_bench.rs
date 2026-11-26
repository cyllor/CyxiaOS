//! Compare actual public algorithms compiled from three source trees.
//! Synthetic metadata and model workloads only; no physical pages or native
//! control-core latency claims. All timings include setup for that workload.
use cyxia_contracts::TaskId;
use cyxia_control_model::native_v0199::{
    Candidate, Scores, SnapshotReplyV3, integer_model, score_operations,
};
use cyxia_kernel_core::contig_frames::ContigFramePool;
use std::{fmt::Debug, hint::black_box, time::Instant};

const SAMPLES: usize = 7;
const ROUNDS: usize = 4096;

#[inline(never)]
fn contig<const N: usize>(base: u64, fragmented: bool) -> u64 {
    let owner = TaskId::new(1).unwrap();
    let mut pool = ContigFramePool::<N>::new(base, 2 * N).unwrap();
    let mut addresses = [0u64; N];
    let mut checksum = 0u64;
    for (i, address) in addresses.iter_mut().enumerate() {
        *address = pool.allocate(2, owner).unwrap();
        assert_eq!(*address, base + i as u64 * 8192);
        checksum = checksum.wrapping_add(*address);
    }
    if fragmented {
        for i in (1..N).rev().filter(|i| i % 2 != 0) {
            pool.release(addresses[i], 2, owner).unwrap();
        }
        for &expected in addresses.iter().skip(1).step_by(2) {
            let found = pool.allocate(2, owner).unwrap();
            assert_eq!(found, expected);
            checksum = checksum.wrapping_add(found);
        }
    }
    assert_eq!(pool.snapshot().used, 2 * N);
    for address in addresses {
        pool.release(address, 2, owner).unwrap();
    }
    assert_eq!(pool.snapshot().free, 2 * N);
    checksum
}

#[inline(never)]
fn operations(s: &SnapshotReplyV3, cs: &[Candidate], parameters: &[u8]) -> Scores {
    score_operations(s, cs, parameters).unwrap()
}

fn measure<T: Copy + Eq + Debug>(name: &str, mut work: impl FnMut() -> T) {
    let check = work();
    assert_eq!(work(), check);
    println!("check,{name},{check:?}");
    for _ in 0..32 {
        black_box(work());
    }
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..ROUNDS {
            black_box(work());
        }
        println!(
            "sample,{name},{}",
            start.elapsed().as_nanos() / ROUNDS as u128
        );
    }
}

fn measure_contig<const N: usize>() {
    let dense = format!("contig-dense-{N}");
    let fragmented = format!("contig-fragmented-{N}");
    measure(&dense, || contig::<N>(black_box(0x1000), false));
    measure(&fragmented, || contig::<N>(black_box(0x1000), true));
}

fn main() {
    measure_contig::<4>();
    measure_contig::<8>();
    measure_contig::<9>();
    measure_contig::<16>();
    measure_contig::<17>();
    measure_contig::<18>();
    measure_contig::<19>();
    measure_contig::<20>();
    measure_contig::<21>();
    measure_contig::<22>();
    measure_contig::<23>();
    measure_contig::<24>();
    measure_contig::<25>();
    measure_contig::<26>();
    measure_contig::<27>();
    measure_contig::<28>();
    measure_contig::<29>();
    measure_contig::<30>();
    measure_contig::<31>();
    measure_contig::<32>();
    measure_contig::<64>();
    let mut parameters = [0u8; integer_model::MODEL_BYTES];
    for (i, weight) in parameters[..2576].iter_mut().enumerate() {
        *weight = ((i * 73 % 17) as i8 - 8) as u8;
    }
    for (i, bytes) in parameters[2576..].chunks_exact_mut(4).enumerate() {
        bytes.copy_from_slice(&(i as i32 - 24).to_le_bytes());
    }
    let s = SnapshotReplyV3 {
        snapshot_seq: 1,
        boot_epoch: 1,
        ledger_generation: 1,
        core_generation: 1,
        target_id: 1,
        target_generation: 1,
        sampled_ns: 100,
        domain: 1,
        fields: [
            Some(500),
            Some(1000),
            Some(32),
            Some(250),
            Some(750),
            None,
            Some(50000),
            None,
            Some(32),
            Some(64),
            Some(1),
            Some(1),
        ],
    };
    // Frozen ActionSchema v2 values for every local resource domain.
    // These are scoring inputs only; no candidate is granted authority.
    for domain in 1..=15 {
        let actions: &[(u64, Option<u64>)] = match domain {
            1 | 2 | 8 | 11 => &[(1, None), (2, None), (4, None), (8, None)],
            3 => &[
                (64, Some(4)),
                (256, Some(16)),
                (1024, Some(32)),
                (4096, Some(64)),
            ],
            4 => &[(0, Some(4)), (2, Some(8)), (8, Some(16)), (16, Some(32))],
            5 => &[(8, Some(1)), (32, Some(4)), (64, Some(8)), (128, Some(16))],
            6 => &[(1, None), (2, None), (3, None)],
            7 => &[(0, None), (50, None), (200, None), (1000, None)],
            9 => &[(100, None), (250, None), (500, None), (750, None)],
            10 => &[(1, None), (4, None), (8, None), (16, None)],
            12 => &[(4, None), (8, None), (16, None), (32, None)],
            13 => &[(50, None), (100, None), (200, None), (400, None)],
            14 => &[(0, None), (1, None), (2, None)],
            15 => &[(1, None), (8, None), (32, None), (64, None)],
            _ => unreachable!(),
        };
        let candidates: Vec<_> = actions
            .iter()
            .map(|&(a1, a2)| Candidate {
                a1,
                a2,
                cpu: if domain == 6 {
                    [Some(a1 * 100), Some(256), Some(10), Some(1)]
                } else {
                    [None; 4]
                },
            })
            .collect();
        let snapshot = SnapshotReplyV3 { domain, ..s };
        measure(&format!("operations-d{domain:02}"), || {
            operations(
                black_box(&snapshot),
                black_box(candidates.as_slice()),
                black_box(&parameters),
            )
        });
    }
}
