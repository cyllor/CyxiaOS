//! Compare actual public algorithms compiled from two immutable source trees.
//! Synthetic metadata and model workloads only; no physical pages or native
//! control-core latency claims. All timings include setup for that workload.
use cyxia_contracts::TaskId;
use cyxia_control_model::native_v0199::{
    Candidate, Scores, SnapshotReplyV3, integer_model, score_operations,
};
use cyxia_kernel_core::contig_frames::ContigFramePool;
use std::{fmt::Debug, hint::black_box, time::Instant};

const SAMPLES: usize = 7;
const ROUNDS: usize = 256;

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

fn main() {
    measure("contig-dense-8", || contig::<8>(black_box(0x1000), false));
    measure("contig-fragmented-8", || {
        contig::<8>(black_box(0x1000), true)
    });
    measure("contig-dense-64", || contig::<64>(black_box(0x1000), false));
    measure("contig-fragmented-64", || {
        contig::<64>(black_box(0x1000), true)
    });
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
    let d01 = [1, 2, 4, 8].map(|a1| Candidate {
        a1,
        a2: None,
        cpu: [None; 4],
    });
    let d06 = [1, 2, 3].map(|a1| Candidate {
        a1,
        a2: None,
        cpu: [Some(a1 * 100), Some(256), Some(10), Some(1)],
    });
    measure("operations-d01", || {
        operations(black_box(&s), black_box(&d01), black_box(&parameters))
    });
    let irq = SnapshotReplyV3 { domain: 6, ..s };
    measure("operations-d06", || {
        operations(black_box(&irq), black_box(&d06), black_box(&parameters))
    });
}
