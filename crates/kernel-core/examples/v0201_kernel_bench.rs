//! Compare actual public algorithms compiled from three source trees.
//! Synthetic metadata and model workloads only; no physical pages or native
//! control-core latency claims. All timings include setup for that workload.
use cyxia_contracts::{ConsoleOps, MemoryRegion, PhysAddr, PlatformError, RegionKind, TaskId};
use cyxia_control_model::native_v0199::{
    Candidate, Scores, SnapshotReplyV3, integer_model, score_operations, score_security,
};
use cyxia_kernel_core::{
    console::OutputQueue,
    contig_frames::ContigFramePool,
    control_plane::{
        Identity,
        d07_owner_v0199::{TimerClass, programmed_ns},
    },
    frames::{FrameError, FrameMeta, FramePool, PageZeroer},
    security::ipc_receive_v3::{DirectionalEndpoint, Endpoint, FRAME_BYTES, HEADER_BYTES},
};
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

fn measure<T: Copy + Eq + Debug>(name: &str, work: impl FnMut() -> T) {
    measure_rounds(name, ROUNDS, work);
}

fn measure_rounds<T: Copy + Eq + Debug>(name: &str, rounds: usize, mut work: impl FnMut() -> T) {
    let check = work();
    assert_eq!(work(), check);
    println!("check,{name},{check:?}");
    for _ in 0..32 {
        black_box(work());
    }
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..rounds {
            black_box(work());
        }
        println!(
            "sample,{name},{}",
            start.elapsed().as_nanos() / rounds as u128
        );
    }
}

fn measure_contig<const N: usize>() {
    let dense = format!("contig-dense-{N}");
    let fragmented = format!("contig-fragmented-{N}");
    measure(&dense, || contig::<N>(black_box(0x1000), false));
    measure(&fragmented, || contig::<N>(black_box(0x1000), true));
}

// Synthetic PageZeroer records the requested operation, never maps physical
// memory. These results measure metadata admission/clean allocation only.
struct CountZero(usize);

impl PageZeroer for CountZero {
    fn zero(&mut self, page: PhysAddr) -> Result<(), FrameError> {
        black_box(page);
        self.0 += 1;
        Ok(())
    }
}

#[inline(never)]
fn clean_pool<const N: usize>(base: u64) -> (u64, usize) {
    let ram = [MemoryRegion {
        start: PhysAddr(base),
        len: N as u64 * 4096,
        kind: RegionKind::Ram,
    }];
    let mut metadata = [FrameMeta::EMPTY; N];
    let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
    let mut zeroer = CountZero(0);
    for _ in 0..N {
        assert!(pool.clean_one(&mut zeroer).unwrap());
    }
    assert!(!pool.clean_one(&mut zeroer).unwrap());
    let owner = TaskId::new(1).unwrap();
    let mut checksum = 0u64;
    for i in 0..N {
        let handle = pool.alloc_clean(owner).unwrap();
        assert_eq!(handle.index(), i);
        assert_eq!(handle.address(), PhysAddr(base + i as u64 * 4096));
        pool.check_owned(handle, owner).unwrap();
        checksum = checksum.wrapping_add(handle.address().0);
    }
    assert_eq!(pool.alloc_clean(owner), Err(FrameError::Exhausted));
    assert_eq!(pool.snapshot().used, N);
    assert_eq!(zeroer.0, N);
    (checksum, zeroer.0)
}

#[inline(never)]
fn ipc_roundtrip<const N: usize>(seed: u8) -> u64 {
    let sender = Identity {
        id: 1,
        generation: 1,
    };
    let receiver = Identity {
        id: 2,
        generation: 1,
    };
    let endpoint = Endpoint {
        id: 3,
        generation: 1,
        receiver,
    };
    let mut q = DirectionalEndpoint::<N>::new(endpoint, sender).unwrap();
    let payload = |id: u64| [seed.wrapping_add(id as u8); 16];
    for id in 1..=N as u64 {
        q.send(sender, 1, id, &payload(id)).unwrap();
    }
    // The oldest and newest retained exact requests must not enqueue again.
    q.send(sender, 1, 1, &payload(1)).unwrap();
    q.send(sender, 1, N as u64, &payload(N as u64)).unwrap();
    assert_eq!(q.pending(), N);
    let mut checksum = 0u64;
    for id in 1..=N as u64 {
        let ticket = q
            .reserve_receive(receiver, 1, id, FRAME_BYTES, true, 0, id, || Ok(()))
            .unwrap();
        assert_eq!(ticket.message().request_id(), id);
        assert_eq!(&ticket.message().bytes()[HEADER_BYTES..], &payload(id));
        assert_eq!(q.finish_copy(ticket, true).unwrap(), HEADER_BYTES + 16);
        q.ack(receiver, 1, id, || Ok(())).unwrap();
        checksum = checksum.wrapping_add(u64::from(payload(id)[0]));
    }
    assert_eq!(q.pending(), 0);
    checksum
}

struct CaptureConsole {
    data: [u8; 1024],
    len: usize,
}

impl ConsoleOps for CaptureConsole {
    fn try_write(&mut self, data: &[u8]) -> Result<usize, PlatformError> {
        let end = self.len + data.len();
        self.data[self.len..end].copy_from_slice(data);
        self.len = end;
        Ok(data.len())
    }
}

#[inline(never)]
fn wrapped_console<const N: usize>(seed: u8) -> (usize, u64) {
    let payload: [u8; N] = core::array::from_fn(|i| seed.wrapping_add(i as u8));
    let mut queue = OutputQueue::<N>::new();
    let mut sink = CaptureConsole {
        data: [0; 1024],
        len: 0,
    };
    let half = N / 2;
    queue.enqueue(&payload).unwrap();
    assert_eq!(queue.drain(&mut sink, half).unwrap(), half);
    queue.enqueue(&payload[..half]).unwrap();
    assert_eq!(queue.pending(), N);
    assert_eq!(queue.drain(&mut sink, N).unwrap(), N);
    assert_eq!(queue.pending(), 0);
    assert_eq!(&sink.data[..N], &payload);
    assert_eq!(&sink.data[N..sink.len], &payload[..half]);
    let checksum = sink.data[..sink.len].iter().map(|&x| u64::from(x)).sum();
    (sink.len, checksum)
}

#[inline(never)]
fn timer_batch(seed: u64) -> [u64; 32] {
    core::array::from_fn(|i| {
        let deadline = if i % 5 == 0 {
            u64::MAX - i as u64
        } else {
            seed.wrapping_add(i as u64 * 17777)
        };
        let slack = [0, 1, 100_000, u64::MAX][i / 4 % 4];
        let us = [0, 50, 200, 1000][i % 4];
        let now = if i % 7 == 0 { deadline } else { 0 };
        programmed_ns(TimerClass::Soft, slack, deadline, now, us).unwrap()
    })
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
    measure_rounds("frame-clean-64", 512, || clean_pool::<64>(black_box(4096)));
    measure_rounds("frame-clean-256", 512, || {
        clean_pool::<256>(black_box(4096))
    });
    measure_rounds("ipc-roundtrip-8", 512, || ipc_roundtrip::<8>(black_box(17)));
    measure_rounds("ipc-roundtrip-64", 512, || {
        ipc_roundtrip::<64>(black_box(17))
    });
    measure("console-wrap-64", || wrapped_console::<64>(black_box(13)));
    measure("console-wrap-257", || wrapped_console::<257>(black_box(13)));
    measure("timer-rounding-32", || timer_batch(black_box(1234567)));
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
    // Exercise each defined independent security-brain schema kind.
    for (kind, domain) in [(1, 12), (2, 3), (3, 10), (4, 11), (5, 4)] {
        let snapshot = SnapshotReplyV3 { domain, ..s };
        measure(&format!("security-kind{kind:02}"), || {
            score_security(
                black_box(&snapshot),
                black_box(kind),
                black_box(0xf00),
                black_box(&parameters),
            )
            .unwrap()
        });
    }
}
