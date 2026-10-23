//! Real target std, not a no_std facade. No host services implement these APIs.
use std::cell::Cell;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// AArch64 Linux UAPI, deliberately exercised beneath std as well as by it.
// This is real SVC; no host service or libc replacement supplies a result.
unsafe fn syscall(number: u64, args: [u64; 6]) -> i64 {
    let mut result = args[0];
    unsafe {
        std::arch::asm!("svc #0", in("x8") number,
        inout("x0") result, in("x1") args[1], in("x2") args[2],
        in("x3") args[3], in("x4") args[4], in("x5") args[5],
        options(nostack));
    }
    result as i64
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Stack {
    base: u64,
    flags: u32,
    padding: u32,
    size: u64,
}
#[repr(C)]
#[derive(Default)]
struct Action {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}
static ALT_BASE: AtomicUsize = AtomicUsize::new(0);
static ALT_SIZE: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_HITS: AtomicUsize = AtomicUsize::new(0);
static SIGNAL_ERRORS: AtomicUsize = AtomicUsize::new(0);
static SLEEP_SIGNALS: AtomicUsize = AtomicUsize::new(0);
std::arch::global_asm!(
    ".global rust_probe_restore",
    "rust_probe_restore:",
    "mov x8, #139",
    "svc #0",
    "brk #0"
);
unsafe extern "C" {
    fn rust_probe_restore();
}

extern "C" fn on_alternate_stack(_: i32) {
    let marker = 0u8;
    let address = std::hint::black_box(&marker) as *const _ as usize;
    let base = ALT_BASE.load(Ordering::Relaxed);
    let size = ALT_SIZE.load(Ordering::Relaxed);
    if address < base || address >= base + size {
        SIGNAL_ERRORS.fetch_or(1, Ordering::Relaxed);
    }
    let mut current = Stack::default();
    let query = unsafe { syscall(132, [0, &mut current as *mut _ as u64, 0, 0, 0, 0]) };
    if query != 0 || current.flags != 1 || current.base != base as u64 {
        SIGNAL_ERRORS.fetch_or(2, Ordering::Relaxed);
    }
    let disable = Stack {
        flags: 2,
        ..Stack::default()
    };
    if unsafe { syscall(132, [&disable as *const _ as u64, 0, 0, 0, 0, 0]) } != -1 {
        SIGNAL_ERRORS.fetch_or(4, Ordering::Relaxed);
    }
    if SIGNAL_HITS.fetch_add(1, Ordering::Relaxed) == 0 {
        unsafe {
            let pid = syscall(172, [0; 6]);
            let tid = syscall(178, [0; 6]);
            if syscall(131, [pid as u64, tid as u64, 10, 0, 0, 0]) != 0 {
                SIGNAL_ERRORS.fetch_or(8, Ordering::Relaxed);
            }
        }
    }
}

extern "C" fn on_regular_stack(_: i32) {
    let disable = Stack {
        flags: 2,
        ..Stack::default()
    };
    if unsafe { syscall(132, [&disable as *const _ as u64, 0, 0, 0, 0, 0]) } != 0 {
        SIGNAL_ERRORS.fetch_or(16, Ordering::Relaxed);
    }
    SIGNAL_HITS.fetch_add(1, Ordering::Relaxed);
}

fn alternate_stack() {
    let mut prior = Stack::default();
    assert_eq!(
        unsafe { syscall(132, [0, &mut prior as *mut _ as u64, 0, 0, 0, 0]) },
        0
    );
    // Rust's own startup must have registered its overflow-handler stack.
    assert_eq!(prior.flags, 0);
    assert!(prior.size >= 6144);
    let mut memory = vec![0u8; 32768];
    let stack = Stack {
        base: memory.as_mut_ptr() as u64,
        size: memory.len() as u64,
        ..Stack::default()
    };
    ALT_BASE.store(stack.base as usize, Ordering::Relaxed);
    ALT_SIZE.store(stack.size as usize, Ordering::Relaxed);
    assert_eq!(
        unsafe { syscall(132, [&stack as *const _ as u64, 0, 0, 0, 0, 0]) },
        0
    );
    let too_small = Stack {
        size: 6143,
        ..stack
    };
    assert_eq!(
        unsafe { syscall(132, [&too_small as *const _ as u64, 0, 0, 0, 0, 0]) },
        -12
    );
    let autodisarm = Stack {
        flags: 0x8000_0000,
        ..stack
    };
    assert_eq!(
        unsafe { syscall(132, [&autodisarm as *const _ as u64, 0, 0, 0, 0, 0]) },
        -22
    );
    let action = Action {
        handler: on_alternate_stack as *const () as u64,
        flags: 0x4c00_0000,
        restorer: rust_probe_restore as *const () as u64,
        mask: 0,
    };
    let mut old_action = Action::default();
    assert_eq!(
        unsafe {
            syscall(
                134,
                [
                    10,
                    &action as *const _ as u64,
                    &mut old_action as *mut _ as u64,
                    8,
                    0,
                    0,
                ],
            )
        },
        0
    );
    unsafe {
        let pid = syscall(172, [0; 6]);
        let tid = syscall(178, [0; 6]);
        assert_eq!(syscall(131, [pid as u64, tid as u64, 10, 0, 0, 0]), 0);
    }
    assert_eq!(SIGNAL_HITS.load(Ordering::Relaxed), 2);
    assert_eq!(SIGNAL_ERRORS.load(Ordering::Relaxed), 0);
    // A handler on the ordinary stack may change its alternate stack. Linux
    // rt_sigreturn restores the interrupted uc_stack, rather than treating the
    // successful sigaltstack call as a corrupt frame.
    let ordinary = Action {
        handler: on_regular_stack as *const () as u64,
        flags: 0x0400_0000,
        restorer: action.restorer,
        mask: 0,
    };
    assert_eq!(
        unsafe { syscall(134, [10, &ordinary as *const _ as u64, 0, 8, 0, 0]) },
        0
    );
    unsafe {
        let pid = syscall(172, [0; 6]);
        let tid = syscall(178, [0; 6]);
        assert_eq!(syscall(131, [pid as u64, tid as u64, 10, 0, 0, 0]), 0);
    }
    assert_eq!(SIGNAL_HITS.load(Ordering::Relaxed), 3);
    assert_eq!(SIGNAL_ERRORS.load(Ordering::Relaxed), 0);
    let mut restored = Stack::default();
    assert_eq!(
        unsafe { syscall(132, [0, &mut restored as *mut _ as u64, 0, 0, 0, 0]) },
        0
    );
    assert_eq!(
        (restored.base, restored.size, restored.flags),
        (stack.base, stack.size, 0)
    );
    assert_eq!(
        unsafe { syscall(134, [10, &old_action as *const _ as u64, 0, 8, 0, 0]) },
        0
    );
    assert_eq!(
        unsafe { syscall(132, [&prior as *const _ as u64, 0, 0, 0, 0, 0]) },
        0
    );
    println!("RUST_STD_PROBE ALTSTACK PASS");
}

fn futex_bitsets() {
    let word = Arc::new(AtomicU32::new(0));
    let child_word = word.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let child = thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || {
            let mut deadline = [0u64; 2];
            assert_eq!(
                unsafe { syscall(113, [1, deadline.as_mut_ptr() as u64, 0, 0, 0, 0]) },
                0
            );
            deadline[0] += 2;
            ready_tx.send(()).unwrap();
            unsafe {
                syscall(
                    98,
                    [
                        child_word.as_ptr() as u64,
                        9 | 128,
                        0,
                        deadline.as_ptr() as u64,
                        0,
                        2,
                    ],
                )
            }
        })
        .unwrap();
    ready_rx.recv().unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        assert_eq!(
            unsafe { syscall(98, [word.as_ptr() as u64, 10 | 128, 1, 0, 0, 1]) },
            0
        );
        let woke = unsafe { syscall(98, [word.as_ptr() as u64, 10 | 128, 1, 0, 0, 2]) };
        if woke == 1 {
            break;
        }
        assert_eq!(woke, 0);
        assert!(Instant::now() < until);
        thread::yield_now();
    }
    assert_eq!(child.join().unwrap(), 0);
    assert_eq!(
        unsafe { syscall(98, [word.as_ptr() as u64, 10 | 128, 1, 0, 0, 0]) },
        -22
    );
    let expired = [0u64; 2];
    assert_eq!(
        unsafe {
            syscall(
                98,
                [
                    word.as_ptr() as u64,
                    9 | 128,
                    0,
                    expired.as_ptr() as u64,
                    0,
                    2,
                ],
            )
        },
        -110
    );
    println!("RUST_STD_PROBE FUTEX_BITSET PASS");
}

extern "C" fn interrupt_sleep(_: i32) {
    SLEEP_SIGNALS.fetch_add(1, Ordering::Relaxed);
}

fn clock_ns() -> u64 {
    let mut time = [0u64; 2];
    assert_eq!(
        unsafe { syscall(113, [1, time.as_mut_ptr() as u64, 0, 0, 0, 0]) },
        0
    );
    time[0] * 1_000_000_000 + time[1]
}

fn clock_sleep() {
    let action = Action {
        handler: interrupt_sleep as *const () as u64,
        flags: 0x0400_0000,
        restorer: rust_probe_restore as *const () as u64,
        mask: 0,
    };
    let mut previous = Action::default();
    assert_eq!(
        unsafe {
            syscall(
                134,
                [
                    12,
                    &action as *const _ as u64,
                    &mut previous as *mut _ as u64,
                    8,
                    0,
                    0,
                ],
            )
        },
        0
    );
    let pid = unsafe { syscall(172, [0; 6]) };
    let tid = unsafe { syscall(178, [0; 6]) };
    let start = Arc::new(Barrier::new(2));
    let sender_start = start.clone();
    let sender = thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || {
            sender_start.wait();
            thread::sleep(Duration::from_millis(20));
            assert_eq!(
                unsafe { syscall(131, [pid as u64, tid as u64, 12, 0, 0, 0]) },
                0
            );
        })
        .unwrap();
    start.wait();
    let request = [0u64, 100_000_000];
    let mut remaining = [u64::MAX; 2];
    let began = clock_ns();
    assert_eq!(
        unsafe {
            syscall(
                115,
                [
                    1,
                    0,
                    request.as_ptr() as u64,
                    remaining.as_mut_ptr() as u64,
                    0,
                    0,
                ],
            )
        },
        -4
    );
    assert_eq!(SLEEP_SIGNALS.load(Ordering::Relaxed), 1);
    assert_eq!(remaining[0], 0);
    assert!(remaining[1] > 0 && remaining[1] < request[1]);
    assert_eq!(
        unsafe { syscall(115, [1, 0, remaining.as_ptr() as u64, 0, 0, 0]) },
        0
    );
    assert!(clock_ns() - began >= request[1]);
    sender.join().unwrap();
    assert_eq!(
        unsafe { syscall(134, [12, &previous as *const _ as u64, 0, 8, 0, 0]) },
        0
    );

    let expired = [0u64; 2];
    // Absolute waits ignore the remaining pointer, including this invalid one.
    assert_eq!(
        unsafe { syscall(115, [1, 1, expired.as_ptr() as u64, 1, 0, 0]) },
        0
    );
    let deadline = clock_ns() + 3_000_000;
    let absolute = [deadline / 1_000_000_000, deadline % 1_000_000_000];
    assert_eq!(
        unsafe { syscall(115, [1, 1, absolute.as_ptr() as u64, 1, 0, 0]) },
        0
    );
    assert!(clock_ns() >= deadline);
    println!("RUST_STD_PROBE CLOCK_SLEEP PASS");
}

thread_local! { static COOKIE: Cell<usize> = const { Cell::new(0) }; }

fn main() {
    println!("RUST_STD_PROBE START");
    let words: Vec<u64> = (0..8192).map(|x| x * 17).collect();
    assert_eq!(words.iter().sum::<u64>(), 17 * 8191 * 8192 / 2);
    assert!(std::env::args().next().unwrap().contains("rust-std-probe"));
    println!("RUST_STD_PROBE STARTUP_ALLOC PASS");
    let mut map = HashMap::new();
    for i in 0..128 {
        map.insert(format!("key-{i}"), i * 7);
    }
    assert_eq!(map["key-73"], 511);
    assert_eq!(map.len(), 128);
    println!("RUST_STD_PROBE HASHMAP PASS");
    alternate_stack();

    let path = "/rust-std-probe.txt";
    let renamed = "/rust-std-probe-renamed.txt";
    let value = b"real Rust std through CyxiaOS\n";
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.write_all(value).unwrap();
    assert_eq!(file.metadata().unwrap().len(), value.len() as u64);
    drop(file);
    fs::rename(path, renamed).unwrap();
    let mut read = Vec::new();
    fs::File::open(renamed)
        .unwrap()
        .read_to_end(&mut read)
        .unwrap();
    assert_eq!(read, value);
    fs::remove_file(renamed).unwrap();
    println!("RUST_STD_PROBE FILE PASS");

    let state = Arc::new((Mutex::new(0usize), Condvar::new()));
    let start = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for id in 1..=2 {
        let state = state.clone();
        let start = start.clone();
        threads.push(
            thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn(move || {
                    COOKIE.with(|v| {
                        assert_eq!(v.get(), 0);
                        v.set(id);
                    });
                    start.wait();
                    for _ in 0..1000 {
                        *state.0.lock().unwrap() += 1;
                        thread::yield_now();
                    }
                    state.1.notify_one();
                    COOKIE.with(|v| assert_eq!(v.get(), id));
                    id * 31
                })
                .unwrap(),
        );
    }
    start.wait();
    let lock = state.0.lock().unwrap();
    let guard = state.1.wait_while(lock, |v| *v < 2000).unwrap();
    assert_eq!(*guard, 2000);
    drop(guard);
    assert_eq!(
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .sum::<usize>(),
        93
    );
    COOKIE.with(|v| assert_eq!(v.get(), 0));
    println!("RUST_STD_PROBE THREAD_TLS_SYNC PASS");

    let before = Instant::now();
    let lock = state.0.lock().unwrap();
    let (guard, timeout) = state
        .1
        .wait_timeout(lock, Duration::from_millis(20))
        .unwrap();
    assert!(timeout.timed_out());
    assert!(before.elapsed() >= Duration::from_millis(20));
    drop(guard);
    let before = Instant::now();
    thread::sleep(Duration::from_millis(5));
    assert!(before.elapsed() >= Duration::from_millis(5));
    println!("RUST_STD_PROBE TIMEOUT PASS");
    futex_bitsets();
    clock_sleep();
    println!("RUST_STD_PROBE PASS");
}
