//! Host-only deterministic interleavings of the actual kernel boot worker.
//! Architecture, clocks and scheduler are explicit mocks, not native evidence.
#![allow(dead_code)]
extern crate self as cyxia_prototype;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub mod domains {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        Busy,
        Budget,
        Stale,
    }
    pub mod tasks {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct ControlCredit {
            pub sequence: u64,
            pub reserved_ns: u64,
            pub window: u64,
        }
    }
}
pub mod boot_model {
    pub const OUTPUT_MAGIC: u64 = 0x4359_584d_5445_5354;
    pub const CASES: usize = 4;
}
mod user {
    pub struct Context {
        pub pc: u64,
        pub kind: u64,
        pub esr: u64,
        pub regs: [u64; 31],
    }
}
use domains::Error;
use domains::tasks::ControlCredit;
static CPU: AtomicUsize = AtomicUsize::new(0);
static WALL: AtomicU64 = AtomicU64::new(10_000_000);
static CLOCK: AtomicU64 = AtomicU64::new(0);
static BODY_CPU: AtomicU64 = AtomicU64::new(100);
static CHECKPOINT_CPU: AtomicU64 = AtomicU64::new(200);
static KIND: AtomicU64 = AtomicU64::new(8);
static ESR: AtomicU64 = AtomicU64::new((0x15 << 26) | 0x543);
static REPLY: AtomicU64 = AtomicU64::new(1);
static MAGIC: AtomicU64 = AtomicU64::new(boot_model::OUTPUT_MAGIC);
static CASES: AtomicU64 = AtomicU64::new(boot_model::CASES as u64);
static RESERVE: AtomicU64 = AtomicU64::new(0);
struct MockState {
    active: Option<ControlCredit>,
    sequence: u64,
    busy: u64,
    error: Option<Error>,
    entries: Vec<u64>,
    receipts: Vec<(ControlCredit, u64, u64)>,
    evidence: Option<(u64, bool)>,
    fresh: u64,
}
static MOCK: Mutex<MockState> = Mutex::new(MockState {
    active: None,
    sequence: 0,
    busy: 0,
    error: None,
    entries: Vec::new(),
    receipts: Vec::new(),
    evidence: None,
    fresh: 0,
});
mod cpu {
    pub fn slot() -> usize {
        super::CPU.load(super::Ordering::Relaxed)
    }
}
mod timer {
    pub fn cpu_ticks() -> u64 {
        super::CLOCK.load(super::Ordering::Relaxed)
    }
    pub fn cpu_ns(delta: u64) -> u64 {
        delta
    }
    pub fn cpu_elapsed_ns(start: u64) -> u64 {
        cpu_ticks().saturating_sub(start)
    }
}
mod domain_tasks {
    use super::*;
    pub fn now_ns() -> u64 {
        WALL.load(Ordering::Relaxed)
    }
    pub fn begin_control(required: u64, cleanup: bool) -> Result<Option<ControlCredit>, Error> {
        assert_eq!(cpu::slot(), 1);
        assert_eq!(required, 8_000_000, "recovery credit must not be enlarged");
        assert!(!cleanup);
        match RESERVE.load(Ordering::Relaxed) {
            1 => return Ok(None),
            2 => return Err(Error::Busy),
            _ => {}
        }
        let mut state = MOCK.lock().unwrap();
        assert!(state.active.is_none(), "second execution while original credit is pending");
        state.sequence += 1;
        let credit = ControlCredit {
            sequence: state.sequence,
            reserved_ns: required,
            window: now_ns() / 100_000_000,
        };
        state.active = Some(credit);
        Ok(Some(credit))
    }
    pub fn complete_control(credit: ControlCredit, actual: u64, end: u64) -> Result<(), Error> {
        let mut state = MOCK.lock().unwrap();
        assert_eq!(state.active, Some(credit));
        state.receipts.push((credit, actual, end));
        if state.busy != 0 {
            state.busy -= 1;
            return Err(Error::Busy);
        }
        state.active = None;
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        if actual > credit.reserved_ns {
            Err(Error::Budget)
        } else {
            Ok(())
        }
    }
}
mod boot_recovery {
    use super::*;
    pub fn model_corruption() -> bool {
        REPLY.load(Ordering::Relaxed) == 0
    }
    pub fn model_turn(checkpoint: u64, _kind: u64, result: Option<bool>) {
        if let Some(passed) = result {
            MOCK.lock().unwrap().evidence = Some((checkpoint, passed));
        }
        CLOCK.fetch_add(CHECKPOINT_CPU.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    pub fn model_settled(spent: u64, passed: bool) {
        assert_eq!(cpu::slot(), 0);
        let mut state = MOCK.lock().unwrap();
        assert!(state.active.is_none(), "model verdict published before physical settlement");
        state.evidence = Some((spent, passed));
    }
}
fn fresh(mode: u64) -> user::Context {
    assert!(matches!(mode, 6 | 7));
    MOCK.lock().unwrap().fresh += 1;
    user::Context {
        pc: 0x10000,
        kind: 0,
        esr: 0,
        regs: [0; 31],
    }
}
fn execute(context: &mut user::Context, root: usize) {
    assert_eq!(root, 3);
    assert!(MOCK.lock().unwrap().active.is_some());
    MOCK.lock().unwrap().entries.push(context.pc);
    context.pc += 4;
    context.kind = KIND.load(Ordering::Relaxed);
    context.esr = ESR.load(Ordering::Relaxed);
    context.regs[0] = MAGIC.load(Ordering::Relaxed);
    context.regs[1] = REPLY.load(Ordering::Relaxed);
    context.regs[2] = CASES.load(Ordering::Relaxed);
    CLOCK.fetch_add(BODY_CPU.load(Ordering::Relaxed), Ordering::Relaxed);
    WALL.fetch_add(1_000_000, Ordering::Relaxed);
}
fn wake_workers() {}
#[path = "../../kernel/src/prototype_runtime/boot_model.rs"]
mod worker;
fn step(check: &mut worker::Check) {
    CPU.store(1, Ordering::Relaxed);
    let _ = check.step();
}
fn result() -> Option<bool> {
    CPU.store(0, Ordering::Relaxed);
    worker::result()
}
fn no_model_receipt() {
    assert_eq!(MOCK.lock().unwrap().evidence, None, "non-model failure/pending bill certified a model result");
}
fn main() {
    let scenario = std::env::args().nth(1).expect("scenario");
    let mut check = worker::Check::new();
    worker::request();
    match scenario.as_str() {
        "exact-final-cpu" | "valid-rejection" => {
            let passed = scenario == "exact-final-cpu";
            REPLY.store(u64::from(passed), Ordering::Relaxed);
            step(&mut check);
            assert_eq!(result(), Some(passed));
            assert_eq!(MOCK.lock().unwrap().evidence, Some((300, passed)));
        }
        "pending-settlement" => {
            MOCK.lock().unwrap().busy = 2;
            step(&mut check);
            assert_eq!(result(), None);
            no_model_receipt();
            step(&mut check);
            assert_eq!(result(), None);
            no_model_receipt();
            step(&mut check);
            assert_eq!(result(), Some(true));
            let state = MOCK.lock().unwrap();
            assert_eq!(state.entries.len(), 1);
            assert_eq!(state.receipts.len(), 3);
            assert!(state.receipts.iter().all(|receipt| *receipt == state.receipts[0]));
            assert_eq!(state.evidence, Some((300, true)));
        }
        "cancelled-return" | "late-settlement" => {
            MOCK.lock().unwrap().busy = 1;
            step(&mut check);
            if scenario == "cancelled-return" {
                CPU.store(0, Ordering::Relaxed);
                worker::cancel();
            } else {
                WALL.store(2_000_000_000, Ordering::Relaxed);
            }
            step(&mut check);
            assert_eq!(result(), Some(false));
            no_model_receipt();
            assert!(MOCK.lock().unwrap().active.is_none());
            assert_eq!(MOCK.lock().unwrap().entries.len(), 1);
        }
        "unexpected-trap" | "wrong-magic" | "wrong-cases" | "invalid-boolean" => {
            match scenario.as_str() {
                "unexpected-trap" => ESR.store(0x24 << 26, Ordering::Relaxed),
                "wrong-magic" => MAGIC.store(0, Ordering::Relaxed),
                "wrong-cases" => CASES.store(0, Ordering::Relaxed),
                _ => REPLY.store(2, Ordering::Relaxed),
            }
            step(&mut check);
            assert_eq!(result(), Some(false));
            no_model_receipt();
        }
        "settlement-error" | "cpu-overrun" => {
            REPLY.store(0, Ordering::Relaxed);
            if scenario == "settlement-error" {
                MOCK.lock().unwrap().error = Some(Error::Budget);
            } else {
                BODY_CPU.store(8_000_001, Ordering::Relaxed);
            }
            step(&mut check);
            assert_eq!(result(), Some(false));
            no_model_receipt();
        }
        "preempt-resume" | "aggregate-overrun" => {
            let overrun = scenario == "aggregate-overrun";
            if overrun {
                BODY_CPU.store(4_100_000, Ordering::Relaxed);
                REPLY.store(0, Ordering::Relaxed);
            }
            KIND.store(9, Ordering::Relaxed);
            step(&mut check);
            assert_eq!(result(), None);
            no_model_receipt();
            step(&mut check);
            assert_eq!(MOCK.lock().unwrap().entries.len(), 1);
            WALL.store(100_000_000, Ordering::Relaxed);
            KIND.store(8, Ordering::Relaxed);
            step(&mut check);
            assert_eq!(result(), Some(!overrun));
            if overrun {
                no_model_receipt();
            } else {
                assert_eq!(MOCK.lock().unwrap().evidence, Some((600, true)));
            }
            let state = MOCK.lock().unwrap();
            assert_eq!(state.entries, vec![0x10000, 0x10004]);
            assert_eq!(state.fresh, 1, "preemption restarted instead of resuming the saved context");
        }
        "no-credit-deadline" => {
            RESERVE.store(1, Ordering::Relaxed);
            step(&mut check);
            assert_eq!(result(), None);
            RESERVE.store(2, Ordering::Relaxed);
            step(&mut check);
            assert_eq!(result(), None);
            WALL.store(1_010_000_000, Ordering::Relaxed);
            step(&mut check);
            assert_eq!(result(), Some(false));
            no_model_receipt();
            assert!(MOCK.lock().unwrap().entries.is_empty());
        }
        _ => panic!("unknown scenario"),
    }
    println!("HOST_ONLY {scenario} PASS; native_acceptance_status=NOT_RUN");
}
