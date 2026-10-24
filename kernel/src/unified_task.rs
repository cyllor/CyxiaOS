//! One reserved pure-compute thread on the stable business CPU. EL0 owns no
//! filesystem/device capability and uses the same AI-issued CPU credits as local
//! business work. Publication/release use an acquire/release mailbox.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_arch_aarch64::{cpu, mmu, timer, user};
use cyxia_contracts::PhysAddr;
use cyxia_kernel_core::control_plane::task_admission::{Authority, Terms, expire_quiescent};
use sha2::{Digest, Sha256};
static mut AUTHORITY: Authority = Authority::new();
static TASK_WINDOW: AtomicU64 = AtomicU64::new(u64::MAX);
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/prototype-task.elf"));
#[repr(C, align(4096))]
struct Page([u64; 512]);
static mut TABLES: [Page; 3] = [const { Page([0; 512]) }; 3];
static mut CODE: Page = Page([0; 512]);
static mut META: Page = Page([0; 512]);
static mut INPUT: [Page; 8] = [const { Page([0; 512]) }; 8];
static mut OUTPUT: Page = Page([0; 512]);
static mut STACK: Page = Page([0; 512]);
static mut CONTEXT: user::Context = user::Context::empty();
// 0 free,1reserved,2queued,3running,4done,5failed/cancelled.
static STATE: AtomicU64 = AtomicU64::new(0);
static TOKEN: AtomicU64 = AtomicU64::new(0);
static EPOCH: AtomicU64 = AtomicU64::new(0);
static LENGTH: AtomicU64 = AtomicU64::new(0);
static DEADLINE: AtomicU64 = AtomicU64::new(0);
static CANCEL: AtomicBool = AtomicBool::new(false);
static STARTS: AtomicU64 = AtomicU64::new(0);
static FINISHES: AtomicU64 = AtomicU64::new(0);
static DEBITS: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);
static MAX_SLICE: AtomicU64 = AtomicU64::new(0);
fn phys(p: u64) -> u64 {
    p.checked_sub(crate::HIGH).unwrap()
}
fn word(at: usize) -> u64 {
    u64::from_le_bytes(ELF[at..at + 8].try_into().unwrap())
}
pub fn init() {
    assert_eq!(cpu::slot(), 0);
    // The separately linked package is exactly one RX segment and no interpreter,
    // runtime relocations, data segment, or writable executable page.
    assert_eq!(&ELF[..7], b"\x7fELF\x02\x01\x01");
    assert_eq!(&ELF[16..24], &[2, 0, 183, 0, 1, 0, 0, 0]);
    assert_eq!(word(24), 0x10000);
    assert_eq!(&ELF[54..58], &[56, 0, 1, 0]);
    let ph = word(32) as usize;
    assert!(ph + 56 <= ELF.len());
    assert_eq!(&ELF[ph..ph + 8], &[1, 0, 0, 0, 5, 0, 0, 0]);
    let off = word(ph + 8) as usize;
    let len = word(ph + 32) as usize;
    assert_eq!(word(ph + 16), 0x10000);
    assert_eq!(word(ph + 40), len as u64);
    assert!(len > 0 && len <= 4096 && off.checked_add(len).is_some_and(|v| v <= ELF.len()));
    unsafe {
        let tables = &mut *core::ptr::addr_of_mut!(TABLES);
        tables[0].0[0] = phys(core::ptr::addr_of!(tables[1]) as u64) | 3;
        tables[1].0[0] = phys(core::ptr::addr_of!(tables[2]) as u64) | 3;
        let code = core::ptr::addr_of_mut!(CODE).cast::<u8>();
        core::ptr::copy_nonoverlapping(ELF.as_ptr().add(off), code, len);
        tables[2].0[16] = mmu::encode_user_leaf(PhysAddr(phys(code as u64)), false, true).unwrap();
        tables[2].0[32] = mmu::encode_user_leaf(
            PhysAddr(phys(core::ptr::addr_of!(META) as u64)),
            false,
            false,
        )
        .unwrap();
        for i in 0..8 {
            tables[2].0[33 + i] = mmu::encode_user_leaf(
                PhysAddr(phys(core::ptr::addr_of!(INPUT).cast::<Page>().add(i) as u64)),
                false,
                false,
            )
            .unwrap();
        }
        tables[2].0[48] = mmu::encode_user_leaf(
            PhysAddr(phys(core::ptr::addr_of!(OUTPUT) as u64)),
            true,
            false,
        )
        .unwrap();
        tables[2].0[64] = mmu::encode_user_leaf(
            PhysAddr(phys(core::ptr::addr_of!(STACK) as u64)),
            true,
            false,
        )
        .unwrap();
        for offset in (0..4096).step_by(64) {
            core::arch::asm!("dc cvau, {}",in(reg)code.add(offset),options(nostack));
        }
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack));
    }
}
/// CPU3 only, called inside an actual business gate and already-debited quantum.
pub fn step(slot: usize) -> bool {
    if slot != 3 {
        return false;
    }
    let state = STATE.load(Ordering::Acquire);
    if state != 2 && state != 3 {
        return false;
    }
    if CANCEL.load(Ordering::Acquire)
        || timer::ticks() / (timer::frequency() / 1000) >= DEADLINE.load(Ordering::Relaxed)
    {
        STATE.store(5, Ordering::Release);
        return true;
    }
    // Dedicated remote CPU subledger: one prepaid 10ms upper bound per aligned
    // 100ms window (100 milli). The surrounding business ledger also debits it.
    let now = timer::ticks();
    let quantum = timer::frequency() / 100;
    let origin = crate::smp::prototype_runtime::budget_origin();
    let window = (now - origin) / (timer::frequency() / 10);
    if TASK_WINDOW.load(Ordering::Relaxed) == window
        || now + quantum > origin + (window + 1) * (timer::frequency() / 10)
    {
        return false;
    }
    TASK_WINDOW.store(window, Ordering::Relaxed);
    DEBITS.fetch_add(100, Ordering::Relaxed);
    unsafe {
        let context = &mut *core::ptr::addr_of_mut!(CONTEXT);
        if state == 2 {
            *context = user::Context::empty();
            context.pc = 0x10000;
            context.sp = 0x41000;
            (*core::ptr::addr_of_mut!(OUTPUT)).0.fill(0);
            (*core::ptr::addr_of_mut!(STACK)).0.fill(0);
            STATE.store(3, Ordering::Release);
        }
        let deadline = DEADLINE
            .load(Ordering::Relaxed)
            .checked_mul(timer::frequency())
            .expect("bounded contract clock")
            / 1000;
        let begin = timer::ticks();
        if begin >= deadline {
            STATE.store(5, Ordering::Release);
            return true;
        }
        timer::arm((begin + timer::frequency() / 1000).min(deadline));
        if state == 2 {
            STARTS.fetch_add(1, Ordering::Relaxed);
        }
        user::enter(context, phys(core::ptr::addr_of!(TABLES) as u64));
        cpu::disable_timer();
        let spent = timer::ticks() - begin;
        TICKS.fetch_add(spent, Ordering::Relaxed);
        MAX_SLICE.fetch_max(spent, Ordering::Relaxed);
        if CANCEL.load(Ordering::Acquire) || timer::ticks() >= deadline {
            STATE.store(5, Ordering::Release);
        } else if context.kind == 8 && context.esr >> 26 == 0x15 && context.esr & 0xffff == 0x44 {
            let ok = (*core::ptr::addr_of!(OUTPUT)).0[0] == 0;
            FINISHES.fetch_add(1, Ordering::Relaxed);
            STATE.store(if ok { 4 } else { 5 }, Ordering::Release);
        } else if context.kind != 9 {
            STATE.store(5, Ordering::Release);
        }
    }
    true
}

/// CPU3 calls this while no task EL0 context is executing, even when its
/// execution-credit ledger is closed. Expiry/cancellation is quiescence work,
/// not a new dispatch: a poisoned credit must not strand STARTED forever.
pub fn expire_idle(slot: usize) {
    if slot != 3 {
        return;
    }
    // No task-memory access follows the release. CPU0 can then persist failure
    // and release the reservation, even if this core has no execution credits.
    expire_quiescent(
        &STATE,
        &CANCEL,
        timer::ticks() / (timer::frequency() / 1000),
        &DEADLINE,
    );
}
/// CPU0 broker. Returns (ABI status, bytes, returned token). Inputs are copied;
/// phase2 is the actual final admission point after durable STARTED intent.
pub fn request(
    phase: u64,
    token: u64,
    offset: u64,
    payload: &mut [u8; 4096],
    len: usize,
    now: u64,
    connected: bool,
    epoch: u64,
) -> (u64, usize, u64) {
    assert_eq!(cpu::slot(), 0);
    let state = STATE.load(Ordering::Acquire);
    if phase == 6 {
        if len < 32 {
            return (3, 0, 0);
        }
        payload[..32].copy_from_slice(&Sha256::digest(ELF));
        return (0, 32, 0);
    }
    if phase == 9 {
        if token != 0 && (!connected || offset != epoch) {
            return (3, 0, 0);
        }
        let result =
            unsafe { (&mut *core::ptr::addr_of_mut!(AUTHORITY)).session(epoch, token, now) };
        return (if result.is_ok() { 0 } else { 3 }, 0, 0);
    }
    if phase == 0 {
        if !connected || epoch == 0 || state != 0 {
            return (1, 0, 0);
        }
        if len != 104 {
            return (3, 0, 0);
        }
        let n = |at| u64::from_le_bytes(payload[at..at + 8].try_into().unwrap());
        let terms = Terms {
            cpu_milli: n(0),
            memory_pages: n(8),
            runtime_ms: n(16),
            contract: payload[24..40].try_into().unwrap(),
            input_hash: payload[40..72].try_into().unwrap(),
            package_hash: payload[72..104].try_into().unwrap(),
        };
        let Ok(next) = (unsafe {
            (&mut *core::ptr::addr_of_mut!(AUTHORITY)).reserve(
                terms,
                Sha256::digest(ELF).into(),
                now,
            )
        }) else {
            return (3, 0, 0);
        };
        TOKEN.store(next, Ordering::Relaxed);
        EPOCH.store(epoch, Ordering::Relaxed);
        LENGTH.store(0, Ordering::Relaxed);
        CANCEL.store(false, Ordering::Relaxed);
        STATE.store(1, Ordering::Release);
        return (0, 0, next);
    }
    if token == 0 || TOKEN.load(Ordering::Relaxed) != token {
        return (3, 0, 0);
    }
    match phase {
        1 => {
            let old = LENGTH.load(Ordering::Relaxed);
            if state != 1 || offset != old || old + len as u64 > 32768 {
                return (3, 0, 0);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    core::ptr::addr_of_mut!(INPUT)
                        .cast::<u8>()
                        .add(old as usize),
                    len,
                );
            }
            LENGTH.store(old + len as u64, Ordering::Relaxed);
            (0, 0, token)
        }
        2 => {
            if state != 1 || len != 48 || !connected || epoch != EPOCH.load(Ordering::Relaxed) {
                return (3, 0, 0);
            }
            let input = u64::from_le_bytes(payload[..8].try_into().unwrap());
            let end = u64::from_le_bytes(payload[8..16].try_into().unwrap());
            let bound = u64::from_le_bytes(payload[16..24].try_into().unwrap());
            if bound != epoch
                || input != LENGTH.load(Ordering::Relaxed)
                || input == 0
                || !input.is_multiple_of(8)
                || end <= now
                || end - now > 60000
            {
                return (3, 0, 0);
            }
            let grant = u64::from_le_bytes(payload[24..32].try_into().unwrap());
            let contract = payload[32..48].try_into().unwrap();
            let digest = unsafe {
                Sha256::digest(core::slice::from_raw_parts(
                    core::ptr::addr_of!(INPUT).cast::<u8>(),
                    input as usize,
                ))
                .into()
            };
            if unsafe {
                (&mut *core::ptr::addr_of_mut!(AUTHORITY)).start(
                    token,
                    contract,
                    grant,
                    end,
                    bound,
                    digest,
                    timer::ticks() / (timer::frequency() / 1000),
                )
            }
            .is_err()
            {
                return (3, 0, 0);
            }
            unsafe {
                (*core::ptr::addr_of_mut!(META)).0[0] = input;
            }
            DEADLINE.store(end, Ordering::Relaxed);
            STATE.store(2, Ordering::Release);
            (0, 0, token)
        }
        3 => {
            if state == 4 {
                if len < 8 {
                    return (3, 0, 0);
                }
                let result = unsafe { (*core::ptr::addr_of!(OUTPUT)).0[1] };
                payload[..8].copy_from_slice(&result.to_le_bytes());
                (0, 8, token)
            } else if state == 5 {
                (3, 0, token)
            } else {
                (1, 0, token)
            }
        }
        4 => {
            if !matches!(state, 1 | 4 | 5) {
                return (1, 0, token);
            }
            unsafe {
                core::ptr::write_bytes(core::ptr::addr_of_mut!(INPUT).cast::<u8>(), 0, 32768);
            }
            if unsafe { (&mut *core::ptr::addr_of_mut!(AUTHORITY)).release(token) }.is_err() {
                return (3, 0, 0);
            }
            STATE.store(0, Ordering::Release);
            (0, 0, token)
        }
        5 => {
            CANCEL.store(true, Ordering::Release);
            if state == 1 {
                STATE.store(5, Ordering::Release);
            }
            (0, 0, token)
        }
        7 => {
            if state != 1 || len != 32 || !connected {
                return (3, 0, 0);
            }
            let deadline = u64::from_le_bytes(payload[..8].try_into().unwrap());
            let grant = u64::from_le_bytes(payload[8..16].try_into().unwrap());
            let contract = payload[16..32].try_into().unwrap();
            let result = unsafe {
                (&mut *core::ptr::addr_of_mut!(AUTHORITY))
                    .grant(token, contract, grant, deadline, now)
            };
            (if result.is_ok() { 0 } else { 3 }, 0, token)
        }
        8 => (if matches!(state, 1 | 4 | 5) { 0 } else { 1 }, 0, state),
        _ => (3, 0, 0),
    }
}
pub fn counts() -> (u64, u64) {
    (
        STARTS.load(Ordering::Acquire),
        FINISHES.load(Ordering::Acquire),
    )
}

/// Mechanical transport loss closes new execution before returning to EL0.
pub fn transport(connected: bool) {
    assert_eq!(cpu::slot(), 0);
    if !connected {
        unsafe {
            (&mut *core::ptr::addr_of_mut!(AUTHORITY)).disconnect();
        }
    }
}

pub fn budget() -> (u64, u64, u64) {
    (
        DEBITS.load(Ordering::Acquire),
        TICKS.load(Ordering::Acquire),
        MAX_SLICE.load(Ordering::Acquire),
    )
}
