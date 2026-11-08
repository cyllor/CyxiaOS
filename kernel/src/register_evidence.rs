//! Raw real EL0 context captures, not a complete A06 acceptance provider.
use super::*;
const MAGIC: u64 = 0x4359585245473031;
const CONFIG_MAGIC: u64 = 0x4359585245474346;
const ROW: usize = 928;
const EVENT: usize = 112;
const WORDS: usize = 64 + 6 * ROW;
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.boot")]
pub static REGISTER_V15_PROFILE: [u64; 4] = [1, 4, 6, WORDS as u64];
#[repr(C, align(64))]
pub struct Config([AtomicU64; 16]);
#[used]
#[unsafe(no_mangle)]
pub static REGISTER_V15_CONFIG: Config = Config({
    let mut words = [const { AtomicU64::new(0) }; 16];
    // File-backed data survives the entry assembly's BSS zeroing, unlike an
    // all-zero static overwritten by the debugger before the first instruction.
    words[0] = AtomicU64::new(CONFIG_MAGIC);
    words[1] = AtomicU64::new(1);
    words
});
#[repr(C, align(64))]
pub struct Capture([AtomicU64; WORDS]);
#[used]
#[unsafe(no_mangle)]
pub static REGISTER_V15_EVIDENCE: Capture = Capture([const { AtomicU64::new(0) }; WORDS]);
static DONE: AtomicU64 = AtomicU64::new(0);
fn put(i: usize, value: u64) {
    REGISTER_V15_EVIDENCE.0[i].store(value, Ordering::Relaxed);
}
fn get(i: usize) -> u64 {
    REGISTER_V15_EVIDENCE.0[i].load(Ordering::Acquire)
}
fn seed(j: usize) -> u64 {
    ((get(10) ^ get(11).rotate_left(17)) & 0xffff0000) + (j as u64 + 1) * 0x100000000 + j as u64 + 1
}
pub fn init() {
    assert_eq!(
        REGISTER_V15_CONFIG.0[0].load(Ordering::Acquire),
        CONFIG_MAGIC
    );
    assert_eq!(REGISTER_V15_CONFIG.0[1].load(Ordering::Acquire), 1);
    assert_ne!(
        REGISTER_V15_CONFIG.0[2].load(Ordering::Acquire)
            | REGISTER_V15_CONFIG.0[3].load(Ordering::Acquire),
        0
    );
    for i in 0..16 {
        put(8 + i, REGISTER_V15_CONFIG.0[i].load(Ordering::Acquire));
    }
    put(0, MAGIC);
    put(1, 1);
    put(2, 1);
    put(4, 6);
    put(6, timer::frequency());
    put(7, timer::ticks().max(1));
}
fn capture(
    ctx: &user::Context,
    b: usize,
    count: usize,
    turn: u64,
    start: u64,
    end: u64,
    kind: u64,
    j: usize,
    irqs: u64,
) {
    let at = b + 32 + count * EVENT;
    for (i, v) in [turn, start, end, kind, j as u64, 1, turn - 1, irqs]
        .iter()
        .enumerate()
    {
        put(at + i, *v);
    }
    // Context's 104-word repr(C) and every offset are asserted by user.rs.
    let raw = core::ptr::from_ref(ctx).cast::<u64>();
    for i in 0..104 {
        put(at + 8 + i, unsafe { raw.add(i).read() });
    }
}
pub fn worker(slot: usize) -> ! {
    let mut contexts = [user::Context::empty(), user::Context::empty()];
    let mut counts = [[0usize; 2]; 2];
    for (local, ctx) in contexts.iter_mut().enumerate() {
        let j = (slot - 1) * 2 + local;
        let i = slot * 2 + local;
        ctx.pc = CODE;
        ctx.sp = STACK + 4096;
        ctx.regs[0] = seed(j);
        ctx.regs[1] = DATA;
        ctx.regs[2] = 5;
        let b = 64 + j * ROW;
        let root = unsafe { core::ptr::addr_of!(ROOTS).cast::<Page>().add(i) as u64 };
        for (n, v) in [slot as u64, local as u64, seed(j), phys(root)]
            .iter()
            .enumerate()
        {
            put(b + n, *v);
        }
    }
    for turn in 1..=256u64 {
        let local = ((turn - 1) % 2) as usize;
        let j = (slot - 1) * 2 + local;
        let b = 64 + j * ROW;
        let ctx = &mut contexts[local];
        let before = IRQS[slot].load(Ordering::Acquire);
        let start = timer::ticks();
        execute(ctx, slot * 2 + local);
        let end = timer::ticks();
        let irqs = IRQS[slot].load(Ordering::Acquire).saturating_sub(before);
        let data = unsafe {
            &*core::ptr::addr_of!(DATA_PAGES)
                .cast::<Page>()
                .add(slot * 2 + local)
        };
        let fresh = unsafe { core::ptr::addr_of!(data.0[2]).read_volatile() };
        let ready = unsafe { core::ptr::addr_of!(data.0[3]).read_volatile() };
        put(b + 6, fresh);
        put(b + 7, ready);
        put(b + 8, turn);
        let kind = if ctx.kind == 9 && irqs == 1 {
            0
        } else if ctx.kind == 8 && irqs == 0 && ctx.esr >> 26 == 0x15 && ctx.esr & 0xffff == 0x606 {
            1
        } else {
            put(b + 9, ctx.esr.max(1));
            put(5, 1);
            break;
        };
        if ready == 1 && counts[local][kind] < 4 {
            let n = counts[local][kind];
            capture(
                ctx,
                b,
                kind * 4 + n,
                turn,
                start,
                end,
                kind as u64 + 1,
                j,
                irqs,
            );
            counts[local][kind] += 1;
            put(b + 4 + kind, counts[local][kind] as u64);
            put(b + 10, (counts[local][0] + counts[local][1]) as u64);
        }
        if counts == [[4, 4]; 2] {
            break;
        }
    }
    if counts != [[4, 4]; 2] {
        put(5, 1);
    }
    DONE.fetch_or(1 << slot, Ordering::Release);
    loop {
        core::hint::spin_loop();
    }
}
pub fn finish() -> ! {
    wait(|| DONE.load(Ordering::Acquire) == 14);
    put(3, ONLINE.load(Ordering::Acquire));
    REGISTER_V15_EVIDENCE.0[2].store(2, Ordering::Release);
    report("REGISTER_CONTEXT_DONE", get(5), 6, 0);
    loop {
        core::hint::spin_loop();
    }
}
