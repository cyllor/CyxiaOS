//! Native integer-kernel engineering fixtures, not a continuously running CACP.
//! CPU1 runs the EL0 image; CPU0 only copies immutable fixtures and records traps.
use super::*;
#[path = "../../user/prototype-control/abi.rs"]
mod abi;
use cyxia_kernel_core::control_plane::image::{BASE, Image, PAGES};
#[used]
#[unsafe(no_mangle)]
static PROTOTYPE_SERVICE_ELF: [u8; include_bytes!(concat!(
    env!("OUT_DIR"),
    "/prototype-control.elf"
))
.len()] = *include_bytes!(concat!(env!("OUT_DIR"), "/prototype-control.elf"));
const REQUESTS: &[u8; abi::CASES * abi::INPUT_WORDS * 8] =
    include_bytes!("../../ports/prototype/requests.bin");
#[repr(C, align(4096))]
pub struct ModelEvidence([AtomicU64; 2048]);
#[used]
#[unsafe(no_mangle)]
static MODEL_V13_EVIDENCE: ModelEvidence = ModelEvidence([const { AtomicU64::new(0) }; 2048]);
static mut IMAGE: [Page; PAGES] = [const { Page::ZERO }; PAGES];
static mut INPUT: Page = Page::ZERO;
static mut OUTPUT: Page = Page::ZERO;
static mut STACK_PAGES: [Page; 8] = [const { Page::ZERO }; 8];
static ENTRY: AtomicU64 = AtomicU64::new(0);
static START: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);
fn put(index: usize, value: u64) {
    MODEL_V13_EVIDENCE.0[index].store(value, Ordering::Relaxed);
}
fn bytes(at: usize, value: &[u8]) {
    assert!(value.len().is_multiple_of(8));
    for (i, chunk) in value.chunks_exact(8).enumerate() {
        put(at / 8 + i, u64::from_le_bytes(chunk.try_into().unwrap()));
    }
}
pub(super) unsafe fn init() {
    let image = Image::parse(&PROTOTYPE_SERVICE_ELF).expect("prototype EL0 image");
    unsafe {
        // Only CPU1's control root receives the model. Remove legacy fixture
        // code/data/stack aliases before any secondary is released.
        let leaf = &mut *core::ptr::addr_of_mut!(LEAVES).cast::<Page>().add(3);
        leaf.0.fill(0);
        let arena = core::ptr::addr_of_mut!(IMAGE).cast::<u8>();
        for segment in image.segments.iter().take(image.count) {
            let offset = (segment.address - BASE) as usize;
            core::ptr::copy_nonoverlapping(
                image.bytes.as_ptr().add(segment.offset),
                arena.add(offset),
                segment.file_size,
            );
            for page in offset / 4096..(offset + segment.memory_size).div_ceil(4096) {
                leaf.0[BASE as usize / 4096 + page] = mmu::encode_user_leaf(
                    PhysAddr(phys(arena.add(page * 4096) as u64)),
                    false,
                    segment.executable,
                )
                .unwrap();
            }
        }
        for offset in (0..PAGES * 4096).step_by(64) {
            core::arch::asm!("dc cvau, {}",in(reg)arena.add(offset),options(nostack));
        }
        core::arch::asm!("dsb ish", options(nostack));
        leaf.0[abi::INPUT_VA as usize / 4096] = mmu::encode_user_leaf(
            PhysAddr(phys(core::ptr::addr_of!(INPUT) as u64)),
            false,
            false,
        )
        .unwrap();
        leaf.0[abi::OUTPUT_VA as usize / 4096] = mmu::encode_user_leaf(
            PhysAddr(phys(core::ptr::addr_of!(OUTPUT) as u64)),
            true,
            false,
        )
        .unwrap();
        for n in 0..8 {
            let address = core::ptr::addr_of!(STACK_PAGES).cast::<Page>().add(n);
            leaf.0[0xb1 + n] =
                mmu::encode_user_leaf(PhysAddr(phys(address as u64)), true, false).unwrap();
        }
    }
    ENTRY.store(image.entry, Ordering::Release);
}
fn fresh(mode: u64) -> user::Context {
    let mut ctx = user::Context::empty();
    ctx.pc = ENTRY.load(Ordering::Acquire);
    ctx.sp = abi::STACK_TOP;
    ctx.regs[0] = mode;
    ctx
}
fn completion(ctx: &mut user::Context) -> u64 {
    let end = deadline();
    let mut preemptions = 0;
    loop {
        execute(ctx, 3);
        if ctx.kind != 9 {
            return preemptions;
        }
        preemptions += 1;
        if timer::ticks() >= end {
            fatal(141);
        }
    }
}
pub(super) fn step() {
    if !START.load(Ordering::Acquire) || DONE.load(Ordering::Acquire) {
        return;
    }
    assert_eq!(cpu::slot(), 1);
    unsafe {
        core::arch::asm!("ic iallu", "dsb ish", "isb", options(nostack));
    }
    let begin = timer::ticks();
    for (i, (address, fsc)) in [
        (abi::INPUT_VA, 0x4f),
        (abi::MODEL_VA, 0x4f),
        (0xb0000, 0x47),
        (0x30000, 0x07),
    ]
    .into_iter()
    .enumerate()
    {
        let mut ctx = fresh(i as u64 + 1);
        completion(&mut ctx);
        for (j, v) in [i as u64 + 1, ctx.kind, ctx.esr, ctx.far]
            .into_iter()
            .enumerate()
        {
            put(32 + i * 4 + j, v);
        }
        if ctx.kind != 8 || ctx.esr >> 26 != 0x24 || ctx.esr & 0x7f != fsc || ctx.far != address {
            fatal(142 + i as u64);
        }
    }
    let mut stall = fresh(5);
    execute(&mut stall, 3);
    if stall.kind != 9 {
        fatal(148);
    }
    put(5, 1); // This is an intentional stalled-user timer test, not model throughput.
    put(6, 4);
    for case in 0..abi::CASES {
        let request = &REQUESTS[case * 576..(case + 1) * 576];
        unsafe {
            for (i, chunk) in request.chunks_exact(8).enumerate() {
                (*core::ptr::addr_of_mut!(INPUT)).0[i] =
                    u64::from_le_bytes(chunk.try_into().unwrap());
            }
            (*core::ptr::addr_of_mut!(OUTPUT)).0.fill(0);
            // Stack is exclusively owned and no old user context remains live.
            for n in 0..8 {
                (*core::ptr::addr_of_mut!(STACK_PAGES).cast::<Page>().add(n))
                    .0
                    .fill(0);
            }
            core::arch::asm!("dsb ish", options(nostack));
        }
        let offset = 4096 + case * 1536;
        bytes(offset, request);
        let mut ctx = fresh(0);
        let start = timer::ticks();
        let preemptions = completion(&mut ctx);
        let end = timer::ticks();
        if ctx.kind != 8
            || ctx.esr >> 26 != 0x15
            || ctx.esr & 0xffff != abi::SUBMIT
            || ctx.regs[0] != abi::OUTPUT_VA
            || ctx.regs[1] != (abi::OUTPUT_WORDS * 8) as u64
        {
            fatal(149);
        }
        for i in 0..abi::OUTPUT_WORDS {
            let value = unsafe {
                (*core::ptr::addr_of!(OUTPUT))
                    .0
                    .as_ptr()
                    .add(i)
                    .read_volatile()
            };
            put((offset + 576) / 8 + i, value);
        }
        // Preserve raw FAR, although FAR is not meaningful for an SVC exception.
        for (i, value) in [start, end, preemptions, 1, ctx.kind, ctx.esr, ctx.far, 0]
            .into_iter()
            .enumerate()
        {
            put((offset + 1088) / 8 + i, value);
        }
    }
    put(10, timer::ticks() - begin);
    DONE.store(true, Ordering::Release);
}
pub(super) fn run() -> ! {
    wait(|| PROGRESS[4].load(Ordering::Acquire) >= 4 && PROGRESS[6].load(Ordering::Acquire) >= 4);
    let before = [
        PROGRESS[4].load(Ordering::Acquire),
        PROGRESS[6].load(Ordering::Acquire),
    ];
    START.store(true, Ordering::Release);
    wait(|| DONE.load(Ordering::Acquire));
    // Quiesce all fixture workers before publishing the final immutable page.
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(|| (1..REQUIRED).all(|i| GATES[i].quiescent()));
    QUIT.store(true, Ordering::Release);
    wait(|| STOPPED.load(Ordering::Acquire) == 14);
    check_failures();
    let business = [
        PROGRESS[4].load(Ordering::Acquire) - before[0],
        PROGRESS[6].load(Ordering::Acquire) - before[1],
    ];
    assert!(business[0] > 0 && business[1] > 0);
    put(0, 0x4359584d4c503133);
    put(1, 1);
    put(3, 1);
    put(4, 8);
    put(7, business[0]);
    put(8, business[1]);
    put(9, timer::frequency());
    put(11, 6);
    unsafe {
        put(
            13,
            phys(core::ptr::addr_of!(ROOTS).cast::<Page>().add(3) as u64),
        );
        put(
            14,
            phys(core::ptr::addr_of!(ROOTS).cast::<Page>().add(4) as u64),
        );
    }
    MODEL_V13_EVIDENCE.0[2].store(1, Ordering::Release);
    super::super::log(b"MODEL_V13_READY cases=8 cpu=1\n");
    super::super::halt()
}
