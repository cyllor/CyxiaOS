//! Opt-in native model-service integration. Telemetry windows are declared test
//! inputs; inference, SVC, private address spaces, preemption and handoff are real.
use super::*;
use cyxia_control_model::abi::{self, INPUT_WORDS, Input, OUTPUT_WORDS, Output};
use cyxia_kernel_core::control_plane::image::{BASE, PAGES};
use cyxia_kernel_core::control_plane::{
    Epochs, Identity,
    exchange::Exchange,
    image::Image,
    service::{Config, Decision, Port},
};
const MODEL_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/control-service.elf"));
const MODE: u64 = include!(concat!(env!("OUT_DIR"), "/control-mode.rs"));
#[used]
#[unsafe(no_mangle)]
static CYXIA_AI_PROFILE: [u64; 8] = [1, MODE, INPUT_WORDS as u64, OUTPUT_WORDS as u64, 1, 0, 0, 0];
#[used]
#[unsafe(no_mangle)]
static CONTROL_SERVICE_ELF: [u8; MODEL_ELF.len()] =
    *include_bytes!(concat!(env!("OUT_DIR"), "/control-service.elf"));
#[used]
#[unsafe(no_mangle)]
static CONTROL_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};
static mut IMAGE: [Page; PAGES] = [const { Page::ZERO }; PAGES];
static mut INPUTS: [Page; C] = [const { Page::ZERO }; C];
static mut OUTPUTS: [Page; C] = [const { Page::ZERO }; C];
static mut STACK_PAGES: [Page; C * 8] = [const { Page::ZERO }; C * 8];
static ENTRY: AtomicU64 = AtomicU64::new(0);
static EXCHANGES: [Exchange<INPUT_WORDS, OUTPUT_WORDS>; C] = [const { Exchange::new() }; C];
static REASONS: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static RESTART: [AtomicBool; C] = [const { AtomicBool::new(false) }; C];
static RUNS: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static SLICES: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static ELAPSED: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static USER_ESR: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
static USER_FAR: [AtomicU64; C] = [const { AtomicU64::new(0) }; C];
/// Before any secondary can run, install approved RX/RO code and independent
/// per-service RO snapshot/RW result/guarded stack pages. No kernel page is EL0.
pub(super) unsafe fn init() {
    let image = Image::parse(MODEL_ELF).expect("bounded control ELF");
    unsafe {
        let arena = core::ptr::addr_of_mut!(IMAGE).cast::<u8>();
        for seg in image.segments.iter().take(image.count) {
            let offset = (seg.address - BASE) as usize;
            core::ptr::copy_nonoverlapping(
                image.bytes.as_ptr().add(seg.offset),
                arena.add(offset),
                seg.file_size,
            );
            for slot in 1..C {
                let leaves = &mut *core::ptr::addr_of_mut!(LEAVES)
                    .cast::<Page>()
                    .add(slot * 2 + 1);
                for page in (offset / 4096)..(offset + seg.memory_size).div_ceil(4096) {
                    leaves.0[(BASE / 4096) as usize + page] = mmu::encode_user_leaf(
                        PhysAddr(phys(arena.add(page * 4096) as u64)),
                        false,
                        seg.executable,
                    )
                    .unwrap();
                }
            }
        }
        // Publish generated instructions to the coherency point before any CPU
        // installs them. Each service CPU separately invalidates its I-cache.
        for off in (0..PAGES * 4096).step_by(64) {
            core::arch::asm!("dc cvau, {}",in(reg)arena.add(off),options(nostack));
        }
        core::arch::asm!("dsb ish", options(nostack));
        for slot in 1..C {
            let leaf = &mut *core::ptr::addr_of_mut!(LEAVES)
                .cast::<Page>()
                .add(slot * 2 + 1);
            let input = core::ptr::addr_of_mut!(INPUTS).cast::<Page>().add(slot);
            let output = core::ptr::addr_of_mut!(OUTPUTS).cast::<Page>().add(slot);
            leaf.0[abi::INPUT_VA as usize / 4096] =
                mmu::encode_user_leaf(PhysAddr(phys(input as u64)), false, false).unwrap();
            leaf.0[abi::OUTPUT_VA as usize / 4096] =
                mmu::encode_user_leaf(PhysAddr(phys(output as u64)), true, false).unwrap();
            for n in 0..8 {
                let page = core::ptr::addr_of_mut!(STACK_PAGES)
                    .cast::<Page>()
                    .add(slot * 8 + n);
                leaf.0[0xb1 + n] =
                    mmu::encode_user_leaf(PhysAddr(phys(page as u64)), true, false).unwrap();
            }
        }
    }
    ENTRY.store(image.entry, Ordering::Release);
}
pub(super) fn context() -> user::Context {
    let mut ctx = user::Context::empty();
    ctx.pc = ENTRY.load(Ordering::Acquire);
    ctx.sp = abi::STACK_TOP;
    ctx
}
/// Runs only on an admitted control CPU under its dispatch Permit. No business
/// path invokes this routine. EL0 cannot choose the actor or CPU for submission.
pub(super) fn step(ctx: &mut user::Context) {
    let slot = cpu::slot();
    if RESTART[slot].swap(false, Ordering::AcqRel) {
        *ctx = context();
        unsafe {
            for n in 0..8 {
                (*core::ptr::addr_of_mut!(STACK_PAGES)
                    .cast::<Page>()
                    .add(slot * 8 + n))
                .0
                .fill(0);
            }
            (*core::ptr::addr_of_mut!(OUTPUTS).cast::<Page>().add(slot))
                .0
                .fill(0);
        }
        REASONS[slot].store(0, Ordering::Release);
    }
    if REASONS[slot].load(Ordering::Acquire) != 0 {
        return;
    }
    let Some(work) = EXCHANGES[slot].take() else {
        return;
    };
    unsafe {
        let input = core::ptr::addr_of_mut!(INPUTS).cast::<Page>().add(slot);
        for (i, word) in work.input.iter().enumerate() {
            (*input).0.as_mut_ptr().add(i).write_volatile(*word);
        }
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb", options(nostack));
    }
    let start = timer::ticks();
    // CPU budget is local elapsed service time; it includes each return/copy.
    // A wedged service cannot retain the management worker indefinitely.
    let end = start.checked_add(timer::frequency() / 20).unwrap();
    for _ in 0..8 {
        execute(ctx, slot * 2 + 1);
        SLICES[slot].fetch_add(1, Ordering::Relaxed);
        PROGRESS[slot * 2 + 1].fetch_add(1, Ordering::Release);
        let now = timer::ticks();
        if now >= end || now >= work.input[9] {
            REASONS[slot].store(1, Ordering::Release);
            break;
        }
        if ctx.kind == 9 {
            continue;
        }
        USER_ESR[slot].store(ctx.esr, Ordering::Relaxed);
        USER_FAR[slot].store(ctx.far, Ordering::Relaxed);
        if ctx.kind == 8
            && ctx.esr >> 26 == 0x15
            && ctx.esr & 0xffff == abi::SUBMIT_SVC
            && ctx.regs[0] == abi::OUTPUT_VA
            && ctx.regs[1] == (OUTPUT_WORDS * 8) as u64
        {
            let words = core::array::from_fn(|i| unsafe {
                (*core::ptr::addr_of!(OUTPUTS).cast::<Page>().add(slot))
                    .0
                    .as_ptr()
                    .add(i)
                    .read_volatile()
            });
            RUNS[slot].fetch_add(1, Ordering::Release);
            ELAPSED[slot].fetch_add(now - start, Ordering::Relaxed);
            work.complete(words);
            return;
        }
        REASONS[slot].store(
            if ctx.kind == 8 && ctx.esr >> 26 == 0x15 {
                2
            } else {
                3
            },
            Ordering::Release,
        );
        break;
    }
    if REASONS[slot].load(Ordering::Acquire) == 0 {
        REASONS[slot].store(1, Ordering::Release);
    }
    ELAPSED[slot].fetch_add(timer::ticks() - start, Ordering::Relaxed);
    // Work::drop returns an invalid reply, never an old output. User context
    // remains stopped until authenticated management requests a fresh epoch.
}
fn actor(slot: usize, generation: u64) -> Identity {
    Identity {
        id: 100 + slot as u64,
        generation,
    }
}
fn epochs(o: &Ownership<C>, controller: u64) -> Epochs {
    Epochs {
        boot: 1,
        controller,
        model: 1,
        resources: 1,
        cores: o.snapshot().generation,
    }
}
fn input(o: &Ownership<C>, e: Epochs, high: bool) -> Input {
    let s = o.snapshot();
    let mut f = [0i16; 64];
    f[..4].copy_from_slice(if high {
        &[30000, 30000, 28000, 2000]
    } else {
        &[1000, 1000, 1000, 2000]
    });
    for slot in 0..C {
        for (j, mask) in [s.online, s.control, 2, 1].into_iter().enumerate() {
            f[8 + slot * 7 + j] = if mask & (1 << slot) != 0 { 32767 } else { 0 };
        }
        if s.online & (1 << slot) != 0 {
            f[8 + slot * 7 + 4] = if slot == 2 { 28000 } else { 8000 };
            f[8 + slot * 7 + 5] = 20000;
        }
    }
    Input {
        boot: e.boot,
        controller: e.controller,
        model_epoch: e.model,
        resources: e.resources,
        cores: e.cores,
        sequence: 1,
        window: 1,
        sample_start: 0,
        sampled_at: 1,
        issued: 0,
        expires: 1,
        online: s.online,
        control: s.control,
        protected_control: 2,
        protected_business: 1,
        features: f,
    }
}
fn sample(
    o: &Ownership<C>,
    e: Epochs,
    high: bool,
    sample_state: &mut (u64, u64),
    ticks: u64,
) -> Input {
    let before = sample_state.1;
    wait(|| timer::ticks() - before >= ticks);
    let end = timer::ticks();
    sample_state.0 += 1;
    sample_state.1 = end;
    Input {
        window: sample_state.0,
        sample_start: before,
        sampled_at: end,
        ..input(o, e, high)
    }
}
fn response(slot: usize) -> [u64; OUTPUT_WORDS] {
    let mut reply = None;
    wait(|| {
        reply = EXCHANGES[slot].receive();
        reply.is_some()
    });
    reply.unwrap()
}
fn business_after_stop(
    o: &mut Ownership<C>,
) -> (cyxia_kernel_core::control_plane::cores::Ticket, u64) {
    close_gate(&GATES[1]);
    wait(|| GATES[1].quiescent());
    let ticket = o.fault(1, timer::ticks()).unwrap();
    let stopped = PROGRESS[3].load(Ordering::Acquire);
    let before = PROGRESS[6].load(Ordering::Acquire);
    wait(|| PROGRESS[6].load(Ordering::Acquire) >= before + 8);
    assert_eq!(PROGRESS[3].load(Ordering::Acquire), stopped);
    let delta = PROGRESS[6].load(Ordering::Acquire) - before;
    report(
        "AI_BUSINESS_SURVIVED",
        stopped,
        delta,
        REASONS[1].load(Ordering::Acquire),
    );
    (ticket, delta)
}
pub(super) fn run(mut owner: Ownership<C>) -> ! {
    let config = Config {
        grow_windows: 2,
        shrink_windows: 4,
        high: 24576,
        low: 8192,
        minimum_benefit: 16384,
        dwell_ticks: timer::frequency() / 500,
        request_ticks: timer::frequency() / 2,
        window_ticks: timer::frequency() / 500,
    };
    let mut port = Port::new(actor(1, 1), epochs(&owner, 1), config, timer::ticks()).unwrap();
    let initial = timer::ticks();
    wait(|| timer::ticks() - initial >= config.dwell_ticks);
    let mut transitions = 0u64;
    let mut rejects = 0u64;
    let mut helper = 0u64;
    let mut last = [0; OUTPUT_WORDS];
    let mut records = [[0u64; 16]; 8];
    let mut record_count = 0;
    let mut sampling = (0, timer::ticks());
    let high = true;
    let request = port
        .issue(
            sample(
                &owner,
                port.epochs(),
                high,
                &mut sampling,
                config.window_ticks,
            ),
            timer::ticks(),
        )
        .unwrap();
    EXCHANGES[1].submit(request.encode()).unwrap();
    let words = response(1);
    if MODE != 0 {
        let decision = port.accept(actor(1, 1), 1, words, owner.snapshot(), timer::ticks());
        if MODE == 2 {
            assert_eq!(decision, Err(abi::Error::Denied));
            rejects += 1;
        } else {
            assert!(decision.is_err());
        }
        let (_, progress) = business_after_stop(&mut owner);
        finish(
            &owner,
            transitions,
            rejects,
            helper,
            0,
            progress,
            &records,
            record_count,
        )
    }
    // Six frozen pressure windows feed EL0 inference. Desired sets come only
    // from its model, not the sequencer. Assertions below are test oracles.
    for window in 0..6 {
        let req = if window == 0 {
            request
        } else {
            port.issue(
                sample(
                    &owner,
                    port.epochs(),
                    window < 2,
                    &mut sampling,
                    config.window_ticks,
                ),
                timer::ticks(),
            )
            .unwrap()
        };
        if window != 0 {
            EXCHANGES[1].submit(req.encode()).unwrap();
        }
        let reply = if window == 0 { words } else { response(1) };
        let out = Output::decode(reply).unwrap();
        last = reply;
        if owner.snapshot().control == 6 && helper == 0 {
            EXCHANGES[2].submit(req.encode()).unwrap();
            let assisted = response(2);
            assert_eq!(assisted, reply);
            assert_eq!(
                port.accept(actor(2, 1), 2, assisted, owner.snapshot(), timer::ticks()),
                Err(abi::Error::Denied)
            );
            helper += 1;
            rejects += 1;
            report("AI_HELPER_DENIED_PUBLICATION", 2, req.sequence, 0);
        }
        let before = owner.snapshot().control;
        let verdict = port
            .accept(actor(1, 1), 1, reply, owner.snapshot(), timer::ticks())
            .unwrap();
        if let Decision::Scale(p) = verdict {
            transition_request(&mut owner, p);
            port.published(epochs(&owner, 1), timer::ticks()).unwrap();
            transitions += 1;
        }
        let after = owner.snapshot().control;
        // Provenance event connects input/sequence -> model logit -> approved
        // action -> independent CoreOwner state. Logs alone are not acceptance.
        report("AI_DECISION", req.sequence, out.desired, after);
        let r = &mut records[record_count];
        r[..13].copy_from_slice(&[
            req.sequence,
            req.controller,
            req.cores,
            before,
            out.desired,
            after,
            out.action,
            req.features[0] as u64,
            req.features[1] as u64,
            out.logits[0] as u16 as u64,
            out.logits[1] as u16 as u64,
            out.logits[2] as u16 as u64,
            u64::from(matches!(verdict, Decision::Scale(_))),
        ]);
        r[13..16].copy_from_slice(&[req.window, req.sample_start, req.sampled_at]);
        record_count += 1;
        let start = timer::ticks();
        wait(|| timer::ticks() - start >= config.dwell_ticks);
    }
    assert_eq!(transitions, 2);
    assert_eq!(owner.snapshot().control, 2);
    assert_eq!(helper, 1);
    // Actual service failure: corrupt one snapshot schema in the test transport.
    // EL0 rejects it and traps; EL1 stops that incarnation and quarantines it.
    let next = port
        .issue(
            sample(
                &owner,
                port.epochs(),
                false,
                &mut sampling,
                config.window_ticks,
            ),
            timer::ticks(),
        )
        .unwrap();
    let mut broken = next.encode();
    broken[20] ^= 1;
    EXCHANGES[1].submit(broken).unwrap();
    assert_eq!(response(1), [0; OUTPUT_WORDS]);
    assert_eq!(REASONS[1].load(Ordering::Acquire), 2);
    let (ticket, progress) = business_after_stop(&mut owner);
    owner
        .acknowledge_recovery(ticket, 1, Proof::RECOVERY, timer::ticks())
        .unwrap();
    owner.restore(ticket, timer::ticks(), limits()).unwrap();
    port.restart(actor(1, 2), epochs(&owner, 2), timer::ticks())
        .unwrap();
    RESTART[1].store(true, Ordering::Release);
    GATES[1]
        .open(Token {
            generation: GATES[1].view().token.unwrap().generation + 1,
            plane: Plane::Control,
        })
        .unwrap();
    let new = port
        .issue(
            sample(
                &owner,
                port.epochs(),
                false,
                &mut sampling,
                config.window_ticks,
            ),
            timer::ticks(),
        )
        .unwrap();
    assert_eq!(
        port.accept(actor(1, 2), 1, last, owner.snapshot(), timer::ticks()),
        Err(abi::Error::Stale)
    );
    rejects += 1;
    EXCHANGES[1].submit(new.encode()).unwrap();
    let reply = response(1);
    assert_eq!(
        port.accept(actor(1, 2), 1, reply, owner.snapshot(), timer::ticks()),
        Ok(Decision::Hold)
    );
    report(
        "AI_CONTROLLER_RECOVERED",
        2,
        new.sequence,
        owner.snapshot().generation,
    );
    finish(
        &owner,
        transitions,
        rejects,
        helper,
        1,
        progress,
        &records,
        record_count,
    )
}
#[allow(clippy::too_many_arguments)]
fn finish(
    owner: &Ownership<C>,
    transitions: u64,
    rejects: u64,
    helper: u64,
    recovered: u64,
    progress: u64,
    records: &[[u64; 16]; 8],
    count: usize,
) -> ! {
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(|| (1..REQUIRED).all(|i| GATES[i].quiescent()));
    QUIT.store(true, Ordering::Release);
    wait(|| STOPPED.load(Ordering::Acquire) == 14);
    check_failures();
    let s = owner.snapshot();
    let mut prefix = [0u64; 32];
    prefix[..16].copy_from_slice(&[
        0x4359584149303031,
        1,
        0,
        MODE,
        15,
        14,
        transitions,
        rejects,
        helper,
        recovered,
        progress,
        s.generation,
        s.control,
        s.business,
        s.quarantined,
        count as u64,
    ]);
    prefix[16..20].copy_from_slice(&abi::MODEL_SHA256);
    prefix[20..24].copy_from_slice(&abi::SCHEMA_SHA256);
    for (i, v) in prefix.into_iter().enumerate() {
        CONTROL_EVIDENCE.words[i].store(v, Ordering::Relaxed);
    }
    for slot in 0..REQUIRED {
        let values = [
            RUNS[slot].load(Ordering::Acquire),
            SLICES[slot].load(Ordering::Acquire),
            ELAPSED[slot].load(Ordering::Acquire),
            REASONS[slot].load(Ordering::Acquire),
            PROGRESS[slot * 2].load(Ordering::Acquire),
            PROGRESS[slot * 2 + 1].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
            FAULT_PROBES[slot].load(Ordering::Acquire),
            USER_ESR[slot].load(Ordering::Acquire),
            USER_FAR[slot].load(Ordering::Acquire),
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        for (j, v) in values.into_iter().enumerate() {
            CONTROL_EVIDENCE.words[32 + slot * 16 + j].store(v, Ordering::Relaxed);
        }
        report("AI_CPU_EVIDENCE", slot as u64, values[0], values[6]);
    }
    for (i, record) in records.iter().take(count).enumerate() {
        for (j, v) in record.iter().enumerate() {
            CONTROL_EVIDENCE.words[96 + i * 16 + j].store(*v, Ordering::Relaxed);
        }
    }
    CONTROL_EVIDENCE.words[2].store(1, Ordering::Release);
    super::super::log(b"AI_SCOPE inference=EL0 telemetry=synthetic production_isolation=false physical_isolation=false\n");
    super::super::log(b"AI_CONTROL_PASS cpus=4\n");
    super::super::halt()
}
