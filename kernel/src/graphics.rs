//! VirtIO display mechanism: boot test pattern, fenced blits and raw input.
//! All pools are reserved BOOTSTRAP memory, never labelled as AI allocations.
use super::virtio_platform::Board;
use core::fmt::Write;
use cyxia_ai_runtime::display_policy::{self, Pacer, Phase};
use cyxia_driver_virtio::{
    Error, EventQueue, InputEvent, Platform, Queue, QueueMemory, Transport,
    gpu::{Gpu, HEIGHT, WIDTH},
    input_buffer::{InputBuffer, KEY_BYTES},
};

#[repr(C, align(4096))]
struct Frame([u32; WIDTH * HEIGHT]);
static mut FRAME: Frame = Frame([0; WIDTH * HEIGHT]);
static mut GPU_QUEUE: QueueMemory = QueueMemory::zeroed();
static mut GPU: Option<Gpu> = None;
static mut INPUT_QUEUES: [QueueMemory; 2] = [QueueMemory::zeroed(), QueueMemory::zeroed()];
static mut INPUTS: [Option<Input>; 2] = [None, None];
static mut EVENTS: InputBuffer = InputBuffer::new();
// One pinned CPU-only staging slot, not an AI memory grant. It retains a
// complete accepted rectangle across a model-selected wait without borrowing
// a syscall's temporary buffer or changing the X.Org ABI.
static mut STAGED: [u32; display_policy::MAX_PIXELS] = [0; display_policy::MAX_PIXELS];
static mut RECT: (usize, usize, usize, usize) = (0, 0, 0, 0);
static mut PACER: Pacer = Pacer::new();
struct Input {
    transport: Transport,
    queue: EventQueue,
}

pub fn init(info: &cyxia_contracts::BootInfo) {
    // Called once on CPU0 before interrupts; no other owner accesses these pools.
    super::log(b"GRAPHICS_BEGIN D1 BOOTSTRAP\n");
    let mut gpu_found = false;
    let mut inputs = 0;
    for resource in &info.virtio[..info.virtio_count] {
        // entry.S maps this board-specific 2 MiB Device window. Discovery remains
        // DTB-based, and resources outside the window are never dereferenced.
        if resource.base.0 < 0x0a000000
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|end| end > 0x0a200000)
        {
            continue;
        }
        let transport = unsafe {
            Transport::attach(
                (super::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        };
        let Ok(mut transport) = transport else {
            continue;
        };
        match transport.device_id() {
            16 if !gpu_found => {
                gpu_found = true;
                let result = (|| {
                    transport.negotiate(&Board)?;
                    let memory = unsafe { &mut *core::ptr::addr_of_mut!(GPU_QUEUE) };
                    let queue = Queue::configure(&mut transport, memory, 0, &Board)?;
                    transport.start(&Board)?;
                    let mut gpu = Gpu::new(transport, queue)?;
                    let frame = unsafe { &mut *core::ptr::addr_of_mut!(FRAME) };
                    // Eight exact colour bars make host pixel validation independent
                    // of any future desktop widget implementation.
                    let colors = [
                        0x00ffffff, 0x00ffff00, 0x0000ffff, 0x0000ff00, 0x00ff00ff, 0x00ff0000,
                        0x000000ff, 0,
                    ];
                    for (i, pixel) in frame.0.iter_mut().enumerate() {
                        *pixel = colors[(i % WIDTH) * 8 / WIDTH];
                    }
                    unsafe {
                        gpu.show(core::ptr::addr_of!(FRAME) as usize, &Board)?;
                    }
                    Ok::<Gpu, Error>(gpu)
                })();
                match result {
                    Ok(gpu) => {
                        // CPU0's foreground owns this handle from now on. FRAME
                        // may only be borrowed through Gpu::submit_update after show.
                        unsafe { *core::ptr::addr_of_mut!(GPU) = Some(gpu) };
                        super::log(b"GRAPHICS_FRAME_OK 1024x768 BOOTSTRAP\n");
                    }
                    Err(error) => {
                        super::log(b"GRAPHICS_GPU_ERROR BOOTSTRAP\n");
                        super::hex(error as u64);
                    }
                }
            }
            18 if inputs < 2 => {
                let slot = inputs;
                inputs += 1;
                let result = (|| {
                    transport.negotiate(&Board)?;
                    let memory = unsafe { &mut (*core::ptr::addr_of_mut!(INPUT_QUEUES))[slot] };
                    let queue = Queue::configure(&mut transport, memory, 0, &Board)?;
                    transport.start(&Board)?;
                    let queue = EventQueue::prime(queue, &mut transport, &Board)?;
                    unsafe {
                        (*core::ptr::addr_of_mut!(INPUTS))[slot] = Some(Input { transport, queue });
                    }
                    Ok::<(), Error>(())
                })();
                match result {
                    Ok(()) => super::log(b"GRAPHICS_INPUT_READY BOOTSTRAP\n"),
                    Err(_) => super::log(b"GRAPHICS_INPUT_ERROR BOOTSTRAP\n"),
                }
            }
            _ => {}
        }
    }
    if !gpu_found {
        super::log(b"GRAPHICS_NO_GPU BOOTSTRAP\n");
    }
}

/// Copy a tightly packed BGRX rectangle and submit its transfer without waiting.
/// Success only means queued: the caller must retain request ownership and wait
/// for `poll_blit` before reporting success to an application. Busy submissions
/// do not borrow or modify the frame or staging slot. The bounded local display
/// model establishes a one-shot 0/1 ms pacing decision before hardware access.
/// Pixel placement, fence completion and input routing remain mechanisms.
///
/// CPU0 foreground calls only, after init. IRQ handlers and other CPUs must not
/// call this function or access GPU/FRAME. User pointers must already have been
/// copied into a kernel-owned buffer; pixels must not alias the DMA backing.
pub fn begin_blit(
    owner: u32,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    pixels: &[u32],
) -> Result<(), Error> {
    if width == 0
        || height == 0
        || x.checked_add(width).is_none_or(|right| right > WIDTH)
        || y.checked_add(height).is_none_or(|bottom| bottom > HEIGHT)
        || width.checked_mul(height) != Some(pixels.len())
        || pixels.len() > display_policy::MAX_PIXELS
    {
        return Err(Error::Address);
    }
    if unsafe { &*core::ptr::addr_of!(GPU) }.is_none() {
        return Err(Error::Device);
    }
    // No GPU/queue borrow is held during inference. CPU0 foreground is the
    // only owner, so the validated snapshot cannot race another admission.
    let pacer = unsafe { &mut *core::ptr::addr_of_mut!(PACER) };
    let now = Board.now_ms();
    pacer
        .admit(owner, pixels.len(), now)
        .map_err(|error| match error {
            display_policy::Error::Busy => Error::Busy,
            display_policy::Error::Invalid => Error::Address,
            display_policy::Error::Exhausted => Error::Exhausted,
            _ => Error::Timeout,
        })?;
    // A committed plan owns the only staging slot through completion, even if
    // the originating process dies. Subsequent calls cannot replace it.
    unsafe {
        let staged = &mut *core::ptr::addr_of_mut!(STAGED);
        staged[..pixels.len()].copy_from_slice(pixels);
        *core::ptr::addr_of_mut!(RECT) = (x, y, width, height);
    }
    if pacer.ready(now) {
        submit_staged()?;
    }
    Ok(())
}

/// Submit the sole admitted rectangle. The pacing decision has already run;
/// copying pixels and issuing the exact GPU protocol are deterministic work.
fn submit_staged() -> Result<(), Error> {
    let pacer = unsafe { &mut *core::ptr::addr_of_mut!(PACER) };
    let now = Board.now_ms();
    if !pacer.ready(now) {
        return Err(Error::Busy);
    }
    let (x, y, width, height) = unsafe { *core::ptr::addr_of!(RECT) };
    let pixels = unsafe { &*core::ptr::addr_of!(STAGED) };
    // SAFETY: the single CPU foreground serializes all calls. No IRQ handler
    // touches these statics. Gpu guards CPU access against in-flight DMA.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(GPU) };
    let Some(gpu) = slot.as_mut() else {
        let _ = pacer.finish(now, false);
        return Err(Error::Device);
    };
    let result = gpu.submit_update(
        |frame| {
            for row in 0..height {
                let destination = (y + row) * WIDTH + x;
                let source = row * width;
                frame[destination..destination + width]
                    .copy_from_slice(&pixels[source..source + width]);
            }
        },
        &Board,
    );
    if result.is_err() {
        // Driver errors quarantine the device. Dropping the handle here does
        // not release FRAME or GPU_QUEUE: their static pages remain reserved.
        *slot = None;
        let _ = pacer.finish(Board.now_ms(), false);
        super::log(b"GRAPHICS_UPDATES_STOPPED MECHANISM\n");
    } else if pacer.submitted(now).is_err() {
        // An internal receipt invariant failed after DMA acceptance. Keep DMA
        // memory pinned, quarantine the handle, and report failure, never reuse.
        *slot = None;
        let _ = pacer.finish(Board.now_ms(), false);
        return Err(Error::Device);
    }
    result
}

/// CPU0 foreground only. Returns one completion for the outstanding blit, or
/// None when idle/pending. Each call checks at most one response and may queue
/// the next phase; it never waits for GPU progress. Even if an application dies,
/// the caller must keep polling until this completes so DMA ownership is settled.
pub fn poll_blit() -> Option<Result<(), Error>> {
    let status = unsafe { &*core::ptr::addr_of!(PACER) }.status();
    if status.phase == Phase::Queued {
        if !unsafe { &*core::ptr::addr_of!(PACER) }.ready(Board.now_ms()) {
            return None;
        }
        return match submit_staged() {
            Ok(()) => None,
            Err(error) => Some(Err(error)),
        };
    }
    if status.phase != Phase::Submitted {
        return None;
    }
    // SAFETY: same sole foreground ownership as begin_blit; no IRQ accesses GPU.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(GPU) };
    let gpu = slot.as_mut()?;
    match gpu.poll_update(&Board) {
        Ok(false) => None,
        Ok(true) => {
            let pacer = unsafe { &mut *core::ptr::addr_of_mut!(PACER) };
            if pacer.finish(Board.now_ms(), true).is_err() {
                *slot = None;
                let _ = pacer.finish(Board.now_ms(), false);
                Some(Err(Error::Device))
            } else {
                Some(Ok(()))
            }
        }
        Err(error) => {
            // FAILED is not a reset acknowledgement. Neither DMA pool is reused.
            *slot = None;
            let _ = unsafe { &mut *core::ptr::addr_of_mut!(PACER) }.finish(Board.now_ms(), false);
            super::log(b"GRAPHICS_UPDATES_STOPPED MECHANISM\n");
            Some(Err(error))
        }
    }
}

/// Foreground-only bounded aggregate/last-receipt view. It contains no pixels,
/// keystrokes or motion payload. A proposal is not counted as hardware success.
pub fn ai_status(out: &mut impl Write) {
    let s = unsafe { &*core::ptr::addr_of!(PACER) }.status();
    let available = unsafe { &*core::ptr::addr_of!(GPU) }.is_some();
    let _ = writeln!(
        out,
        "AI_DOMAIN name=display available={} phase={:?} scope=submit_pacing model={} version={} proposals={} admitted={} ai_admitted={} guard_admitted={} submitted={} completed={} failed={} busy={} policy_invalid={} clock_rejected={} guards={} delayed={} planned_wait_ms={} actual_queue_ms={} max_queue_ms={} last_fence_ms={} max_fence_ms={} staging_bytes=65536 staging_source=BOOTSTRAP learning=fixed_feedback\r",
        available,
        s.phase,
        display_policy::MODEL,
        display_policy::VERSION,
        s.proposals,
        s.admitted,
        s.ai_admitted,
        s.guard_admitted,
        s.submitted,
        s.completed,
        s.failed,
        s.busy,
        s.invalid,
        s.clock_rejected,
        s.guards,
        s.delayed,
        s.planned_wait_ms,
        s.actual_queue_ms,
        s.max_queue_ms,
        s.fence_ms,
        s.max_fence_ms
    );
    if let Some(p) = s.latest {
        let _ = writeln!(
            out,
            "AI_DISPLAY_RECEIPT id={} owner={} model={} proposed_model={} version={} source={} pixels={} accepted_at={} ready_at={} delay_ms={} score={} observed_fence_ms={} observed_completed={} phase={:?} outcome={:?}\r",
            p.id,
            p.owner,
            if p.source == cyxia_contracts::DecisionSource::AiDirect {
                display_policy::MODEL
            } else {
                0
            },
            display_policy::MODEL,
            display_policy::VERSION,
            if p.source == cyxia_contracts::DecisionSource::AiDirect {
                "AI_DIRECT"
            } else {
                "SAFETY_GUARD"
            },
            p.pixels,
            p.accepted_at,
            p.ready_at,
            p.delay_ms,
            p.score,
            p.observed_fence_ms,
            p.observed_completed,
            s.phase,
            s.outcome
        );
    }
}

/// Current fixed scanout geometry. CPU0 foreground only; no IRQ accesses GPU.
pub fn info() -> Result<(u32, u32), Error> {
    // SAFETY: foreground owns the handle and cannot concurrently submit/poll it.
    if unsafe { &*core::ptr::addr_of!(GPU) }.is_none() {
        return Err(Error::Device);
    }
    Ok((WIDTH as u32, HEIGHT as u32))
}

/// Drain at most 32 merged eight-byte input events. Busy means an empty queue.
/// Sources share one stream; SYN_REPORT records from both devices are retained.
/// After SYN_DROPPED + SYN_REPORT, obtain key_state to avoid stuck keys/buttons.
/// Relative motion lost on overflow is not reconstructed. CPU0 foreground only.
pub fn read_events(out: &mut [InputEvent]) -> Result<usize, Error> {
    // SAFETY: input polling and syscall dispatch are serialized on CPU0. No IRQ
    // handler or DMA engine reads/writes this software-owned buffer.
    let events = unsafe { &mut *core::ptr::addr_of_mut!(EVENTS) };
    if events.is_empty()
        && unsafe { &*core::ptr::addr_of!(INPUTS) }
            .iter()
            .all(Option::is_none)
    {
        return Err(Error::Device);
    }
    events.read(out)
}

/// Current merged EV_KEY state, 768 bits, least significant bit first per byte.
/// It remains queryable after a device error so cleared keys can be recovered.
/// CPU0 foreground only, serialized with poll and read_events.
pub fn key_state(out: &mut [u8; KEY_BYTES]) {
    // SAFETY: this foreground-only copy does not overlap any input mutation.
    unsafe { &*core::ptr::addr_of!(EVENTS) }.key_state(out);
}

pub fn poll() {
    // CPU0 foreground sole owner; IRQ handlers never inspect device queues.
    let inputs = unsafe { &mut *core::ptr::addr_of_mut!(INPUTS) };
    let events = unsafe { &mut *core::ptr::addr_of_mut!(EVENTS) };
    for (source, entry) in inputs.iter_mut().enumerate() {
        let Some(input) = entry else {
            continue;
        };
        match input.queue.poll(&mut input.transport, &Board) {
            Ok(Some(event)) => {
                if event.kind == 1 || event.kind == 2 {
                    super::log(b"GRAPHICS_INPUT_EVENT MECHANISM\n");
                    super::hex(
                        (u64::from(event.kind) << 48)
                            | (u64::from(event.code) << 32)
                            | u64::from(event.value as u32),
                    );
                }
                if events.push(source, event) == Ok(true) {
                    super::log(b"GRAPHICS_INPUT_DROPPED MECHANISM\n");
                }
            }
            Ok(None) => {}
            Err(_) => {
                input.transport.fail();
                *entry = None;
                // Preserve a visible loss record and release this device's
                // known keys. Pending DMA storage itself remains quarantined.
                let _ = events.disconnect(source);
                super::log(b"GRAPHICS_INPUT_STOPPED MECHANISM\n");
            }
        }
    }
}
