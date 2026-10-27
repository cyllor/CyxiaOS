use core::arch::asm;
use cyxia_prototype_cluster::abi::*;
const SERVICE_FAULT: u64 = include!(concat!(env!("OUT_DIR"), "/service-fault.rs"));
fn page() -> *mut Shared {
    SHARED_VA as *mut Shared
}
pub fn clock_ns() -> u64 {
    unsafe { core::ptr::addr_of!((*page()).monotonic_ns).read_volatile() }
}
pub fn domains() -> DomainInput {
    unsafe { core::ptr::addr_of!((*page()).domains).read_volatile() }
}
pub fn domain_feedback(feedback: DomainFeedback) {
    unsafe {
        let shared = page();
        let sequence = core::ptr::addr_of_mut!((*shared).feedback_sequence);
        let base = sequence.read_volatile() & !1;
        let Some(completed) = base.checked_add(2) else {
            return;
        };
        sequence.write_volatile(base + 1);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        asm!("dmb ish", options(nostack, preserves_flags));
        core::ptr::addr_of_mut!((*shared).domain_feedback).write_volatile(feedback);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        asm!("dmb ish", options(nostack, preserves_flags));
        sequence.write_volatile(completed);
    }
}
pub fn boot() -> (u64, [u8; 16], [u8; 32], [u8; 32]) {
    let p = page();
    unsafe {
        if core::ptr::addr_of!((*p).magic).read_volatile() != MAGIC
            || core::ptr::addr_of!((*p).version).read_volatile() != VERSION
        {
            fatal(0xfe);
        }
        (
            core::ptr::addr_of!((*p).boot_epoch).read_volatile(),
            core::ptr::addr_of!((*p).uuid).read_volatile(),
            core::ptr::addr_of!((*p).local_node).read_volatile(),
            core::ptr::addr_of!((*p).peer_node).read_volatile(),
        )
    }
}
pub fn service_generation() -> u64 {
    unsafe { core::ptr::addr_of!((*page()).service_generation).read_volatile() }
}
pub fn request(
    op: u64,
    input: &[u8],
    output: &mut [u8],
    offset: u64,
    args: [u64; 3],
) -> Result<(usize, u64), u64> {
    let len = input.len().max(output.len());
    if !valid_request(op, len as u64, offset) {
        return Err(FAILED);
    }
    let p = page();
    unsafe {
        core::ptr::addr_of_mut!((*p).op).write_volatile(op);
        core::ptr::addr_of_mut!((*p).len).write_volatile(len as u64);
        core::ptr::addr_of_mut!((*p).offset).write_volatile(offset);
        core::ptr::addr_of_mut!((*p).arg0).write_volatile(args[0]);
        core::ptr::addr_of_mut!((*p).arg1).write_volatile(args[1]);
        core::ptr::addr_of_mut!((*p).arg2).write_volatile(args[2]);
        core::ptr::addr_of_mut!((*p).status).write_volatile(FAILED);
        let seq = core::ptr::addr_of!((*p).sequence)
            .read_volatile()
            .wrapping_add(1);
        core::ptr::addr_of_mut!((*p).sequence).write_volatile(seq);
        let bytes = core::ptr::addr_of_mut!((*p).payload).cast::<u8>();
        for (i, b) in input.iter().enumerate() {
            bytes.add(i).write_volatile(*b);
        }
        asm!("svc #0x43", clobber_abi("C"), options(nostack));
        if core::ptr::addr_of!((*p).sequence).read_volatile() != seq {
            return Err(FAILED);
        }
        let status = core::ptr::addr_of!((*p).status).read_volatile();
        if status != OK {
            return Err(status);
        }
        let n = core::ptr::addr_of!((*p).len).read_volatile() as usize;
        if n > len || n > PAYLOAD {
            return Err(FAILED);
        }
        for (i, b) in output.iter_mut().take(n).enumerate() {
            *b = bytes.add(i).read_volatile();
        }
        Ok((n, core::ptr::addr_of!((*p).arg0).read_volatile()))
    }
}
pub fn entropy(out: &mut [u8]) -> Result<(), u64> {
    for chunk in out.chunks_mut(PAYLOAD) {
        let (n, _) = request(OP_ENTROPY, &[], chunk, 0, [0; 3])?;
        if n != chunk.len() {
            out.fill(0);
            return Err(FAILED);
        }
    }
    Ok(())
}
pub fn time() -> Option<(u64, u64)> {
    request(OP_TIME, &[], &mut [], 0, [0; 3]).ok()?;
    let p = page();
    unsafe {
        Some((
            core::ptr::addr_of!((*p).monotonic_ms).read_volatile(),
            core::ptr::addr_of!((*p).unix_seconds).read_volatile(),
        ))
    }
}
pub fn poll() -> Result<(bool, u64), u64> {
    let (_, connected) = request(OP_POLL, &[], &mut [], 0, [0; 3])?;
    Ok((connected == 1, unsafe {
        core::ptr::addr_of!((*page()).connection_epoch).read_volatile()
    }))
}
pub fn trace(event: u64) {
    let _ = request(OP_TRACE, &[], &mut [], 0, [event, 0, 0]);
    if service_fault_due(SERVICE_FAULT, service_generation(), event) {
        // BRK is a genuine synchronous EL0 exception. The supervisor must
        // retire this context and must never return to this instruction.
        unsafe { asm!("brk #0", options(noreturn, nostack)) }
    }
}
pub fn yield_now() {
    let _ = request(OP_YIELD, &[], &mut [], 0, [0; 3]);
}
pub fn close() {
    let _ = request(OP_CLOSE, &[], &mut [], 0, [0; 3]);
}
pub fn fatal(code: u64) -> ! {
    trace(TRACE_FATAL_BIT | code);
    loop {
        yield_now();
    }
}
