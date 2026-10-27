//! Bounded EL0 file capabilities. CPU0 delivers receipts after actual operations.
//! A copyout retry re-delivers a retained result; it never replays a disk effect.
#[path = "../../user/prototype-task/files_abi.rs"]
pub mod abi;
use crate::{domain_storage as storage, domain_tasks};
use abi::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_arch_aarch64::user::Context;
use cyxia_prototype::{
    domains::{
        Error, ObjectKey,
        filesystem::{Handle, OpenMode, Stat},
    },
    storage::InodeKind,
};
#[derive(Clone, Copy)]
struct Grant {
    owner: ObjectKey,
    cap: ObjectKey,
    rights: u16,
    last_request: u64,
}
#[derive(Clone, Copy)]
struct Open {
    owner: ObjectKey,
    cap: ObjectKey,
    file: Handle,
    object: ObjectKey,
    readable: bool,
}
struct Delivery {
    owner: ObjectKey,
    address: u64,
    frame: Frame,
    data_address: u64,
    data_len: usize,
    capture_len: usize,
    capture_misses: u64,
    capture_io: Option<[u64; 4]>,
}
static BUSY: AtomicBool = AtomicBool::new(false);
static PENDING_ID: AtomicU64 = AtomicU64::new(0);
static PENDING_GENERATION: AtomicU64 = AtomicU64::new(0);
static mut GRANTS: [Option<Grant>; 64] = [None; 64];
static mut HANDLES: [Option<Open>; 64] = [None; 64];
static mut GENERATION: u64 = 0;
static mut DATA: [u8; MAX_IO] = [0; MAX_IO];
static mut PENDING: Option<Delivery> = None;
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}
fn acquire() -> Result<Guard, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    Ok(Guard)
}
fn generation() -> Result<u64, Error> {
    let epoch = crate::prototype_storage::identity()
        .ok_or(Error::NotReady)?
        .epoch;
    unsafe {
        GENERATION = GENERATION
            .checked_add(1)
            .filter(|v| *v <= u64::from(u32::MAX))
            .ok_or(Error::Overflow)?;
        epoch
            .checked_mul(1u64 << 32)
            .and_then(|v| v.checked_add(GENERATION))
            .ok_or(Error::Overflow)
    }
}
pub fn grant(owner: ObjectKey, rights: u16) -> Result<ObjectKey, Error> {
    let _guard = acquire()?;
    if owner.id == 0 || owner.generation == 0 || rights == 0 || rights & !ALL_RIGHTS != 0 {
        return Err(Error::Auth);
    }
    let grants = unsafe { &mut *core::ptr::addr_of_mut!(GRANTS) };
    if let Some(g) = grants.iter().flatten().find(|g| g.owner == owner) {
        return if g.rights == rights {
            Ok(g.cap)
        } else {
            Err(Error::Conflict)
        };
    }
    let at = grants
        .iter()
        .position(Option::is_none)
        .ok_or(Error::Capacity)?;
    let cap = ObjectKey {
        id: at as u64 + 1,
        generation: generation()?,
    };
    grants[at] = Some(Grant {
        owner,
        cap,
        rights,
        last_request: 0,
    });
    Ok(cap)
}
pub fn pending_delivery(owner: ObjectKey) -> bool {
    PENDING_ID.load(Ordering::Acquire) == owner.id
        && PENDING_GENERATION.load(Ordering::Acquire) == owner.generation
}
fn clear_pending() {
    unsafe {
        *core::ptr::addr_of_mut!(PENDING) = None;
    }
    PENDING_ID.store(0, Ordering::Release);
    PENDING_GENERATION.store(0, Ordering::Relaxed);
}
pub fn exit(owner: ObjectKey) -> Result<(), Error> {
    let _guard = acquire()?;
    let handles = unsafe { &mut *core::ptr::addr_of_mut!(HANDLES) };
    for h in handles {
        if h.is_some_and(|h| h.owner == owner) {
            storage::close(h.unwrap().file)?;
            *h = None;
        }
    }
    let grants = unsafe { &mut *core::ptr::addr_of_mut!(GRANTS) };
    for g in grants {
        if g.is_some_and(|g| g.owner == owner) {
            *g = None;
        }
    }
    if pending_delivery(owner) {
        clear_pending();
    }
    Ok(())
}
fn errno(e: Error) -> i64 {
    match e {
        Error::Auth => -13,
        Error::Stale => -116,
        Error::Capacity => -28,
        Error::Budget | Error::Again => -11,
        Error::Busy => -16,
        Error::NotFound => -2,
        Error::Exists => -17,
        Error::NotDirectory => -20,
        Error::IsDirectory => -21,
        Error::NotEmpty => -39,
        Error::Io => -5,
        Error::Overflow => -75,
        Error::Expired => -110,
        Error::NotReady => -19,
        Error::Unsupported => -38,
        _ => -22,
    }
}
fn retryable_before_run(e: Error) -> bool {
    matches!(e, Error::Busy | Error::Again | Error::NotReady)
}
fn handle(owner: ObjectKey, frame: &Frame) -> Result<(usize, Open), Error> {
    let cap = ObjectKey {
        id: frame.u64(OFF_HANDLE_ID),
        generation: frame.u64(OFF_HANDLE_GENERATION),
    };
    let at =
        usize::try_from(cap.id.checked_sub(1).ok_or(Error::Stale)?).map_err(|_| Error::Stale)?;
    let h = unsafe { (*core::ptr::addr_of!(HANDLES)).get(at).copied().flatten() }
        .filter(|h| h.owner == owner && h.cap == cap)
        .ok_or(Error::Stale)?;
    Ok((at, h))
}
fn object(frame: &mut Frame, key: ObjectKey) {
    frame.set_u64(OFF_OBJECT_ID, key.id);
    frame.set_u64(OFF_OBJECT_GENERATION, key.generation);
}
fn stat_result(frame: &mut Frame, s: Stat) {
    object(frame, s.object);
    frame.set_u64(OFF_COUNT, s.size);
    frame.set_u16(OFF_MODE, if s.kind == InodeKind::File { 1 } else { 2 });
    frame.set_u64(OFF_WRITE_SEQ, s.write_seq);
    frame.set_u64(OFF_DURABLE_SEQ, s.durable_write_seq);
}
fn authorize(owner: ObjectKey, f: &Frame) -> Result<usize, Error> {
    let cap = ObjectKey {
        id: f.u64(OFF_AUTH_ID),
        generation: f.u64(OFF_AUTH_GENERATION),
    };
    let at = usize::try_from(cap.id.checked_sub(1).ok_or(Error::Auth)?).map_err(|_| Error::Auth)?;
    let g = unsafe { (*core::ptr::addr_of!(GRANTS)).get(at).copied().flatten() }
        .filter(|g| g.owner == owner && g.cap == cap)
        .ok_or(Error::Auth)?;
    if f.u64(OFF_REQUEST) == 0 || f.u64(OFF_REQUEST) <= g.last_request {
        return Err(Error::Stale);
    }
    let required = match f.u16(OFF_OPERATION) {
        CREATE | MKDIR => RIGHT_CREATE,
        READ | READDIR | STAT | GET_STAT_CAP => RIGHT_READ,
        WRITE | FSYNC => RIGHT_WRITE,
        UNLINK => RIGHT_DELETE,
        CLOSE => 0,
        OPEN => match f.u16(OFF_MODE) {
            MODE_READ | MODE_DIRECTORY => RIGHT_READ,
            MODE_WRITE => RIGHT_WRITE,
            MODE_READ_WRITE => RIGHT_READ | RIGHT_WRITE,
            _ => return Err(Error::Format),
        },
        _ => return Err(Error::Unsupported),
    };
    if g.rights & required != required {
        return Err(Error::Auth);
    }
    Ok(at)
}
fn validate_shape(address: u64, f: &Frame) -> Result<(), Error> {
    if f.u64(OFF_MAGIC) != MAGIC
        || f.u16(OFF_VERSION) != VERSION
        || usize::from(f.u16(OFF_LENGTH)) != FRAME_BYTES
        || f.u16(OFF_FLAGS) != 0
    {
        return Err(Error::Format);
    }
    let path = usize::from(f.u16(OFF_PATH_LENGTH));
    if path > PATH_BYTES || f.bytes[OFF_PATH + path..].iter().any(|b| *b != 0) {
        return Err(Error::Format);
    }
    let op = f.u16(OFF_OPERATION);
    if matches!(op, CREATE | OPEN | MKDIR | UNLINK | STAT) {
        if path == 0 {
            return Err(Error::Format);
        }
        core::str::from_utf8(&f.bytes[OFF_PATH..OFF_PATH + path]).map_err(|_| Error::Format)?;
    } else if path != 0 {
        return Err(Error::Format);
    }
    let len = f.u32(OFF_DATA_LENGTH) as usize;
    if len > MAX_IO {
        return Err(Error::Range);
    }
    let uses_data = matches!(op, READ | WRITE | READDIR);
    if !uses_data && (len != 0 || f.u64(OFF_DATA) != 0) {
        return Err(Error::Format);
    }
    if op == READDIR && len < DIRENT_BYTES {
        return Err(Error::Range);
    }
    if uses_data && len != 0 {
        let data = f.u64(OFF_DATA);
        let end = data.checked_add(len as u64).ok_or(Error::Range)?;
        let frame_end = address
            .checked_add(FRAME_BYTES as u64)
            .ok_or(Error::Range)?;
        if data < frame_end && address < end {
            return Err(Error::Format);
        }
    }
    Ok(())
}
fn validate(owner: ObjectKey, address: u64, f: &Frame) -> Result<(), Error> {
    validate_shape(address, f)?;
    domain_tasks::probe_user(owner, address, FRAME_BYTES, true)?;
    let op = f.u16(OFF_OPERATION);
    let len = f.u32(OFF_DATA_LENGTH) as usize;
    if matches!(op, READ | WRITE | READDIR) && len != 0 {
        domain_tasks::probe_user(owner, f.u64(OFF_DATA), len, op != WRITE)?;
    }
    Ok(())
}
/// Only stopped, pending file requests can compete with background disk work.
/// Inspect immutable copied frames and loaded inode/cache metadata; this does
/// not run requests, consume request IDs, create handles, or issue disk I/O.
pub(crate) fn pending_block_demand() -> Result<bool, Error> {
    let _guard = acquire()?;
    let requests = domain_tasks::pending_file_requests()?;
    for (owner, address) in requests.into_iter().flatten() {
        if pending_delivery(owner) {
            continue;
        }
        let mut frame = Frame {
            bytes: [0; FRAME_BYTES],
        };
        let demand = (|| {
            domain_tasks::copyin(owner, address, &mut frame.bytes)?;
            validate_shape(address, &frame)?;
            authorize(owner, &frame)?;
            let offset = frame.u64(OFF_OFFSET);
            let length = frame.u32(OFF_DATA_LENGTH) as usize;
            match frame.u16(OFF_OPERATION) {
                // These real implementations refresh reserved metadata before
                // pathname resolution, including a lookup of the root itself.
                OPEN | STAT => Ok(true),
                READ => storage::read_io_demand(handle(owner, &frame)?.1.file, offset, length),
                WRITE => storage::write_io_demand(handle(owner, &frame)?.1.file, offset, length),
                READDIR => storage::readdir_io_demand(handle(owner, &frame)?.1.file),
                // Close, capability/stat-by-cap, and cache-only writes do no
                // ordinary I/O. fsync/create/unlink use the separate Recovery path.
                _ => Ok(false),
            }
        })();
        match demand {
            Ok(true) => return Ok(true),
            Err(error @ (Error::Busy | Error::Again | Error::NotReady)) => return Err(error),
            Ok(false) | Err(_) => (), // Rejected/stale calls cannot require a block grant.
        }
    }
    Ok(false)
}
fn run(
    owner: ObjectKey,
    input: &Frame,
    out: &mut Frame,
    data: &mut [u8],
    progress: &mut dyn FnMut(),
) -> Result<usize, Error> {
    let path_len = usize::from(input.u16(OFF_PATH_LENGTH));
    let path = core::str::from_utf8(&input.bytes[OFF_PATH..OFF_PATH + path_len])
        .map_err(|_| Error::Format)?;
    let length = input.u32(OFF_DATA_LENGTH) as usize;
    let offset = input.u64(OFF_OFFSET);
    match input.u16(OFF_OPERATION) {
        CREATE => {
            object(out, storage::create(path, progress)?);
        }
        MKDIR => {
            object(out, storage::mkdir(path, progress)?);
        }
        OPEN => {
            let mode = match input.u16(OFF_MODE) {
                MODE_READ => OpenMode::Read,
                MODE_WRITE => OpenMode::Write,
                MODE_READ_WRITE => OpenMode::ReadWrite,
                MODE_DIRECTORY => OpenMode::Directory,
                _ => return Err(Error::Format),
            };
            let at = unsafe {
                (&*core::ptr::addr_of!(HANDLES))
                    .iter()
                    .position(Option::is_none)
            }
            .ok_or(Error::Capacity)?;
            let cap = ObjectKey {
                id: at as u64 + 1,
                generation: generation()?,
            };
            let file = storage::open(path, mode, progress)?;
            let key = match storage::handle_object(file) {
                Ok(k) => k,
                Err(e) => {
                    let _ = storage::close(file);
                    return Err(e);
                }
            };
            unsafe {
                (*core::ptr::addr_of_mut!(HANDLES))[at] = Some(Open {
                    owner,
                    cap,
                    file,
                    object: key,
                    readable: matches!(
                        mode,
                        OpenMode::Read | OpenMode::ReadWrite | OpenMode::Directory
                    ),
                });
            }
            out.set_u64(OFF_HANDLE_ID, cap.id);
            out.set_u64(OFF_HANDLE_GENERATION, cap.generation);
            object(out, key);
        }
        READ => {
            let (_, h) = handle(owner, input)?;
            let n = storage::read(h.file, offset, &mut data[..length], progress)?;
            out.set_u64(OFF_COUNT, n as u64);
            object(out, h.object);
            return Ok(n);
        }
        WRITE => {
            let (_, h) = handle(owner, input)?;
            let n = storage::write(h.file, offset, &data[..length], progress)?;
            out.set_u64(OFF_COUNT, n as u64);
            object(out, h.object);
        }
        FSYNC => {
            let (_, h) = handle(owner, input)?;
            let receipt = storage::fsync(h.file, progress)?;
            object(out, receipt.object);
            out.set_u64(OFF_WRITE_SEQ, receipt.write_seq);
            out.set_u64(OFF_DURABLE_SEQ, receipt.write_seq);
        }
        CLOSE => {
            let (at, h) = handle(owner, input)?;
            storage::close(h.file)?;
            unsafe {
                (*core::ptr::addr_of_mut!(HANDLES))[at] = None;
            }
        }
        READDIR => {
            let (_, h) = handle(owner, input)?;
            let cookie = u16::try_from(offset).map_err(|_| Error::Range)?;
            if let Some(entry) = storage::readdir(h.file, cookie, progress)? {
                data[..DIRENT_BYTES].fill(0);
                data[..8].copy_from_slice(&entry.object.id.to_le_bytes());
                data[8..16].copy_from_slice(&entry.object.generation.to_le_bytes());
                data[16..18].copy_from_slice(
                    &(if entry.kind == InodeKind::File {
                        1u16
                    } else {
                        2
                    })
                    .to_le_bytes(),
                );
                data[18..20].copy_from_slice(&u16::from(entry.name_len).to_le_bytes());
                data[20..24].copy_from_slice(&u32::from(entry.next_cookie).to_le_bytes());
                data[24..24 + usize::from(entry.name_len)]
                    .copy_from_slice(&entry.name[..usize::from(entry.name_len)]);
                out.set_u64(OFF_COUNT, 1);
                return Ok(DIRENT_BYTES);
            }
        }
        UNLINK => storage::unlink(path, progress)?,
        STAT => stat_result(out, storage::stat(path, progress)?),
        GET_STAT_CAP => {
            let (_, h) = handle(owner, input)?;
            if !h.readable {
                return Err(Error::Auth);
            }
            let cap = domain_tasks::grant_file_cap(owner, h.object)?;
            out.set_u64(OFF_COUNT, cap);
            object(out, h.object);
        }
        _ => return Err(Error::Unsupported),
    }
    Ok(0)
}
fn deliver(owner: ObjectKey, context: &mut Context) -> Result<(), Error> {
    let pending = unsafe { (&*core::ptr::addr_of!(PENDING)).as_ref() }.ok_or(Error::NotReady)?;
    if pending.owner != owner || context.regs[1] != pending.address {
        return Err(Error::Busy);
    }
    if pending.data_len != 0 {
        let bytes = unsafe { &*core::ptr::addr_of!(DATA) };
        domain_tasks::copyout(owner, pending.data_address, &bytes[..pending.data_len])?;
    }
    domain_tasks::copyout(owner, pending.address, &pending.frame.bytes)?;
    context.regs[0] = pending.frame.u64(OFF_RESULT);
    if crate::storage_fault_capture::selected(owner) {
        let bytes = unsafe { &*core::ptr::addr_of!(DATA) };
        if let Some(io) = pending.capture_io {
            crate::storage_fault_capture::delivered(
                owner,
                &pending.frame.bytes,
                &bytes[..pending.capture_len],
                pending.capture_misses,
                io,
            );
        } else {
            crate::storage_fault_capture::snapshot_failed();
        }
    }
    clear_pending();
    Ok(())
}
pub fn dispatch(owner: ObjectKey, context: &mut Context, progress: &mut dyn FnMut()) -> bool {
    if context.regs[8] != DISPATCH {
        return false;
    }
    let _guard = match acquire() {
        Ok(g) => g,
        Err(e) => {
            context.regs[0] = if retryable_before_run(e) {
                (-11i64) as u64
            } else {
                errno(e) as u64
            };
            return true;
        }
    };
    if PENDING_ID.load(Ordering::Acquire) != 0 {
        if !pending_delivery(owner) {
            context.regs[0] = (-11i64) as u64;
            return true;
        }
        if let Err(e) = deliver(owner, context) {
            context.regs[0] = errno(e) as u64;
        }
        return true;
    }
    let address = context.regs[1];
    let mut input = Frame {
        bytes: [0; FRAME_BYTES],
    };
    if let Err(e) = domain_tasks::copyin(owner, address, &mut input.bytes) {
        context.regs[0] = if retryable_before_run(e) {
            (-11i64) as u64
        } else {
            errno(e) as u64
        };
        return true;
    }
    let mut output = input;
    output.set_u64(OFF_RESULT, 0);
    output.set_u64(OFF_COUNT, 0);
    output.set_u64(OFF_OBJECT_ID, 0);
    output.set_u64(OFF_OBJECT_GENERATION, 0);
    output.set_u64(OFF_WRITE_SEQ, 0);
    output.set_u64(OFF_DURABLE_SEQ, 0);
    if let Err(e) = validate(owner, address, &input) {
        if retryable_before_run(e) {
            context.regs[0] = (-11i64) as u64;
            return true;
        }
        context.regs[0] = errno(e) as u64;
        output.set_u64(OFF_RESULT, errno(e) as u64);
        let _ = domain_tasks::copyout(owner, address, &output.bytes);
        return true;
    }
    let data = unsafe { &mut *core::ptr::addr_of_mut!(DATA) };
    // All user input is copied before the first filesystem effect. A lock
    // collision here is an explicit no-effect retry and leaves the frame intact.
    if input.u16(OFF_OPERATION) == WRITE {
        let len = input.u32(OFF_DATA_LENGTH) as usize;
        if let Err(e) = domain_tasks::copyin(owner, input.u64(OFF_DATA), &mut data[..len]) {
            if retryable_before_run(e) {
                context.regs[0] = (-11i64) as u64;
                return true;
            }
            context.regs[0] = errno(e) as u64;
            output.set_u64(OFF_RESULT, errno(e) as u64);
            let _ = domain_tasks::copyout(owner, address, &output.bytes);
            return true;
        }
    }
    let capture_selected = crate::storage_fault_capture::selected(owner);
    let capture_misses_before = if capture_selected {
        storage::metrics().cache_misses
    } else {
        0
    };
    if crate::storage_fault_capture::PROFILE
        && authorize(owner, &input).is_ok()
        && matches!(
            crate::storage_fault_capture::entered(owner, &input.bytes),
            Err(Error::Busy)
        )
    {
        context.regs[0] = (-11i64) as u64;
        return true;
    }
    let result = (|| {
        let grant = authorize(owner, &input)?;
        let result = run(owner, &input, &mut output, data, progress);
        if input.u16(OFF_OPERATION) == GET_STAT_CAP
            && result.as_ref().is_err_and(|e| retryable_before_run(*e))
        {
            return result;
        }
        // Even an uncertain media error consumes this invocation. Its result is
        // retained below, while a user retry requires a fresh request identity.
        unsafe {
            (*core::ptr::addr_of_mut!(GRANTS))[grant]
                .as_mut()
                .unwrap()
                .last_request = input.u64(OFF_REQUEST);
        }
        result
    })();
    if input.u16(OFF_OPERATION) == GET_STAT_CAP
        && result.as_ref().is_err_and(|e| retryable_before_run(*e))
    {
        context.regs[0] = (-11i64) as u64;
        return true;
    }
    let len = match result {
        Ok(n) => n,
        Err(e) => {
            output.set_u64(OFF_RESULT, errno(e) as u64);
            0
        }
    };
    let capture_len =
        if output.u64(OFF_RESULT) == 0 && matches!(input.u16(OFF_OPERATION), READ | WRITE) {
            output.u64(OFF_COUNT) as usize
        } else {
            0
        };
    let capture_io = if capture_selected {
        crate::storage_fault_capture::snapshot()
    } else {
        None
    };
    unsafe {
        *core::ptr::addr_of_mut!(PENDING) = Some(Delivery {
            owner,
            address,
            frame: output,
            data_address: input.u64(OFF_DATA),
            data_len: len,
            capture_len,
            capture_misses: if capture_selected {
                storage::metrics()
                    .cache_misses
                    .saturating_sub(capture_misses_before)
            } else {
                0
            },
            capture_io,
        });
    }
    PENDING_GENERATION.store(owner.generation, Ordering::Relaxed);
    PENDING_ID.store(owner.id, Ordering::Release);
    if let Err(e) = deliver(owner, context) {
        context.regs[0] = errno(e) as u64;
    }
    true
}
