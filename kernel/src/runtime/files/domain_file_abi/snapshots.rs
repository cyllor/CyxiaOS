//! Protected FileServiceSchemaV2 transport. The outer call binds the complete
//! capability (index and generation); a public request key grants no authority.
use super::*;
use abi::snapshot as wire;
use cyxia_prototype::snapshot::{FileReqKey, Request, SnapshotKey, history_prefix_digest};

const AUTHORITIES: usize = 16;
const CAP_BASE: u64 = 256;
#[derive(Clone, Copy)]
struct Authority {
    owner: ObjectKey,
    cap: ObjectKey,
    fs_uuid: [u8; 16],
    client_slot: u32,
    client_generation: u64,
    rights: u16,
    recovery: bool,
    prefix_len: u16,
    prefix_digest: [u8; 32],
    last_read_request: u64,
}
static mut AUTHORITIES_BANK: [Option<Authority>; AUTHORITIES] = [None; AUTHORITIES];
struct Completion {
    owner: ObjectKey,
    capability: ObjectKey,
    request_address: u64,
    response_address: u64,
    capacity: u64,
    length: usize,
}
static mut COMPLETION: Option<Completion> = None;
pub(super) const AUTHORITY_STORAGE_BYTES: usize =
    core::mem::size_of::<[Option<Authority>; AUTHORITIES]>();
pub(super) const COMPLETION_STORAGE_BYTES: usize = core::mem::size_of::<Option<Completion>>();
// Count the complete core manager conservatively, including its control and
// catalog mirrors, rather than charging only its small coordination fields.
pub(super) const COORDINATION_STORAGE_BYTES: usize = AUTHORITY_STORAGE_BYTES
    + COMPLETION_STORAGE_BYTES
    + core::mem::size_of::<cyxia_prototype::snapshot::Manager>()
    + core::mem::size_of::<Option<FileReqKey>>() // filesystem capture barrier
    + core::mem::size_of::<AtomicU64>() // native maintenance timestamp
    + core::mem::size_of::<[u16; cyxia_prototype::storage::BUSINESS_INODE_COUNT as usize]>()
    + if cfg!(snapshot_probe) {
        core::mem::size_of::<[AtomicU64; 16]>() // optional two-role exit evidence
    } else {
        0
    };
const _: () = assert!(COORDINATION_STORAGE_BYTES <= 4096);

/// Kernel-root-only enrollment. No EL0 opcode grants or widens this authority.
/// Recovery and protection permissions require the separate recovery entry.
pub fn grant_snapshots(
    owner: ObjectKey,
    fs_uuid: [u8; 16],
    client_slot: u32,
    client_generation: u64,
    rights: u16,
    path_prefix: &str,
) -> Result<ObjectKey, Error> {
    if rights & wire::RECOVERY_RIGHTS != 0 {
        return Err(Error::Auth);
    }
    mint(
        owner,
        fs_uuid,
        client_slot,
        client_generation,
        rights,
        path_prefix,
        false,
    )
}
/// Explicit enrollment of a trusted recovery supervisor. Keeping this separate
/// from ordinary grants prevents ALL_RIGHTS or a user-supplied mode widening
/// business authority into restore, thaw, or write-gate control.
pub fn grant_snapshot_recovery(
    owner: ObjectKey,
    fs_uuid: [u8; 16],
    client_slot: u32,
    client_generation: u64,
    rights: u16,
    path_prefix: &str,
) -> Result<ObjectKey, Error> {
    mint(
        owner,
        fs_uuid,
        client_slot,
        client_generation,
        rights,
        path_prefix,
        true,
    )
}
fn mint(
    owner: ObjectKey,
    fs_uuid: [u8; 16],
    client_slot: u32,
    client_generation: u64,
    rights: u16,
    path_prefix: &str,
    recovery: bool,
) -> Result<ObjectKey, Error> {
    let _guard = acquire()?;
    if owner.id == 0
        || owner.generation == 0
        || fs_uuid == [0; 16]
        || client_generation == 0
        || (!recovery && client_slot >= 14)
        || (recovery && (client_slot != 15 || rights & wire::RIGHT_CREATE != 0))
        || rights == 0
        || rights & !wire::KNOWN_RIGHTS != 0
        || (rights & wire::RIGHT_HISTORY_READ != 0 && !wire::canonical_path(path_prefix.as_bytes()))
        || (rights & wire::RIGHT_HISTORY_READ == 0 && !path_prefix.is_empty())
    {
        return Err(Error::Auth);
    }
    if storage::snapshot_uuid()? != fs_uuid {
        return Err(Error::Stale);
    }
    let prefix_digest = history_prefix_digest(path_prefix.as_bytes());
    let bank = unsafe { &mut *core::ptr::addr_of_mut!(AUTHORITIES_BANK) };
    if let Some(existing) = bank.iter().flatten().find(|g| {
        g.owner == owner
            && g.fs_uuid == fs_uuid
            && g.client_slot == client_slot
            && g.client_generation == client_generation
            && g.rights == rights
            && g.recovery == recovery
            && usize::from(g.prefix_len) == path_prefix.len()
            && g.prefix_digest == prefix_digest
    }) {
        return Ok(existing.cap);
    }
    let at = bank
        .iter()
        .position(Option::is_none)
        .ok_or(Error::Capacity)?;
    let cap = ObjectKey {
        id: CAP_BASE + at as u64,
        generation: generation()?,
    };
    bank[at] = Some(Authority {
        owner,
        cap,
        fs_uuid,
        client_slot,
        client_generation,
        rights,
        recovery,
        prefix_len: path_prefix.len() as u16,
        prefix_digest,
        last_read_request: 0,
    });
    Ok(cap)
}
fn authority(owner: ObjectKey, cap: ObjectKey) -> Result<(usize, Authority), Error> {
    let at = usize::try_from(cap.id.checked_sub(CAP_BASE).ok_or(Error::Auth)?)
        .map_err(|_| Error::Auth)?;
    let grant = unsafe { &*core::ptr::addr_of!(AUTHORITIES_BANK) }
        .get(at)
        .copied()
        .flatten()
        .filter(|g| g.owner == owner && g.cap == cap)
        .ok_or(Error::Auth)?;
    if storage::snapshot_uuid()? != grant.fs_uuid {
        return Err(Error::Stale);
    }
    Ok((at, grant))
}
pub(super) fn authorize_read(owner: ObjectKey, frame: &Frame) -> Result<usize, Error> {
    let cap = ObjectKey {
        id: frame.u64(OFF_AUTH_ID),
        generation: frame.u64(OFF_AUTH_GENERATION),
    };
    let (at, grant) = authority(owner, cap)?;
    if grant.rights & wire::RIGHT_HISTORY_READ == 0 {
        return Err(Error::Auth);
    }
    let (_, open) = handle(owner, frame)?;
    if open.history != cap {
        return Err(Error::Auth);
    }
    let request = frame.u64(OFF_REQUEST);
    if request == 0 || request <= grant.last_read_request {
        return Err(Error::Stale);
    }
    match frame.u16(OFF_OPERATION) {
        READ | READDIR | CLOSE => Ok(at),
        WRITE | FSYNC => Err(Error::ReadOnly),
        _ => Err(Error::Auth),
    }
}
pub(super) fn consume_read(at: usize, request: u64) {
    unsafe {
        if let Some(grant) = (&mut *core::ptr::addr_of_mut!(AUTHORITIES_BANK))[at].as_mut() {
            grant.last_read_request = request;
        }
    }
}
pub(super) fn revoke(owner: ObjectKey) {
    for grant in unsafe { &mut *core::ptr::addr_of_mut!(AUTHORITIES_BANK) } {
        if grant.is_some_and(|grant| grant.owner == owner) {
            *grant = None;
        }
    }
}
pub(super) fn clear_pending() {
    unsafe {
        *core::ptr::addr_of_mut!(COMPLETION) = None;
    }
}
fn wire_error(error: wire::WireError) -> Error {
    match error {
        wire::WireError::Version => Error::Schema,
        wire::WireError::Format => Error::Format,
        wire::WireError::Range => Error::Range,
        wire::WireError::Unsupported => Error::Unsupported,
    }
}
fn status(error: Error) -> i32 {
    match error {
        Error::Schema => -93,
        Error::Range => -34,
        _ => errno(error) as i32,
    }
}
fn req_key(bytes: &[u8]) -> Result<FileReqKey, Error> {
    FileReqKey::decode(bytes).map_err(|_| Error::Format)
}
fn snapshot_key(bytes: &[u8]) -> Result<SnapshotKey, Error> {
    SnapshotKey::decode(bytes).map_err(|_| Error::Format)
}
fn own_key(grant: Authority, key: FileReqKey, allow_supervisor: bool) -> Result<(), Error> {
    if key.fs_uuid != grant.fs_uuid {
        return Err(Error::Stale);
    }
    if key.client_slot != grant.client_slot || key.client_generation != grant.client_generation {
        if !allow_supervisor || !grant.recovery {
            return Err(Error::Auth);
        }
    }
    Ok(())
}
fn history_prefix(grant: Authority, path: &[u8]) -> Result<&str, Error> {
    let prefix = path
        .get(..usize::from(grant.prefix_len))
        .ok_or(Error::Auth)?;
    if !wire::within_prefix(path, prefix) || history_prefix_digest(prefix) != grant.prefix_digest {
        return Err(Error::Auth);
    }
    core::str::from_utf8(prefix).map_err(|_| Error::Auth)
}
fn authorize_request(
    owner: ObjectKey,
    cap: ObjectKey,
    request: wire::Request<'_>,
) -> Result<Authority, Error> {
    let (_, grant) = authority(owner, cap)?;
    if u64::from(request.cap_index) != cap.id {
        return Err(Error::Auth);
    }
    let required = wire::required_right(request.operation).ok_or(Error::Unsupported)?;
    if grant.rights & required != required {
        return Err(Error::Auth);
    }
    // The maintenance principal and periodic slots have no public issuer.
    // Automatic rotation is reachable only through the trusted owner timer.
    if request.operation == wire::SNAP_CREATE && wire::u32_at(request.payload, 8) != 2 {
        return Err(Error::Auth);
    }
    if wire::persistent(request.operation) {
        own_key(grant, req_key(request.request_key)?, false)?;
    } else if matches!(request.operation, wire::QUERY_REQUEST | wire::ACK_REQUEST) {
        own_key(grant, req_key(&request.payload[..36])?, true)?;
    }
    if matches!(
        request.operation,
        wire::SNAP_EXTEND
            | wire::SNAP_DELETE
            | wire::SNAP_RESTORE
            | wire::SNAP_QUERY
            | wire::SNAP_OPEN
    ) && snapshot_key(&request.payload[..40])?.fs_uuid != grant.fs_uuid
    {
        return Err(Error::Stale);
    }
    if request.operation == wire::SNAP_OPEN {
        history_prefix(grant, &request.payload[48..])?;
    }
    Ok(grant)
}
fn run_request(
    owner: ObjectKey,
    grant: Authority,
    request: wire::Request<'_>,
    out: &mut [u8],
    progress: &mut dyn FnMut(),
) -> Result<(usize, u32, i32), Error> {
    let payload = &mut out[wire::RESPONSE_HEADER_BYTES..];
    match request.operation {
        operation if wire::persistent(operation) => {
            let record = storage::snapshot_execute(
                Request {
                    key: req_key(request.request_key)?,
                    expected_live_view_epoch: request.expected_live_view_epoch,
                },
                operation,
                request.payload,
                progress,
            )?;
            let length = usize::try_from(record.result_payload_len).map_err(|_| Error::Format)?;
            if length > record.result_payload.len() {
                return Err(Error::Format);
            }
            payload[..length].copy_from_slice(&record.result_payload[..length]);
            Ok((length, record.state as u32, record.result_code))
        }
        wire::SNAP_LIST => Ok((storage::snapshot_status(payload)?, 0, 0)),
        wire::SNAP_QUERY => Ok((
            storage::snapshot_query(snapshot_key(request.payload)?, payload)?,
            0,
            0,
        )),
        wire::SNAP_OPEN => {
            let range = if grant.recovery {
                ORDINARY_HANDLES..128
            } else {
                0..ORDINARY_HANDLES
            };
            let at = range
                .into_iter()
                .find(|&at| unsafe { (*core::ptr::addr_of!(HANDLES))[at].is_none() })
                .ok_or(Error::Again)?;
            let token = generation()?;
            let path = core::str::from_utf8(&request.payload[48..]).map_err(|_| Error::Format)?;
            // Resolve the exact verified prefix slice in the historical tree.
            // A missing prefix never falls back to any live namespace path.
            let prefix = history_prefix(grant, &request.payload[48..])?;
            let key = snapshot_key(&request.payload[..40])?;
            let file = if grant.recovery {
                storage::snapshot_open_recovery(key, path, prefix, progress)?
            } else {
                storage::snapshot_open(key, path, prefix, progress)?
            };
            unsafe {
                (*core::ptr::addr_of_mut!(HANDLES))[at] = Some(Open {
                    owner,
                    cap: ObjectKey {
                        id: token,
                        generation: 0,
                    },
                    file,
                    readable: true,
                    history: grant.cap,
                });
            }
            wire::put_u64(payload, 0, token);
            Ok((8, 0, 0))
        }
        wire::QUERY_REQUEST => {
            let record = storage::snapshot_query_request(req_key(request.payload)?, progress)?;
            record
                .encode(&mut payload[..512])
                .map_err(|_| Error::Format)?;
            Ok((512, record.state as u32, 0))
        }
        wire::ACK_REQUEST => {
            let digest = request.payload[36..68]
                .try_into()
                .map_err(|_| Error::Format)?;
            storage::snapshot_ack(req_key(&request.payload[..36])?, digest, progress)?;
            Ok((0, 2, 0))
        }
        _ => Err(Error::Unsupported),
    }
}
fn deliver(owner: ObjectKey, context: &mut Context) -> Result<(), Error> {
    let completion = unsafe { &*core::ptr::addr_of!(COMPLETION) }
        .as_ref()
        .ok_or(Error::NotReady)?;
    if completion.owner != owner
        || context.regs[0] != completion.capability.id
        || context.regs[1] != completion.request_address
        || context.regs[2] != completion.capability.generation
        || context.regs[3] != completion.response_address
        || context.regs[4] != completion.capacity
    {
        return Err(Error::Busy);
    }
    domain_tasks::with_user_memory(owner, |memory| {
        let bytes = unsafe { &*core::ptr::addr_of!(DATA) };
        memory.copyout(completion.response_address, &bytes[..completion.length])
    })?;
    let bytes = unsafe { &*core::ptr::addr_of!(DATA) };
    context.regs[0] = (wire::u32_at(bytes, 16) as i32 as i64) as u64;
    context.regs[1] = completion.length as u64;
    super::clear_pending();
    Ok(())
}
/// x0=cap index, x1=request, x2=cap generation, x3=response, x4=response
/// capacity. Request length is copied from its bounded 64-byte header. Neither
/// the capability nor a user pointer is inferred from a public FileReqKey.
pub(super) fn dispatch(
    owner: ObjectKey,
    context: &mut Context,
    progress: &mut dyn FnMut(),
) -> DispatchResult {
    let _guard = match acquire() {
        Ok(guard) => guard,
        Err(error) => {
            if !retryable_before_run(error) {
                context.regs[0] = status(error) as i64 as u64;
            }
            return rejected_before_effect(error);
        }
    };
    if PENDING_ID.load(Ordering::Acquire) != 0 {
        if !pending_delivery(owner) || unsafe { (&*core::ptr::addr_of!(COMPLETION)).is_none() } {
            // x0 is part of the captured authority. CPU0 retains this stopped
            // call, so a pre-effect retry must preserve all input registers.
            context.regs[6] = (-11i64) as u64;
            return DispatchResult::RetryBeforeEffect;
        }
        if let Err(error) = deliver(owner, context) {
            // Preserve the captured input registers for CPU0's custody retry.
            context.regs[6] = status(error) as i64 as u64;
        }
        return DispatchResult::Returned;
    }
    let cap = ObjectKey {
        id: context.regs[0],
        generation: context.regs[2],
    };
    let address = context.regs[1];
    let response = context.regs[3];
    let capacity = context.regs[4];
    let mut input = [0; wire::MAX_REQUEST];
    let prepared = domain_tasks::with_user_memory(owner, |memory| {
        memory.copyin(address, &mut input[..wire::HEADER_BYTES])?;
        let length = wire::request_length(&input[..wire::HEADER_BYTES]).map_err(wire_error)?;
        if capacity < wire::response_bound(wire::u16_at(&input, 8)) as u64
            || capacity > wire::MAX_RESPONSE as u64
        {
            return Err(Error::Range);
        }
        let end = address.checked_add(length as u64).ok_or(Error::Range)?;
        let response_end = response.checked_add(capacity).ok_or(Error::Range)?;
        if address < response_end && response < end {
            return Err(Error::Format);
        }
        memory.probe(response, capacity as usize, true)?;
        memory.copyin(
            address + wire::HEADER_BYTES as u64,
            &mut input[wire::HEADER_BYTES..length],
        )?;
        wire::Request::decode(&input[..length]).map_err(wire_error)?;
        Ok(length)
    });
    let length = match prepared {
        Ok(length) => length,
        Err(error) => {
            if !retryable_before_run(error) {
                context.regs[0] = status(error) as i64 as u64;
            }
            return rejected_before_effect(error);
        }
    };
    // All shape and output access checks precede capability or disk effects.
    let request = match wire::Request::decode(&input[..length]) {
        Ok(request) => request,
        Err(error) => {
            context.regs[0] = error.errno() as i64 as u64;
            return DispatchResult::Returned;
        }
    };
    let mut output = [0; wire::MAX_RESPONSE];
    let result = authorize_request(owner, cap, request)
        .and_then(|grant| run_request(owner, grant, request, &mut output, progress));
    let (payload, state, code) = match result {
        Ok(result) => result,
        Err(error) => (
            0,
            if error == Error::Io && wire::persistent(request.operation) {
                5
            } else {
                0
            },
            status(error),
        ),
    };
    let length = wire::response_header(&mut output, request.operation, code, state, payload)
        .expect("bounded snapshot result");
    unsafe {
        // The shared PENDING owner gate excludes v1 payload access until this
        // completion is delivered. Reuse the existing broker buffer instead
        // of adding a second retained-response pool.
        (&mut *core::ptr::addr_of_mut!(DATA))[..length].copy_from_slice(&output[..length]);
        *core::ptr::addr_of_mut!(COMPLETION) = Some(Completion {
            owner,
            capability: cap,
            request_address: address,
            response_address: response,
            capacity,
            length,
        });
    }
    PENDING_GENERATION.store(owner.generation, Ordering::Relaxed);
    PENDING_ID.store(owner.id, Ordering::Release);
    if let Err(error) = deliver(owner, context) {
        context.regs[6] = status(error) as i64 as u64;
    }
    DispatchResult::Returned
}
