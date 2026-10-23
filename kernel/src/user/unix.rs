//! Foreground-owned local socket pool. AI decides ordinary object admission;
//! generation/owner/path/capacity enforcement remains a kernel mechanism.
use cyxia_posix::{
    Errno,
    unix::{Handle, UnixSockets},
};
static mut SOCKETS: UnixSockets = UnixSockets::new();

pub(super) fn with<T>(f: impl FnOnce(&mut UnixSockets) -> Result<T, Errno>) -> Result<T, Errno> {
    // SAFETY: CPU0 foreground is the sole caller; IRQs and DMA never reference
    // these pools. No borrowed reference escapes this serialized operation.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(SOCKETS) };
    let result = f(pool);
    // Only this pool may be inspected here: ancillary cleanup can nest a
    // different pool operation while the Unix pool is mutably borrowed.
    super::objects::table().observe_backend(|source| {
        let cyxia_posix::epoll::Source::Socket { owner, handle: raw } = source else {
            return None;
        };
        let ready = pool.poll(owner, handle(raw)).ok()?;
        let bits = u32::from(ready.readable)
            | (u32::from(ready.writable) << 2)
            | if ready.hangup {
                cyxia_posix::epoll::HUP
            } else {
                0
            }
            | if ready.read_hangup {
                cyxia_posix::epoll::RDHUP
            } else {
                0
            };
        Some((bits, pool.wake_mask(owner, handle(raw)).unwrap_or(0)))
    });
    pool.clear_wakes();
    result
}

/// Admit logical pool occupancy, then record the actual mechanism outcome.
/// A proposal is not a socket/binding/connection commit or a successful syscall.
pub(super) fn admit<T>(
    endpoints: u32,
    connections: u32,
    bindings: u32,
    operation: impl FnOnce(&mut UnixSockets) -> Result<T, Errno>,
) -> Result<T, Errno> {
    let mut attempt = cyxia_ai_runtime::accounting::Attempt::default();
    let result = (|| {
        let capacity = with(|s| Ok(s.capacity()))?;
        // The foreground cannot interleave a mutation between observation and
        // operation. A multi-pool rejection reserves nothing and needs no refund.
        for (free, needed) in [
            (capacity.free_endpoints, endpoints),
            (capacity.free_connections, connections),
            (capacity.free_bindings, bindings),
        ] {
            if needed != 0 {
                attempt.proposed(8193);
                let (allowed, model) = cyxia_ai_runtime::user_memory_policy(free as u32, needed)
                    .map_err(|_| Errno::Io)?;
                attempt.decided(allowed, model);
                if !allowed {
                    return Err(Errno::Again);
                }
            }
        }
        with(operation)
    })();
    super::ai::admission(super::ai::Domain::Unix, attempt, &result);
    if result.is_ok() {
        super::super::log(b"UNIX_ADMISSION AI_DIRECT model=8193 committed=true\n");
    }
    result
}

pub(super) fn handle(raw: u64) -> Handle {
    Handle::from_raw(raw)
}

/// Release detached tickets outside any OFD RefCell borrow. The whitelist
/// excludes sockets, so this cannot recursively borrow the Unix socket pool.
fn discard(
    fs: &mut cyxia_ai_fs::FileSystem,
    ticket: cyxia_posix::ancillary::Ticket,
    cancelled: bool,
) -> Result<(), Errno> {
    let (released, count) = super::objects::table().discard_rights(fs, ticket)?;
    for item in released {
        super::objects::release(fs, item)?;
    }
    receipt_release(count, cancelled);
    Ok(())
}
pub(super) fn receipt_release(count: usize, cancelled: bool) {
    for (domain, units) in [
        (super::ai::Domain::AncillaryMessages, 1),
        (super::ai::Domain::AncillaryReferences, count as u64),
    ] {
        super::ai::record(domain, |c| {
            c.release(units);
            if cancelled {
                c.cancelled();
            }
        });
    }
}
pub(super) fn read(
    fs: &mut cyxia_ai_fs::FileSystem,
    owner: u32,
    raw: u64,
    out: &mut [u8],
) -> Result<usize, Errno> {
    let (n, ticket) = with(|s| s.read_message(owner, handle(raw), out))?;
    if let Some(ticket) = ticket {
        discard(fs, ticket, false)?;
    }
    Ok(n)
}
pub(super) fn close(fs: &mut cyxia_ai_fs::FileSystem, owner: u32, raw: u64) -> Result<(), Errno> {
    let mut failed = None;
    with(|s| {
        s.close_with(owner, handle(raw), &mut |ticket| {
            if let Err(e) = discard(fs, ticket, false) {
                failed = Some(e);
            }
        })
    })?;
    failed.map_or(Ok(()), Err)
}
pub(super) fn shutdown(
    fs: &mut cyxia_ai_fs::FileSystem,
    owner: u32,
    raw: u64,
    how: u64,
) -> Result<(), Errno> {
    let mut failed = None;
    with(|s| {
        s.shutdown_with(owner, handle(raw), how, &mut |ticket| {
            if let Err(e) = discard(fs, ticket, false) {
                failed = Some(e);
            }
        })
    })?;
    failed.map_or(Ok(()), Err)
}
pub(super) fn write_rights(
    fs: &mut cyxia_ai_fs::FileSystem,
    process: &cyxia_posix::Process<'_>,
    owner: u32,
    raw: u64,
    bytes: &[u8],
    fds: &[i32],
) -> Result<usize, Errno> {
    use super::ai::{self, Domain};
    use cyxia_ai_runtime::accounting::Attempt;
    let mut attempts = [Attempt::default(); 2];
    let domains = [Domain::AncillaryMessages, Domain::AncillaryReferences];
    let result = (|| {
        process.validate_rights(fds)?;
        if bytes.is_empty() {
            return Err(Errno::Inval);
        }
        let capacity = super::objects::table().rights_capacity();
        for (i, (free, needed)) in [(capacity.messages, 1), (capacity.references, fds.len())]
            .into_iter()
            .enumerate()
        {
            attempts[i].proposed(8193);
            let (allowed, model) = cyxia_ai_runtime::user_memory_policy(free as u32, needed as u32)
                .map_err(|_| Errno::Io)?;
            attempts[i].decided(allowed, model);
            // Metadata pressure is explicit; ordinary POLLOUT only describes
            // byte-ring capacity and must not spin on a full ancillary pool.
            if !allowed {
                return Err(Errno::Nobufs);
            }
        }
        let ticket = process.stage_rights(fds)?;
        ai::record(domains[0], |c| c.grant(1));
        ai::record(domains[1], |c| c.grant(fds.len() as u64));
        let result = with(|s| s.write_message(owner, handle(raw), bytes, Some(ticket)));
        if result.is_ok() {
            // All validation/allocation was completed while staging. CPU0
            // cannot interleave a close or another ticket transition here.
            super::objects::table()
                .commit_rights(ticket)
                .expect("owned staged rights");
        } else {
            discard(fs, ticket, true)?;
        }
        result
    })();
    for (domain, attempt) in domains.into_iter().zip(attempts) {
        ai::admission(domain, attempt, &result);
    }
    result
}
