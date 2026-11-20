//! The CPU0 foreground owns all shared OFD mutations. IRQs and DMA do not touch
//! this table; RefCell additionally rejects accidental foreground reentrancy.
use cyxia_posix::{Errno, OpenDescriptions, Released};
struct ForegroundStore(OpenDescriptions);
// SAFETY: only the serialized CPU0 supervisor invokes this module. There is no
// IRQ/DMA access; a multicore port must replace this boundary with synchronization.
unsafe impl Sync for ForegroundStore {}
static OBJECTS: ForegroundStore = ForegroundStore(OpenDescriptions::new());
pub(super) const fn table() -> &'static OpenDescriptions {
    &OBJECTS.0
}

pub(super) fn release(
    fs: &mut cyxia_ai_fs::FileSystem,
    released: Option<Released>,
) -> Result<(), Errno> {
    #[cfg(feature = "ported")]
    {
        // No queued/staged reference means a non-final close cannot lose the
        // root of a socket cycle. Preserve the ordinary no-backend fast path.
        if released.is_none()
            && table().rights_capacity().references == cyxia_posix::ancillary::REFERENCES
        {
            return Ok(());
        }
        let reclaimed = super::unix::with(|sockets| {
            table().reclaim_socket_rights(fs, sockets, released, &[], false)
        })?;
        finish_reclaim(fs, reclaimed)
    }
    #[cfg(not(feature = "ported"))]
    {
        let _ = (fs, released);
        if released.is_none() {
            Ok(())
        } else {
            Err(Errno::Nosys)
        }
    }
}

#[cfg(feature = "ported")]
pub(super) fn finish_reclaim(
    _fs: &mut cyxia_ai_fs::FileSystem,
    reclaimed: cyxia_posix::ancillary::Reclaimed,
) -> Result<(), Errno> {
    // The Unix borrow is over. Other pools can now publish their own wakes.
    for released in reclaimed.external.into_iter().flatten() {
        match released {
            Released::Socket { .. } => return Err(Errno::Io),
            Released::Pipe { owner, handle } => super::pipes::with(|p| p.close(owner, handle))?,
            Released::Pty { owner, handle } => super::pty::with(|p| p.close(owner, handle))?,
            Released::Memfd { handle } => crate::shared_memory::release_description(handle)?,
        }
    }
    for receipt in reclaimed.receipts.into_iter().flatten() {
        super::unix::receipt_release(receipt.references, receipt.cancelled);
    }
    Ok(())
}
