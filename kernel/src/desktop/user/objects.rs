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
    let Some(released) = released else {
        return Ok(());
    };
    #[cfg(feature = "ported")]
    match released {
        Released::Socket { owner, handle } => super::unix::close(fs, owner, handle),
        Released::Pipe { owner, handle } => super::pipes::with(|p| p.close(owner, handle)),
        Released::Pty { owner, handle } => super::pty::with(|p| p.close(owner, handle)),
        Released::Memfd { handle } => crate::shared_memory::release_description(handle),
    }
    #[cfg(not(feature = "ported"))]
    {
        let _ = (fs, released);
        Err(Errno::Nosys)
    }
}
