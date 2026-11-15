//! Post-admission anonymous allocation while every user root is stopped/retired.
//! The caller authenticates the exact owner/page count in `request`, serializes
//! backing access, and publishes no new mapping until this transaction succeeds.
use cyxia_contracts::{PageCount, RedemptionId};
use cyxia_kernel_core::grants::{
    AuthorizedGrantRequest, BoundedGrantLedger, Owner, ReleaseReceipt,
};
use cyxia_posix::{
    Errno,
    vm::{Page, PageBatch, Vm},
};

pub trait Backing {
    /// Record any acquired frame before a later staging operation can fail.
    fn stage(&mut self, page: Page) -> Result<(), Errno>;
    /// Remove desired PTEs without releasing backing; tolerate unstaged pages.
    fn unstage(&mut self, page: Page);
    /// Clear and release recorded backing after all new PTEs are removed.
    /// A page that acquired no backing must succeed without changing ownership.
    fn release(&mut self, page: Page) -> Result<(), Errno>;
}

/// Commit one admitted grant and stage its complete virtual range. Ordinary
/// allocation failures restore mappings and capacity; scratch output and consumed
/// identity sequences are not restored. Reclamation failures retain VM/grant
/// charges instead of manufacturing a completed-revocation receipt.
pub fn allocate<const N: usize>(
    vm: &mut Vm,
    batch: &mut PageBatch,
    ledger: &mut BoundedGrantLedger<N>,
    request: AuthorizedGrantRequest,
    owner: Owner,
    pages: usize,
    backing: &mut impl Backing,
    mut account: impl FnMut(bool, usize),
) -> Result<RedemptionId, Errno> {
    let redemption = ledger
        .commit_and_redeem(request)
        .map_err(|_| Errno::Nomem)?;
    account(true, pages);
    let result = vm.allocate_into(pages, batch).and_then(|()| {
        for page in batch.iter() {
            backing.stage(page)?;
        }
        Ok(())
    });
    if let Err(error) = result {
        // Vm empties the output on allocation failure. Otherwise every entry is
        // newly reserved, including pages whose staging was never attempted.
        if batch.page_count() != 0 {
            for page in batch.iter() {
                backing.unstage(page);
            }
            for page in batch.iter() {
                backing.release(page)?;
            }
            vm.unmap_into(batch.start(), pages, batch)?;
        }
        // New pages were never published, and all staged backing has now been
        // revoked. Existing allocations and their grants remain untouched.
        ledger
            .release_completed(unsafe {
                ReleaseReceipt::after_revoke(redemption, owner, PageCount(pages as u32))
            })
            .map_err(|_| Errno::Io)?;
        account(false, pages);
        return Err(error);
    }
    Ok(redemption)
}
