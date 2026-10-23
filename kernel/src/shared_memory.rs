//! CPU0-owned shared physical backing. Physical pages are charged once, while
//! OFD and mapping lifetimes independently keep the object alive.
use crate::user::ai::{self, Domain};
use cyxia_ai_runtime::accounting::Attempt;
use cyxia_contracts::{BootInfo, PageCount, RedemptionId};
use cyxia_kernel_core::grants::{
    AuthorizedGrantRequest, BoundedGrantLedger, Owner, ReleaseReceipt,
};
use cyxia_posix::{
    Errno,
    shared_memory::{self as metadata, Backings, Batch, Info, OBJECTS, PAGE_SIZE, PAGES},
};

#[cfg(feature = "large-memory")]
pub const RESERVED_BYTES: u64 = (PAGES * PAGE_SIZE) as u64;
struct Store {
    backing: Backings,
    batch: Batch,
    owners: [Option<Owner>; OBJECTS],
    pages: [Option<(Owner, RedemptionId)>; PAGES],
    ledger: BoundedGrantLedger<PAGES>,
    base: u64,
}
impl Store {
    const fn new() -> Self {
        Self {
            backing: Backings::new(),
            batch: Batch::new(),
            owners: [None; OBJECTS],
            pages: [None; PAGES],
            ledger: BoundedGrantLedger::new(PageCount(PAGES as u32)),
            base: 0,
        }
    }
    fn pointer(&self, slot: usize, offset: usize) -> *mut u8 {
        assert!(self.base != 0 && slot < PAGES && offset < PAGE_SIZE);
        (crate::HIGH + self.base + (slot * PAGE_SIZE + offset) as u64) as *mut u8
    }
    fn release_batch(&mut self) -> Result<(), Errno> {
        for slot in self.batch.iter() {
            // All mapping references are gone, or shrink proved none existed.
            // CPU0 returned from EL0 with TTBR0 disabled and global TLBI complete.
            unsafe {
                core::ptr::write_bytes(self.pointer(slot, 0), 0, PAGE_SIZE);
            }
            let (owner, id) = self.pages[slot].take().ok_or(Errno::Io)?;
            self.ledger
                .release_completed(unsafe { ReleaseReceipt::after_revoke(id, owner, PageCount(1)) })
                .map_err(|_| Errno::Io)?;
            ai::record(Domain::SharedPages, |c| c.release(1));
        }
        Ok(())
    }
    fn clear_range(&self, handle: u64, start: usize, end: usize) -> Result<(), Errno> {
        let mut at = start;
        while at < end {
            let slot = self.backing.page(handle, at / PAGE_SIZE)?;
            let offset = at % PAGE_SIZE;
            let n = (PAGE_SIZE - offset).min(end - at);
            unsafe {
                core::ptr::write_bytes(self.pointer(slot, offset), 0, n);
            }
            at += n;
        }
        Ok(())
    }
    fn resize(&mut self, handle: u64, size: usize, attempt: &mut Attempt) -> Result<(), Errno> {
        self.backing.check_resize(handle, size)?;
        let old = self.backing.info(handle)?.size;
        let growth = size
            .div_ceil(PAGE_SIZE)
            .saturating_sub(old.div_ceil(PAGE_SIZE));
        let owner = self.owners[(handle & 255) as usize].ok_or(Errno::Io)?;
        let grant = if growth != 0 {
            attempt.proposed(8194);
            let (allowed, model) = cyxia_ai_runtime::anonymous_memory_policy(
                self.ledger.snapshot().free,
                growth as u32,
            )
            .map_err(|_| Errno::Io)?;
            attempt.decided(allowed, model);
            if !allowed {
                return Err(Errno::Nomem);
            }
            let request = unsafe {
                AuthorizedGrantRequest::validated_ai(owner, PageCount(growth as u32), model)
            }
            .map_err(|_| Errno::Io)?;
            Some(self.ledger.commit(request).map_err(|_| Errno::Nomem)?)
        } else {
            None
        };
        if let Err(error) = self.backing.resize(handle, size, &mut self.batch) {
            if let Some(grant) = grant {
                self.ledger
                    .cancel_unused(grant, owner)
                    .map_err(|_| Errno::Io)?;
            }
            return Err(error);
        }
        if let Some(grant) = grant {
            // commit() reserved one redemption record for each promised page.
            for slot in self.batch.iter() {
                let id = self
                    .ledger
                    .redeem(grant, owner, PageCount(1))
                    .expect("preflighted shared redemption");
                self.pages[slot] = Some((owner, id));
                unsafe {
                    core::ptr::write_bytes(self.pointer(slot, 0), 0, PAGE_SIZE);
                }
                ai::record(Domain::SharedPages, |c| c.grant(1));
            }
        } else if size < old {
            self.release_batch()?;
        }
        if size > old {
            self.clear_range(handle, old, size)?;
        }
        // A future grow must not reveal bytes formerly beyond a shrunken EOF.
        if size < old && !size.is_multiple_of(PAGE_SIZE) {
            self.clear_range(handle, size, size.div_ceil(PAGE_SIZE) * PAGE_SIZE)?;
        }
        Ok(())
    }
}
static mut STORE: Store = Store::new();
fn with<T>(f: impl FnOnce(&mut Store) -> Result<T, Errno>) -> Result<T, Errno> {
    // SAFETY: only serialized CPU0 foreground calls; IRQ/DMA never access this store.
    f(unsafe { &mut *core::ptr::addr_of_mut!(STORE) })
}
pub fn init(info: &mut BootInfo) -> Result<(), Errno> {
    #[cfg(feature = "large-memory")]
    {
        let range = cyxia_platform_virt::reserve_user_pool(info, RESERVED_BYTES)
            .map_err(|_| Errno::Nomem)?;
        with(|s| {
            if s.base != 0 {
                return Err(Errno::Busy);
            }
            s.base = range.start.0;
            Ok(())
        })
    }
    #[cfg(not(feature = "large-memory"))]
    {
        let _ = info;
        Err(Errno::Nodev)
    }
}
pub fn create(owner: Owner, allow_sealing: bool) -> Result<u64, Errno> {
    let mut attempt = Attempt::default();
    let result = with(|s| {
        if s.base == 0 {
            return Err(Errno::Nodev);
        }
        attempt.proposed(8193);
        let (allowed, model) =
            cyxia_ai_runtime::user_memory_policy(s.backing.free_objects() as u32, 1)
                .map_err(|_| Errno::Io)?;
        attempt.decided(allowed, model);
        if !allowed {
            return Err(Errno::Nomem);
        }
        let h = s.backing.create(allow_sealing)?;
        s.owners[(h & 255) as usize] = Some(owner);
        ai::record(Domain::SharedObjects, |c| c.grant(1));
        Ok(h)
    });
    ai::admission(Domain::SharedObjects, attempt, &result);
    result
}
pub fn info(handle: u64) -> Result<Info, Errno> {
    with(|s| s.backing.info(handle))
}
pub fn resize(handle: u64, size: usize) -> Result<(), Errno> {
    let mut attempt = Attempt::default();
    let result = with(|s| s.resize(handle, size, &mut attempt));
    ai::admission(Domain::SharedPages, attempt, &result);
    result
}
pub fn add_seals(handle: u64, seals: u32) -> Result<(), Errno> {
    with(|s| s.backing.add_seals(handle, seals))
}
pub fn mapping_permissions(handle: u64, protection: u8, fd_writable: bool) -> Result<bool, Errno> {
    with(|s| {
        s.backing
            .mapping_permissions(handle, protection, fd_writable)
    })
}
pub fn private_snapshot_bytes(
    handle: u64,
    offset: usize,
    length: usize,
    protection: u8,
) -> Result<usize, Errno> {
    with(|s| {
        s.backing
            .private_snapshot_bytes(handle, offset, length, protection)
    })
}
pub fn hold_mapping(handle: u64, offset: usize, len: usize, may_write: bool) -> Result<(), Errno> {
    with(|s| s.backing.hold_mapping(handle, offset, len, may_write))
}
pub fn release_description(handle: u64) -> Result<(), Errno> {
    with(|s| {
        if s.backing.close_description(handle, &mut s.batch)? {
            s.release_batch()?;
            s.owners[(handle & 255) as usize] = None;
            ai::record(Domain::SharedObjects, |c| c.release(1));
        }
        Ok(())
    })
}
pub fn drop_mapping(handle: u64, may_write: bool) -> Result<(), Errno> {
    with(|s| {
        if s.backing.drop_mapping(handle, may_write, &mut s.batch)? {
            s.release_batch()?;
            s.owners[(handle & 255) as usize] = None;
            ai::record(Domain::SharedObjects, |c| c.release(1));
        }
        Ok(())
    })
}
pub fn physical(handle: u64, page: usize) -> Result<u64, Errno> {
    with(|s| Ok(s.base + s.backing.page(handle, page)? as u64 * PAGE_SIZE as u64))
}
pub fn read(handle: u64, offset: usize, out: &mut [u8]) -> Result<usize, Errno> {
    with(|s| {
        let size = s.backing.info(handle)?.size;
        let n = out.len().min(size.saturating_sub(offset));
        let mut done = 0;
        while done < n {
            let at = offset + done;
            let slot = s.backing.page(handle, at / PAGE_SIZE)?;
            let len = (PAGE_SIZE - at % PAGE_SIZE).min(n - done);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    s.pointer(slot, at % PAGE_SIZE),
                    out[done..].as_mut_ptr(),
                    len,
                );
            }
            done += len;
        }
        Ok(n)
    })
}
pub fn write(handle: u64, offset: usize, data: &[u8]) -> Result<usize, Errno> {
    let end = offset.checked_add(data.len()).ok_or(Errno::Overflow)?;
    let size = info(handle)?.size;
    if data.is_empty() {
        return Ok(0);
    }
    // Check before growth or copying, so rejected writes neither change EOF nor
    // consume a backing page/AI grant.
    with(|s| s.backing.check_write(handle))?;
    if end > size {
        resize(handle, end)?;
    }
    with(|s| {
        let mut done = 0;
        while done < data.len() {
            let at = offset + done;
            let slot = s.backing.page(handle, at / PAGE_SIZE)?;
            let len = (PAGE_SIZE - at % PAGE_SIZE).min(data.len() - done);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data[done..].as_ptr(),
                    s.pointer(slot, at % PAGE_SIZE),
                    len,
                );
            }
            done += len;
        }
        Ok(data.len())
    })
}
/// User-copy path may access the zero-filled tail of the final mapped page,
/// independently of the file's byte length, matching page-granular PTE access.
pub fn copy_mapping(
    handle: u64,
    offset: usize,
    bytes: &mut [u8],
    writing: bool,
) -> Result<(), Errno> {
    with(|s| {
        let size = s.backing.info(handle)?.size.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        if offset.checked_add(bytes.len()).is_none_or(|end| end > size) {
            return Err(Errno::Fault);
        }
        if writing && !bytes.is_empty() {
            s.backing.check_write(handle)?;
        }
        let mut done = 0;
        while done < bytes.len() {
            let at = offset + done;
            let slot = s.backing.page(handle, at / PAGE_SIZE)?;
            let len = (PAGE_SIZE - at % PAGE_SIZE).min(bytes.len() - done);
            unsafe {
                if writing {
                    core::ptr::copy_nonoverlapping(
                        bytes[done..].as_ptr(),
                        s.pointer(slot, at % PAGE_SIZE),
                        len,
                    );
                } else {
                    core::ptr::copy_nonoverlapping(
                        s.pointer(slot, at % PAGE_SIZE),
                        bytes[done..].as_mut_ptr(),
                        len,
                    );
                }
            }
            done += len;
        }
        Ok(())
    })
}
pub fn write_mapping(handle: u64, offset: usize, bytes: &[u8]) -> Result<(), Errno> {
    with(|s| {
        let size = s.backing.info(handle)?.size.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        if offset.checked_add(bytes.len()).is_none_or(|end| end > size) {
            return Err(Errno::Fault);
        }
        if !bytes.is_empty() {
            s.backing.check_write(handle)?;
        }
        let mut done = 0;
        while done < bytes.len() {
            let at = offset + done;
            let slot = s.backing.page(handle, at / PAGE_SIZE)?;
            let len = (PAGE_SIZE - at % PAGE_SIZE).min(bytes.len() - done);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes[done..].as_ptr(),
                    s.pointer(slot, at % PAGE_SIZE),
                    len,
                );
            }
            done += len;
        }
        Ok(())
    })
}
pub fn status(out: &mut impl core::fmt::Write) {
    let _ = with(|s| {
        let ledger = s.ledger.snapshot();
        writeln!(out,"SHARED_OBJECTS available={} objects={} pages={} mappings={} description_refs={} mapping_refs={} free_pages={} grant_reserved={} grant_used={} metadata_capacity={} page_capacity={} MECHANISM\r",
            s.base!=0,s.backing.live_objects(),PAGES-s.backing.free_pages(),s.backing.mapping_count(),
            s.backing.description_count(),s.backing.mapping_count(),
            ledger.free,ledger.reserved_unredeemed,ledger.in_use,metadata::OBJECTS,metadata::PAGES).unwrap();
        Ok(())
    });
}
