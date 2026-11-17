//! Per-process desired pages and the owned CPU address-space publication boundary.
//! x86 staging entries are metadata; only arch::space builds real four-level PTEs.
use cyxia_posix::Errno;

#[cfg(target_arch = "aarch64")]
#[repr(C, align(4096))]
pub struct PageTable(pub [u64; 512]);
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct Page {
    physical: u64,
    protection: u8,
}
#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
pub struct PageTable([Page; 512]);
impl PageTable {
    pub const fn empty() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            Self([0; 512])
        }
        #[cfg(target_arch = "x86_64")]
        {
            Self(
                [Page {
                    physical: 0,
                    protection: 0,
                }; 512],
            )
        }
    }
    pub fn clear(&mut self) {
        #[cfg(target_arch = "aarch64")]
        self.0.fill(0);
        #[cfg(target_arch = "x86_64")]
        self.0.fill(Page {
            physical: 0,
            protection: 0,
        });
    }
    pub fn remove(&mut self, index: usize) {
        #[cfg(target_arch = "aarch64")]
        {
            self.0[index] = 0;
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.0[index] = Page {
                physical: 0,
                protection: 0,
            };
        }
    }
    pub fn set(&mut self, index: usize, physical: u64, protection: u8) -> Result<(), Errno> {
        if index >= 512 || physical % 4096 != 0 || protection & !7 != 0 || protection & 6 == 6 {
            return Err(Errno::Inval);
        }
        if protection == 0 {
            self.remove(index);
            return Ok(());
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.0[index] = cyxia_arch_aarch64::mmu::encode_user_leaf(
                cyxia_contracts::PhysAddr(physical),
                protection & 2 != 0,
                protection & 4 != 0,
            )
            .map_err(|_| Errno::Inval)?;
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.0[index] = Page {
                physical,
                protection,
            };
        }
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    pub fn publish(&self, space: &mut ProcessSpace, base: u64) -> Result<(), Errno> {
        for (index, page) in self.0.iter().enumerate() {
            if page.protection != 0 {
                space.map(base + index as u64 * 4096, page.physical, page.protection)?;
            }
        }
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
pub const TABLE_PAGES_PER_PROCESS: usize = 128;
#[cfg(target_arch = "x86_64")]
pub const TABLE_POOL_BYTES: u64 =
    (TABLE_PAGES_PER_PROCESS * 4096 * cyxia_posix::usermem::MAX_PROCESSES) as u64;
#[cfg(target_arch = "x86_64")]
static TABLE_POOL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
pub fn init_pc() -> Result<cyxia_contracts::PhysAddr, Errno> {
    use core::sync::atomic::Ordering;
    if TABLE_POOL.load(Ordering::Acquire) != 0 {
        return Err(Errno::Busy);
    }
    let base = crate::os::reserve_pool(TABLE_POOL_BYTES)?;
    TABLE_POOL.store(base.0, Ordering::Release);
    Ok(base)
}
#[cfg(target_arch = "x86_64")]
pub struct ProcessSpace {
    current: Option<cyxia_arch_x86_64::space::AddressSpace<'static>>,
    slot: usize,
    pid: u32,
    retire_ns: u64,
}
// SAFETY: this owner exclusively reserves its table frames in the globally
// identical HIGH+PA direct map. Transfers occur only while no resume owns the
// space; a published mailbox pins it until the AP has returned and cleared
// residency. This permits ownership transfer, not concurrent table access.
#[cfg(target_arch = "x86_64")]
unsafe impl Send for ProcessSpace {}
#[cfg(target_arch = "x86_64")]
impl ProcessSpace {
    pub const fn new() -> Self {
        Self {
            current: None,
            slot: usize::MAX,
            pid: 0,
            retire_ns: 0,
        }
    }
    pub fn bind(&mut self, slot: usize, pid: u32) {
        assert!(self.current.is_none());
        self.slot = slot;
        self.pid = pid;
        self.retire_ns = 0;
    }
    pub fn begin(&mut self) -> Result<(), Errno> {
        use cyxia_arch_x86_64::space::{AddressSpace, SpaceId, TableArena};
        self.retire();
        let pool = TABLE_POOL.load(core::sync::atomic::Ordering::Acquire);
        if pool == 0 || self.slot >= cyxia_posix::usermem::MAX_PROCESSES || self.pid == 0 {
            return Err(Errno::Nodev);
        }
        let physical = pool + self.slot as u64 * TABLE_PAGES_PER_PROCESS as u64 * 4096;
        let arena = unsafe {
            TableArena::from_raw(
                (crate::HIGH + physical) as *mut u8,
                physical,
                TABLE_PAGES_PER_PROCESS,
            )
        }
        .map_err(|_| Errno::Nomem)?;
        self.current = Some(
            unsafe {
                AddressSpace::new(
                    arena,
                    crate::machine::runtime::kernel_mappings(),
                    SpaceId {
                        id: u64::from(self.pid),
                        generation: 1,
                    },
                )
            }
            .map_err(|_| Errno::Io)?,
        );
        Ok(())
    }
    pub fn map(
        &mut self,
        virtual_address: u64,
        physical: u64,
        protection: u8,
    ) -> Result<(), Errno> {
        if protection & 4 != 0 {
            crate::process_arch::publish_code(crate::HIGH + physical, 4096)?;
        }
        let permissions = cyxia_arch_x86_64::space::UserPermissions {
            writable: protection & 2 != 0,
            executable: protection & 4 != 0,
        };
        self.current
            .as_mut()
            .ok_or(Errno::Nodev)?
            .map(virtual_address, physical, permissions)
            .map_err(|_| Errno::Io)
    }
    pub fn root(&self) -> Result<&cyxia_arch_x86_64::space::AddressSpace<'static>, Errno> {
        self.current.as_ref().ok_or(Errno::Nodev)
    }
    /// The caller already returned from resume: kernel CR3 is live, no PCID or
    /// global user mappings exist, and no other CPU may enter this process.
    pub fn retire(&mut self) {
        if self.current.is_none() {
            return;
        }
        let started = crate::process_arch::now_ns();
        drop(self.current.take());
        self.retire_ns = self.retire_ns.saturating_add(
            crate::process_arch::now_ns().saturating_sub(started),
        );
    }
    /// Read only after the owned job has returned; no live AP is inspected.
    pub fn retired_ns(&self) -> u64 {
        self.retire_ns
    }
}
