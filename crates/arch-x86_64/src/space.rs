//! Owned four-level user tables. Allocation policy and frame custody stay with
//! the process owner; this module never silently frees a mapped frame.
use core::marker::PhantomData;

pub const PAGE_BYTES: u64 = 4096;
pub const KERNEL_BASE: u64 = 0xffff800000000000;
const MASK: u64 = 0x000f_ffff_ffff_f000;
const P: u64 = 1;
const W: u64 = 2;
const U: u64 = 4;
const NX: u64 = 1 << 63;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    Permissions,
    Capacity,
    Conflict,
    Identity,
    Active,
    Unsupported,
    Timeout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceId {
    pub id: u64,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPermissions {
    pub writable: bool,
    pub executable: bool,
}
impl UserPermissions {
    pub const RX: Self = Self {
        writable: false,
        executable: true,
    };
    pub const RO: Self = Self {
        writable: false,
        executable: false,
    };
    pub const RW: Self = Self {
        writable: true,
        executable: false,
    };
}
#[derive(Clone, Copy, Debug)]
pub struct Translation {
    pub physical: u64,
    pub permissions: UserPermissions,
}
#[derive(Clone, Copy, Debug)]
pub struct RetiredMapping {
    pub physical: u64,
    pub space: SpaceId,
    pub epoch: u64,
    pub virtual_address: u64,
}
pub struct KernelMappings {
    upper: [u64; 256],
    ram_bytes: u64,
}
impl KernelMappings {
    pub fn new(upper: [u64; 256], ram_bytes: u64) -> Result<Self, Error> {
        if ram_bytes == 0
            || !ram_bytes.is_multiple_of(PAGE_BYTES)
            || ram_bytes > 1 << 52
            || upper.iter().any(|entry| entry & U != 0)
        {
            return Err(Error::Address);
        }
        Ok(Self { upper, ram_bytes })
    }
    pub fn ram_bytes(&self) -> u64 {
        self.ram_bytes
    }
}
/// A private pinned span of page-table frames. Its raw mapping is valid until
/// every resident CPU has left and all invalidation tickets have completed.
pub struct TableArena<'a> {
    virtual_base: *mut u8,
    physical_base: u64,
    pages: usize,
    used: usize,
    _owner: PhantomData<&'a mut [u8]>,
}
impl<'a> TableArena<'a> {
    /// # Safety
    /// The caller exclusively owns `pages` contiguous aligned frames and their
    /// writable kernel mapping. They remain pinned for the arena's lifetime.
    pub unsafe fn from_raw(
        virtual_base: *mut u8,
        physical_base: u64,
        pages: usize,
    ) -> Result<Self, Error> {
        if pages < 4
            || pages > 4096
            || virtual_base.is_null()
            || (virtual_base as usize) % 4096 != 0
            || physical_base == 0
            || !physical_base.is_multiple_of(PAGE_BYTES)
            || physical_base
                .checked_add(pages as u64 * PAGE_BYTES)
                .is_none_or(|end| end > 1 << 52)
        {
            return Err(Error::Address);
        }
        Ok(Self {
            virtual_base,
            physical_base,
            pages,
            used: 0,
            _owner: PhantomData,
        })
    }
    fn allocate(&mut self) -> Result<u64, Error> {
        if self.used == self.pages {
            return Err(Error::Capacity);
        }
        let index = self.used;
        self.used += 1;
        unsafe {
            core::ptr::write_bytes(self.virtual_base.add(index * 4096), 0, 4096);
        }
        Ok(self.physical_base + index as u64 * PAGE_BYTES)
    }
    fn table(&self, physical: u64) -> Result<*mut u64, Error> {
        let offset = physical
            .checked_sub(self.physical_base)
            .ok_or(Error::Address)?;
        if !offset.is_multiple_of(PAGE_BYTES) || offset / PAGE_BYTES >= self.used as u64 {
            return Err(Error::Address);
        }
        Ok(unsafe { self.virtual_base.add(offset as usize).cast() })
    }
}
pub struct AddressSpace<'a> {
    arena: TableArena<'a>,
    root: u64,
    id: SpaceId,
    ram_bytes: u64,
    epoch: core::sync::atomic::AtomicU64,
    residents: core::sync::atomic::AtomicU64,
}
impl<'a> AddressSpace<'a> {
    /// # Safety
    /// Kernel upper entries refer to immutable pinned supervisor tables. The
    /// arena is exclusively owned and remains pinned while contexts can run.
    pub unsafe fn new(
        mut arena: TableArena<'a>,
        kernel: &KernelMappings,
        id: SpaceId,
    ) -> Result<Self, Error> {
        if id.id == 0 || id.generation == 0 {
            return Err(Error::Identity);
        }
        let root = arena.allocate()?;
        unsafe {
            core::ptr::copy_nonoverlapping(kernel.upper.as_ptr(), arena.table(root)?.add(256), 256);
        }
        Ok(Self {
            arena,
            root,
            id,
            ram_bytes: kernel.ram_bytes,
            epoch: core::sync::atomic::AtomicU64::new(1),
            residents: core::sync::atomic::AtomicU64::new(0),
        })
    }
    pub fn id(&self) -> SpaceId {
        self.id
    }
    pub fn root_phys(&self) -> u64 {
        self.root
    }
    pub fn resident_cpus(&self) -> u64 {
        self.residents.load(core::sync::atomic::Ordering::Acquire)
    }
    pub fn epoch(&self) -> u64 {
        self.epoch.load(core::sync::atomic::Ordering::Acquire)
    }
    fn address(address: u64) -> Result<(), Error> {
        if address < PAGE_BYTES
            || address >= 0x0000_8000_0000_0000
            || !address.is_multiple_of(PAGE_BYTES)
        {
            return Err(Error::Address);
        }
        Ok(())
    }
    fn leaf(&self, address: u64) -> Option<*mut u64> {
        let mut table = self.arena.table(self.root).ok()?;
        for shift in [39, 30, 21] {
            let value = unsafe {
                table
                    .add(((address >> shift) & 511) as usize)
                    .read_volatile()
            };
            if value & P == 0 || value & (1 << 7) != 0 {
                return None;
            }
            table = self.arena.table(value & MASK).ok()?;
        }
        Some(unsafe { table.add(((address >> 12) & 511) as usize) })
    }
    pub fn map(
        &mut self,
        address: u64,
        physical: u64,
        permissions: UserPermissions,
    ) -> Result<(), Error> {
        Self::address(address)?;
        if !physical.is_multiple_of(PAGE_BYTES) || physical >= self.ram_bytes {
            return Err(Error::Address);
        }
        if permissions.writable && permissions.executable {
            return Err(Error::Permissions);
        }
        #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
        if permissions.executable || permissions.writable {
            unsafe extern "C" {
                fn x86_runtime_code_sealed(physical: u64) -> bool;
            }
            let sealed = unsafe { x86_runtime_code_sealed(physical) };
            if permissions.executable && !sealed || permissions.writable && sealed {
                return Err(Error::Permissions);
            }
        }
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        let mut table = self.arena.table(self.root)?;
        for shift in [39, 30, 21] {
            let entry = unsafe { table.add(((address >> shift) & 511) as usize) };
            let mut value = unsafe { entry.read_volatile() };
            if value & P == 0 {
                let child = self.arena.allocate()?;
                value = child | P | W | U;
                unsafe {
                    entry.write_volatile(value);
                }
            }
            if value & (1 << 7) != 0 {
                return Err(Error::Conflict);
            }
            table = self.arena.table(value & MASK)?;
        }
        let leaf = unsafe { table.add(((address >> 12) & 511) as usize) };
        if unsafe { leaf.read_volatile() } & P != 0 {
            return Err(Error::Conflict);
        }
        let value = physical
            | P
            | U
            | if permissions.writable { W } else { 0 }
            | if permissions.executable { 0 } else { NX };
        mapping_change(physical, None, Some(permissions))?;
        unsafe {
            leaf.write_volatile(value);
        }
        self.epoch
            .fetch_add(1, core::sync::atomic::Ordering::Release);
        Ok(())
    }
    pub fn translate(&self, address: u64) -> Option<Translation> {
        if address >= 0x0000_8000_0000_0000 {
            return None;
        }
        let value = unsafe { self.leaf(address)?.read_volatile() };
        if value & P == 0 {
            return None;
        }
        Some(Translation {
            physical: (value & MASK) | (address & 4095),
            permissions: UserPermissions {
                writable: value & W != 0,
                executable: value & NX == 0,
            },
        })
    }
    pub fn unmap(&mut self, address: u64) -> Result<RetiredMapping, Error> {
        Self::address(address)?;
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        let leaf = self.leaf(address).ok_or(Error::Address)?;
        let old = unsafe { leaf.read_volatile() };
        if old & P == 0 {
            return Err(Error::Address);
        }
        mapping_change(
            old & MASK,
            Some(UserPermissions {
                writable: old & W != 0,
                executable: old & NX == 0,
            }),
            None,
        )?;
        unsafe {
            leaf.write_volatile(0);
        }
        let epoch = self
            .epoch
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel)
            + 1;
        Ok(RetiredMapping {
            physical: old & MASK,
            space: self.id,
            epoch,
            virtual_address: address,
        })
    }
    pub fn protect(&mut self, address: u64, permissions: UserPermissions) -> Result<(), Error> {
        Self::address(address)?;
        if self.resident_cpus() != 0 {
            return Err(Error::Active);
        }
        if permissions.writable && permissions.executable {
            return Err(Error::Permissions);
        }
        let leaf = self.leaf(address).ok_or(Error::Address)?;
        let old = unsafe { leaf.read_volatile() };
        if old & P == 0 {
            return Err(Error::Address);
        }
        #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
        if permissions.executable || permissions.writable {
            unsafe extern "C" {
                fn x86_runtime_code_sealed(physical: u64) -> bool;
            }
            let sealed = unsafe { x86_runtime_code_sealed(old & MASK) };
            if permissions.executable && !sealed || permissions.writable && sealed {
                return Err(Error::Permissions);
            }
        }
        mapping_change(
            old & MASK,
            Some(UserPermissions {
                writable: old & W != 0,
                executable: old & NX == 0,
            }),
            Some(permissions),
        )?;
        unsafe {
            leaf.write_volatile(
                (old & MASK)
                    | P
                    | U
                    | if permissions.writable { W } else { 0 }
                    | if permissions.executable { 0 } else { NX },
            );
        }
        self.epoch
            .fetch_add(1, core::sync::atomic::Ordering::Release);
        Ok(())
    }
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    pub(crate) fn enter_cpu(&self, slot: usize) -> Result<(), Error> {
        if slot >= 4 {
            return Err(Error::Address);
        }
        self.residents
            .fetch_or(1 << slot, core::sync::atomic::Ordering::AcqRel);
        Ok(())
    }
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    pub(crate) fn leave_cpu(&self, slot: usize) {
        self.residents
            .fetch_and(!(1 << slot), core::sync::atomic::Ordering::Release);
    }
}

fn mapping_change(
    physical: u64,
    old: Option<UserPermissions>,
    new: Option<UserPermissions>,
) -> Result<(), Error> {
    #[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
    {
        unsafe extern "C" {
            fn x86_runtime_mapping_change(physical: u64, old: u64, new: u64) -> bool;
        }
        let flags = |p: Option<UserPermissions>| {
            p.map_or(0, |p| {
                1 | u64::from(p.writable) << 1 | u64::from(p.executable) << 2
            })
        };
        if !unsafe { x86_runtime_mapping_change(physical, flags(old), flags(new)) } {
            return Err(Error::Permissions);
        }
    }
    #[cfg(not(all(feature = "runtime", target_arch = "x86_64", target_os = "none")))]
    let _ = (physical, old, new);
    Ok(())
}
impl Drop for AddressSpace<'_> {
    fn drop(&mut self) {
        assert_eq!(self.resident_cpus(), 0, "dropping an entered address space");
        fn retire(space: &AddressSpace<'_>, physical: u64, level: u8, entries: usize) {
            let Ok(table) = space.arena.table(physical) else {
                return;
            };
            for index in 0..entries {
                let value = unsafe { table.add(index).read_volatile() };
                if value & P == 0 {
                    continue;
                }
                if level == 1 {
                    let _ = mapping_change(
                        value & MASK,
                        Some(UserPermissions {
                            writable: value & W != 0,
                            executable: value & NX == 0,
                        }),
                        None,
                    );
                } else {
                    retire(space, value & MASK, level - 1, 512);
                }
            }
        }
        retire(self, self.root, 4, 256);
    }
}
