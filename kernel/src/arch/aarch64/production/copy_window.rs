//! Checked views of the stopped CPU0 role's pinned buffers for native SVCs.

#[cfg(cyxia_startup_catalog)]
use super::signed_resident::SignedCaller;
#[cfg(feature = "v020-production-diagnostic")]
use super::trapped_ttbr0;
use super::{EFAULT, cpu, frames};
#[cfg(any(
    feature = "v020-production-snapshot-catalog",
    feature = "v020-production-file-read",
    feature = "v020-production-fsync-scratch",
    feature = "v020-production-live-control"
))]
use super::{NativeRole, Role, role_asid, trapped_pie_cap};
#[cfg(any(
    cyxia_startup_catalog,
    feature = "v020-production-snapshot-catalog",
    feature = "v020-production-file-read",
    feature = "v020-production-fsync-scratch",
    feature = "v020-production-live-control"
))]
use super::{phys, role_loader::stack_span};
use crate::machine::copy_window;
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_kernel_core::{
    control_plane::Identity,
    security::{Error, memory::PAGE_SIZE},
};

struct ClosedCopies {
    reads: AtomicU64,
    writes: AtomicU64,
}

impl ClosedCopies {
    const fn new() -> Self {
        Self {
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
        }
    }

    #[cfg(feature = "v020-production-diagnostic")]
    fn counts(&self) -> (u64, u64, bool) {
        (
            self.reads.load(Ordering::Relaxed),
            self.writes.load(Ordering::Relaxed),
            copy_window::cpu0_closed(),
        )
    }
}

static SYSCALL_COPIES: ClosedCopies = ClosedCopies::new();
#[cfg(any(
    feature = "v020-production-snapshot-catalog",
    feature = "v020-production-file-read",
    feature = "v020-production-fsync-scratch"
))]
static FILE_COPIES: ClosedCopies = ClosedCopies::new();
#[cfg(feature = "v020-production-live-control")]
static AUDIT_COPIES: ClosedCopies = ClosedCopies::new();

/// A range verified against the stopped role's actual table walk and its
/// exclusive static backing. Callers hold only this checked description.
pub(super) struct VerifiedSpan<'call> {
    physical: u64,
    length: usize,
    owner: Identity,
    root_asid: u64,
    write: bool,
    closed: &'static ClosedCopies,
    origin: Origin<'call>,
}

enum Origin<'call> {
    #[cfg(feature = "v020-production-diagnostic")]
    Vector(core::marker::PhantomData<&'call ()>),
    #[cfg(cyxia_startup_catalog)]
    Signed(&'call SignedCaller),
}

impl Origin<'_> {
    fn matches_root(&self, root_asid: u64) -> bool {
        match self {
            #[cfg(feature = "v020-production-diagnostic")]
            Self::Vector(_) => trapped_ttbr0() == root_asid,
            #[cfg(cyxia_startup_catalog)]
            Self::Signed(caller) => caller.root_asid() == root_asid && caller.registered(),
        }
    }
}

impl<'call> VerifiedSpan<'call> {
    #[cfg(cyxia_startup_catalog)]
    pub(super) fn verify_signed(
        caller: &'call SignedCaller,
        address: u64,
        length: usize,
        write: bool,
    ) -> Result<Self, i64> {
        if !caller.registered() {
            return Err(EFAULT);
        }
        let physical = phys(stack_span(caller.index, address, length, write).ok_or(EFAULT)?);
        Self::from_static(
            physical,
            length,
            caller.member.actor,
            caller.root_asid(),
            write,
            &SYSCALL_COPIES,
            Origin::Signed(caller),
        )
    }
}

#[cfg(feature = "v020-production-diagnostic")]
pub(super) type StackSpan = VerifiedSpan<'static>;

#[cfg(feature = "v020-production-diagnostic")]
impl StackSpan {
    #[cfg(any(
        feature = "v020-production-snapshot-catalog",
        feature = "v020-production-file-read",
        feature = "v020-production-fsync-scratch"
    ))]
    pub(super) fn verify(
        index: usize,
        member: NativeRole,
        address: u64,
        length: usize,
        write: bool,
    ) -> Result<Self, i64> {
        if member.role != Role::Supervisor {
            return Err(EFAULT);
        }
        Self::verify_stack(index, member, address, length, write, &FILE_COPIES)
    }

    #[cfg(feature = "v020-production-live-control")]
    pub(super) fn verify_audit(
        index: usize,
        member: NativeRole,
        address: u64,
        length: usize,
        write: bool,
    ) -> Result<Self, i64> {
        if member.role != Role::Supervisor {
            return Err(EFAULT);
        }
        Self::verify_stack(index, member, address, length, write, &AUDIT_COPIES)
    }

    #[cfg(feature = "v020-production-live-control")]
    pub(super) fn verify_syscall(
        index: usize,
        member: NativeRole,
        address: u64,
        length: usize,
        write: bool,
    ) -> Result<Self, i64> {
        Self::verify_stack(index, member, address, length, write, &SYSCALL_COPIES)
    }

    /// # Safety
    /// The selected role and root are authenticated, and the actual user
    /// page tables grant access to this exclusive advice backing. That
    /// backing stays pinned and stopped for this synchronous dispatch.
    pub(super) unsafe fn from_syscall_static(
        physical: u64,
        length: usize,
        owner: Identity,
        root_asid: u64,
        write: bool,
    ) -> Result<Self, i64> {
        Self::from_static(
            physical,
            length,
            owner,
            root_asid,
            write,
            &SYSCALL_COPIES,
            Origin::Vector(core::marker::PhantomData),
        )
    }

    #[cfg(any(
        feature = "v020-production-live-control",
        feature = "v020-production-fsync-scratch"
    ))]
    fn verify_stack(
        index: usize,
        member: NativeRole,
        address: u64,
        length: usize,
        write: bool,
        closed: &'static ClosedCopies,
    ) -> Result<Self, i64> {
        trapped_pie_cap(index, member).map_err(|_| EFAULT)?;
        let root_asid = member.ttbr0_root | (u64::from(role_asid(index)) << 48);
        let physical = phys(stack_span(index, address, length, write).ok_or(EFAULT)?);
        Self::from_static(
            physical,
            length,
            member.actor,
            root_asid,
            write,
            closed,
            Origin::Vector(core::marker::PhantomData),
        )
    }
}

impl<'call> VerifiedSpan<'call> {
    fn from_static(
        physical: u64,
        length: usize,
        owner: Identity,
        root_asid: u64,
        write: bool,
        closed: &'static ClosedCopies,
        origin: Origin<'call>,
    ) -> Result<Self, i64> {
        let end = physical.checked_add(length as u64).ok_or(EFAULT)?;
        if length == 0
            || !owner.valid()
            || root_asid >> 48 == 0
            || cpu::registered_slot() != Some(0)
            || !origin.matches_root(root_asid)
            || physical < cyxia_platform_virt::ENTRY
            || end > cyxia_platform_virt::KERNEL_POOL_END
            || !frames::statically_pinned_control_span(physical..end)
        {
            return Err(EFAULT);
        }
        Ok(Self {
            physical,
            length,
            owner,
            root_asid,
            write,
            closed,
            origin,
        })
    }

    pub(super) fn copy_in(&self, buffer: &mut [u8]) -> Result<(), i64> {
        if self.write {
            return Err(EFAULT);
        }
        self.copy(buffer.len(), |physical, at, count, asid| {
            // SAFETY: self describes the stopped role's pinned span. The
            // endpoint-local buffer is separate and the fragment fits a page.
            unsafe {
                copy_window::copy_in(physical, self.owner, asid, &mut buffer[at..at + count])?;
            }
            Ok(true)
        })
        .map(|_| ())
    }

    #[cfg(any(
        cyxia_startup_catalog,
        feature = "v020-production-live-control",
        feature = "v020-production-fsync-scratch"
    ))]
    pub(super) fn copy_out_and_check(&self, buffer: &[u8]) -> Result<bool, i64> {
        if !self.write {
            return Err(EFAULT);
        }
        self.copy(buffer.len(), |physical, at, count, asid| {
            // SAFETY: self proves write permission over this pinned span.
            // The endpoint-local input is disjoint from the destination.
            unsafe {
                copy_window::copy_out_and_check(physical, self.owner, asid, &buffer[at..at + count])
            }
        })
    }

    fn copy(
        &self,
        length: usize,
        mut transfer: impl FnMut(u64, usize, usize, u8) -> Result<bool, Error>,
    ) -> Result<bool, i64> {
        if length == 0
            || length > self.length
            || cpu::registered_slot() != Some(0)
            || !self.origin.matches_root(self.root_asid)
        {
            return Err(EFAULT);
        }
        let asid = (self.root_asid >> 48) as u8;
        let closed = if self.write {
            &self.closed.writes
        } else {
            &self.closed.reads
        };
        let mut at = 0;
        while at < length {
            let physical = self.physical + at as u64;
            let count = (length - at).min((PAGE_SIZE - physical % PAGE_SIZE) as usize);
            let exact = transfer(physical, at, count, asid).map_err(|_| EFAULT)?;
            closed.fetch_add(1, Ordering::Relaxed);
            if !exact {
                return Ok(false);
            }
            at += count;
        }
        Ok(true)
    }
}

#[cfg(feature = "v020-production-diagnostic")]
pub(super) fn syscall_closed_counts() -> (u64, u64, bool) {
    SYSCALL_COPIES.counts()
}

#[cfg(any(
    feature = "v020-production-snapshot-catalog",
    feature = "v020-production-file-read",
    feature = "v020-production-fsync-scratch"
))]
pub(super) fn closed_counts() -> (u64, u64, bool) {
    FILE_COPIES.counts()
}

#[cfg(feature = "v020-production-live-control")]
pub(super) fn audit_closed_counts() -> (u64, u64, bool) {
    AUDIT_COPIES.counts()
}
