//! SEC-M: bounded mapping checks and non-forgetting TLB/DMA retirement.
//! This is not a hardware PTE flusher or a replacement for the platform ledger.
use super::Error;

pub const PAGE_SIZE: u64 = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind { User, Kernel, Control, Recovery, Device }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub owner: u64,
    pub generation: u64,
    pub kind: FrameKind,
    pub zeroed: bool,
    /// Any writable/executable alias of the same physical frame must count.
    pub writable_alias: bool,
    pub executable_alias: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}
/// An EL1 registry-owned shared-memory permission, not a caller boolean.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedGrant {
    owner: u64,
    grantee: u64,
    frame_generation: u64,
}
impl SharedGrant {
    #[allow(dead_code)]
    pub(crate) const fn from_registry(owner: u64, grantee: u64, frame_generation: u64) -> Self {
        Self { owner, grantee, frame_generation }
    }
}
pub fn authorize_mapping(
    frame: Frame,
    caller: u64,
    rights: Permissions,
    shared: Option<SharedGrant>,
) -> Result<(), Error> {
    if caller == 0 || frame.generation == 0 || frame.kind != FrameKind::User {
        return Err(Error::Unauthorized);
    }
    if frame.owner != caller && !shared.is_some_and(|g| {
        g.owner == frame.owner && g.grantee == caller && g.frame_generation == frame.generation
    }) {
        return Err(Error::Unauthorized);
    }
    if !frame.zeroed {
        return Err(Error::Busy);
    }
    if (rights.write && rights.execute)
        || (rights.write && frame.executable_alias)
        || (rights.execute && frame.writable_alias)
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
pub fn checked_user_span(
    base: u64, length: usize, window_base: u64, window_end: u64,
) -> Result<(u64, u64), Error> {
    if length == 0 || window_base >= window_end {
        return Err(Error::Invalid);
    }
    let length = u64::try_from(length).map_err(|_| Error::Invalid)?;
    let end = base.checked_add(length).ok_or(Error::Invalid)?;
    if base < window_base || end > window_end { return Err(Error::Unauthorized); }
    Ok((base, end))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shootdown {
    pub request_id: u64,
    pub generation: u64,
    targets: u64,
    acknowledged: u64,
    references: u16,
    pins: u16,
    dma_inflight: u16,
    revoked: bool,
}
impl Shootdown {
    pub fn begin(
        request_id: u64, generation: u64, targets: u64,
        references: u16, pins: u16, dma_inflight: u16,
    ) -> Result<Self, Error> {
        if request_id == 0 || generation == 0 { return Err(Error::Invalid); }
        Ok(Self {
            request_id, generation, targets, acknowledged: 0,
            references, pins, dma_inflight, revoked: false,
        })
    }
    /// Native adapter must revoke page-table access and execute the required
    /// barrier BEFORE acknowledging that revocation here.
    pub fn revoke_pte(&mut self) { self.revoked = true; }
    /// A CPU's actual generation and architectural TLB completion are evidence,
    /// not an AI assertion or a message payload.
    pub fn acknowledge(
        &mut self, request_id: u64, generation: u64, cpu: u8,
    ) -> Result<(), Error> {
        if !self.revoked || request_id != self.request_id || generation != self.generation {
            return Err(Error::Stale);
        }
        let bit = 1u64.checked_shl(cpu as u32).ok_or(Error::Invalid)?;
        if self.targets & bit == 0 { return Err(Error::Unauthorized); }
        self.acknowledged |= bit;
        Ok(())
    }
    pub fn release_reference(&mut self) -> Result<(), Error> {
        self.references = self.references.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn release_pin(&mut self) -> Result<(), Error> {
        if self.dma_inflight != 0 { return Err(Error::Busy); }
        self.pins = self.pins.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn complete_dma(&mut self) -> Result<(), Error> {
        self.dma_inflight = self.dma_inflight.checked_sub(1).ok_or(Error::Invalid)?;
        Ok(())
    }
    pub fn may_reuse(&self) -> bool {
        self.revoked && (self.acknowledged & self.targets) == self.targets
            && self.references == 0 && self.pins == 0 && self.dma_inflight == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user() -> Frame {
        Frame {
            owner: 7, generation: 3, kind: FrameKind::User,
            zeroed: true, writable_alias: false, executable_alias: false,
        }
    }
    fn data() -> Permissions { Permissions { read: true, write: true, execute: false } }
    #[test] fn sec_m01_never_map_private_kernel_or_control_frames() {
        let mut f = user();
        f.kind = FrameKind::Control;
        assert_eq!(authorize_mapping(f, 7, data(), None), Err(Error::Unauthorized));
        f.kind = FrameKind::User;
        assert_eq!(authorize_mapping(f, 8, data(), None), Err(Error::Unauthorized));
    }
    #[test] fn sec_m02_wx_and_aliases_rejected() {
        let f = user();
        assert_eq!(authorize_mapping(f, 7, Permissions { execute: true, ..data() }, None), Err(Error::Unauthorized));
        let mut alias = user(); alias.executable_alias = true;
        assert_eq!(authorize_mapping(alias, 7, data(), None), Err(Error::Unauthorized));
    }
    #[test] fn sec_m03_unzeroed_user_frame_cannot_be_published() {
        let mut f = user(); f.zeroed = false;
        assert_eq!(authorize_mapping(f, 7, data(), None), Err(Error::Busy));
    }
    #[test] fn sec_m04_missing_tlb_ack_retains_frame() {
        let mut s = Shootdown::begin(1, 2, 0b110, 0, 0, 0).unwrap();
        s.revoke_pte();
        s.acknowledge(1, 2, 1).unwrap();
        assert!(!s.may_reuse());
        s.acknowledge(1, 2, 2).unwrap();
        assert!(s.may_reuse());
    }
    #[test] fn sec_m05_checked_user_copy_range() {
        assert_eq!(checked_user_span(u64::MAX, 2, 1, u64::MAX), Err(Error::Invalid));
        assert_eq!(checked_user_span(5, 4, 8, 12), Err(Error::Unauthorized));
        assert_eq!(checked_user_span(8, 4, 8, 12), Ok((8, 12)));
    }
    #[test] fn sec_m06_dma_and_pin_survive_cpu_unmap() {
        let mut s = Shootdown::begin(1, 2, 1, 0, 1, 1).unwrap();
        s.revoke_pte();
        s.acknowledge(1, 2, 0).unwrap();
        assert!(!s.may_reuse());
        assert_eq!(s.release_pin(), Err(Error::Busy));
        s.complete_dma().unwrap();
        s.release_pin().unwrap();
        assert!(s.may_reuse());
    }
    #[test] fn sec_m07_no_reuse_before_all_references_release() {
        let mut s = Shootdown::begin(1, 2, 0, 1, 0, 0).unwrap();
        s.revoke_pte();
        assert!(!s.may_reuse());
        s.release_reference().unwrap();
        assert!(s.may_reuse());
    }
    #[test] fn sec_m08_stale_tlb_generation_not_an_ack() {
        let mut s = Shootdown::begin(1, 2, 1, 0, 0, 0).unwrap();
        s.revoke_pte();
        assert_eq!(s.acknowledge(1, 1, 0), Err(Error::Stale));
        assert!(!s.may_reuse());
    }
}
