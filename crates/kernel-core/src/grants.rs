//! Capacity accounting only. Physical mapping/revocation belongs to the caller.
use cyxia_contracts::*;
// Small services retain the default bound; anonymous heaps reserve a larger
// table explicitly. Metadata capacity never changes the page admission limit.
pub type GrantLedger = BoundedGrantLedger<128>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    Invalid,
    Capacity,
    Metadata,
    Owner,
    Stale,
    Exhausted,
    NotReady,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub task: TaskId,
    pub generation: Generation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedGrantRequest {
    owner: Owner,
    pages: u32,
    origin: DecisionOrigin,
}
impl AuthorizedGrantRequest {
    /// # Safety
    /// Only the trusted boot admission path may authorize capacity. Never expose to applications.
    pub unsafe fn bootstrap(owner: Owner, pages: PageCount) -> Self {
        Self {
            owner,
            pages: pages.0,
            origin: DecisionOrigin::bootstrap(),
        }
    }
    pub fn from_ai() -> Result<Self, GrantError> {
        Err(GrantError::NotReady)
    }
    /// # Safety
    /// Only a trusted resource service may call this after authenticating the
    /// model and validating its current decision, owner and resource request.
    /// AI provenance alone is not authorization. Never expose this to tasks.
    pub unsafe fn validated_ai(
        owner: Owner,
        pages: PageCount,
        model: u64,
    ) -> Result<Self, GrantError> {
        let origin = DecisionOrigin::new(DecisionSource::AiDirect, Some(model), None, None)
            .map_err(|_| GrantError::Invalid)?;
        Ok(Self {
            owner,
            pages: pages.0,
            origin,
        })
    }
}
#[derive(Debug, Clone, Copy)]
pub struct ResourceGrant {
    id: GrantId,
    owner: Owner,
    remaining: u32,
    in_use: u32,
    origin: DecisionOrigin,
    closed: bool,
}
impl ResourceGrant {
    pub fn origin(&self) -> DecisionOrigin {
        self.origin
    }
}
#[derive(Debug, Clone, Copy)]
struct Redemption {
    id: RedemptionId,
    grant: GrantId,
    owner: Owner,
    pages: u32,
}
#[derive(Debug, Clone, Copy)]
pub struct ReleaseReceipt {
    id: RedemptionId,
    owner: Owner,
    pages: u32,
}
impl ReleaseReceipt {
    /// # Safety
    /// Caller must have revoked every mapping and completed required TLB/DMA synchronization
    /// for the entire redemption. This is not a user-callable proof constructor.
    pub unsafe fn after_revoke(id: RedemptionId, owner: Owner, pages: PageCount) -> Self {
        Self {
            id,
            owner,
            pages: pages.0,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerSnapshot {
    pub capacity: u32,
    pub free: u32,
    pub reserved_unredeemed: u32,
    pub in_use: u32,
}
pub struct BoundedGrantLedger<const RECORDS: usize> {
    capacity: u32,
    // Exact sums of the live grant records, updated after validation. Their
    // combined value is bounded by capacity, including promised pages.
    reserved_unredeemed: u32,
    in_use: u32,
    grants: [Option<ResourceGrant>; RECORDS],
    redemptions: [Option<Redemption>; RECORDS],
    live_redemptions: usize,
    next_grant: u64,
    next_redemption: u64,
    #[cfg(test)]
    record_checks: core::cell::Cell<usize>,
}
impl<const RECORDS: usize> BoundedGrantLedger<RECORDS> {
    pub const fn new(capacity: PageCount) -> Self {
        Self {
            capacity: capacity.0,
            reserved_unredeemed: 0,
            in_use: 0,
            grants: [None; RECORDS],
            redemptions: [None; RECORDS],
            live_redemptions: 0,
            next_grant: 1,
            next_redemption: 1,
            #[cfg(test)]
            record_checks: core::cell::Cell::new(0),
        }
    }
    /// Restrict a fresh ledger to the frames actually reserved at boot.
    pub fn limit_boot_capacity(&mut self, capacity: PageCount) -> Result<(), GrantError> {
        if self.next_grant != 1 || self.next_redemption != 1 {
            return Err(GrantError::NotReady);
        }
        if capacity.0 == 0 || capacity.0 > self.capacity {
            return Err(GrantError::Capacity);
        }
        self.capacity = capacity.0;
        Ok(())
    }
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            capacity: self.capacity,
            free: self.capacity - (self.reserved_unredeemed + self.in_use),
            reserved_unredeemed: self.reserved_unredeemed,
            in_use: self.in_use,
        }
    }
    fn find_record<T>(
        &self,
        records: &[Option<T>; RECORDS],
        id: u64,
        mut accepts: impl FnMut(&Option<T>) -> bool,
    ) -> Option<usize> {
        let preferred = id.checked_rem(RECORDS as u64)? as usize;
        let mut check = |record: &Option<T>| {
            #[cfg(test)]
            self.record_checks.set(self.record_checks.get() + 1);
            accepts(record)
        };
        // IDs retain their full identity. Collisions can place a record away
        // from its preferred slot, so lookups validate the record and fall back.
        if check(&records[preferred]) {
            Some(preferred)
        } else {
            records.iter().position(check)
        }
    }
    pub fn commit(&mut self, r: AuthorizedGrantRequest) -> Result<GrantId, GrantError> {
        if r.pages == 0 {
            return Err(GrantError::Invalid);
        }
        let s = self.snapshot();
        if r.pages > s.free {
            return Err(GrantError::Capacity);
        }
        // Reserve identity space for the worst case: every promised page is
        // redeemed separately. checked_add deliberately never issues MAX.
        let promised_ids = u64::from(s.reserved_unredeemed) + u64::from(r.pages);
        if promised_ids > u64::MAX - self.next_redemption {
            return Err(GrantError::Exhausted);
        }
        // One future redemption record per unredeemed page guarantees bounded metadata.
        if self.live_redemptions as u64 + promised_ids > RECORDS as u64 {
            return Err(GrantError::Metadata);
        }
        let slot = self
            .find_record(&self.grants, self.next_grant, Option::is_none)
            .ok_or(GrantError::Metadata)?;
        let next = self
            .next_grant
            .checked_add(1)
            .ok_or(GrantError::Exhausted)?;
        let id = GrantId::new(self.next_grant).map_err(|_| GrantError::Exhausted)?;
        self.grants[slot] = Some(ResourceGrant {
            id,
            owner: r.owner,
            remaining: r.pages,
            in_use: 0,
            origin: r.origin,
            closed: false,
        });
        self.next_grant = next;
        self.reserved_unredeemed += r.pages;
        Ok(id)
    }
    /// Atomically admit and redeem one indivisible allocation. Unlike commit(),
    /// no promise of later page-by-page redemption is created, so a large region
    /// needs one redemption record. All failures leave the ledger unchanged.
    pub fn commit_and_redeem(
        &mut self,
        r: AuthorizedGrantRequest,
    ) -> Result<RedemptionId, GrantError> {
        if r.pages == 0 {
            return Err(GrantError::Invalid);
        }
        let snapshot = self.snapshot();
        if r.pages > snapshot.free {
            return Err(GrantError::Capacity);
        }
        let promised_ids = u64::from(snapshot.reserved_unredeemed) + 1;
        if promised_ids > u64::MAX - self.next_redemption {
            return Err(GrantError::Exhausted);
        }
        if self.live_redemptions as u64 + promised_ids > RECORDS as u64 {
            return Err(GrantError::Metadata);
        }
        let grant_slot = self
            .find_record(&self.grants, self.next_grant, Option::is_none)
            .ok_or(GrantError::Metadata)?;
        let redemption_slot = self
            .find_record(&self.redemptions, self.next_redemption, Option::is_none)
            .ok_or(GrantError::Metadata)?;
        let next_grant = self
            .next_grant
            .checked_add(1)
            .ok_or(GrantError::Exhausted)?;
        let next_redemption = self
            .next_redemption
            .checked_add(1)
            .ok_or(GrantError::Exhausted)?;
        let grant = GrantId::new(self.next_grant).map_err(|_| GrantError::Exhausted)?;
        let id = RedemptionId::new(self.next_redemption).map_err(|_| GrantError::Exhausted)?;
        self.grants[grant_slot] = Some(ResourceGrant {
            id: grant,
            owner: r.owner,
            remaining: 0,
            in_use: r.pages,
            origin: r.origin,
            closed: true,
        });
        self.redemptions[redemption_slot] = Some(Redemption {
            id,
            grant,
            owner: r.owner,
            pages: r.pages,
        });
        self.live_redemptions += 1;
        self.next_grant = next_grant;
        self.next_redemption = next_redemption;
        self.in_use += r.pages;
        Ok(id)
    }
    fn index(&self, id: GrantId, owner: Owner) -> Result<usize, GrantError> {
        let i = self
            .find_record(&self.grants, id.get(), |g| g.is_some_and(|g| g.id == id))
            .ok_or(GrantError::Stale)?;
        if self.grants[i].unwrap().owner != owner {
            Err(GrantError::Owner)
        } else {
            Ok(i)
        }
    }
    pub fn redeem(
        &mut self,
        id: GrantId,
        owner: Owner,
        pages: PageCount,
    ) -> Result<RedemptionId, GrantError> {
        let i = self.index(id, owner)?;
        let g = self.grants[i].unwrap();
        if g.closed || pages.0 == 0 || pages.0 > g.remaining {
            return Err(GrantError::Invalid);
        }
        let j = self
            .find_record(&self.redemptions, self.next_redemption, Option::is_none)
            .ok_or(GrantError::Metadata)?;
        let next = self
            .next_redemption
            .checked_add(1)
            .ok_or(GrantError::Exhausted)?;
        let rid = RedemptionId::new(self.next_redemption).map_err(|_| GrantError::Exhausted)?;
        self.redemptions[j] = Some(Redemption {
            id: rid,
            grant: id,
            owner,
            pages: pages.0,
        });
        self.live_redemptions += 1;
        self.grants[i] = Some(ResourceGrant {
            remaining: g.remaining - pages.0,
            in_use: g.in_use + pages.0,
            ..g
        });
        self.next_redemption = next;
        self.reserved_unredeemed -= pages.0;
        self.in_use += pages.0;
        Ok(rid)
    }
    pub fn cancel_unused(&mut self, id: GrantId, owner: Owner) -> Result<PageCount, GrantError> {
        let i = self.index(id, owner)?;
        let g = self.grants[i].unwrap();
        if g.closed {
            return Err(GrantError::Stale);
        };
        self.grants[i] = if g.in_use == 0 {
            None
        } else {
            Some(ResourceGrant {
                remaining: 0,
                closed: true,
                ..g
            })
        };
        self.reserved_unredeemed -= g.remaining;
        Ok(PageCount(g.remaining))
    }
    pub fn release_completed(&mut self, r: ReleaseReceipt) -> Result<(), GrantError> {
        let j = self
            .find_record(&self.redemptions, r.id.get(), |x| x.is_some_and(|x| x.id == r.id))
            .ok_or(GrantError::Stale)?;
        let d = self.redemptions[j].unwrap();
        if d.owner != r.owner || d.pages != r.pages {
            return Err(GrantError::Invalid);
        }
        let i = self.index(d.grant, r.owner)?;
        let g = self.grants[i].unwrap();
        let used = g.in_use.checked_sub(r.pages).ok_or(GrantError::Invalid)?;
        self.redemptions[j] = None;
        self.live_redemptions -= 1;
        self.grants[i] = if used == 0 && g.remaining == 0 {
            None
        } else {
            Some(ResourceGrant { in_use: used, ..g })
        };
        self.in_use -= r.pages;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noncolliding_ids_check_one_record_per_table_at_full_occupancy() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let request = unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(1)) };
        let mut ledger = GrantLedger::new(PageCount(129));
        let mut last = None;
        for _ in 0..ledger.grants.len() {
            ledger.record_checks.set(0);
            last = Some(ledger.commit_and_redeem(request).unwrap());
            assert_eq!(ledger.record_checks.get(), 2);
        }
        assert_eq!(ledger.commit_and_redeem(request), Err(GrantError::Metadata));
        ledger.record_checks.set(0);
        let receipt = unsafe { ReleaseReceipt::after_revoke(last.unwrap(), owner, PageCount(1)) };
        ledger.release_completed(receipt).unwrap();
        assert_eq!(ledger.record_checks.get(), 2);
        assert_eq!(ledger.snapshot().free, 2);
        assert_rescan(&ledger);
    }

    #[test]
    fn colliding_ids_keep_generations_owners_and_receipts_distinct() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let other = Owner {
            generation: Generation::new(2).unwrap(),
            ..owner
        };
        let request = |owner, pages| unsafe {
            AuthorizedGrantRequest::bootstrap(owner, PageCount(pages))
        };
        let receipt = |id, owner| unsafe { ReleaseReceipt::after_revoke(id, owner, PageCount(1)) };
        let mut ledger = BoundedGrantLedger::<3>::new(PageCount(12));
        let first = ledger.commit(request(owner, 1)).unwrap();
        let first_redemption = ledger.redeem(first, owner, PageCount(1)).unwrap();
        for _ in 0..2 {
            let temporary = ledger.commit_and_redeem(request(other, 1)).unwrap();
            ledger.release_completed(receipt(temporary, other)).unwrap();
        }
        let colliding = ledger.commit(request(other, 2)).unwrap();
        let second_redemption = ledger.redeem(colliding, other, PageCount(1)).unwrap();
        assert_eq!(colliding.get() - first.get(), 3);
        assert_eq!(second_redemption.get() - first_redemption.get(), 3);
        let before = ledger.snapshot();
        assert_eq!(ledger.cancel_unused(colliding, owner), Err(GrantError::Owner));
        assert_eq!(
            ledger.release_completed(receipt(second_redemption, owner)),
            Err(GrantError::Invalid)
        );
        assert_eq!(ledger.snapshot(), before);
        assert_rescan(&ledger);

        ledger.release_completed(receipt(first_redemption, owner)).unwrap();
        assert_eq!(ledger.cancel_unused(first, owner), Err(GrantError::Stale));
        assert_eq!(
            ledger.release_completed(receipt(first_redemption, owner)),
            Err(GrantError::Stale)
        );
        assert_eq!(ledger.cancel_unused(colliding, other), Ok(PageCount(1)));
        ledger.release_completed(receipt(second_redemption, other)).unwrap();
        assert_eq!(ledger.snapshot().free, 12);
        assert_rescan(&ledger);
    }

    fn assert_rescan<const N: usize>(ledger: &BoundedGrantLedger<N>) {
        // Independent oracle: never use the cached aggregates to derive totals.
        let reserved: u64 = ledger
            .grants
            .iter()
            .flatten()
            .map(|g| u64::from(g.remaining))
            .sum();
        let used: u64 = ledger
            .grants
            .iter()
            .flatten()
            .map(|g| u64::from(g.in_use))
            .sum();
        let redeemed: u64 = ledger
            .redemptions
            .iter()
            .flatten()
            .map(|r| u64::from(r.pages))
            .sum();
        assert_eq!(
            ledger.live_redemptions,
            ledger.redemptions.iter().flatten().count()
        );
        assert_eq!(used, redeemed);
        assert!(reserved + used <= u64::from(ledger.capacity));
        assert_eq!(
            ledger.snapshot(),
            LedgerSnapshot {
                capacity: ledger.capacity,
                free: (u64::from(ledger.capacity) - reserved - used) as u32,
                reserved_unredeemed: reserved as u32,
                in_use: used as u32,
            }
        );
    }
    #[test]
    fn snapshots_match_records_across_reuse_and_rejected_transitions() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let other = Owner {
            generation: Generation::new(2).unwrap(),
            ..owner
        };
        let request = |pages| unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(pages)) };
        let mut ledger = BoundedGrantLedger::<4>::new(PageCount(12));
        assert_rescan(&ledger);
        for _ in 0..1000 {
            assert_eq!(ledger.commit(request(0)), Err(GrantError::Invalid));
            assert_eq!(
                ledger.commit_and_redeem(request(0)),
                Err(GrantError::Invalid)
            );
            assert_rescan(&ledger);
            let grant = ledger.commit(request(3)).unwrap();
            assert_rescan(&ledger);
            assert_eq!(
                ledger.redeem(grant, other, PageCount(1)),
                Err(GrantError::Owner)
            );
            assert_eq!(
                ledger.redeem(grant, owner, PageCount(0)),
                Err(GrantError::Invalid)
            );
            assert_eq!(
                ledger.redeem(grant, owner, PageCount(4)),
                Err(GrantError::Invalid)
            );
            assert_eq!(ledger.cancel_unused(grant, other), Err(GrantError::Owner));
            assert_rescan(&ledger);
            let first = ledger.redeem(grant, owner, PageCount(1)).unwrap();
            assert_rescan(&ledger);
            assert_eq!(ledger.commit(request(2)), Err(GrantError::Metadata));
            assert_rescan(&ledger);
            let second = ledger.commit_and_redeem(request(5)).unwrap();
            assert_rescan(&ledger);
            assert_eq!(
                ledger.commit_and_redeem(request(5)),
                Err(GrantError::Capacity)
            );
            assert_eq!(ledger.commit(request(5)), Err(GrantError::Capacity));
            assert_rescan(&ledger);
            assert_eq!(ledger.cancel_unused(grant, owner), Ok(PageCount(2)));
            assert_rescan(&ledger);
            assert_eq!(ledger.cancel_unused(grant, owner), Err(GrantError::Stale));
            assert_eq!(
                ledger.redeem(grant, owner, PageCount(1)),
                Err(GrantError::Invalid)
            );
            // No real mappings exist in this accounting-only test.
            let receipt = unsafe { ReleaseReceipt::after_revoke(first, owner, PageCount(1)) };
            assert_eq!(
                ledger.release_completed(ReleaseReceipt {
                    owner: other,
                    ..receipt
                }),
                Err(GrantError::Invalid)
            );
            assert_eq!(
                ledger.release_completed(ReleaseReceipt {
                    pages: 2,
                    ..receipt
                }),
                Err(GrantError::Invalid)
            );
            assert_rescan(&ledger);
            ledger.release_completed(receipt).unwrap();
            assert_rescan(&ledger);
            assert_eq!(ledger.release_completed(receipt), Err(GrantError::Stale));
            assert_rescan(&ledger);
            ledger
                .release_completed(unsafe {
                    ReleaseReceipt::after_revoke(second, owner, PageCount(5))
                })
                .unwrap();
            assert_rescan(&ledger);
            assert_eq!(ledger.snapshot().free, 12);
            // Release an open grant before consuming its remaining promise.
            let grant = ledger.commit(request(2)).unwrap();
            let redemption = ledger.redeem(grant, owner, PageCount(1)).unwrap();
            ledger
                .release_completed(unsafe {
                    ReleaseReceipt::after_revoke(redemption, owner, PageCount(1))
                })
                .unwrap();
            assert_rescan(&ledger);
            assert_eq!(ledger.cancel_unused(grant, owner), Ok(PageCount(1)));
            assert_rescan(&ledger);
            assert_eq!(ledger.snapshot().free, 12);
        }
    }
    #[test]
    fn snapshot_totals_support_entire_u32_capacity() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let mut ledger = BoundedGrantLedger::<2>::new(PageCount(u32::MAX));
        let first = ledger
            .commit_and_redeem(unsafe {
                AuthorizedGrantRequest::bootstrap(owner, PageCount(u32::MAX - 1))
            })
            .unwrap();
        let second = ledger
            .commit_and_redeem(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(1)) })
            .unwrap();
        assert_rescan(&ledger);
        assert_eq!(ledger.snapshot().free, 0);
        ledger
            .release_completed(unsafe {
                ReleaseReceipt::after_revoke(first, owner, PageCount(u32::MAX - 1))
            })
            .unwrap();
        assert_rescan(&ledger);
        ledger
            .release_completed(unsafe { ReleaseReceipt::after_revoke(second, owner, PageCount(1)) })
            .unwrap();
        assert_rescan(&ledger);
        assert_eq!(ledger.snapshot().free, u32::MAX);
    }
    #[test]
    fn large_atomic_redemption_is_one_record_and_capacity_failures_are_atomic() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let mut ledger = GrantLedger::new(PageCount(4096));
        let first = ledger
            .commit_and_redeem(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(1024)) })
            .unwrap();
        let second = ledger
            .commit_and_redeem(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(3072)) })
            .unwrap();
        assert_eq!(ledger.snapshot().free, 0);
        let snapshot = ledger.snapshot();
        assert_eq!(
            ledger.commit_and_redeem(unsafe {
                AuthorizedGrantRequest::bootstrap(owner, PageCount(1))
            }),
            Err(GrantError::Capacity)
        );
        assert_eq!(ledger.snapshot(), snapshot);
        let receipt = unsafe { ReleaseReceipt::after_revoke(first, owner, PageCount(1024)) };
        ledger.release_completed(receipt).unwrap();
        assert_eq!(ledger.release_completed(receipt), Err(GrantError::Stale));
        ledger
            .release_completed(unsafe {
                ReleaseReceipt::after_revoke(second, owner, PageCount(3072))
            })
            .unwrap();
        assert_eq!(ledger.snapshot().free, 4096);
    }
    #[test]
    fn atomic_redemption_preserves_promised_identity_space() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let mut ledger = GrantLedger::new(PageCount(4096));
        ledger.next_redemption = u64::MAX - 2;
        let promised = ledger
            .commit(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(2)) })
            .unwrap();
        let snapshot = ledger.snapshot();
        assert_eq!(
            ledger.commit_and_redeem(unsafe {
                AuthorizedGrantRequest::bootstrap(owner, PageCount(100))
            }),
            Err(GrantError::Exhausted)
        );
        assert_eq!(ledger.snapshot(), snapshot);
        ledger.redeem(promised, owner, PageCount(1)).unwrap();
        ledger.redeem(promised, owner, PageCount(1)).unwrap();
    }
    #[test]
    fn exhausted_ids_do_not_mutate() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let mut l = GrantLedger::new(PageCount(4));
        l.next_grant = u64::MAX;
        assert_eq!(
            l.commit(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(1)) }),
            Err(GrantError::Exhausted)
        );
        assert_eq!(l.snapshot().free, 4);
        l.next_grant = 1;
        let g = l
            .commit(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(2)) })
            .unwrap();
        l.next_redemption = u64::MAX;
        assert_eq!(l.redeem(g, owner, PageCount(1)), Err(GrantError::Exhausted));
        assert_eq!(l.snapshot().reserved_unredeemed, 2);
    }
    #[test]
    fn plan_expiry_does_not_void_committed_grant() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let plan = PlanAllowance {
            plan: PlanId::new(1).unwrap(),
            limit: PageCount(100),
            expires: TimeNs(10),
        };
        let mut l = GrantLedger::new(PageCount(200));
        let g = l
            .commit(AuthorizedGrantRequest {
                owner,
                pages: 100,
                origin: DecisionOrigin::new(DecisionSource::AiPlan, Some(1), Some(plan.plan), None)
                    .unwrap(),
            })
            .unwrap();
        l.redeem(g, owner, PageCount(20)).unwrap();
        let now = TimeNs(11);
        assert!(now > plan.expires);
        l.redeem(g, owner, PageCount(1)).unwrap();
        assert_eq!(l.snapshot().reserved_unredeemed, 79);
    }
    #[test]
    fn commit_reserves_redemption_ids_for_all_promised_pages() {
        let owner = Owner {
            task: TaskId::new(1).unwrap(),
            generation: Generation::new(1).unwrap(),
        };
        let mut l = GrantLedger::new(PageCount(4));
        l.next_redemption = u64::MAX - 2;
        let g = l
            .commit(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(1)) })
            .unwrap();
        let before = l.snapshot();
        assert_eq!(
            l.commit(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(2)) }),
            Err(GrantError::Exhausted)
        );
        assert_eq!(l.snapshot(), before);
        l.redeem(g, owner, PageCount(1)).unwrap();
        let g2 = l
            .commit(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(1)) })
            .unwrap();
        l.redeem(g2, owner, PageCount(1)).unwrap();
        let before = l.snapshot();
        assert_eq!(
            l.commit(unsafe { AuthorizedGrantRequest::bootstrap(owner, PageCount(1)) }),
            Err(GrantError::Exhausted)
        );
        assert_eq!(l.snapshot(), before);
    }
}
