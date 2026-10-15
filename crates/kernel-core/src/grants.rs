//! Capacity accounting only. Physical mapping/revocation belongs to the caller.
use cyxia_contracts::*;
const GRANTS: usize = 64;
const REDEMPTIONS: usize = 128;
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
pub struct GrantLedger {
    capacity: u32,
    grants: [Option<ResourceGrant>; GRANTS],
    redemptions: [Option<Redemption>; REDEMPTIONS],
    next_grant: u64,
    next_redemption: u64,
}
impl GrantLedger {
    pub const fn new(capacity: PageCount) -> Self {
        Self {
            capacity: capacity.0,
            grants: [None; GRANTS],
            redemptions: [None; REDEMPTIONS],
            next_grant: 1,
            next_redemption: 1,
        }
    }
    pub fn snapshot(&self) -> LedgerSnapshot {
        let mut s = LedgerSnapshot {
            capacity: self.capacity,
            free: self.capacity,
            reserved_unredeemed: 0,
            in_use: 0,
        };
        for g in self.grants.iter().flatten() {
            s.reserved_unredeemed += g.remaining;
            s.in_use += g.in_use;
        }
        s.free -= s.reserved_unredeemed + s.in_use;
        s
    }
    pub fn commit(&mut self, r: AuthorizedGrantRequest) -> Result<GrantId, GrantError> {
        if r.pages == 0 {
            return Err(GrantError::Invalid);
        }
        let s = self.snapshot();
        if r.pages > s.free {
            return Err(GrantError::Capacity);
        }
        // One future redemption record per unredeemed page guarantees bounded metadata.
        let records = self.redemptions.iter().flatten().count();
        if records as u64 + s.reserved_unredeemed as u64 + r.pages as u64 > REDEMPTIONS as u64 {
            return Err(GrantError::Metadata);
        }
        let slot = self
            .grants
            .iter()
            .position(Option::is_none)
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
        Ok(id)
    }
    fn index(&self, id: GrantId, owner: Owner) -> Result<usize, GrantError> {
        let i = self
            .grants
            .iter()
            .position(|g| g.is_some_and(|g| g.id == id))
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
            .redemptions
            .iter()
            .position(Option::is_none)
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
        self.grants[i] = Some(ResourceGrant {
            remaining: g.remaining - pages.0,
            in_use: g.in_use + pages.0,
            ..g
        });
        self.next_redemption = next;
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
        Ok(PageCount(g.remaining))
    }
    pub fn release_completed(&mut self, r: ReleaseReceipt) -> Result<(), GrantError> {
        let j = self
            .redemptions
            .iter()
            .position(|x| x.is_some_and(|x| x.id == r.id))
            .ok_or(GrantError::Stale)?;
        let d = self.redemptions[j].unwrap();
        if d.owner != r.owner || d.pages != r.pages {
            return Err(GrantError::Invalid);
        }
        let i = self.index(d.grant, r.owner)?;
        let g = self.grants[i].unwrap();
        let used = g.in_use.checked_sub(r.pages).ok_or(GrantError::Invalid)?;
        self.redemptions[j] = None;
        self.grants[i] = if used == 0 && g.remaining == 0 {
            None
        } else {
            Some(ResourceGrant { in_use: used, ..g })
        };
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
}
