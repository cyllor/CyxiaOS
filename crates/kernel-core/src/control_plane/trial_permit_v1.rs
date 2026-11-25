//! V0.19.9 TrialTemplate/TrialPermit v1, exact 256-byte layouts.
//! Internal protected owner, no new ABI. The signed payload parser must
//! identify the actual template catalog entry; raw user bytes never mint
//! a permit. Only ordinary (non-Canary) trial instantiation is implemented
//! here; model management must separately prove a verified Canary model.
use super::{Error, Identity};
use crate::security::{
    durable_role_epoch_v0199::DurableEpochGate, offline_config_v1::VerifiedOfflineConfig,
};
use sha2::{Digest, Sha256};
pub const BYTES: usize = 256;
pub const MAX_PERMITS: usize = 32;
const TEMPLATE: u32 = 0x43595454;
const PERMIT: u32 = 0x43595450;
fn u16at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn p16(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}
fn p64(b: &mut [u8], i: usize, v: u64) {
    b[i..i + 8].copy_from_slice(&v.to_le_bytes());
}
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permit {
    pub permit_id: u64,
    pub boot_epoch: u64,
    pub rules_generation: u64,
    pub target_id: u64,
    pub target_generation: u64,
    pub start_ns: u64,
    pub expires_ns: u64,
    pub rule_id: u32,
    pub domain: u16,
    pub order_count: u16,
    pub flags: u16,
    pub max_submissions: u32,
    pub cpu_budget_ns: u64,
    pub memory_budget_bytes: u64,
    pub rule_hash: [u8; 32],
    pub model_hash: [u8; 32],
    pub template_id: u64,
    pub model_generation: u64,
    pub order: [u16; 32],
}
impl Permit {
    fn decode_kind(b: &[u8], template: bool) -> Result<Self, Error> {
        if b.len() != BYTES
            || u32at(b, 0) != if template { TEMPLATE } else { PERMIT }
            || u16at(b, 4) != 1
            || u16at(b, 6) != 256
            || u16at(b, 70) != 1
            || b[240..].iter().any(|&v| v != 0)
        {
            return Err(Error::Invalid);
        }
        let p = Self {
            permit_id: u64at(b, 8),
            boot_epoch: u64at(b, 16),
            rules_generation: u64at(b, 24),
            target_id: u64at(b, 32),
            target_generation: u64at(b, 40),
            start_ns: u64at(b, 48),
            expires_ns: u64at(b, 56),
            rule_id: u32at(b, 64),
            domain: u16at(b, 68),
            order_count: u16at(b, 72),
            flags: u16at(b, 74),
            max_submissions: u32at(b, 76),
            cpu_budget_ns: u64at(b, 80),
            memory_budget_bytes: u64at(b, 88),
            rule_hash: b[96..128].try_into().unwrap(),
            model_hash: b[128..160].try_into().unwrap(),
            template_id: u64at(b, 160),
            model_generation: u64at(b, 168),
            order: core::array::from_fn(|i| u16at(b, 176 + 2 * i)),
        };
        if p.rules_generation == 0
            || p.target_id == 0
            || p.rule_id == 0
            || !(1..=15).contains(&p.domain)
            || !(1..=32).contains(&p.order_count)
            || p.flags > 1
            || p.max_submissions == 0
            || p.cpu_budget_ns == 0
            || p.template_id == 0
            || p.rule_hash == [0; 32]
            || p.order[..usize::from(p.order_count)].contains(&u16::MAX)
            || p.order[usize::from(p.order_count)..]
                .iter()
                .any(|&v| v != u16::MAX)
            || p.flags == 1 && (p.domain != 15 || p.max_submissions > 300)
        {
            return Err(Error::Invalid);
        }
        if template {
            if [
                p.permit_id,
                p.boot_epoch,
                p.target_generation,
                p.start_ns,
                p.model_generation,
            ] != [0; 5]
                || p.expires_ns == 0
                || p.model_hash != [0; 32]
            {
                return Err(Error::Invalid);
            }
        } else if p.permit_id == 0
            || p.boot_epoch == 0
            || p.target_generation == 0
            || p.expires_ns <= p.start_ns
            || (p.flags == 0 && (p.model_generation != 0 || p.model_hash != [0; 32]))
            || (p.flags == 1
                && (p.model_generation == 0
                    || p.model_hash == [0; 32]
                    || p.expires_ns - p.start_ns > 30_000_000_000))
        {
            return Err(Error::Invalid);
        }
        Ok(p)
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        Self::decode_kind(b, false)
    }
    pub fn decode_template(b: &[u8]) -> Result<Self, Error> {
        Self::decode_kind(b, true)
    }
    pub fn encode(self) -> Result<[u8; BYTES], Error> {
        let mut b = [0; BYTES];
        p32(&mut b, 0, PERMIT);
        p16(&mut b, 4, 1);
        p16(&mut b, 6, 256);
        for (at, v) in [
            (8, self.permit_id),
            (16, self.boot_epoch),
            (24, self.rules_generation),
            (32, self.target_id),
            (40, self.target_generation),
            (48, self.start_ns),
            (56, self.expires_ns),
            (80, self.cpu_budget_ns),
            (88, self.memory_budget_bytes),
            (160, self.template_id),
            (168, self.model_generation),
        ] {
            p64(&mut b, at, v);
        }
        p32(&mut b, 64, self.rule_id);
        p16(&mut b, 68, self.domain);
        p16(&mut b, 70, 1);
        p16(&mut b, 72, self.order_count);
        p16(&mut b, 74, self.flags);
        p32(&mut b, 76, self.max_submissions);
        b[96..128].copy_from_slice(&self.rule_hash);
        b[128..160].copy_from_slice(&self.model_hash);
        for (i, v) in self.order.into_iter().enumerate() {
            p16(&mut b, 176 + 2 * i, v);
        }
        if Self::decode(&b)? != self {
            return Err(Error::Invalid);
        }
        Ok(b)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UseKey {
    pub controller_epoch: u64,
    pub plan_seq: u64,
    pub decision_seq: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hold {
    pub permit_id: u64,
    pub key: UseKey,
    pub ordinal: u16,
    pub accepted_count: u32,
    pub cpu_reserved: u64,
    pub memory_reserved: u64,
}
#[derive(Clone, Copy)]
struct Row {
    permit: Permit,
    count: u32,
    cpu_used: u64,
    memory_used: u64,
    last: Option<UseKey>,
    hold: Option<Hold>,
    accepted: bool,
    closed: bool,
}
pub struct TrialTable {
    boot: u64,
    controller: Identity,
    epoch: u64,
    hi: u64,
    rows: [Option<Row>; MAX_PERMITS],
}
impl TrialTable {
    pub fn new(boot: u64, controller: Identity, epoch: u64) -> Result<Self, Error> {
        if boot == 0 || !controller.valid() || epoch == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            boot,
            controller,
            epoch,
            hi: 0,
            rows: [None; MAX_PERMITS],
        })
    }
    /// Only the authenticated offline schema owner resolves the template
    /// index. Bind its bytes to the exact signed config already committed
    /// on this mounted volume. Ordinary role2 cannot mint model permits.
    // Stable wide permit API; regrouping arguments would change the public contract.
    #[allow(clippy::too_many_arguments)]
    pub fn instantiate(
        &mut self,
        actor: Identity,
        epochs: &DurableEpochGate,
        config: &VerifiedOfflineConfig<'_>,
        template_offset: usize,
        target: Identity,
        start_ns: u64,
        now_ns: u64,
        profile: &super::rule_profile_v2::Profile<'_>,
        verify_signed_entry: impl FnOnce(usize, &Permit) -> Result<(), Error>,
    ) -> Result<[u8; BYTES], Error> {
        if actor != self.controller
            || epochs
                .confirmed_config_boot(config)
                .map_err(|_| Error::Denied)?
                != self.boot
            || !target.valid()
            || start_ns < now_ns
        {
            return Err(Error::Denied);
        }
        // Templates reside after the 256-byte envelope header and 16
        // principal records, never in the signature or unrelated header.
        let wire = config.wire();
        let end = template_offset.checked_add(BYTES).ok_or(Error::Invalid)?;
        if template_offset < 512 || end > wire.len().checked_sub(64).ok_or(Error::Invalid)? {
            return Err(Error::Invalid);
        }
        let t = Permit::decode_template(&wire[template_offset..end])?;
        if t.flags != 0
            || t.target_id != target.id
            || t.rules_generation != profile.generation
            || t.rule_hash != hash(profile.canonical_bytes())
            || t.rules_generation != config.header().rule_generation
            || t.rule_hash != config.header().rule_hash
        {
            return Err(Error::Denied);
        }
        // Include all retained permit slots in the shared 64KiB rule/permit
        // budget. The owner must also account for all signed templates.
        if profile
            .canonical_bytes()
            .len()
            .checked_add(core::mem::size_of::<Self>())
            .and_then(|n| n.checked_add(BYTES))
            .is_none_or(|n| n > 65536)
        {
            return Err(Error::Exhausted);
        }
        profile.validate_trial_template(
            t.rule_id,
            t.domain,
            t.target_id,
            &t.order[..usize::from(t.order_count)],
        )?;
        verify_signed_entry(template_offset, &t)?;
        let id = self.hi.checked_add(1).ok_or(Error::Exhausted)?;
        let p = Permit {
            permit_id: id,
            boot_epoch: self.boot,
            target_generation: target.generation,
            start_ns,
            expires_ns: start_ns.checked_add(t.expires_ns).ok_or(Error::Clock)?,
            ..t
        };
        let bytes = p.encode()?;
        self.insert(p)?;
        self.hi = id;
        Ok(bytes)
    }
    fn insert(&mut self, p: Permit) -> Result<(), Error> {
        if p.boot_epoch != self.boot
            || self.rows.iter().flatten().any(|r| {
                r.permit.permit_id == p.permit_id
                    || r.permit.template_id == p.template_id && r.permit.target_id == p.target_id
            })
        {
            return Err(Error::Busy);
        }
        let slot = self
            .rows
            .iter_mut()
            .find(|v| v.is_none())
            .ok_or(Error::Exhausted)?;
        *slot = Some(Row {
            permit: p,
            count: 0,
            cpu_used: 0,
            memory_used: 0,
            last: None,
            hold: None,
            accepted: false,
            closed: false,
        });
        Ok(())
    }
    fn row(&self, id: u64) -> Result<&Row, Error> {
        self.rows
            .iter()
            .flatten()
            .find(|r| r.permit.permit_id == id)
            .ok_or(Error::Stale)
    }
    fn row_mut(&mut self, id: u64) -> Result<&mut Row, Error> {
        self.rows
            .iter_mut()
            .flatten()
            .find(|r| r.permit.permit_id == id)
            .ok_or(Error::Stale)
    }
    /// Exactly the next permitted static ordinal; no skip after a failed
    /// or unavailable candidate. Reevaluate current rule at both gates.
    // Stable wide permit API; regrouping arguments would change the public contract.
    #[allow(clippy::too_many_arguments)]
    pub fn next(
        &self,
        id: u64,
        boot: u64,
        target: Identity,
        domain: u16,
        now: u64,
        rules_generation: u64,
        rules_hash: [u8; 32],
    ) -> Result<(Permit, u16), Error> {
        let r = self.row(id)?;
        let p = r.permit;
        if r.closed
            || p.boot_epoch != boot
            || p.target_id != target.id
            || p.target_generation != target.generation
            || p.domain != domain
            || p.rules_generation != rules_generation
            || p.rule_hash != rules_hash
        {
            return Err(Error::Stale);
        }
        if now < p.start_ns || now >= p.expires_ns {
            return Err(Error::Expired);
        }
        if r.hold.is_some() {
            return Err(Error::Busy);
        }
        if r.count >= p.max_submissions {
            return Err(Error::Exhausted);
        }
        Ok((p, p.order[(r.count % u32::from(p.order_count)) as usize]))
    }
    /// Reserve before publication side effect; an ambiguous result retains
    /// the exact hold and blocks subsequent use. CPU/memory charges are
    /// conservative reservations pending independently verified settlement.
    // Stable wide permit API; regrouping arguments would change the public contract.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        id: u64,
        key: UseKey,
        ordinal: u16,
        cpu: u64,
        memory: u64,
        now: u64,
        verify_native: impl FnOnce(&Permit) -> Result<(), Error>,
    ) -> Result<Hold, Error> {
        if key.controller_epoch != self.epoch
            || key.plan_seq == 0
            || key.decision_seq == 0
            || cpu == 0
        {
            return Err(Error::Denied);
        }
        let r = self.row_mut(id)?;
        if let Some(h) = r.hold {
            return if h.key == key
                && h.ordinal == ordinal
                && h.cpu_reserved == cpu
                && h.memory_reserved == memory
            {
                Ok(h)
            } else {
                Err(Error::Busy)
            };
        }
        if r.closed || now < r.permit.start_ns || now >= r.permit.expires_ns {
            return Err(Error::Expired);
        }
        if r.last
            .is_some_and(|v| v.plan_seq >= key.plan_seq || v.decision_seq >= key.decision_seq)
        {
            return Err(Error::Stale);
        }
        if r.count >= r.permit.max_submissions
            || ordinal != r.permit.order[(r.count % u32::from(r.permit.order_count)) as usize]
            || cpu > r.permit.cpu_budget_ns.saturating_sub(r.cpu_used)
            || memory > r.permit.memory_budget_bytes.saturating_sub(r.memory_used)
        {
            return Err(Error::Exhausted);
        }
        verify_native(&r.permit)?;
        let h = Hold {
            permit_id: id,
            key,
            ordinal,
            accepted_count: r.count,
            cpu_reserved: cpu,
            memory_reserved: memory,
        };
        r.hold = Some(h);
        r.accepted = false;
        Ok(h)
    }
    /// Count only at real publication acceptance. The reservation remains
    /// owned until the independent completion/cost verifier settles it.
    pub fn confirm_accept(
        &mut self,
        h: Hold,
        verify_native: impl FnOnce(Hold) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let r = self.row_mut(h.permit_id)?;
        if r.hold != Some(h) {
            return Err(Error::Stale);
        }
        if r.accepted {
            return Ok(());
        }
        let count = r.count.checked_add(1).ok_or(Error::Exhausted)?;
        verify_native(h)?;
        r.count = count;
        r.accepted = true;
        r.last = Some(h.key);
        Ok(())
    }
    pub(super) fn hold_is_settled(&self, h: Hold) -> Result<bool, Error> {
        let r = self.row(h.permit_id)?;
        Ok(r.hold.is_none() && r.last == Some(h.key))
    }
    #[cfg(test)]
    pub(super) fn insert_fixture(&mut self, p: Permit) -> Result<(), Error> {
        p.encode()?;
        self.insert(p)
    }
    /// Only independent real acceptance/recovery may settle the hold.
    /// Failed-to-prove leaves it retained. Actual CPU overruns stay charged
    /// and permanently close the permit; no clamping or automatic retry.
    pub fn settle(
        &mut self,
        h: Hold,
        accepted: bool,
        actual_cpu: u64,
        actual_memory: u64,
        verify_native: impl FnOnce(Hold, bool) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let r = self.row_mut(h.permit_id)?;
        if r.hold != Some(h) {
            return Err(Error::Stale);
        }
        let cpu = r.cpu_used.checked_add(actual_cpu).ok_or(Error::Exhausted)?;
        let memory = r
            .memory_used
            .checked_add(actual_memory)
            .ok_or(Error::Exhausted)?;
        if r.accepted && !accepted {
            return Err(Error::Denied);
        }
        let count = r
            .count
            .checked_add(u32::from(accepted && !r.accepted))
            .ok_or(Error::Exhausted)?;
        verify_native(h, accepted)?;
        r.cpu_used = cpu;
        r.memory_used = memory;
        r.count = count;
        r.last = Some(h.key);
        r.hold = None;
        r.accepted = false;
        if actual_cpu > h.cpu_reserved
            || actual_memory > h.memory_reserved
            || cpu > r.permit.cpu_budget_ns
            || memory > r.permit.memory_budget_bytes
        {
            r.closed = true;
            return Err(Error::Exhausted);
        }
        Ok(())
    }
}
const _: () = assert!(core::mem::size_of::<TrialTable>() <= 16 * 1024);
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_order_and_unknown_reservation_never_skip_or_refill() {
        let mut t = TrialTable::new(
            1,
            Identity {
                id: 2,
                generation: 1,
            },
            3,
        )
        .unwrap();
        let mut order = [u16::MAX; 32];
        order[..3].copy_from_slice(&[1, 3, 1]);
        let p = Permit {
            permit_id: 1,
            boot_epoch: 1,
            rules_generation: 1,
            target_id: 7,
            target_generation: 2,
            start_ns: 10,
            expires_ns: 100,
            rule_id: 5,
            domain: 1,
            order_count: 3,
            flags: 0,
            max_submissions: 3,
            cpu_budget_ns: 100,
            memory_budget_bytes: 20,
            rule_hash: [9; 32],
            model_hash: [0; 32],
            template_id: 1,
            model_generation: 0,
            order,
        };
        assert_eq!(Permit::decode(&p.encode().unwrap()), Ok(p));
        t.insert(p).unwrap();
        let k = UseKey {
            controller_epoch: 3,
            plan_seq: 1,
            decision_seq: 1,
        };
        assert_eq!(
            t.reserve(1, k, 3, 10, 1, 20, |_| panic!()),
            Err(Error::Exhausted)
        );
        let h = t.reserve(1, k, 1, 10, 1, 20, |_| Ok(())).unwrap();
        assert_eq!(t.reserve(1, k, 1, 10, 1, 20, |_| panic!()), Ok(h));
        assert_eq!(
            t.next(
                1,
                1,
                Identity {
                    id: 7,
                    generation: 2
                },
                1,
                20,
                1,
                [9; 32]
            ),
            Err(Error::Busy)
        );
        assert_eq!(
            t.settle(h, true, 10, 1, |_, _| Err(Error::NotReady)),
            Err(Error::NotReady)
        );
        t.settle(h, true, 10, 1, |_, _| Ok(())).unwrap();
        assert_eq!(
            t.next(
                1,
                1,
                Identity {
                    id: 7,
                    generation: 2
                },
                1,
                21,
                1,
                [9; 32]
            )
            .unwrap()
            .1,
            3
        );
        assert_eq!(
            t.reserve(1, k, 3, 10, 1, 21, |_| panic!()),
            Err(Error::Stale)
        );
        let h = t
            .reserve(
                1,
                UseKey {
                    plan_seq: 2,
                    decision_seq: 2,
                    ..k
                },
                3,
                5,
                1,
                21,
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(
            t.settle(h, true, 6, 1, |_, _| Ok(())),
            Err(Error::Exhausted)
        );
        assert_eq!(
            t.next(
                1,
                1,
                Identity {
                    id: 7,
                    generation: 2
                },
                1,
                22,
                1,
                [9; 32]
            ),
            Err(Error::Stale)
        );
    }
}
