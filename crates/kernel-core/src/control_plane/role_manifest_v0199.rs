//! V0.19.9 eight-role *native EL0 launch contract* (G0/G1).
//!
//! Validation is a necessary boot-time check, NOT proof that eight page tables
//! or threads have actually been constructed or that the CPU0 migration is
//! complete. EL1 must supply VERIFIED TTBR roots, distinct page ownership,
//! actual task IDs and privileged capability table. No role number in a wire
//! message confers authority. Unverified roles fail closed; no fallback to
//! hosted agents or CPU1 controllers.
use super::{Error, Identity};

pub const CONTROL_CPU:usize=0;
pub const CONTROL_MASK:u64=1u64<<CONTROL_CPU;
pub const BUSINESS_MASK:u64=0b1110;
pub const REQUIRED_ONLINE_MASK:u64=0b1111;
pub const ROLE_COUNT:usize=8;
pub const CONTROL_POOL_LIMIT:usize=8*1024*1024;
pub const CONTROL_NS_PER_100MS:u64=70_000_000;
pub const OPERATIONS_MAX_NS:u64=30_000_000;
pub const SECURITY_MAX_NS:u64=8_000_000;
pub const PAGE_SIZE:u64=4096;

pub const SNAPSHOT:u64=1<<0;
pub const SEND_ADVICE:u64=1<<1;
pub const SEND_FINDING:u64=1<<2;
pub const READ_RULES:u64=1<<3;
pub const DECISION_REGISTER:u64=1<<4;
pub const READ_DECISIONS:u64=1<<5;
pub const PUBLISH_PLAN:u64=1<<6;
pub const CANDIDATE_READ:u64=1<<7;
pub const VALIDATION_REGISTER:u64=1<<8;
pub const MODEL_MANAGE:u64=1<<9;
pub const TRIAL_D15:u64=1<<10;
pub const LEARNING_FEEDBACK:u64=1<<11;
pub const CANDIDATE_SUBMIT:u64=1<<12;
pub const AUDIT_READ:u64=1<<13;
pub const FINDING_REVIEW:u64=1<<14;

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Role{
    Operations,
    Security,
    DeterministicController,
    Publisher,
    Validator,
    ModelManager,
    Learner,
    Supervisor,
}
impl Role{
    pub const fn id(self)->u16{
        match self{
            Self::Operations=>6,Self::Security=>7,
            Self::DeterministicController=>2,Self::Publisher=>8,
            Self::Validator=>9,Self::ModelManager=>3,
            Self::Learner=>10,Self::Supervisor=>11,
        }
    }
    pub const fn allowed_caps(self)->u64{
        match self{
            Self::Operations=>SNAPSHOT|SEND_ADVICE,
            Self::Security=>SNAPSHOT|SEND_FINDING,
            Self::DeterministicController=>READ_RULES|DECISION_REGISTER,
            Self::Publisher=>READ_DECISIONS|PUBLISH_PLAN,
            Self::Validator=>CANDIDATE_READ|VALIDATION_REGISTER,
            Self::ModelManager=>MODEL_MANAGE|TRIAL_D15,
            Self::Learner=>LEARNING_FEEDBACK|CANDIDATE_SUBMIT,
            Self::Supervisor=>AUDIT_READ|FINDING_REVIEW,
        }
    }
}
pub const ROLES:[Role;ROLE_COUNT]=[
    Role::Operations,Role::Security,Role::DeterministicController,
    Role::Publisher,Role::Validator,Role::ModelManager,
    Role::Learner,Role::Supervisor,
];

/// Region is derived from EL1 owned-page metadata, not a naked model VA.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct PrivateRegion{
    pub base:u64,
    pub bytes:u64,
}
impl PrivateRegion{
    fn valid(self)->bool{
        self.base!=0 && self.base%PAGE_SIZE==0
            && self.bytes>=PAGE_SIZE && self.bytes%PAGE_SIZE==0
            && self.base.checked_add(self.bytes).is_some()
    }
    fn overlaps(self,other:Self)->bool{
        // Safe because caller first validates both intervals.
        self.base < other.base+other.bytes && other.base < self.base+self.bytes
    }
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct NativeRole{
    pub role:Role,
    pub actor:Identity,
    /// Actual, EL1-verified nonzero physical TTBR0 root, private per-role.
    pub ttbr0_root:u64,
    /// EL1-owned and mapped private user writable pages (not shared).
    pub private_rw:PrivateRegion,
    pub caps:u64,
    /// Genuine protected per-role CPU budget debit, all on CPU0.
    pub control_ns_per_100ms:u64,
    pub cpu_mask:u64,
    pub thread_count:u16,
    /// Distinct EL1 endpoint selector; cannot be self-reported by EL0.
    pub endpoint_id:u64,
}
#[derive(Clone,Copy)]
pub struct NativeRoleManifest {
    pub online_mask:u64,
    pub members:[NativeRole;ROLE_COUNT],
    pub other_protected_pool_bytes:usize,
    pub other_control_ns_per_100ms:u64,
}
impl NativeRoleManifest {
    pub fn validate(&self)->Result<(),Error>{
        if self.online_mask & REQUIRED_ONLINE_MASK != REQUIRED_ONLINE_MASK
            || self.other_control_ns_per_100ms>=CONTROL_NS_PER_100MS
            || self.other_protected_pool_bytes>=CONTROL_POOL_LIMIT
        {return Err(Error::Denied);}
        let mut charge_ns=self.other_control_ns_per_100ms;
        let mut pool=self.other_protected_pool_bytes;
        for (index,entry) in self.members.iter().enumerate(){
            if entry.role!=ROLES[index]
                || !entry.actor.valid()
                || entry.ttbr0_root==0 || entry.ttbr0_root%PAGE_SIZE!=0
                || entry.cpu_mask!=CONTROL_MASK || entry.thread_count!=1
                || entry.endpoint_id==0 || !entry.private_rw.valid()
                || entry.caps != entry.role.allowed_caps()
                || entry.control_ns_per_100ms==0
                || (entry.role==Role::Operations
                    && entry.control_ns_per_100ms>OPERATIONS_MAX_NS)
                || (entry.role==Role::Security
                    && entry.control_ns_per_100ms>SECURITY_MAX_NS)
            {return Err(Error::Denied);}
            charge_ns=charge_ns.checked_add(entry.control_ns_per_100ms)
                .ok_or(Error::Exhausted)?;
            pool=pool.checked_add(
                usize::try_from(entry.private_rw.bytes).map_err(|_|Error::Exhausted)?
            ).ok_or(Error::Exhausted)?;
            for prior in &self.members[..index]{
                if prior.actor==entry.actor
                    || prior.ttbr0_root==entry.ttbr0_root
                    || prior.endpoint_id==entry.endpoint_id
                    || prior.private_rw.overlaps(entry.private_rw)
                {return Err(Error::Denied);}
            }
        }
        if charge_ns>CONTROL_NS_PER_100MS || pool>CONTROL_POOL_LIMIT {
            return Err(Error::Exhausted);
        }
        Ok(())
    }

    /// No independent role manifests may remap the sole control CPU to a
    /// business core or grant publishers to either advisory brain.
    pub fn can_act(&self,role:Role,actor:Identity,cap:u64,cpu:usize)
        ->Result<(),Error>
    {
        self.validate()?;
        if cpu!=CONTROL_CPU || cap==0 || cap.count_ones()!=1 {
            return Err(Error::Denied);
        }
        let entry=self.members.iter().find(|m|m.role==role)
            .ok_or(Error::Denied)?;
        if entry.actor!=actor || entry.caps&cap==0 {
            return Err(Error::Denied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    fn manifest()->NativeRoleManifest{
        let members=core::array::from_fn(|i| NativeRole{
            role:ROLES[i],
            actor:Identity{id:i as u64+1,generation:1},
            ttbr0_root:0x100000+i as u64*PAGE_SIZE,
            private_rw:PrivateRegion{
                base:0x200000+i as u64*PAGE_SIZE*16,
                bytes:PAGE_SIZE*16,
            },
            caps:ROLES[i].allowed_caps(),
            control_ns_per_100ms:2_000_000,
            cpu_mask:CONTROL_MASK,
            thread_count:1,
            endpoint_id:i as u64+10,
        });
        NativeRoleManifest{
            online_mask:REQUIRED_ONLINE_MASK,
            members,
            other_protected_pool_bytes:5*1024*1024,
            other_control_ns_per_100ms:45_000_000,
        }
    }
    #[test]
    fn v0199_requires_eight_distinct_native_el0_roles_on_cpu0(){
        let m=manifest();m.validate().unwrap();
        for role in ROLES {
            let entry=m.members.iter().find(|e|e.role==role).unwrap();
            m.can_act(role,entry.actor,entry.caps&(!entry.caps+1),0).unwrap();
            assert_eq!(m.can_act(role,entry.actor,entry.caps&(!entry.caps+1),1),Err(Error::Denied));
            assert_eq!(entry.cpu_mask,1);
        }
        let ops=m.members[0];
        assert_eq!(m.can_act(Role::Operations,ops.actor,PUBLISH_PLAN,0),Err(Error::Denied));
        let security=m.members[1];
        assert_eq!(m.can_act(Role::Security,security.actor,DECISION_REGISTER,0),Err(Error::Denied));
        assert_eq!(m.can_act(Role::Publisher,ops.actor,PUBLISH_PLAN,0),Err(Error::Denied));
    }
    #[test]
    fn repeated_ttbr_identity_endpoint_or_rw_pages_fail_closed(){
        let m=manifest();
        let mut bad=m;bad.members[1].ttbr0_root=m.members[0].ttbr0_root;
        assert_eq!(bad.validate(),Err(Error::Denied));
        bad=m;bad.members[1].actor=m.members[0].actor;
        assert_eq!(bad.validate(),Err(Error::Denied));
        bad=m;bad.members[1].endpoint_id=m.members[0].endpoint_id;
        assert_eq!(bad.validate(),Err(Error::Denied));
        bad=m;bad.members[1].private_rw=m.members[0].private_rw;
        assert_eq!(bad.validate(),Err(Error::Denied));
        bad=m;bad.members[1].cpu_mask=0b10;
        assert_eq!(bad.validate(),Err(Error::Denied));
        bad=m;bad.members[1].caps|=PUBLISH_PLAN;
        assert_eq!(bad.validate(),Err(Error::Denied));
    }
    #[test]
    fn single_control_ledger_and_pool_fail_closed_on_overcommit(){
        let mut m=manifest();
        m.other_control_ns_per_100ms=69_000_000;
        assert_eq!(m.validate(),Err(Error::Exhausted));
        m=manifest();m.other_protected_pool_bytes=8*1024*1024-4096;
        assert_eq!(m.validate(),Err(Error::Exhausted));
        m=manifest();m.members[1].control_ns_per_100ms=8_000_001;
        assert_eq!(m.validate(),Err(Error::Denied));
        m=manifest();m.online_mask=0b0111;
        assert_eq!(m.validate(),Err(Error::Denied));
    }
}
