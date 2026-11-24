//! V0.19.9 native four-vCPU topology contract, distinct from the legacy
//! V0.20 CPU1-control/CPU0-EL1-broker profile still used by old code.
//!
//! Fixed C={CPU0}, B={CPU1,CPU2,CPU3}. All EL1 trusted mechanisms remain
//! available on every vCPU. This module validates protected ownership and
//! budget attribution but does not itself start/retarget EL0 tasks, GIC IRQs,
//! timers or page tables. Such native cutover is a separate release gate.
use super::{Error, Plane, cores::{Phase, Snapshot}};

pub const ONLINE:u64=0b1111;
pub const CONTROL_CPU:usize=0;
pub const CONTROL_MASK:u64=0b0001;
pub const BUSINESS_MASK:u64=0b1110;
pub const ALL_BUSINESS_COUNT:u32=3;
pub const CONTROL_BUDGET_NS:u64=70_000_000;
pub const CONTROL_WINDOW_NS:u64=100_000_000;

/// The four-vCPU reference machine has no elastic control-core reallocation.
/// On fault, protected active obligations remain owned until terminal proof;
/// no business CPU automatically becomes the controller.
pub const fn fixed_masks(online:u64,control:u64,business:u64)->bool {
    online==ONLINE && control==CONTROL_MASK && business==BUSINESS_MASK
}
pub fn validate_snapshot(snapshot:Snapshot)->Result<(),Error>{
    if snapshot.phase!=Phase::Stable
        || snapshot.transition!=0 || snapshot.quarantined!=0
        || !fixed_masks(snapshot.online,snapshot.control,snapshot.business)
        || !snapshot.permits(CONTROL_CPU,Plane::Control)
        || snapshot.permits(CONTROL_CPU,Plane::Business)
    {return Err(Error::Denied);}
    for cpu in 1..=3 {
        if snapshot.permits(cpu,Plane::Control)
            || !snapshot.permits(cpu,Plane::Business)
        {return Err(Error::Denied);}
    }
    Ok(())
}

/// Rules apply to CPU0's *single physical control budget* (not one budget per
/// operations/security/controller/learner role). A model or supervisor cannot
/// change total reserved/actual guest execution time or the window.
pub struct ControlWindow {
    pub window_id:u64,
    pub cpu:usize,
    pub reserved_ns:u64,
    pub actual_ns:u64,
}
impl ControlWindow {
    pub fn validate(&self)->Result<(),Error>{
        if self.window_id==0 || self.cpu!=CONTROL_CPU
            || self.reserved_ns>CONTROL_BUDGET_NS
            || self.actual_ns>CONTROL_BUDGET_NS
            || self.actual_ns>CONTROL_WINDOW_NS
        {return Err(Error::Denied);}
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cores::{Limits,Ownership,ScaleProposal};
    fn limits()->Limits {
        Limits {
            resource_epoch:1,min_control_cores:1,
            min_control_capacity:100,min_business_capacity:300,
            committed_business_capacity:300,
            protected_control:CONTROL_MASK,
            protected_business:BUSINESS_MASK,
            cooldown_ticks:0,
        }
    }
    #[test]
    fn cpu0_is_the_only_control_and_three_others_are_business(){
        let s=Ownership::new_v0199_cpu0(
            ONLINE,[100;4],[1,2,4,8],limits()
        ).unwrap().snapshot();
        assert_eq!(s.control,CONTROL_MASK);
        assert_eq!(s.business,BUSINESS_MASK);
        validate_snapshot(s).unwrap();
        let mut bad=s;bad.control=0b0010;
        assert_eq!(validate_snapshot(bad),Err(Error::Denied));
        bad=s;bad.business=0b1100;
        assert_eq!(validate_snapshot(bad),Err(Error::Denied));
        bad=s;bad.online=0b0111;
        assert_eq!(validate_snapshot(bad),Err(Error::Denied));
    }
    #[test]
    fn disabled_dynamic_handoff_and_cpu0_budget_does_not_reallocate(){
        let mut o=Ownership::new_v0199_cpu0(
            ONLINE,[100;4],[1,2,4,8],limits()
        ).unwrap();
        assert_eq!(o.begin(ScaleProposal {
            generation:1,resource_epoch:1,sequence:1,
            desired_control:2,deadline:100,
        },1,limits()),Err(Error::Denied));
        assert_eq!(o.snapshot().control,CONTROL_MASK);
        assert!(ControlWindow {
            window_id:1,cpu:0,reserved_ns:70_000_000,actual_ns:70_000_000
        }.validate().is_ok());
        assert_eq!(ControlWindow {
            window_id:1,cpu:1,reserved_ns:70_000_000,actual_ns:10_000_000
        }.validate(),Err(Error::Denied));
        assert_eq!(ControlWindow {
            window_id:1,cpu:0,reserved_ns:70_000_001,actual_ns:10_000_000
        }.validate(),Err(Error::Denied));
    }
}
