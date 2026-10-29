// Exact production Activate arm. Scope/Registry/hardware are controlled here;
// business activation and service-window setup are counted boundaries.
mod candidate_owner {
    use super::*;
    use control::replay::{self as root,TrialKind};
    type DomainError=Error;
    #[derive(Clone,Copy)]struct Scope{family:Family,target:ObjectKey,frozen_scope_hash:[u8;32],first_ns:u64,observation_ns:u64}
    #[derive(Clone,Copy)]enum Phase{Activate,Run}
    struct State{scope:Option<Scope>,token:Option<root::Token>,kind:TrialKind,phase:Phase,cursor:usize}
    static STATE:Mutex<State>=Mutex::new(State{scope:Some(Scope{family:Family{domain:1,kind:1},target:key(12),
        frozen_scope_hash:[1;32],first_ns:100_000_000,observation_ns:2_000_000_000}),token:Some(root::TOKEN),
        kind:TrialKind::Candidate,phase:Phase::Activate,cursor:0});
    fn with<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{f(&mut STATE.lock().unwrap())}
    #[derive(Clone,Copy)]enum Site{ActivateSetup,ActivateRoot,ActivateFault,ActivatePublished,ActivateBaseline,ActivateWork,ActivateWindows,ActivateCommit}
    struct Trace{words:[u64;24]}
    impl Trace{fn site(&mut self,_:Site){}fn receipt(&mut self,_:Option<(u64,u64,ExecutionState)>) {}}
    struct Receipt{apply:ApplyId,stamp:PolicyStamp,state:ExecutionState}
    struct Status{phase:root::Phase,fault:Option<Error>,receipt:Option<Receipt>}
    fn poll_root(_:root::Token)->Result<Status,Error>{Ok(Status{phase:root::Phase::Running,fault:None,receipt:None})}
    static STARTS:AtomicU64=AtomicU64::new(0);
    fn activate_work()->Result<(),Error>{STARTS.fetch_add(1,Ordering::Relaxed);Ok(())}
    pub fn advance()->Result<bool,Error>{let mut trace=Trace{words:[0;24]};match Phase::Activate{
        // CANDIDATE_ACTIVATE_ARM
        Phase::Run=>(),
    }Ok(true)}
    pub fn scenario(){root::reset();assert_eq!(advance(),Ok(false),"candidate business started before publication committed");
        assert_eq!(STARTS.load(Ordering::Relaxed),0);
        control::with(|_|root::commit(Some(STAMP),ID)).unwrap();assert_eq!(advance(),Ok(true));
        assert_eq!(STARTS.load(Ordering::Relaxed),1);assert_eq!(service_windows::STARTS.load(Ordering::Relaxed),1);
        println!("candidate Activate publication guard passed");}
}
mod service_windows{
    use super::*;pub static STARTS:AtomicU64=AtomicU64::new(0);
    pub fn prepare_started(_:Family,_:ObjectKey,_:[u8;32],_:u64,_:u64)->Result<(),Error>{STARTS.fetch_add(1,Ordering::Relaxed);Ok(())}
}
