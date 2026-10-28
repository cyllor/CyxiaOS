pub enum ClosingWork {
    DrainStart,
    PollReturned { result: Result<bool,Error> },
    PollOrigin { stage:u64,code:u64 },
    ClosingObserved { version:u64,state:ExecutionState },
    ProbeCreated { version:u64,id:u64,deadline:u64 },
    ProbeSubmit { id:u64,entered_ns:u64,result:Result<(),Error> },
    ProbeOutcome { id:u64,result:Result<u64,Error> },
    Block { reason:u64 },
    Drained,
}
pub fn closing(_:ObjectKey,_:u64,_:ApplyId,_:PolicyStamp,_:u64,_:u64,_:u64) {}
pub fn closing_work(_:RunKey,_:ClosingWork,_:u64) {}
pub fn admission_opportunity(_:bool,_:bool,_:bool,_:u64) {}
pub fn admission_body(_:u64,_:u64) {}
pub fn admission_result(_:bool,_:u64) {}
pub fn admitted(_: &cyxia_prototype::domains::tasks::SpawnRequest,_:cyxia_prototype::domains::tasks::SpawnState,_:u64,_:u64) {}
pub fn task_block(_:RunKey,_:u64,_:[u64;6],_:u64) {}
pub fn admission_snapshot()->[u64;64] {[0;64]}
