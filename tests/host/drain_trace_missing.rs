// Pre-feature adapter: compile the real old bodies and fail on missing facts.
static TRACE_DRAIN_WORK_EVIDENCE: Evidence<64> = Evidence::new();
static TRACE_DRAIN_TASK_EVIDENCE: Evidence<128> = Evidence::new();
pub struct WorkWait {pub counts:[u64;3],pub request:[u64;5],pub warm:[u64;3],pub background_done:bool}
pub fn drain_work(_:RunKey,_:WorkWait,_:bool,_:u64) {}
pub fn drain_tracking(_:RunKey)->bool {false}
#[derive(Clone,Copy)] pub struct DrainWatch {pub first_at:u64,pub latest_at:u64}
pub fn drain_watch(_:RunKey,_:u64)->Option<DrainWatch> {None}
#[derive(Clone,Copy)] pub struct DrainTask {pub run:RunKey,pub caller:ObjectKey,pub id:u64,pub child:ObjectKey,pub life:u64,pub flags:u64,pub deadline:u64,pub exit_code:u64,pub exit_finished:u64,pub watch:DrainWatch}
pub fn drain_query(_:DrainTask,_:Result<cyxia_prototype::domains::tasks::SpawnState,Error>,_:Option<Result<u64,Error>>,_:u64) {}
pub fn drain_lifecycle(_:DrainTask,_:u64,_:u64,_:u64) {}
pub fn drain_cleanup(_:DrainTask,_:Result<(),Error>,_:u64,_:u64,_:u64) {}
