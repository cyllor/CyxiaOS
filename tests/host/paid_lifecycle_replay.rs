// Hardware source identity is out of scope; actual cleanup and query run.
pub fn service_admitted(){}
pub fn work_source(_:ObjectKey,_:u64,_:u16)->Option<ObjectKey>{None}
pub fn member_retired(_:ObjectKey){RETIRED.fetch_add(1,Ordering::Relaxed);}
const CLUSTER_CALLER:ObjectKey=ObjectKey{id:999,generation:1};
struct Replay{actor:ObjectKey,run:Option<cyxia_prototype::learning::capture::RunKey>,delivered:[Option<Result<u64,Error>>;256],expected:[u64;256],deadlines:[u64;256]}
static mut REPLAY:Replay=Replay{actor:ObjectKey{id:0x5245504c4341,generation:1},run:None,delivered:[None;256],expected:[55;256],deadlines:[5_100_000_000;256]};
fn state()->&'static mut Replay{unsafe{&mut *core::ptr::addr_of_mut!(REPLAY)}}
fn owner()->Result<(),Error>{Ok(())}
fn index(id:u64)->Result<usize,Error>{usize::try_from(id).ok().filter(|n|*n<256).ok_or(Error::Range)}
pub fn reset(){state().delivered=[None;256];}
