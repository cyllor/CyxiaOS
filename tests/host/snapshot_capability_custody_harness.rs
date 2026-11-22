use cyxia_prototype::{domains::{Error,ObjectKey,io::Class,tasks::*},snapshot::{Control,Request,RequestRecord}};
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicBool,AtomicU64,Ordering}};
const OWNER:ObjectKey=ObjectKey{id:7,generation:1};
const OBJECT:ObjectKey=ObjectKey{id:8,generation:1};
const FILE_SERVICE:ObjectKey=ObjectKey{id:9,generation:1};
static LATE_NOTIFICATION:AtomicBool=AtomicBool::new(false);
static INVALIDATIONS:AtomicU64=AtomicU64::new(0);
mod cpu{pub fn slot()->usize{0}}
mod memory{pub fn invalidate_file(_:super::ObjectKey){super::INVALIDATIONS.fetch_add(1,super::Ordering::Relaxed);}}
struct Metadata{size:u64}
struct Files{epoch:u64,reads:Cell<u64>}
impl Files{
 fn stat_object(&self,_:ObjectKey)->Result<Metadata,Error>{self.reads.set(self.reads.get()+1);Ok(Metadata{size:1})}
 fn read_cache_page(&mut self,_:ObjectKey,_:u64,out:&mut[u8;4096],_:&mut(),_:&mut(),_:&mut[u8;8192])->Result<(),Error>{self.reads.set(self.reads.get()+1);out.fill(1);Ok(())}
 fn snapshot_control(&self)->Result<Control,Error>{let mut c=Control::initial([1;16]);c.live_view_epoch=self.epoch;Ok(c)}
 fn snapshot_execute(&mut self,_:Request,_:u16,_:&[u8],_:&mut(),_:&mut(),_:&mut[u8;8192])->Result<RequestRecord,Error>{self.epoch=2;Ok(RequestRecord::FREE)}
}
thread_local!{static FILES:RefCell<Files>=const{RefCell::new(Files{epoch:1,reads:Cell::new(0)})};}
fn ready_read()->Result<(),Error>{Ok(())} fn ready()->Result<(),Error>{Ok(())}
fn late_notification(){if LATE_NOTIFICATION.swap(false,Ordering::AcqRel){domain_tasks::invalidate_file_capabilities();}}
fn read_files<R>(f:impl FnOnce(&Files)->Result<R,Error>)->Result<R,Error>{late_notification();FILES.with(|v|f(&v.borrow()))}
fn with_files<R>(f:impl FnOnce(&mut Files)->Result<R,Error>)->Result<R,Error>{
 late_notification();FILES.with(|v|{let mut v=v.borrow_mut();let before=v.epoch;let result=f(&mut v);
 if v.epoch!=before{assert!(domain_tasks::file_capabilities_invalidated(),"restored view escaped its owner before capability revocation");}result})
}
mod storage{
 use super::*;
 pub fn validate_io_health()->Result<(),Error>{Ok(())}
 pub fn try_with_class<R>(_:Class,_:&mut dyn FnMut(),f:impl FnOnce(&mut(),&mut(),&mut[u8;8192])->R)->Result<R,Error>{Ok(f(&mut(),&mut(),&mut[0;8192]))}
}
mod domain_storage{use super::*;
// STORAGE_BODIES
}
struct State{tasks:[ObjectKey;1],services:ServiceBatch,validate_file:Option<fn(ObjectKey)->Result<(),Error>>}
thread_local!{static TASKS:RefCell<State>=RefCell::new(State{tasks:[OWNER],services:ServiceBatch::new(),validate_file:Some(domain_storage::validate_file_object)});}
fn task_index(tasks:&[ObjectKey],owner:ObjectKey)->Result<usize,Error>{tasks.iter().position(|v|*v==owner).ok_or(Error::Stale)}
fn locked<R>(f:impl FnOnce(&mut State)->Result<R,Error>)->Result<R,Error>{TASKS.with(|v|f(&mut v.borrow_mut()))}
mod domain_tasks{use super::*;
static FILE_CAPABILITIES_INVALIDATED:AtomicBool=AtomicBool::new(false);
// CAPABILITY_BODIES
pub fn reset_for_test(){FILE_CAPABILITIES_INVALIDATED.store(false,Ordering::Release);}
}
struct Backend;
impl ServiceBackend for Backend{
 fn validate_object(&mut self,_:ObjectKey,_:u16)->Result<(),Error>{Ok(())}
 fn call_batch(&mut self,_:ObjectKey,items:&[ResolvedItem],out:&mut[Option<Result<u64,Error>>])->Result<(),Error>{for i in 0..items.len(){out[i]=Some(Ok(17));}Ok(())}
}
fn resolve(cap:u64,now:u64)->ItemStatus{locked(|s|{
 let mut vector=s.services.submit(OWNER,&[ServiceItem{op:FILE_STAT_BY_CAP,flags:0,cap,object_gen:1,tag:1}],now+100,now)?;
 s.services.step(&mut vector,now,&mut Backend)?;Ok(vector.results()[0].status)
}).unwrap()}
fn main(){
 for operation in 0..3{
  domain_tasks::reset_for_test();FILES.with(|f|f.borrow().reads.set(0));LATE_NOTIFICATION.store(true,Ordering::Release);
  let result=match operation{0=>domain_storage::validate_file_object(OBJECT),1=>domain_storage::stat_file_object(OBJECT).map(|_|()),_=>domain_storage::read_cache_page(OBJECT,0,&mut[0;4096])};
  assert_eq!(result,Err(Error::Stale));FILES.with(|f|assert_eq!(f.borrow().reads.get(),0,"old authority read a new view"));
 }
 domain_tasks::reset_for_test();
 let old=domain_tasks::grant_file_cap(OWNER,OBJECT).unwrap();assert_eq!(resolve(old,1),ItemStatus::Value(17));
 let before=INVALIDATIONS.load(Ordering::Relaxed);
 let request=Request{key:cyxia_prototype::snapshot::FileReqKey::ZERO,expected_live_view_epoch:1};
 domain_storage::snapshot_execute(request,0x23,&[],&mut||{}).unwrap();
 assert_eq!(INVALIDATIONS.load(Ordering::Relaxed),before+1);
 domain_storage::snapshot_execute(request,0x23,&[],&mut||{}).unwrap();
 assert_eq!(INVALIDATIONS.load(Ordering::Relaxed),before+1,"historical retry revoked new capabilities again");
 LATE_NOTIFICATION.store(true,Ordering::Release);
 assert_eq!(domain_tasks::grant_file_cap(OWNER,OBJECT),Err(Error::Stale));
 assert!(domain_tasks::file_capabilities_invalidated(),"new notification overwritten by prior revoke");
 let new=domain_tasks::grant_file_cap(OWNER,OBJECT).unwrap();
 assert!(!domain_tasks::file_capabilities_invalidated());
 assert_eq!(resolve(old,2),ItemStatus::Error(Error::Auth));assert_eq!(resolve(new,3),ItemStatus::Value(17));
 println!("OWNER_PUBLICATION_AND_CAPABILITY_REVOKE PASS");
}
