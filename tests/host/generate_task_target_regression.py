"""Bind the actual ordinary target batch and target lookup to real IPC lifecycle."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
src = (ROOT/'kernel/src/domain_tasks.rs').read_text()
def extract(signature):
    start=src.index(signature); opening=src.index('{',start); depth=1
    for end in range(opening+1,len(src)):
        depth += (src[end]=='{')-(src[end]=='}')
        if depth==0: return src[start:end+1]
    raise ValueError(signature)
code = '''#![allow(dead_code)]
use core::sync::atomic::{AtomicBool,AtomicU64,Ordering};
use cyxia_prototype::domains::{ObjectKey,Error};
use cyxia_prototype::domains::tasks::*;
use std::sync::Mutex;
static READY:AtomicBool=AtomicBool::new(true);
static IPC_TARGETS:[AtomicU64;4]=[AtomicU64::new(1),AtomicU64::new(1),AtomicU64::new(2),AtomicU64::new(1)];
struct State { ipc:Ipc<64>, scheduler:Scheduler }
static STATE:Mutex<Option<State>>=Mutex::new(None);
fn locked<R>(f:impl FnOnce(&mut State)->Result<R,Error>)->Result<R,Error>{
 let mut s=STATE.try_lock().map_err(|_|Error::Busy)?; f(s.as_mut().unwrap())
}
fn group(id:u64)->ObjectKey{ObjectKey{id,generation:1}}
const MEMORY_KEY:ObjectKey=ObjectKey{id:100,generation:1};
const SERVICE_KEY:ObjectKey=ObjectKey{id:101,generation:1};
'''
code += f'#[path="{ROOT}/kernel/src/domain_control/target_batch.rs"] pub mod target_batch;\nmod domain_control {{pub use crate::target_batch;}}\n'
for sig in ['fn target_locked(', 'pub(crate) fn queued_targets(']: code += extract(sig)+'\n'
if 'fn projected_target(' in src: code+=extract('fn projected_target(')+'\n'
control=(ROOT/'kernel/src/domain_control.rs').read_text()
start=control.index('    let start_cursor = s.family_cursor;',control.index('fn next_normal('))
end=control.index('        let Some(target) = target else {',start)
lookup=control[start:end]
for name,path in [('read_snapshot','domain_platform/read_snapshot.rs'),('target_projection','domain_services/target_projection.rs')]:
 code+=f'#[path="{ROOT}/kernel/src/{path}"] pub mod {name};\n'
code+='''
mod domain_platform{pub use crate::read_snapshot;}
static SERVICE_VIEW:read_snapshot::ReadSnapshot<target_projection::Targets>=read_snapshot::ReadSnapshot::new();
#[derive(Clone,Copy)] struct Family{domain:u16,kind:u16,target_source:target_batch::Source}
struct Owner{families:[Option<Family>;18]}
struct Schedule{due:[u64;18],family_cursor:usize,cursor:[usize;18],owner:Owner,preparation:Option<()>}
const WINDOW_NS:u64=100_000_000;
fn preparation_entry_detail(_:u64){}
fn preparation_lookup(_:usize,_:Family,_:usize,_:u64){}
fn read_target_batch(source:target_batch::Source,q:&[target_batch::Query],o:&mut[Option<ObjectKey>])->Result<(),Error>{
 match source {
 target_batch::Source::Tasks=>queued_targets(q,o),
 target_batch::Source::Services=>{
 let targets=target_projection::targets(&SERVICE_VIEW,||100,|v|*v)?;
 target_batch::resolve(q,o,|q|targets.get(target_projection::Query{domain:q.domain,kind:q.kind,ordinal:q.ordinal}))
 },
 _=>panic!("unexpected owner")
 }
}
fn next_lookup(s:&mut Schedule)->Result<Option<ObjectKey>,Error>{
 let wall_started=100u64;
'''+lookup+'''
return Ok(target);
}
Ok(None)
}
'''
code += '''
struct Backend;
impl IpcBackend<64> for Backend {
 fn authorize(&mut self,_:ObjectKey,_:ObjectKey,_:IpcOperation)->Result<(),Error>{Ok(())}
 fn notify(&mut self,_:ObjectKey,_:ObjectKey)->Result<(),Error>{Ok(())}
 fn deliver(&mut self,_:ObjectKey,_:ObjectKey,_:&Message<64>)->Result<(),Error>{panic!("no queued messages")}
}
fn read(ordinal:usize)->Result<Option<ObjectKey>,Error>{
 let mut output=[None];queued_targets(&[target_batch::Query::exact(5,1,ordinal)],&mut output)?;Ok(output[0])
}
fn main(){
 let mut ipc=Ipc::new();for owner in 10..13{ipc.open(group(owner),false).unwrap();}
 ipc.open(group(99),true).unwrap();
 *STATE.lock().unwrap()=Some(State{ipc,scheduler:Scheduler::new()});
 assert_eq!(read(2),Ok(Some(ObjectKey{id:3,generation:3})),"third ordinary endpoint omitted");
 assert_eq!(read(3),Ok(None),"recovery endpoints are intentionally excluded");
 locked(|s|{s.ipc.close(group(11),ObjectKey{id:2,generation:2},&mut Backend)?;Ok(())}).unwrap();
 assert_eq!(read(1),Ok(Some(ObjectKey{id:3,generation:3})),"closed slot must not truncate enumeration");
 let reopened=locked(|s|s.ipc.open(group(14),false)).unwrap();
 assert_eq!(reopened,ObjectKey{id:2,generation:5});
 assert_eq!(read(1),Ok(Some(ObjectKey{id:2,generation:5})),"reopen must publish new generation");
 let mut families=[None;18];
 families[5]=Some(Family{domain:5,kind:1,target_source:target_batch::Source::Tasks});
 families[14]=Some(Family{domain:14,kind:1,target_source:target_batch::Source::Services});
 let mut schedule=Schedule{due:[0;18],family_cursor:5,cursor:[0;18],owner:Owner{families},preparation:None};schedule.cursor[5]=1;
 let service=ObjectKey{id:77,generation:9};
 SERVICE_VIEW.publish(target_projection::Targets{published_ns:100,core:None,services:[Some(service),None],console:service}).unwrap();
 let held=STATE.lock().unwrap();assert_eq!(read(0),Err(Error::Busy));
 assert_eq!(next_lookup(&mut schedule),Err(Error::Busy));
 assert_eq!((schedule.cursor[5],schedule.due[5]),(1,0),"Busy must retain failed object ordinal and due");
 // The task owner stays locked across the next paid selection opportunity.
 assert_eq!(next_lookup(&mut schedule),Ok(Some(service)),"unavailable Tasks owner must not hide an available service family");
 assert_eq!(schedule.due[14],100_000_100);
 assert_eq!((schedule.cursor[5],schedule.due[5]),(1,0));
 // A carried preparation keeps its original family identity on retry.
 schedule.family_cursor=5;schedule.preparation=Some(());
 assert_eq!(next_lookup(&mut schedule),Err(Error::Busy));
 assert_eq!(schedule.family_cursor,5);
 schedule.preparation=None;
 drop(held);
 assert_eq!(next_lookup(&mut schedule),Ok(Some(ObjectKey{id:2,generation:5})));
 assert_eq!((schedule.family_cursor,schedule.cursor[5],schedule.due[5]),(6,2,100_000_100));
 assert_eq!(read(2),Ok(Some(ObjectKey{id:3,generation:3})));
 READY.store(false,Ordering::Release);assert_eq!(read(0),Err(Error::NotReady));READY.store(true,Ordering::Release);
 let queries=[target_batch::Query::exact(5,1,0);19];let mut output=[None;19];
 assert_eq!(queued_targets(&queries,&mut output),Err(Error::Range));
 println!("R08: third endpoint, close/reopen generation, bounded exact continuation, Busy and NotReady passed");
}
'''
(OUT/'main.rs').write_text(code)
(OUT/'Cargo.toml').write_text(f'''[package]
name="task-target-regression"
version="0.1.0"
edition="2024"
[[bin]]
name="task-target-regression"
path="main.rs"
[dependencies]
cyxia-prototype={{path="{ROOT}/crates/prototype"}}
[workspace]
''')
