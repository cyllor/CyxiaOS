"""Safe typed-enumeration regression; no replay scope, reservation, or Frozen probe.
Binds only the production scan's target lookup statement to real ReadSnapshot and
service target projection, and checks its two cursor fields on transient errors.
"""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2];OUT=Path(sys.argv[1]).resolve();OUT.mkdir(parents=True,exist_ok=True)
src=(ROOT/'kernel/src/domain_control/replay.rs').read_text()
start=src.index('                    let Some(target) =',src.index('Phase::Scanning =>'))
end=src.index('                    let action =',start)
lookup=src[start:end]
code='''#![allow(dead_code)]
use cyxia_prototype::domains::{Error,ObjectKey};
'''
for name,path in [('read_snapshot','domain_platform/read_snapshot.rs'),('target_projection','domain_services/target_projection.rs'),('target_batch','domain_control/target_batch.rs')]:
 code+=f'#[path="{ROOT}/kernel/src/{path}"] pub mod {name};\n'
code+='''
mod domain_platform{pub use crate::read_snapshot;}
use target_batch::Source as TargetSource;
use target_projection::{Targets,Query};
static VIEW:read_snapshot::ReadSnapshot<Targets>=read_snapshot::ReadSnapshot::new();
static WALL:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(100);
fn now()->u64{WALL.load(std::sync::atomic::Ordering::Acquire)}
struct Family {domain:u16,kind:u16,target:fn(u16,u16,usize)->Option<ObjectKey>}
struct Cursor{family:usize,ordinal:usize}
fn read_target_batch(_:TargetSource,queries:&[target_batch::Query],output:&mut[Option<ObjectKey>])->Result<(),Error>{
 let targets=target_projection::targets(&VIEW,now,|v|*v)?;
 target_batch::resolve(queries,output,|q|targets.get(Query{domain:q.domain,kind:q.kind,ordinal:q.ordinal}))
}
fn step(r:&mut Cursor)->Result<Option<ObjectKey>,Error>{
 let f=Family{domain:14,kind:1,target:|domain,kind,ordinal|target_projection::target(&VIEW,Query{domain,kind,ordinal},now,|v|*v)};
 // One bounded production lookup; an exhaustion continue exits this iteration.
 for _ in 0..1 {
'''+lookup+'''
 return Ok(Some(target));
 }
 Ok(None)
}
fn main(){
 let mut c=Cursor{family:14,ordinal:1};
 assert_eq!(step(&mut c),Err(Error::NotReady));assert_eq!((c.family,c.ordinal),(14,1));
 let key=ObjectKey{id:21,generation:3};
 VIEW.publish(Targets{published_ns:100,core:None,services:[None,Some(key)],console:key}).unwrap();
 VIEW.inspect(|_|{
   assert_eq!(step(&mut c),Err(Error::Busy),"reader contention must remain typed");
   assert_eq!((c.family,c.ordinal),(14,1),"Busy must not skip the family");
 }).unwrap();
 assert_eq!(step(&mut c),Ok(Some(key)));assert_eq!((c.family,c.ordinal),(14,1));
 WALL.store(50_000_100,std::sync::atomic::Ordering::Release);
 assert_eq!(step(&mut c),Err(Error::Busy));assert_eq!((c.family,c.ordinal),(14,1));
 VIEW.publish(Targets{published_ns:50_000_100,core:None,services:[None,Some(ObjectKey{id:21,generation:4})],console:key}).unwrap();
 assert_eq!(step(&mut c),Ok(Some(ObjectKey{id:21,generation:4})));
 c.ordinal=2;assert_eq!(step(&mut c),Ok(None));assert_eq!((c.family,c.ordinal),(15,0));
 println!("R09: Busy and stale preserve exact cursor; recovery sees live generation; only successful empty advances");
}
'''
(OUT/'main.rs').write_text(code)
(OUT/'Cargo.toml').write_text(f'''[package]
name="replay-target-cursor-regression"
version="0.1.0"
edition="2024"
[[bin]]
name="replay-target-cursor-regression"
path="main.rs"
[dependencies]
cyxia-prototype={{path="{ROOT}/crates/prototype"}}
[workspace]
''')
