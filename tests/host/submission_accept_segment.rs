// Actual accept registry-call and read-only blocks; reply/role/model gate are
// explicit boundaries. Native callbacks and Registry execute real source.
struct Gate;impl Gate{fn check_active_publication(&self,_:ModelBinding,_:ObjectKey)->Result<(),Error>{Ok(())}}
struct SubmitState{owner:Owner,registry:policy::Registry,boot:u64,model_gate:Option<Gate>}
struct Job{sequence:u64,controller:u64,set:policy::CandidateSet,evidence:Option<usize>,started:u64,dependencies:[Option<BoundDependency>;2],work:Option<()>,read_only:bool,publication_debit:policy::CpuTime}
struct Reply{bytes:Vec<u8>,len:usize,scores:[i16;32],action:Action}
fn submit_fixture(mode:u64)->(SubmitState,Job,Reply){let(registry,wire,owner)=setup(mode);let len=wire.len();(SubmitState{owner,registry,boot:11,model_gate:Some(Gate)},Job{sequence:1,controller:9,set:candidates(),evidence:Some(0),started:10,dependencies:[None;2],work:Some(()),read_only:false,publication_debit:policy::CpuTime{cpu:1,ns:0}},Reply{bytes:wire,len,scores:[0;32],action:Action::CpuWeight(2)})}
fn actual_submit(s:&mut SubmitState,job:Job,reply:Reply)->(Result<u64,Error>,[u64;27]){
 let publication_started=policy::PublicationTime{wall_ns:10,cpu:policy::CpuTime{cpu:1,ns:0}};
 let budget=policy::PublicationBudget{started:publication_started,carried:job.publication_debit};
 let mut registry_completed=false;
 let mut provenance=submission::Facts::new(job.sequence,job.read_only,[2,2,3,3],true);
 let result=(||{
 // ACTUAL_ACCEPT_SUBMIT
 })();(result,provenance.words(result,false))
}
fn actual_readonly(s:&mut SubmitState,job:Job,reply:Reply)->(Result<u64,Error>,[u64;27]){
 let mut provenance=submission::Facts::new(job.sequence,job.read_only,[2,2,3,3],true);
 let result=(||{
 // ACTUAL_READONLY_BLOCK
 panic!("readonly fell through to publication")
 })();(result,provenance.words(result,false))
}
#[test]fn submission_accept_segment_keeps_facts_when_registry_returns_before_observer(){
 let(mut s,job,reply)=submit_fixture(1);let(r,w)=actual_submit(&mut s,job,reply);assert_eq!(r,Err(Error::Busy));
 assert_eq!((w[2],w[6],w[7],w[14],w[15],w[16]),(9,1,2,4,6,3),"actual accept lost the executor's original submission facts");
 let(mut s,job,reply)=submit_fixture(0);s.registry.stop_optimization();let(r,w)=actual_submit(&mut s,job,reply);assert_eq!(r,Err(Error::Budget));
 assert_eq!((w[2],w[6],w[14],w[15],w[16],w[17]),(8,0,3,3,3,Error::Budget as u64+1),"Registry early return lost callback facts before question propagation");
 assert_eq!(READS.load(Ordering::Acquire),0);
}
#[test]fn submission_accept_segment_readonly_busy_is_not_a_registry_publication_failure(){
 let(mut s,mut job,reply)=submit_fixture(0);job.read_only=true;s.owner.families[0].as_mut().unwrap().legal=|_,_,_|Err(Error::Busy);
 let(r,w)=actual_readonly(&mut s,job,reply);assert_eq!(r,Err(Error::Busy));assert_eq!((w[2],w[3],w[6],w[14]),(6,1,0,0));assert_eq!(w[5],Error::Busy as u64+1);assert_eq!(s.registry.version(),0);assert_eq!(READS.load(Ordering::Acquire),1);
 let(mut s,mut job,reply)=submit_fixture(0);job.read_only=true;s.model_gate=None;let(r,w)=actual_readonly(&mut s,job,reply);assert_eq!(r,Err(Error::NotReady));assert_eq!((w[2],w[6],w[14]),(5,0,0));assert_eq!(READS.load(Ordering::Acquire),0);
}
