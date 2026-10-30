// Actual final accept continuation, finish_job and abort. Reply verification,
// Root reservation and core-replay delivery are explicit controlled boundaries.
static DELIVERY_BUSY:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
mod core_replay{#[derive(Clone,Copy)]pub struct WorkId;pub fn evaluated(_:WorkId,_:u64,_:Result<u64,super::Error>,_:[u8;32])->Result<(),super::Error>{if super::DELIVERY_BUSY.load(super::Ordering::Acquire){Err(super::Error::Busy)}else{Ok(())}}}
mod replay{pub fn reject_first_job(_:u64,_:u64,_:&super::CandidateSet,_:super::Error){}}
// COMPLETION_JOB_TYPES
struct State{job:Option<Job>,boot:u64}
static STATE:std::sync::Mutex<State>=std::sync::Mutex::new(State{job:None,boot:11});
fn with<T>(f:impl FnOnce(&mut State)->Result<T,Error>)->Result<T,Error>{f(&mut STATE.lock().unwrap())}
// ACTUAL_FINISH_JOB
// ACTUAL_ABORT
fn retry_accept(output:&[u64;512])->Result<u64,Error>{with(|s|{
// ACTUAL_ACCEPT_RETRY_PREFIX
 panic!("retained accept fell through to publication")
})}
// REAL_COMPLETION_EVIDENCE
fn init_record(){let mut input=[0;512];input[2]=1;input[8]=1;input[9]=1;input[10]=1;input[11]=1;domain_evidence::begin(0,&input,[1;32]);}
fn job()->Job{let set=candidates();Job{cpu:1,set,sequence:1,controller:9,base_version:0,started:10,encode_ns:1,evidence:Some(0),dependencies:[None;2],work:Some(core_replay::WorkId),read_only:false,completion:None,publication_debit:policy::CpuTime{cpu:1,ns:0}}}
fn finalize(s:&mut State,mut job:Job,output:&[u64;512],provenance:submission::Facts,result:Result<u64,Error>)->Result<u64,Error>{
 let selected=u64::MAX;let decoding=25;let publication_ns=0;let cpu_ns=1;let output_hash=[1;32];
 // ACTUAL_FINAL_ACCEPT
}
#[test]fn submission_completion_retains_original_facts_before_busy_delivery_and_retry(){
 init_record();DELIVERY_BUSY.store(true,Ordering::Release);let mut s=State{job:None,boot:11};
 let mut facts=submission::Facts::new(1,false,[2,2,3,4],true);facts.accept(submission::AcceptStage::Context);
 assert_eq!(finalize(&mut s,job(),&[0;512],facts,Err(Error::Stale)),Err(Error::Busy));
 let first=domain_evidence::submission_tail(0);assert_eq!(first[0],submission::MAGIC,"actual accept omitted original completion provenance");
 assert_eq!((first[2],first[4],first[5],first[6]),(2,2,Error::Stale as u64+1,0));assert_eq!(&first[23..],[2,2,3,4]);
 let retained=s.job.take().unwrap();assert_eq!(retained.completion.unwrap().result,Err(Error::Stale));
 with(|state|{state.job=Some(retained);Ok(())}).unwrap();DELIVERY_BUSY.store(false,Ordering::Release);assert_eq!(retry_accept(&[0;512]),Err(Error::Stale));assert!(with(|s|Ok(s.job.is_none())).unwrap());assert_eq!(domain_evidence::submission_tail(0),first,"delivery retry replaced original error with its own Busy");
}
#[test]fn submission_completion_abort_reports_only_a_new_expiration_not_existing_completion(){
 init_record();DELIVERY_BUSY.store(false,Ordering::Release);with(|s|{s.job=Some(job());Ok(())}).unwrap();
 assert_eq!(abort(7),Ok(()));let expired=domain_evidence::submission_tail(0);
 assert_eq!(expired[0],submission::MAGIC,"actual abort omitted original completion provenance");assert_eq!((expired[2],expired[4],expired[5],expired[6],expired[22]),(11,2,Error::Expired as u64+1,0,1));assert_eq!(expired[21]&2,0);
 init_record();let mut s=State{job:None,boot:11};DELIVERY_BUSY.store(true,Ordering::Release);let mut facts=submission::Facts::new(1,false,[2,2,3,4],true);facts.accept(submission::AcceptStage::Context);
 assert_eq!(finalize(&mut s,job(),&[0;512],facts,Err(Error::Stale)),Err(Error::Busy));let original=domain_evidence::submission_tail(0);let retained=s.job.take().unwrap();
 with(|s|{s.job=Some(retained);Ok(())}).unwrap();DELIVERY_BUSY.store(false,Ordering::Release);assert_eq!(abort(999),Ok(()));
 assert_eq!(domain_evidence::submission_tail(0),original,"abort overwrote an already completed original submission");
}
