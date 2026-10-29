// Reuse actual Registry/wire fixtures and controlled Executor from submission
// observation. Every clock sample remains the original physical CPU value.
fn submit_debited(r:&mut Registry,wire:&[u8],c:&mut Script,o:&mut Owner,debit:CpuTime)->Result<PlanReceipt,Error>{
 // DEBITED_SUBMIT
}
#[test]fn carried_publication_initial_cost_cannot_be_hidden_before_registry(){
 let(mut r,wire,mut o,mut c)=setup(0);let receipt=submit_debited(&mut r,&wire,&mut c,&mut o,CpuTime{cpu:1,ns:500_000}).unwrap();
 assert_eq!(receipt.state(),ExecutionState::Failed(Error::Budget),"carried publication CPU was ignored");assert_eq!((c.reads,o.checks,o.prepares,o.effects),(2,1,0,0));assert_eq!(observed(&o).stage,3);assert!(r.optimization_stopped());
}
#[test]fn carried_publication_revalidation_and_final_model_checks_share_the_same_bound(){
 for (debit,samples,stage,reads) in [(499_998,vec![1,2,3,4,5],9,4),(499_997,vec![1,2,2,4,5],12,5)]{
  let(mut r,wire,mut o,_)=setup(0);let mut c=Script{samples:samples.into_iter().enumerate().map(|(i,n)|moment(11+i as u64,n)).collect(),reads:0};
  let receipt=submit_debited(&mut r,&wire,&mut c,&mut o,CpuTime{cpu:1,ns:debit}).unwrap();assert_eq!(receipt.state(),ExecutionState::Failed(Error::Budget),"later check lost carried publication CPU");assert_eq!((c.reads,o.effects,o.cancels),(reads,0,1));assert_eq!(observed(&o).stage,stage);assert!(r.optimization_stopped());
 }
}
#[test]fn carried_publication_postcommit_overrun_keeps_real_receipt_and_stops(){
 let(mut r,wire,mut o,mut c)=setup(0);let receipt=submit_debited(&mut r,&wire,&mut c,&mut o,CpuTime{cpu:1,ns:499_996}).unwrap();assert_eq!(receipt.version,1);assert_eq!(receipt.published_ns,14);assert_eq!(receipt.state(),ExecutionState::Pending);assert!(r.optimization_stopped(),"postcommit check discarded carried publication CPU");assert_eq!((c.reads,o.effects,o.cancels),(5,1,0));assert_eq!(observed(&o).result,Ok(()));
 let cached=submit_debited(&mut r,&wire,&mut c,&mut o,CpuTime{cpu:2,ns:u64::MAX}).unwrap();assert_eq!(cached,receipt);assert_eq!((c.reads,o.effects,o.seen.len()),(5,1,1));
}
#[test]fn carried_publication_exact_bound_uses_real_samples_without_changing_wall_time(){
 let(mut r,wire,mut o,mut c)=setup(0);let receipt=submit_debited(&mut r,&wire,&mut c,&mut o,CpuTime{cpu:1,ns:499_995}).unwrap();assert_eq!(receipt.version,1);assert_eq!(receipt.published_ns,14);assert!(!r.optimization_stopped());assert_eq!((c.reads,o.effects),(5,1));assert_eq!(c.samples[0],moment(11,1));assert_eq!(c.samples[4],moment(15,5));
}
#[test]fn carried_publication_cpu_identity_and_overflow_fail_closed(){
 for (cpu,ns,error) in [(2,0,Error::Auth),(1,u64::MAX,Error::Overflow)]{let(mut r,wire,mut o,mut c)=setup(0);let receipt=submit_debited(&mut r,&wire,&mut c,&mut o,CpuTime{cpu,ns}).unwrap();assert_eq!(receipt.state(),ExecutionState::Failed(error),"invalid carried publication cost authorized an effect");assert_eq!((c.reads,o.effects,o.prepares),(2,0,0));assert!(r.optimization_stopped());}
}
#[test]fn carried_publication_wall_and_cpu_rollback_are_still_rejected(){
 for physical in [PublicationTime{wall_ns:9,cpu:CpuTime{cpu:1,ns:1}},PublicationTime{wall_ns:11,cpu:CpuTime{cpu:2,ns:1}}]{let(mut r,wire,mut o,_)=setup(0);let mut c=Script{samples:vec![physical,physical],reads:0};let receipt=submit_debited(&mut r,&wire,&mut c,&mut o,CpuTime{cpu:1,ns:1}).unwrap();assert_eq!(receipt.version,0);assert_eq!(o.effects,0);assert!(r.optimization_stopped());}
}
