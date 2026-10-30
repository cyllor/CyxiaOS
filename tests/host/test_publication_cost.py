"""Actual accept/full Executor/Desired/ADMISSION/Registry and paid recorder.

Hardware, scope authority, Root, history storage and delivery are controlled
kernel boundaries. Missing/misplaced evidence or uncharged recorder cost must
fail without replacing the original Registry receipt or original CPU debit.
"""
import json
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest

from test_active_accept_retry import program, ROOT
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


def source():
    p = program()
    # Keep the complete production publish callback, including actual Desired
    # and ADMISSION writes. Only hardware/scope authority, Root, history
    # storage and final delivery cross explicit controlled kernel boundaries.
    control = (ROOT/'kernel/src/domain_control.rs').read_text()
    p = p.replace('#[derive(Clone,Copy)]struct Desired{state:ExecutionState,execution_observed:bool}',
                  '#[derive(Clone,Copy)]'+function(control, 'struct Desired {'))
    p = p.replace(function(p, "impl<S: PublicationScope> policy::Executor for Executor<'_, S>"),
                  function(control, "impl<S: PublicationScope> policy::Executor for Executor<'_, S>"))
    p += '\n'+function(control, 'fn execution_limit(')
    admission = (ROOT/'kernel/src/domain_control/dependencies.rs').read_text()
    admission += '\nimpl AdmissionView{pub fn snapshot(&self)->[u64;4]{let e=&self.entries[0];[e.domain.load(Ordering::Acquire),e.id.load(Ordering::Acquire),e.version.load(Ordering::Acquire),e.state.load(Ordering::Acquire)]}}'
    p += '\nmod admission_view{\n'+admission+'\n}\nstatic ADMISSION:admission_view::AdmissionView=admission_view::AdmissionView::new();\n'
    history = (ROOT/'kernel/src/learning_history.rs').read_text()
    p += '\nmod learning_history{use super::*;\n'+function(history,"pub struct Publish<'")+'\npub fn record_publish(p:Publish<\'_>)->Result<bool,Error>{assert_eq!(p.plan_version,1);assert_eq!(p.apply.plan_seq,1);Ok(true)}}\n'
    p = p.replace('mod replay{pub fn reject_first_job', 'mod replay{pub fn published(plan:&super::Plan,boot:u64,stamp:Option<super::PolicyStamp>)->Result<(),super::Error>{assert_eq!(boot,11);assert_eq!(plan.header.plan_seq,1);assert_eq!(stamp.unwrap().version,1);super::EFFECTS.fetch_add(1,super::Ordering::AcqRel);Ok(())} pub fn reject_first_job')
    module = ROOT / 'kernel/src/domain_control/publication_cost.rs'
    if module.exists():
        p=p.replace('#[path='+json.dumps(str(module))+'] mod publication_cost;', '')
        body = module.read_text()
        # Explicit controlled CPU boundary: assign actual CPU to entry into
        # the real recorder's preparation body. Its call position, original
        # budget check and stored completion all remain production source.
        entry='pub fn prepare(' if 'pub fn prepare(' in body else 'pub fn finish('
        actual=function(body,entry)
        body=body.replace(actual,actual.replace('{\n','{\n    super::pay(super::DIAGNOSTIC_CPU_COST.load(super::Ordering::Acquire));\n',1))
        actual=function(body,'pub fn finish(')
        body=body.replace(actual,actual.replace('{\n','{\n    super::pay(super::SERIALIZER_CPU_COST.load(super::Ordering::Acquire));\n',1))
        if 'pub fn submit_entry(' in body:
            actual=function(body,'pub fn submit_entry(')
            body=body.replace(actual,actual.replace('{\n','{\n    super::pay(super::SUBMIT_ENTRY_CPU_COST.load(super::Ordering::Acquire));\n',1))
        body=body.replace('if preserve {','if preserve {\n    super::pay(super::RETENTION_CPU_COST.load(super::Ordering::Acquire));',1)
        body += '\npub fn snapshot(cpu:usize)->[u64;64]{let r=&DOMAIN_PUBLICATION_COST.0[cpu-1];core::array::from_fn(|i|if i<63{r.get(i)}else{r.published.load(Ordering::Acquire)})}\n'
        body += '\npub fn reset(){for r in &DOMAIN_PUBLICATION_COST.0{for i in 0..63{r.put(i,0);}r.published.store(0,Ordering::Release);}}\n'
        p=p.replace('fn setup(mode:u64)->[u64;512]{','fn setup(mode:u64)->[u64;512]{SERIALIZER_CPU_COST.store(0,Ordering::Release);DIAGNOSTIC_CPU_COST.store(0,Ordering::Release);publication_cost::reset();')
        p=p.replace('pub fn slot()->usize{1}','pub fn slot()->usize{super::COST_CPU.load(super::Ordering::Acquire)}')
        p+='\nstatic COST_CPU:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(1);\n'
        p+='\nstatic DIAGNOSTIC_CPU_COST:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);\n'
        p+='\nstatic SERIALIZER_CPU_COST:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);\n'
        p+='\nstatic RETENTION_CPU_COST:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);\n'
        p+='\nstatic SUBMIT_ENTRY_CPU_COST:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);\n'
        p+='\nstatic STOP_CONTEXT:std::sync::Mutex<Option<[u64;20]>>=std::sync::Mutex::new(None);\n'
        p=p.replace('pub fn optimization_stop(_:[u64;20]){}','pub fn optimization_stop(w:[u64;20]){*STOP_CONTEXT.lock().unwrap()=Some(w);}')
        p=p.replace('DIAGNOSTIC_CPU_COST.store(0,Ordering::Release);publication_cost::reset();','DIAGNOSTIC_CPU_COST.store(0,Ordering::Release);RETENTION_CPU_COST.store(0,Ordering::Release);SUBMIT_ENTRY_CPU_COST.store(0,Ordering::Release);*STOP_CONTEXT.lock().unwrap()=None;publication_cost::reset();')
        p += '\nmod publication_cost {\n' + body + '\n}\n'
    else:
        # Test-only absent-feature facade allows the unmodified actual source
        # to compile and fail the evidence assertion, never a compiler error.
        p += '\nmod publication_cost {pub fn snapshot(_:usize)->[u64;64]{[0;64]}}\n'
    p += r'''
#[test]fn publication_cost_paid_submit_entry_is_identity_bound_and_cannot_escape_final_charge(){
 let out=setup(0);assert_eq!(accept(&out,10),Ok(1));
 with(|s|{let d=s.owner.desired[0].expect("publication lost actual Desired intent");assert_eq!((d.job,d.apply.plan_seq,d.stamp.version),(1,1,1));assert_eq!(s.registry.query(publisher_fixture(),id())?.version,1);Ok(())}).unwrap();
 assert_eq!(ADMISSION.snapshot(),[1,1,1,1],"publication lost actual ADMISSION intent");
 let w=publication_cost::snapshot(1);
 assert_eq!(w[49],1,"successful actual publication is missing paid native submit entry");
 assert_eq!(&w[2..6],&[1,11,9,1],"submit entry lost original Job/CPU identity");
 assert!(w[12]<=w[47] && w[47]<=w[33] && w[13]<=w[48] && w[48]<=w[34],"submit entry is outside S/R1");
 assert_eq!((w[48]-w[13],w[34]-w[48],w[34]-w[13]),(100_051,1,100_052),"submit entry did not split acquisition/decode from Registry setup");
 assert_eq!((w[47]-w[12],w[33]-w[47],w[33]-w[12]),(1,1,2));
 assert_eq!((w[48]-w[13])+(w[34]-w[48]),w[34]-w[13]);
 assert_eq!((w[47]-w[12])+(w[33]-w[47]),w[33]-w[12]);
 assert_eq!(FINISHED.lock().unwrap().unwrap().1,100_011,"new paid read omitted from enclosing charge");
 let baseline=w[27];
 let out=setup(0);SUBMIT_ENTRY_CPU_COST.store(37,Ordering::Release);
 assert_eq!(accept(&out,10),Ok(1));let paid=publication_cost::snapshot(1);
 assert_eq!(paid[27]-baseline,37,"submit entry recorder cost escaped original charge");
 assert_eq!(paid[34]-paid[48],38,"paid recorder stores escaped the original S/R1 span");
 assert_eq!(FINISHED.lock().unwrap().unwrap().1,100_048,"submit entry recorder cost omitted from original completion");
 let out=setup(0);SUBMIT_ENTRY_CPU_COST.store(37,Ordering::Release);SERIALIZER_CPU_COST.store(399_904,Ordering::Release);
 assert_eq!(accept(&out,10),Ok(1));let w=publication_cost::snapshot(1);let c=STOP_CONTEXT.lock().unwrap().expect("paid entry tail failed to stop at original enclosing boundary");
 assert_eq!((w[27],w[28],w[29],w[31],w[32]),(100_097,0,1,0,0),"checkpoint was relabeled as final charged authority");
 assert_eq!((c[7],c[8],c[12]),(1,0,500_002),"paid entry changed receipt or original charged total");
 println!("ENTRY_STOP=[{:?},{:?}]",w,c);
}
#[test]fn publication_cost_submit_entry_survives_cached_and_early_registry_error_without_r1(){
 let out=setup(0);let job=with(|s|Ok(s.job.unwrap())).unwrap();assert_eq!(accept(&out,10),Ok(1));
 publication_cost::reset();with(|s|{s.job=Some(job);Ok(())}).unwrap();let before=READS.load(Ordering::Acquire);
 assert_eq!(accept(&out,10),Ok(1));let w=publication_cost::snapshot(1);
 assert_eq!(READS.load(Ordering::Acquire)-before,6,"cached return lost paid submit read");
 assert_eq!((w[15],w[20],w[21],w[49]),(0,3,1,1),"cached Registry receipt lost paid entry without R1");
 assert!(w[13]<=w[48] && w[48]<=w[19]);println!("EARLY_COST={:?}",w);
 let out=setup(0);with(|s|{let mut foreign=publisher_fixture();foreign.controller_epoch+=1;s.registry=Registry::new(11,foreign,binding())?;Ok(())}).unwrap();
 assert_eq!(accept(&out,10),Err(Error::Auth));let w=publication_cost::snapshot(1);
 assert_eq!(READS.load(Ordering::Acquire),6,"early Registry error lost paid submit read");
 assert_eq!((w[15],w[20],w[22],w[49]),(0,1,Error::Auth as u64+1,1),"early Registry error lost paid entry without R1");
 assert!(w[13]<=w[48] && w[48]<=w[19]);println!("EARLY_COST={:?}",w);
}
#[test]fn publication_cost_successful_registry_return_precedes_release_cap_failure(){
 let out=setup(0);RELEASE_CPU.store(500_000,Ordering::Release);
 assert_eq!(accept(&out,10),Ok(1));
 let w=publication_cost::snapshot(1);
 assert_eq!(w[0],0x4359505542430003,"successful Registry return and final cap failure lack stage evidence");
 assert_eq!(&w[2..11],&[1,11,9,1,1,1,1,1,1],"original Job/CPU/target/model/action identity changed");
 assert_eq!((w[15],w[20],w[21],w[22]),(5,3,1,0),"successful Registry return was lost");
 assert!(w[17]>w[13] && w[19]>=w[17],"precommit/Registry-return samples missing");
 assert!(w[24]>=w[19]+500_000,"release sample omitted actual release CPU");
 assert_eq!(w[27],w[26]-w[13]+w[11],"final cumulative CPU lost original debit");
 assert_eq!((w[28],w[29],w[30],w[31],w[32]),(Error::Budget as u64+1,1,0,0,1),"final cap failure replaced Registry success");
 assert_eq!(w[63],1);assert_eq!(w[1],1);
 println!("PUBLICATION_COST={:?}",w);
 assert_eq!(ACQUIRES.load(Ordering::Acquire),1);assert_eq!(SELECTIONS.load(Ordering::Acquire),4);
 assert_eq!(READS.load(Ordering::Acquire),12,"diagnostic clock reads escaped the charged path");
 with(|s|{assert_eq!(s.registry.query(publisher_fixture(),id())?.version,1);Ok(())}).unwrap();
 // A stopped record remains tied to the original receipt even if unrelated
 // attempts try to enter the diagnostic bank after optimization stopped.
 publication_cost::begin([11,9,99,1,1,1,1,1],policy::CpuTime{cpu:1,ns:0},policy::PublicationTime{wall_ns:99,cpu:policy::CpuTime{cpu:1,ns:99}},false);
 publication_cost::submit_entry(1,policy::PublicationTime{wall_ns:u64::MAX,cpu:policy::CpuTime{cpu:1,ns:u64::MAX}});
 assert_eq!(publication_cost::snapshot(1),w,"stopped original Job evidence was overwritten");
}
#[test]fn publication_cost_native_precommit_refusal_keeps_paid_entry_and_zero_desired(){
 let out=setup(7);SUBMIT_ENTRY_CPU_COST.store(200_000,Ordering::Release);assert_eq!(accept(&out,10),Err(Error::Budget));let w=publication_cost::snapshot(1);
 assert_eq!((w[15],w[20],w[21],w[22],w[46],w[49]),(5,2,0,Error::Budget as u64+1,1,1));
 assert!(w[13]<=w[48] && w[48]<=w[34] && w[40]<=w[17] && w[17]<=w[42]);
 with(|s|{assert!(s.owner.desired[0].is_none());Ok(())}).unwrap();
 println!("PRECOMMIT_COST={:?}",w);
}
#[test]fn publication_cost_prior_busy_debit_and_registry_refusal_remain_distinct(){
 let out=setup(0);let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();
 assert_eq!(accept(&out,10),Err(Error::Busy));assert_eq!(publication_cost::snapshot(1)[63],0,"partial acquisition evidence marked complete");
 assert_eq!(publication_cost::snapshot(1)[49],0,"acquisition Busy invented submit entry");
 assert_eq!(READS.load(Ordering::Acquire),2,"acquisition retry added an unnecessary diagnostic clock");
 held.release(WALL.load(Ordering::Acquire));RELEASE_CPU.store(500_000,Ordering::Release);
 assert_eq!(accept(&out,10),Ok(1));let w=publication_cost::snapshot(1);
 assert_eq!(w[11],100_001,"original retry debit missing from cost attribution");
 assert_eq!(w[27],w[26]-w[13]+100_001);assert_eq!(w[21],1);
 let out=setup(1);assert_eq!(accept(&out,10),Err(Error::Busy));let w=publication_cost::snapshot(1);
 assert_eq!((w[15],w[20],w[21],w[22]),(2,2,0,Error::Busy as u64+1));
 assert_eq!(w[46],0);assert_eq!(w[30],Error::Busy as u64+1);
 assert_eq!(READS.load(Ordering::Acquire),8);
 assert_eq!(w[49],1,"Registry refusal lost submit entry");
}
#[test]fn publication_cost_identity_conflict_and_overflow_are_explicit_without_authority(){
 setup(0);let at=policy::PublicationTime{wall_ns:100,cpu:policy::CpuTime{cpu:1,ns:100}};
 publication_cost::begin([11,9,7,1,1,1,1,1],policy::CpuTime{cpu:1,ns:u64::MAX},at,false);
 publication_cost::precommit(8,at); // Foreign Job cannot supply a stage.
 publication_cost::submit_entry(8,at);assert_eq!(publication_cost::snapshot(1)[49],0,"foreign Job supplied submit entry");
 let end=policy::PublicationTime{wall_ns:101,cpu:policy::CpuTime{cpu:1,ns:101}};
 publication_cost::released(7,end);publication_cost::prepare(7,0).finish(end,Err(Error::Overflow),Ok(9),Err(Error::Overflow),false,true);
 let w=publication_cost::snapshot(1);assert_eq!(w[1]&7,7,"identity conflict or arithmetic overflow was hidden");
 assert_eq!((w[27],w[29],w[30]),(u64::MAX,9,0));assert_eq!(w[46],0);
}
#[test]fn publication_cost_unsupported_cpu_is_absent_and_does_not_change_job_authority(){
 for cpu in [0,3,99]{
  let out=setup(0);COST_CPU.store(cpu,Ordering::Release);
  let at=policy::PublicationTime{wall_ns:1,cpu:policy::CpuTime{cpu,ns:1}};
  publication_cost::begin([11,9,1,1,1,1,1,1],at.cpu,at,false);
  publication_cost::precommit(1,at);publication_cost::released(1,at);
  publication_cost::prepare(1,0).finish(at,Ok(0),Ok(1),Ok(()),false,true);
  assert_eq!(publication_cost::snapshot(1),[0;64],"unsupported CPU acquired a foreign evidence row");
  assert_eq!(accept(&out,10),Err(Error::Auth));assert!(pending_job().unwrap());
  COST_CPU.store(1,Ordering::Release);
 }
}
#[test]fn publication_cost_excess_registry_samples_report_capacity_instead_of_overwriting(){
 setup(0);let at=policy::PublicationTime{wall_ns:100,cpu:policy::CpuTime{cpu:1,ns:100}};
 publication_cost::begin([11,9,1,1,1,1,1,1],policy::CpuTime{cpu:1,ns:0},at,false);
 let mut clock=publication_cost::Clock{inner:&mut NativeClock,job:1};
 for _ in 0..6{policy::Clock::read(&mut clock);}
 assert_eq!(publication_cost::snapshot(1)[15],6);
 assert_eq!(publication_cost::snapshot(1)[1]&4,4,"extra Registry sample overflow was hidden");
}
#[test]fn publication_cost_terminal_without_registry_remains_complete_and_decodable(){
 let out=setup(0);WALL.fetch_add(50_000_001,Ordering::AcqRel);
 assert_eq!(accept(&out,10),Err(Error::Expired));
 let w=publication_cost::snapshot(1);
 assert_eq!(w[1],1,"terminal-before-Registry row acquired false chronology failure");
 assert_eq!((w[15],w[20],w[63]),(0,0,1));
 assert_eq!(&w[47..50],&[0,0,0],"pre-submit terminal invented entry");
 println!("TERMINAL_COST={:?}",w);
 let out=setup(0);ACQUIRE_CPU.store(99_999,Ordering::Release);
 let held=TASK_GATE.try_acquire(0,WALL.load(Ordering::Acquire),1).unwrap();
 for _ in 0..5{assert_eq!(accept(&out,10),Err(Error::Busy));}
 ACQUIRE_CPU.store(0,Ordering::Release);assert_eq!(accept(&out,10),Err(Error::Budget));
 held.release(WALL.load(Ordering::Acquire));let w=publication_cost::snapshot(1);
 assert_eq!(w[1],1,"exhausted retry acquired false chronology failure");
 assert_eq!((w[11],w[15],w[20]),(500_000,0,0));
 assert_eq!(&w[47..50],&[0,0,0],"pre-reservation budget failure invented entry");
 with(|s|{assert_eq!(s.registry.query(publisher_fixture(),id()).err(),Some(Error::Stale));Ok(())}).unwrap();
 println!("TERMINAL_COST={:?}",w);
 let out=setup(0);with(|s|{let j=s.job.as_mut().unwrap();j.read_only=true;j.work=Some(core_replay::WorkId);Ok(())}).unwrap();
 assert_eq!(accept(&out,10),Ok(0));let w=publication_cost::snapshot(1);
 assert_eq!(w[1],0,"readonly row acquired false chronology failure");
 assert_eq!((w[15],w[20],w[63]),(0,0,1));
 assert_eq!(&w[47..50],&[0,0,0],"readonly invented submit entry");
 println!("TERMINAL_COST={:?}",w);
}
#[test]fn publication_cost_preparation_is_charged_before_original_terminal_cap(){
 let out=setup(0);DIAGNOSTIC_CPU_COST.store(500_000,Ordering::Release);
 assert_eq!(accept(&out,10),Ok(1),"diagnostic cost replaced original successful Registry receipt");
 with(|s|{assert!(s.registry.optimization_stopped(),"diagnostic preparation escaped original cap");assert_eq!(s.registry.query(publisher_fixture(),id())?.version,1);Ok(())}).unwrap();
 let w=publication_cost::snapshot(1);
 assert_eq!((w[27],w[28],w[29],w[30]),(600_060,Error::Budget as u64+1,1,0),"diagnostic preparation cost omitted from original cumulative sample");
 assert_eq!(FINISHED.lock().unwrap().unwrap().1,600_011,"stored publication debit omitted diagnostic preparation CPU");
}
#[test]fn publication_cost_terminal_serialization_is_charged_and_original_receipt_survives(){
 let out=setup(0);let mut next=with(|s|Ok(s.job.unwrap())).unwrap();SERIALIZER_CPU_COST.store(500_000,Ordering::Release);
 assert_eq!(accept(&out,10),Ok(1),"serializer cost replaced successful Registry receipt");
 with(|s|{assert!(s.registry.optimization_stopped(),"terminal serialization escaped actual enclosing publication cap");assert_eq!(s.registry.query(publisher_fixture(),id())?.version,1);Ok(())}).unwrap();
 assert_eq!(FINISHED.lock().unwrap().unwrap().1,600_011,"terminal serialization omitted from original completion CPU");
 let w=publication_cost::snapshot(1);let context=STOP_CONTEXT.lock().unwrap().unwrap();
 assert_eq!((w[27],w[28],w[29],w[32]),(100_060,0,1,0),"checkpoint was relabeled as final charged authority");
 assert_eq!((context[0],context[4],context[7],context[8],context[12],context[18]),(2,1,1,0,600_061,1));
 println!("STOP_BINDING=[{:?},{:?}]",w,context);
 // A later readonly attempt cannot replace the checkpoint whose serializer
 // alone caused the first real stop. Retention itself runs inside this next
 // attempt's actual charged boundary, never after the previous sample.
 SERIALIZER_CPU_COST.store(0,Ordering::Release);RETENTION_CPU_COST.store(500_000,Ordering::Release);next.sequence=2;next.read_only=true;next.work=Some(core_replay::WorkId);next.started=WALL.load(Ordering::Acquire);
 with(|s|{s.job=Some(next);Ok(())}).unwrap();let mut bad=out;bad[0]=0;
 assert_eq!(accept(&bad,10),Err(Error::Format));let retained=publication_cost::snapshot(1);
 assert_eq!(&retained[2..],&w[2..],"later readonly attempt replaced first serializer-stop checkpoint");
 assert_eq!(retained[1],1,"prior stopped checkpoint was not retained");
 assert!(FINISHED.lock().unwrap().unwrap().1>=500_000,"next readonly completion omitted actual retention-flag CPU");
 println!("RETAINED_COST={:?}",retained);
}
#[test]fn publication_cost_registry_and_local_stop_preserve_original_budget_refusal(){
 let out=setup(8);assert_eq!(accept(&out,10),Err(Error::Budget));
 let w=publication_cost::snapshot(1);let context=STOP_CONTEXT.lock().unwrap().unwrap();
 assert_eq!((w[20],w[21],w[22],w[31],w[32]),(2,0,Error::Budget as u64+1,1,1));
 assert_eq!((context[0],context[7],context[8]),(3,0,Error::Budget as u64+1));
 println!("REGISTRY_PAIR=[{:?},{:?}]",w,context);
}
'''
    return p


class PublicationCost(unittest.TestCase):
    def test_actual_source_retains_cost_boundaries(self):
        artifacts = ROOT / 'artifacts/publication-cost'
        artifacts.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'harness.rs').write_text(source())
            (d / 'Cargo.toml').write_text('[package]\nname="publication-cost"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path=' + json.dumps(str(ROOT/'crates/prototype')) + '}\nsha2="=0.10.9"\n[workspace]\n')
            # A fresh package artifact directory prevents another overlapping
            # suite invocation from replacing a mutation binary before launch.
            command = [str(RUST_BIN/'cargo'), 'test', '--offline', '--manifest-path', str(d/'Cargo.toml'), '--target-dir', str(ROOT/'target/host-publication-cost'/d.name), '--', '--nocapture', '--test-threads=1', 'publication_cost_']
            e=env();e['RUST_MIN_STACK']='16777216'
            r=subprocess.run(command,cwd=ROOT,env=e,capture_output=True,text=True,timeout=120)
            (artifacts/'actual-source.log').write_text(r.stdout+r.stderr)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            from publication_cost import decode_publication_cost, bind_publication_stop
            lines=[line.split('PUBLICATION_COST=',1)[1] for line in r.stdout.splitlines() if 'PUBLICATION_COST=' in line]
            self.assertEqual(len(lines),1)
            bank=struct.pack('<128Q',*(json.loads(lines[0])+[0]*64))
            (artifacts/'actual-source-bank.bin').write_bytes(bank)
            rows=decode_publication_cost(bank,expected={1:{'job':1,'boot':11,'controller':9,'target':1,'generation':1,'version':1}})
            self.assertEqual(rows[0]['checkpoint_cumulative_ns'],600_060)
            self.assertIsNotNone(rows[0]['native_submit_entry'])
            entry_stop=[json.loads(line.split('ENTRY_STOP=',1)[1]) for line in r.stdout.splitlines() if 'ENTRY_STOP=' in line]
            self.assertEqual(len(entry_stop),1)
            entry_words,entry_context=entry_stop[0]
            entry_row=decode_publication_cost(struct.pack('<128Q',*(entry_words+[0]*64)))[0]
            self.assertEqual(entry_row['checkpoint_cap_error'],0)
            self.assertEqual(bind_publication_stop(entry_row,entry_context)['charged_cumulative_ns'],500_002)
            early=[json.loads(line.split('EARLY_COST=',1)[1]) for line in r.stdout.splitlines() if 'EARLY_COST=' in line]
            self.assertEqual(len(early),2)
            for words in early:
                row=decode_publication_cost(struct.pack('<128Q',*(words+[0]*64)))[0]
                self.assertEqual(row['registry_samples'],[])
                self.assertIsNotNone(row['native_submit_entry'])
            precommit=[json.loads(line.split('PRECOMMIT_COST=',1)[1]) for line in r.stdout.splitlines() if 'PRECOMMIT_COST=' in line]
            self.assertEqual(len(precommit),1)
            precommit_row=decode_publication_cost(struct.pack('<128Q',*(precommit[0]+[0]*64)))[0]
            self.assertIsNotNone(precommit_row['precommit'])
            self.assertEqual(precommit_row['registry_version'],0)
            terminal=[json.loads(line.split('TERMINAL_COST=',1)[1]) for line in r.stdout.splitlines() if 'TERMINAL_COST=' in line]
            self.assertEqual(len(terminal),3)
            for words in terminal:
                row=decode_publication_cost(struct.pack('<128Q',*(words+[0]*64)),expected={1:{'job':1,'version':0}})[0]
                self.assertIsNone(row['registry_return'])
                self.assertEqual(row['registry_samples'],[])
            bound=[json.loads(line.split('STOP_BINDING=',1)[1]) for line in r.stdout.splitlines() if 'STOP_BINDING=' in line]
            self.assertEqual(len(bound),1)
            words,context=bound[0]
            checkpoint=decode_publication_cost(struct.pack('<128Q',*(words+[0]*64)))[0]
            self.assertFalse(checkpoint['charged_stop_bound'])
            joined=bind_publication_stop(checkpoint,context)
            self.assertEqual(joined['charged_cumulative_ns'],600_061)
            self.assertEqual(joined['final_result_version'],1)
            self.assertNotIn('final',joined)
            local_stop_words=json.loads(lines[0]);local_stop_words[1]=0
            with self.subTest(contradiction='actual checkpoint stop without frozen'):
                with self.assertRaisesRegex(ValueError,'frozen'):
                    decode_publication_cost(struct.pack('<128Q',*(local_stop_words+[0]*64)))
            for index,value,label in [(0,1,'actual serializer stop misattributed to Registry'),(9,1,'actual serializer local stop marked readonly')]:
                bad_context=context.copy();bad_context[index]=value
                with self.subTest(contradiction=label):
                    with self.assertRaises(ValueError,msg=label):bind_publication_stop(checkpoint,bad_context)
            retained=[json.loads(line.split('RETAINED_COST=',1)[1]) for line in r.stdout.splitlines() if 'RETAINED_COST=' in line]
            self.assertEqual(len(retained),1)
            later=decode_publication_cost(struct.pack('<128Q',*(retained[0]+[0]*64)))[0]
            self.assertTrue(later['frozen'])
            self.assertFalse(later['checkpoint_registry_stopped'])
            self.assertFalse(later['checkpoint_local_stop'])
            self.assertTrue(bind_publication_stop(later,context)['charged_stop_bound'])
            both=[json.loads(line.split('REGISTRY_PAIR=',1)[1]) for line in r.stdout.splitlines() if 'REGISTRY_PAIR=' in line]
            self.assertEqual(len(both),1)
            both_words,both_context=both[0]
            both_row=decode_publication_cost(struct.pack('<128Q',*(both_words+[0]*64)))[0]
            self.assertTrue(bind_publication_stop(both_row,both_context)['charged_stop_bound'])
            both_context[0]=1
            with self.assertRaisesRegex(ValueError,'checkpoint.local.stop'):
                bind_publication_stop(both_row,both_context)
            original=source()
            mutants=[
                ('publication_cost::submit_entry(job.sequence, policy::Clock::read(&mut NativeClock));','', 'publication_cost_paid_submit_entry', 'successful actual publication is missing paid native submit entry'),
                ('    super::pay(super::SUBMIT_ENTRY_CPU_COST.load(super::Ordering::Acquire));','', 'publication_cost_paid_submit_entry', 'submit entry recorder cost escaped original charge'),
                ('publication_cost::precommit(self.job, commit);','', 'publication_cost_successful', 'precommit/Registry-return samples missing'),
                ('publication_cost::returned(\n                job.sequence,\n                policy::Clock::read(&mut NativeClock),\n                submitted.as_ref().map_err(|e| *e),\n            );','', 'publication_cost_successful', 'successful Registry return was lost'),
                ('publication_cost::released(job.sequence, policy::Clock::read(&mut NativeClock));','', 'publication_cost_successful', 'release sample omitted actual release CPU'),
                ('row.put(28, cap.err().map_or(0, |e| e as u64 + 1));','row.put(28,0);','publication_cost_successful','final cap failure replaced Registry success'),
                ('if row.get(5) != job {\n        row.flag(2);\n        return None;\n    }','if row.get(5) != job { return None; }','publication_cost_identity','identity conflict or arithmetic overflow was hidden'),
                ('Err(_) => 4','Err(_) => 0','publication_cost_identity','identity conflict or arithmetic overflow was hidden'),
                ('else {\n                row.flag(4);\n            }','else {}','publication_cost_excess','extra Registry sample overflow was hidden'),
                ('if i == 18 && row.get(20) == 0 {','if false {','publication_cost_terminal','terminal-before-Registry row acquired false chronology failure'),
                ('let publication_cost = publication_cost::prepare(job.sequence, decoding);\n        let observed = policy::Clock::read(&mut NativeClock);','let observed = policy::Clock::read(&mut NativeClock);\n        let publication_cost = publication_cost::prepare(job.sequence, decoding);','publication_cost_preparation','diagnostic preparation cost omitted from original cumulative sample'),
                ('publication_cost.finish(\n            observed,\n            checkpoint_elapsed,\n            checkpoint_result,\n            checkpoint_cap,\n            registry_stopped,\n            checkpoint_local_stop,\n        );\n        // No diagnostic access or mutation may follow this charged boundary.\n        let observed = policy::Clock::read(&mut NativeClock);','let observed = policy::Clock::read(&mut NativeClock);\n        publication_cost.finish(\n            observed,\n            checkpoint_elapsed,\n            checkpoint_result,\n            checkpoint_cap,\n            registry_stopped,\n            checkpoint_local_stop,\n        );','publication_cost_terminal_serialization','terminal serialization escaped actual enclosing publication cap'),
                ('if preserve {','if false {','publication_cost_terminal_serialization','later readonly attempt replaced first serializer-stop checkpoint'),
            ]
            entry='publication_cost::submit_entry(job.sequence, policy::Clock::read(&mut NativeClock));'
            boundary='// No diagnostic access or mutation may follow this charged boundary.\n        let observed = policy::Clock::read(&mut NativeClock);'
            self.assertEqual(original.count(boundary),1)
            late=original.replace(entry,'').replace(boundary,boundary+'\n        '+entry)
            mutants.append((original,late,'publication_cost_paid_submit_entry','submit entry is outside S/R1'))
            for i,(old,new,name,message) in enumerate(mutants):
                self.assertEqual(original.count(old),1,old)
                (d/'harness.rs').write_text(original.replace(old,new))
                r=subprocess.run(command[:-1]+[name],cwd=ROOT,env=e,capture_output=True,text=True,timeout=120)
                output=r.stdout+r.stderr
                (artifacts/f'negative-{i}.log').write_text(output)
                self.assertNotEqual(r.returncode,0,output)
                self.assertNotIn('error[E',output)
                self.assertIn('test result: FAILED',output)
                self.assertIn(message,output)


if __name__ == '__main__':
    unittest.main()
