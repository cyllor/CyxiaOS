"""Actual network/checkpoint/service billing with real Scheduler and gate.

TCP/device behavior is a counted boundary here; separate library regressions
cover the fixed operation markers. Diagnostics grant no execution authority.
"""
import json
from pathlib import Path
import shutil
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class NetworkPieceTrace(unittest.TestCase):
    def test_real_driver_reports_fixed_rx_and_queue_stages_without_new_checkpoints(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            shutil.copytree(ROOT / 'crates/driver-virtio/src', directory / 'src')
            (directory / 'Cargo.toml').write_text('[package]\nname="cyxia-driver-virtio"\nversion="0.1.0"\nedition="2024"\n[workspace]\n')
            has_hook = 'fn diagnostic_stage(' in (directory / 'src/lib.rs').read_text()
            for name, fixture in [('queue.rs', 'queue'), ('net/batched.rs', 'rx')]:
                path = directory / 'src' / name
                source = path.read_text()
                source = source.replace('mod tests {', 'mod tests {\nstatic TRACE:std::sync::Mutex<std::vec::Vec<u64>>=std::sync::Mutex::new(std::vec::Vec::new());', 1)
                if has_hook:
                    start = source.index('unsafe impl Platform for Host {')
                    at = source.index('{', start) + 1
                    source = source[:at] + '\nfn diagnostic_stage(&self,n:u64){TRACE.lock().unwrap().push(n);}\n' + source[at:]
                if fixture == 'queue':
                    test = '''
#[test]fn trace_fixed_queue_stages_keep_eight_original_boundaries(){
 let(mut q,mut t,p)=fixture(16);q.enqueue(&mut t,&[],15,true,false,&p).unwrap();used(&mut q,0,15);
 TRACE.lock().unwrap().clear();let mut checkpoints=std::vec::Vec::new();let mut out=[0;15];
 let c=q.poll_with_checkpoint(&mut t,&mut out,&p,&mut||{checkpoints.push(TRACE.lock().unwrap().last().copied().unwrap_or(0));}).unwrap().unwrap();
 assert_eq!(c.len,15);assert_eq!(checkpoints.len(),8);
 assert_eq!(checkpoints,[11,12,13,15,16,17,18,19],"actual queue operations had no fixed stage identity");
 assert_eq!(TRACE.lock().unwrap().last().copied(),Some(20));
}
'''
                else:
                    test = '''
#[test]fn trace_fixed_rx_stages_preserve_copy_and_rearm_custody(){
 let(mut n,p,rx,_)=fixture();unsafe{let response=u64::from_le(read_volatile(rx as *const u64))as usize;
 for i in 0..76{write_volatile((response+i)as *mut u8,if i<12{0}else{0x62});}write_volatile((response+10)as *mut u16,1u16.to_le());used(rx,0,76);}
 TRACE.lock().unwrap().clear();let mut checkpoints=0;let mut out=[0;64];
 assert_eq!(n.receive_with_checkpoint(&mut out,&p,&mut||checkpoints+=1),Ok(Some(64)));
 assert_eq!(out,[0x62;64]);assert_eq!(checkpoints,10);assert_eq!(n.rx.free(),0);assert_eq!(n.rx.stats().published,9);
 let stages=TRACE.lock().unwrap();for id in [6,7,8,9,10]{assert!(stages.contains(&id),"actual RX custody transition had no fixed stage identity");}
}
'''
                source = source[:source.rindex('}')] + test + source[source.rindex('}'):]
                path.write_text(source)
            result = subprocess.run([str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-network-stage-driver'),
                'trace_fixed_', '--', '--test-threads=1'], cwd=ROOT, env=env(), capture_output=True,
                text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('2 passed; 0 failed', result.stdout)

    def test_real_tcp_stages_keep_original_idle_and_clock_error_boundaries(self):
        source = (ROOT / 'crates/cluster-transport/tests/network.rs').read_text()
        source = source.replace('struct Link {', 'struct Link {\n    trace: Vec<u64>,', 1)
        if 'fn diagnostic_stage(' in (ROOT / 'crates/cluster-transport/src/device.rs').read_text():
            source = source.replace('impl Port for TestPort {', 'impl Port for TestPort {\nfn diagnostic_stage(&self,n:u64){self.link.borrow_mut().trace.push(n);}', 1)
        source += '''
#[test]fn trace_fixed_tcp_stages_do_not_schedule_extra_pieces(){
 let link=Rc::new(RefCell::new(Link::default()));let(mut rx,mut tx)=([0;BUFFER_SIZE],[0;BUFFER_SIZE]);let mut storage=[Storage::EMPTY];
 let mut tcp=Tcp::new(TestPort{link:link.clone(),a:false},config(false),0,&mut rx,&mut tx,&mut storage).unwrap();tcp.listen().unwrap();
 link.borrow_mut().trace.clear();let mut checks=0;tcp.poll_with_checkpoints(1,&mut||checks+=1).unwrap();assert_eq!(checks,12);
 let stages=link.borrow().trace.clone();for id in [1,2,3,4,5,21,22,23,24,25,26]{assert!(stages.contains(&id),"actual TCP operation had no fixed stage identity");}
 link.borrow_mut().trace.clear();let mut checks=0;assert_eq!(tcp.poll_with_checkpoints(0,&mut||checks+=1),Err(Error::Clock));assert_eq!(checks,1);
 assert_eq!(link.borrow().trace,[1,2,28]);
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'network.rs').write_text(source)
            (directory / 'Cargo.toml').write_text('[package]\nname="network-stage-tcp"\nversion="0.1.0"\nedition="2024"\n[[test]]\nname="network"\npath="network.rs"\n[dependencies]\ncyxia-cluster-transport={path=' + json.dumps(str(ROOT / 'crates/cluster-transport')) + '}\n[workspace]\n')
            result = subprocess.run([str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-network-stage-tcp'),
                'trace_fixed_', '--', '--test-threads=1'], cwd=ROOT, env=env(), capture_output=True,
                text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('1 passed; 0 failed', result.stdout)

    def test_actual_network_pieces_keep_original_bills_and_stages(self):
        task = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        unified = (ROOT / 'kernel/src/unified.rs').read_text()
        pieces = ['static LOCK: ResettableGate = ResettableGate(core::cell::UnsafeCell::new(owner_gate::Gate::new()));']
        pieces += [function(task, sig) for sig in ['struct Guard', 'impl Guard',
            'impl Drop for Guard', 'fn acquire_guard()', 'fn locked<R>', 'fn locked_with_guard<R>',
            'pub struct Credit', 'fn admit_service(', 'pub fn begin_service_segment()',
            'fn revalidate_unstarted(', 'pub fn revalidate_service_segment()',
            'fn complete_locked(', 'pub fn complete_builtin(', 'pub fn complete_service(',
            'pub fn service_segment<R>']]
        pieces += [function(unified, sig) for sig in ['fn mechanism_progress(',
            'fn resume_network_service(', 'fn network_turn(', 'fn finish_service(']]
        if 'fn finish_network_service(' in unified:
            pieces.append(function(unified, 'fn finish_network_service('))
        pieces.append('#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks/owner_gate.rs')) + '] mod owner_gate;')
        template = (ROOT / 'tests/host/network_piece_trace_harness.rs').read_text()
        template = template.replace('// PRODUCTION_BODIES', '\n'.join(pieces))
        module = ROOT / 'kernel/src/network_diagnostics.rs'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            diagnostic = directory / 'network.rs'
            if module.exists():
                diagnostic.write_text(module.read_text() + '''
pub fn snapshots()->([u64;64],[u64;64]){(core::array::from_fn(|i|CPU0_BANK.get(i)),core::array::from_fn(|i|TASK_BANK.get(i)))}
pub fn reset(){unsafe{*CPU_STATE.0.get()=CpuState::new();}for b in [&CPU0_BANK,&TASK_BANK]{for w in &b.words{w.store(0,Ordering::Relaxed);}}}
pub fn corrupt_pending(i:usize,value:u64){CPU0_BANK.put(i,value);}
''')
            else:
                diagnostic.write_text('''
pub fn stage(_:u64){} pub fn reset(){} pub fn snapshots()->([u64;64],[u64;64]){([0;64],[0;64])}
pub fn corrupt_pending(_:usize,_:u64){}
''')
            template = template.replace('// DIAGNOSTIC_MODULE', '#[path=' + json.dumps(str(diagnostic)) + '] mod network_diagnostics;')
            source = directory / 'harness.rs'
            source.write_text(template)
            (directory / 'Cargo.toml').write_text('[package]\nname="network-piece-trace"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[features]\ndefault=["unified-runtime"]\nunified-runtime=[]\n[dependencies]\ncyxia-prototype={path=' + json.dumps(str(ROOT / 'crates/prototype')) + '}\ncyxia-driver-virtio={path=' + json.dumps(str(ROOT / 'crates/driver-virtio')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-network-piece-trace'),
                '--', '--test-threads=1']
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('8 passed; 0 failed', result.stdout)
            original_diagnostic = diagnostic.read_text()
            normal = 'actual_pieces_have_exact_original_identity_cpu_and_finish'
            stage = function(original_diagnostic, 'pub(crate) fn stage(')
            without_cpu_check = re.sub(r'if cpu::slot\(\) != 0\s*\{\s*return;\s*\}', '', stage, count=1)
            mutants = [
                (template.replace('crate::network_diagnostics::admitted(d);', ''), original_diagnostic,
                    normal, 'actual network settlement identity was absent'),
                (template.replace('crate::network_diagnostics::finish(ticket, actual_ns, finished_ns);', ''), original_diagnostic,
                    normal, 'actual network settlement identity was absent'),
                (re.sub(r'crate::network_diagnostics::settled\([^;]+\);', '', template, count=1), original_diagnostic,
                    normal, 'actual network settlement identity was absent'),
                (template, original_diagnostic.replace('s.active.take().unwrap()', 's.active.unwrap()'),
                    normal, 'new reservation reused prior network diagnostic'),
                (template, original_diagnostic.replace(stage, without_cpu_check),
                    normal, 'foreign CPU or helper relabeled network piece'),
                (template, re.sub(r'if first & 1 != 0\s*\{\s*return None;\s*\}', '', original_diagnostic, count=1),
                    'corrupt_pending_is_ignored_without_changing_real_settlement', 'invalid pending snapshot was silently accepted'),
                (template, original_diagnostic.replace('actual_ns > dispatch.reserved_ns &&', ''),
                    'retained_active_budget_error_is_not_a_physical_overrun', 'Budget code without excess CPU became physical overrun'),
                (template, original_diagnostic.replace('!still_active &&', ''),
                    'retained_active_budget_error_is_not_a_physical_overrun', 'retained Budget attempt became a physical overrun'),
                (template, original_diagnostic.replace('if b.get(36) == 0 {', 'if true {'),
                    'sticky_overrun_comes_from_the_real_scheduler_completion', 'later overrun overwrote first physical overrun'),
            ]
            for altered, bank, case, failure in mutants:
                self.assertTrue(altered != template or bank != original_diagnostic, failure)
                source.write_text(altered)
                diagnostic.write_text(bank)
                negative = subprocess.run(command + ['--exact', case], cwd=ROOT, env=env(),
                    capture_output=True, text=True, timeout=120)
                self.assertNotEqual(negative.returncode, 0, failure)
                self.assertIn(failure, negative.stdout + negative.stderr)


if __name__ == '__main__':
    unittest.main()
