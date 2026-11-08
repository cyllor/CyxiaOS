"""Actual timer-owner progress through production service and full mode4 client.

Console/supervision, physical CPU reservations and root byte/DMA policy are not
modeled. No timer errors are mocked: resource/time errors come from real Timers.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from host_prototype_library import build_host_prototype_library
from test_a01_formal_recorder import function

SERVICE_SOURCE = ROOT / 'kernel/src/domain_services.rs'
HARNESS_SOURCE = Path(__file__).with_name('background_maintenance_harness.rs')

MINIMAL_HEADER = '''
extern crate self as cyxia_arch_aarch64;
use cyxia_prototype::domains::{Error,ObjectKey,filesystem::FlushReceipt};
use std::{cell::RefCell,sync::atomic::{AtomicBool,AtomicU64,Ordering}};
static NOW:AtomicU64=AtomicU64::new(0);
fn clock()->u64{NOW.load(Ordering::Relaxed)}
mod cpu{pub fn slot()->usize{0}}
mod domain_tasks{pub fn service_baseline_progress(){}}
static FLUSH_HARD_ERROR:AtomicBool=AtomicBool::new(false);
static FLUSH_CALLBACK:AtomicBool=AtomicBool::new(false);
mod domain_storage{
 use super::*;
 // This port counts entry. The full-client binary below uses actual FS/Journal.
 pub fn background_flush(_:u64,_:&mut dyn FnMut())->Result<Option<FlushReceipt>,Error>{MAINTENANCE_FLUSH.fetch_add(1,Ordering::Relaxed);if FLUSH_CALLBACK.load(Ordering::Relaxed){NOW.store(LAST_ARM_DEADLINE.load(Ordering::Relaxed),Ordering::Relaxed);domain_platform::poll(clock())?;}if FLUSH_HARD_ERROR.load(Ordering::Relaxed){Err(Error::Io)}else{Ok(None)}}
 pub fn cache_reclaim_turn()->Result<usize,Error>{Ok(0)}
}
'''
MINIMAL_MAIN = '''
fn main(){
 let case=std::env::args().nth(1).unwrap();domain_platform::setup();NOW.store(1_000_000_000,Ordering::Relaxed);
 if case=="no-progress-clock"{ADVANCE.store(false,Ordering::Relaxed);}
 if case=="resource"{
  domain_platform::poll(clock()).unwrap();domain_platform::remove_fired_timer();
  assert_eq!(domain_services::service(clock(),&mut maintenance_progress),Err(Error::Stale));
  assert!(domain_services::due_now());assert_eq!(MAINTENANCE_FLUSH.load(Ordering::Relaxed),0);
  domain_platform::register_missing_timer();
 }else if case=="owner-busy"{
  LOCK_ON_SECOND.store(true,Ordering::Relaxed);
  assert_eq!(domain_services::service(clock(),&mut maintenance_progress),Err(Error::Busy));
  assert!(domain_services::due_now());assert_eq!(MAINTENANCE_FLUSH.load(Ordering::Relaxed),0);
  LOCK_ON_SECOND.store(false,Ordering::Relaxed);domain_services::set_locked(false);
 }else if case=="overflow"{
  NOW.store(u64::MAX-5_000_000,Ordering::Relaxed);
  assert_eq!(domain_services::service(clock(),&mut maintenance_progress),Err(Error::Overflow));
  assert!(domain_services::due_now());assert_eq!(MAINTENANCE_FLUSH.load(Ordering::Relaxed),0);
  println!("OVERFLOW_ORIGINAL_ERROR_PENDING_PASS");return;
 }else if case=="entry-stale"{
  domain_platform::poll(clock()+1_000_000).unwrap();
  assert_eq!(domain_services::service(clock(),&mut maintenance_progress),Err(Error::Stale));
  assert!(domain_services::due_now());assert_eq!(MAINTENANCE_FLUSH.load(Ordering::Relaxed),0);
  NOW.fetch_add(2_000_000,Ordering::Relaxed);
 }else if case=="hard-flush"||case=="hard-flush-callback"{
  FLUSH_HARD_ERROR.store(true,Ordering::Relaxed);FLUSH_CALLBACK.store(case=="hard-flush-callback",Ordering::Relaxed);
  assert_eq!(domain_services::service(clock(),&mut maintenance_progress),Err(Error::Io));
  assert_eq!(domain_services::due_now(),case=="hard-flush-callback","hard flush failure changed a newly delivered due callback");
  assert_eq!(MAINTENANCE_FLUSH.load(Ordering::Relaxed),1);
  let deadline=LAST_ARM_DEADLINE.load(Ordering::Relaxed);
  if case=="hard-flush"{assert!(deadline>clock());NOW.store(deadline,Ordering::Relaxed);domain_platform::poll(clock()).unwrap();}
  FLUSH_HARD_ERROR.store(false,Ordering::Relaxed);FLUSH_CALLBACK.store(false,Ordering::Relaxed);
  assert!(domain_services::due_now(),"previously armed timer was lost after hard flush error");
 }
 let before=clock();assert_eq!(domain_services::service(before,&mut maintenance_progress),Ok(()));
 assert!(!domain_services::due_now());assert_eq!(MAINTENANCE_FLUSH.load(Ordering::Relaxed),if case=="hard-flush"||case=="hard-flush-callback"{2}else{1});
 assert_eq!(LAST_ARM_DEADLINE.load(Ordering::Relaxed)-LAST_ARM_NOW.load(Ordering::Relaxed),10_000_000,"original background period changed");
 assert_eq!(LAST_ARM_NOW.load(Ordering::Relaxed),clock(),"timer arm did not use current owner time");
 println!("REAL_TIMER_MAINTENANCE_PASS case={case} progress_calls={} flush_calls={}",PROGRESS_CALLS.load(Ordering::Relaxed),MAINTENANCE_FLUSH.load(Ordering::Relaxed));
}
'''


class BackgroundMaintenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='maintenance-progress-')
        cls.directory = Path(cls.temporary.name)
        source = SERVICE_SOURCE.read_text()
        fixture = HARNESS_SOURCE.read_text()
        names = ['fn now_ns()', 'impl Drop for Guard', 'fn with<R>', 'fn due(', 'pub fn service(']
        pieces = ['struct Guard;'] + [function(source, name) for name in names]
        pieces = [part.replace('fn due(', 'pub(super) fn due(', 1) for part in pieces]
        fixture = fixture.replace('// PRODUCTION_SERVICE_BODIES', '\n'.join(pieces))
        period = re.search(r'^const BACKGROUND_PERIOD:.*;$', source, re.M)[0]
        fixture = fixture.replace('// PRODUCTION_BACKGROUND_PERIOD', period)
        fixture = fixture.replace('// PRODUCTION_MECHANISM', function(
            (ROOT / 'kernel/src/unified.rs').read_text(), 'fn mechanism_progress('))
        minimal = MINIMAL_HEADER + fixture + MINIMAL_MAIN
        full = (ROOT / 'tests/host/a10_write_backpressure_harness.rs').read_text()
        full = full.replace('__BROKER__', str(ROOT / 'kernel/src/domain_file_abi.rs'))
        full = full.replace('__CLIENT__', str(ROOT / 'user/prototype-client/storage_fault.rs'))
        full = full.replace('// ACTUAL_FILE_CALL', function(
            (ROOT / 'user/prototype-client/main.rs').read_text(), 'fn file_call('))
        old = 'if !STALLED.load(Ordering::Relaxed){with_fs(|f,j,d,s|{f.background_flush(clock(),j,d,s).unwrap();});}'
        if full.count(old) != 1:
            raise AssertionError('actual whole-client maintenance hook changed')
        full = full.replace(old, 'let _=domain_services::service(clock(),&mut maintenance_progress);')
        full = full.replace('mod domain_storage{use super::*;', 'mod domain_storage{use super::*;'
            'pub fn background_flush(now:u64,_:&mut dyn FnMut())->Result<Option<FlushReceipt>,Error>{'
            'MAINTENANCE_FLUSH.fetch_add(1,Ordering::Relaxed);with_fs(|f,j,d,s|f.background_flush(now,j,d,s))}'
            'pub fn cache_reclaim_turn()->Result<usize,Error>{Ok(with_fs(|f,_,_,_|f.reclaim_cache()))}')
        full = full.replace('mod domain_tasks{use super::*;',
            'mod domain_tasks{use super::*;pub fn service_baseline_progress(){}')
        full = full.replace('FS.with(|s|*s.borrow_mut()=Some(State{fs,journal,disk,scratch}));',
            'FS.with(|s|*s.borrow_mut()=Some(State{fs,journal,disk,scratch}));domain_platform::setup();')
        full += '\n' + fixture
        deps, library = build_host_prototype_library()
        cls.binaries = {}
        for label, rendered in [('minimal', minimal), ('full', full)]:
            path = cls.directory / (label + '.rs')
            path.write_text(rendered)
            binary = cls.directory / label
            command = [str(RUST_BIN / 'rustc'), '--edition=2024', '-C', 'panic=abort', '-C',
                'opt-level=1', str(path), '-L', 'dependency=' + str(deps), '--extern',
                'cyxia_prototype=' + str(library), '-o', str(binary)]
            result = subprocess.run(command, env=env(), capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise AssertionError(result.stderr)
            cls.binaries[label] = binary

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_case(self, case):
        result = subprocess.run([str(self.binaries['minimal']), case], capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_actual_progress_refreshes_timer_owner_time_and_preserves_period(self):
        self.assertIn('REAL_TIMER_MAINTENANCE_PASS', self.run_case('normal'))

    def test_removing_elapsed_progress_keeps_control_green(self):
        self.assertIn('REAL_TIMER_MAINTENANCE_PASS', self.run_case('no-progress-clock'))

    def test_real_missing_timer_error_remains_pending_until_resource_returns(self):
        self.assertIn('REAL_TIMER_MAINTENANCE_PASS', self.run_case('resource'))

    def test_real_owner_lock_failure_restores_due_before_retry(self):
        self.assertIn('REAL_TIMER_MAINTENANCE_PASS', self.run_case('owner-busy'))

    def test_real_timer_rejects_old_entry_time_without_losing_due(self):
        self.assertIn('REAL_TIMER_MAINTENANCE_PASS', self.run_case('entry-stale'))

    def test_deadline_overflow_keeps_pending_and_original_error(self):
        self.assertIn('OVERFLOW_ORIGINAL_ERROR_PENDING_PASS', self.run_case('overflow'))

    def test_hard_flush_error_retains_armed_timer_without_immediate_retry(self):
        self.assertIn('REAL_TIMER_MAINTENANCE_PASS', self.run_case('hard-flush'))

    def test_hard_flush_error_preserves_a_new_real_timer_callback(self):
        self.assertIn('REAL_TIMER_MAINTENANCE_PASS', self.run_case('hard-flush-callback'))

    def test_actual_whole_client_with_real_timed_maintenance(self):
        result = subprocess.run([str(self.binaries['full']), 'normal'], capture_output=True,
            text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('REAL_DURABLE_PRESSURE both_8MiB_exact seq128 original8192 PASS', result.stdout)
        self.assertIn('REAL_CACHE_EVICTION final_misses=', result.stdout)


if __name__ == '__main__':
    unittest.main()
