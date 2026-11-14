"""Actual FS/Journal + kernel file broker + actual mode4 client; host regression only."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from doctor import ROOT,RUST_BIN,env
from host_prototype_library import build_host_prototype_library
from test_a01_formal_recorder import function

CLIENT_SOURCE=ROOT/'user/prototype-client/storage_fault.rs'
HARNESS_SOURCE=ROOT/'tests/host/a10_write_backpressure_harness.rs'

class ActualWriteBackpressure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='a10-real-write-')
        cls.directory=Path(cls.temporary.name)
        source=HARNESS_SOURCE.read_text().replace('__BROKER__',str(ROOT/'kernel/src/runtime/files/domain_file_abi.rs')).replace('__CLIENT__',str(CLIENT_SOURCE))
        source=source.replace('// ACTUAL_FILE_CALL',function((ROOT/'user/prototype-client/main.rs').read_text(),'fn file_call('))
        path=cls.directory/'harness.rs';path.write_text(source)
        deps,library=build_host_prototype_library();cls.binary=cls.directory/'harness'
        result=subprocess.run([str(RUST_BIN/'rustc'),'--edition=2024','-C','panic=abort','-C','opt-level=1',str(path),'-L','dependency='+str(deps),'--extern','cyxia_prototype='+str(library),'-o',str(cls.binary)],env=env(),capture_output=True,text=True,timeout=60)
        if result.returncode:raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def check_case(self,case,signal):
        result=subprocess.run([str(self.binary),case],capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn(signal,result.stdout)

    def test_whole_actual_client_retries_real_cache_pressure_and_verifies_bytes(self):
        self.check_case('normal','REAL_DURABLE_PRESSURE both_8MiB_exact seq128 original8192 PASS')

    def test_partial_page_prepare_again_does_not_change_file_or_disk(self):
        self.check_case('partial','REAL_DURABLE_PRESSURE both_8MiB_exact seq128 original8192 PASS')

    def test_global_limit_counts_completed_again_across_the_workload(self):
        self.check_case('stalled','GLOBAL_RETRY_LIMIT retries90 completed_EAGAIN91 exact_error214')

    def test_completed_again_requires_a_fresh_request_identity(self):
        self.check_case('identity','OLD_COMPLETED_ID_STALE new_request_same_offset_after_actual_flush_success PASS')

    def test_original_absolute_deadline_still_stops_before_another_write(self):
        self.check_case('deadline','ORIGINAL_ABSOLUTE_DEADLINE error205 no_new_write PASS')

    def test_real_nontransient_authorization_error_is_not_retried(self):
        self.check_case('auth','REAL_AUTH_FAILURE fatal207 no_retry PASS')

if __name__=='__main__':unittest.main()
