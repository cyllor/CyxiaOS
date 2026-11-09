"""Host-only matrix/operator wiring; native producer and verifier are explicit seams."""
import copy
import inspect
from pathlib import Path
import unittest
from unittest.mock import patch

import run_v16_a10_matrix_v4 as runner
import v16_a10_matrix_v4 as matrix
from v16_a10_live_watch_v1 import OperatorDiagnosticStop
import test_v16_a10_matrix_v4 as fixtures


class MatrixWatchR2(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.MatrixTraversalV4('test_empty_and_bounded_prefix_never_claim_cache_or_complete')
        self.fixture.setUp()
    def tearDown(self):self.fixture.tearDown()

    def test_opt_in_uses_original_mode4_argv_and_stop_cannot_credit_or_retry(self):
        f=self.fixture;f.root.rmdir()
        request=copy.deepcopy(f.request)
        request.update(max_storage_bytes=8*1024**3,operator_diagnose_stalled_cache=True)
        def review(root,request,progress,*,context):
            return matrix.inspect_progress(root,request,progress,context=context,loader=f.loader,
                selectors=f.selectors,verify_snapshot=False,window_validator=lambda *a:None)
        def produce(build,parent,directory,*,mode,**kwargs):
            self.assertNotEqual(mode,4,'mode4 must use its isolated original subprocess when opted in')
            task=matrix.Task(directory.relative_to(f.root).as_posix(),mode,parent,
                             kwargs.get('expected_mutation'),kwargs['phase'],kwargs['unflushed'])
            ref=f.make(task,directory)
            return f.facts[ref['directory']].summary
        def check(task,ref,*,context):
            return matrix.check_child(task,ref,context=context,loader=f.loader)
        def monitor(argv,**kwargs):
            self.assertEqual(Path(argv[2]),runner.ROOT/'tools/run_v13_a10.py')
            for option,value in (('--mode','4'),('--timeout','21720'),('--cut','0'),
                                 ('--phase','before'),('--unflushed','drop'),('--sample-ms','30000')):
                self.assertEqual(argv[argv.index(option)+1],value)
            self.assertIn('--reverse-replies',argv)
            self.assertEqual(kwargs['capture'],f.root/'cache-eviction')
            self.assertFalse(kwargs['diagnostics'].is_relative_to(f.root))
            raise OperatorDiagnosticStop(kwargs['diagnostics']/'observation.json')
        args=dict(output=f.root,seed=f.seed,prepare=f.prepare,overwrite_probe=f.probe,
            source_root=runner.ROOT.resolve(),build_manifest=f.base/'build.json',qemu_binary=f.base/'qemu',
            qemu_source=f.base/'qemu-source',native_lock=f.base/'native.lock',max_new_children=2,
            max_storage_bytes=8*1024**3,operator_diagnose_stalled_cache=True)
        with patch.object(runner,'snapshot',return_value=request),patch.object(runner,'idle_native_host'),\
             patch.object(runner,'inspect_progress',side_effect=review),\
             patch.object(runner,'check_child',side_effect=check),\
             patch.object(runner,'scenario_budget',return_value=dict(capture_timeout_seconds=21720)),\
             patch.object(runner,'run_cut',side_effect=produce),\
             patch.object(runner,'run_clean',side_effect=produce),\
             patch.object(runner,'run_monitored_clean',side_effect=monitor) as watched:
            runner.run(**args)
            before=matrix.load_progress(f.root)
            result=runner.run(**args,resume=True)
            self.assertTrue(result['operator_interrupted'])
            self.assertEqual(result['status'],'NOT_RUN')
            self.assertFalse(result['cache_eviction_verified'])
            self.assertFalse(result['A10_complete'])
            self.assertEqual(result['invocation_verified_children'],0)
            self.assertEqual(matrix.load_progress(f.root),before)
            self.assertEqual(watched.call_count,1)
            with self.assertRaisesRegex(ValueError,'preserves original failed campaign'):
                runner.run(**args,resume=True)
            self.assertEqual(watched.call_count,1)

    def test_default_is_off_and_old_request_cannot_enter_new_revision(self):
        self.assertIs(inspect.signature(runner.run).parameters['operator_diagnose_stalled_cache'].default,False)
        legacy=dict(schema_version=4,test_id='A10',version='a10-all-matrix-native-v4',
            overwrite_points='all',recovery_points='all',phases=list(matrix.PHASES),losses=list(matrix.LOSSES),
            sample_ms=30000,reverse_replies=True,source_root='/source',build_manifest='/build.json',
            build_manifest_sha256='0'*64,code_source_sha256='0'*64,qemu_binary='/qemu',qemu_source='/qemu-source',
            qemu_identity={},tools={},seed={},prepare={},overwrite_probe={},max_storage_bytes=8*1024**3,
            per_child_reserve_bytes=matrix.PER_CHILD_RESERVE)
        with self.assertRaisesRegex(ValueError,'request schema'):
            matrix.validate_snapshot(legacy,source_root=Path('/source'),build_manifest=Path('/build.json'),
                                     qemu_binary=Path('/qemu'),qemu_source=Path('/qemu-source'))


if __name__=='__main__':unittest.main()
