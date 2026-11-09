"""Synthetic traversal fixtures exercise the real matrix graph, never native proof."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import v16_a10_matrix_v4 as matrix


class MatrixTraversalV4(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='a10-matrix-v4-')
        self.base=Path(self.tmp.name).resolve()
        self.root=self.base/'campaign';self.root.mkdir()
        self.seed=self.base/'seed.raw';self.seed.write_bytes(b'host fixture seed')
        self.prepare=self.base/'prepare';self.probe=self.base/'probe'
        self.facts={}
        self.row=lambda point:dict(cut=point,kind=1,offset=point*512,length=512,data_sha256='1'*64)
        self.overwrite={1:self.row(1),2:self.row(2)}
        self.progress=dict(schema_version=4,status='IN_PROGRESS',completed={})
        self.make(matrix.Task('prepare',1,self.seed),self.prepare)
        self.make(matrix.Task('overwrite-probe',2,self.prepare/'disk.raw'),self.probe)
        self.request=dict(seed=dict(path=str(self.seed)),prepare=matrix.entry(self.prepare),
                          overwrite_probe=matrix.entry(self.probe),overwrite_points='all',recovery_points='all')

    def tearDown(self):
        self.tmp.cleanup()

    def selectors(self,path):
        return self.overwrite if Path(path)==self.probe else {1:self.row(1)}

    def make(self,task,directory):
        directory.mkdir(parents=True,exist_ok=True)
        (directory/'initial.raw').write_bytes(task.parent.read_bytes())
        (directory/'disk.raw').write_bytes(('fixture '+task.name).encode())
        (directory/'summary.json').write_text('{"host_fixture_only":true}\n')
        cut=task.selector is not None
        inputs=dict(mode=task.mode,cut=task.selector['cut'] if cut else 0,phase=task.phase,
                    unflushed=task.loss,reverse_replies=True,sample_ms=30000,
                    initial_disk_sha256=matrix.sha256(task.parent))
        if cut:inputs['caller_mutation']=copy.deepcopy(task.selector)
        summary=dict(status='NOT_RUN' if cut else 'PASS',native_mode_verified=not cut,
                     cut_observed=cut,native_matrix_cut_custody_verified=cut,
                     nbd_trace=dict(reordered_replies=task.name=='overwrite-probe'),
                     consumption_boundary=dict(present=cut and task.mode==2),
                     observation=dict(consumption_boundary=dict(present=task.mode in (1,2)),
                                      cache_eviction_verified=task.mode==4,pressure_pages=4096))
        self.facts[str(directory)]=SimpleNamespace(inputs=inputs,summary=summary,
                                context=dict(initial_source=str(task.parent)))
        return matrix.entry(directory)

    def loader(self,task,directory,context):
        return self.facts[str(directory)]

    def review(self):
        return matrix.inspect_progress(self.root,self.request,self.progress,context={},
                    loader=self.loader,selectors=self.selectors,verify_snapshot=False,
                    window_validator=lambda probe,child,selected:None)

    def fill(self):
        # tasks() derives second-level mutation rows only after that exact
        # damaged-parent recovery probe has become available.
        verified={}
        for task in matrix.tasks(self.root,self.prepare,self.probe,verified,selectors=self.selectors):
            ref=self.make(task,self.root/task.name)
            self.progress['completed'][task.name]=ref
            verified[task.name]=self.facts[ref['directory']]

    def test_empty_and_bounded_prefix_never_claim_cache_or_complete(self):
        result,ready=self.review()
        self.assertEqual(result['status'],'NOT_RUN')
        self.assertFalse(result['cache_eviction_verified'])
        self.assertEqual(result['required_primary_cases'],8)
        self.assertIsNone(result['exact_total_new_children'])
        self.assertEqual(ready[0].name,'overwrite/p0001-before-drop/cut')
        task=ready[0]
        self.progress['completed'][task.name]=self.make(task,self.root/task.name)
        result,ready=self.review()
        self.assertEqual(result['overwrite_cases'],1)
        self.assertFalse(result['A10_complete'])
        self.assertFalse(result['cache_eviction_verified'])
        self.assertEqual(ready[0].name,'overwrite/p0001-before-drop/recovery-probe')
        self.assertEqual(ready[0].parent,self.root/task.name/'disk.raw')

    def test_all_cartesian_rows_and_true_cache_are_required(self):
        self.fill()
        result,ready=self.review()
        self.assertEqual(len(self.progress['completed']),81)
        self.assertEqual(result['exact_total_new_children'],81)
        self.assertEqual(result['overwrite_cases'],8)
        self.assertEqual(result['recovery_point_selections'],8)
        self.assertEqual(result['interrupted_recovery_cases'],32)
        self.assertTrue(result['cache_eviction_verified'])
        self.assertTrue(result['A10_complete'])
        self.assertEqual(ready,[])
        self.assertEqual(result['legacy_mandatory_slots'],0)
        self.assertEqual(result['native_acceptance_status'],'NOT_RUN')
        for name in ('cache-eviction',
            'overwrite/p0002-after-ack-reverse-half/recovery/r0001-after-ack-reverse-half/final'):
            saved=self.progress['completed'].pop(name)
            result,_=self.review()
            self.assertFalse(result['A10_complete'])
            self.progress['completed'][name]=saved

    def test_wrong_phase_loss_reverse_or_selector_is_rejected_at_loader(self):
        result,ready=self.review();task=ready[0]
        row=self.make(task,self.root/task.name)
        self.progress['completed'][task.name]=row
        child=self.facts[row['directory']]
        original=copy.deepcopy(child.inputs)
        for key,value in (('phase','after-ack'),('unflushed','reverse-half'),
                          ('reverse_replies',False),('mode',True),('cut',True),
                          ('caller_mutation',dict(task.selector,data_sha256='0'*64))):
            child.inputs=copy.deepcopy(original);child.inputs[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.review()
        child.inputs=original

    def test_recovery_uses_damaged_cut_not_clean_probe_output(self):
        self.fill()
        name='overwrite/p0001-before-drop/recovery/r0001-before-drop/cut'
        child=self.facts[self.progress['completed'][name]['directory']]
        child.context['initial_source']=str(self.root/'overwrite/p0001-before-drop/recovery-probe/disk.raw')
        with self.assertRaisesRegex(ValueError,'parent mismatch'):self.review()

    def test_orphan_changed_summary_and_false_complete_are_rejected(self):
        self.fill()
        self.progress['status']='COMPLETE'
        self.review()
        removed=self.progress['completed'].pop('cache-eviction')
        with self.assertRaisesRegex(ValueError,'falsely completed'):self.review()
        self.progress['status']='IN_PROGRESS'
        self.progress['completed']['unexpected']=removed
        with self.assertRaisesRegex(ValueError,'unknown/orphan'):self.review()
        self.progress['completed'].pop('unexpected')
        self.progress['completed']['cache-eviction']=removed
        (Path(removed['directory'])/'summary.json').write_text('{"host_fixture_tampered":true}')
        with self.assertRaisesRegex(ValueError,'summary/media changed'):self.review()

    def test_unknown_recovery_descendants_cannot_be_credited(self):
        self.fill()
        self.progress['completed'].pop('overwrite/p0001-before-drop/recovery-probe')
        with self.assertRaisesRegex(ValueError,'unknown/orphan'):self.review()

    def test_recut_cannot_supply_primary_fsync_consumption_credit(self):
        self.fill()
        for name,row in self.progress['completed'].items():
            self.facts[row['directory']].summary['consumption_boundary']['present']=False
        selected='overwrite/p0001-before-drop/recovery/r0001-before-drop/cut'
        self.facts[self.progress['completed'][selected]['directory']].summary['consumption_boundary']['present']=True
        with self.assertRaisesRegex(ValueError,'recut reconsumed'):
            self.review()

    def test_actual_orchestrator_pauses_resumes_and_never_retries_existing_failure(self):
        # Exercise the real durable progress/locking/pause logic, substituting
        # explicit host fixtures at the native boundary only. No VM is launched.
        import run_v16_a10_matrix_v4 as runner
        self.root.rmdir()
        request=copy.deepcopy(self.request);request['max_storage_bytes']=8*1024**3
        request['operator_diagnose_stalled_cache']=False
        def inspect(root,request,progress,*,context):
            return matrix.inspect_progress(root,request,progress,context=context,
                loader=self.loader,selectors=self.selectors,verify_snapshot=False,
                window_validator=lambda probe,child,selected:None)
        def produce(build,parent,directory,*,mode,**kwargs):
            task=matrix.Task(directory.relative_to(self.root).as_posix(),mode,parent,
                kwargs.get('expected_mutation'),kwargs['phase'],kwargs['unflushed'])
            row=self.make(task,directory)
            return self.facts[row['directory']].summary
        def check(task,ref,*,context):
            return matrix.check_child(task,ref,context=context,loader=self.loader)
        args=dict(output=self.root,seed=self.seed,prepare=self.prepare,overwrite_probe=self.probe,
                  source_root=runner.ROOT.resolve(),build_manifest=self.base/'build.json',
                  qemu_binary=self.base/'qemu',qemu_source=self.base/'qemu-source',
                  native_lock=self.base/'native.lock',max_new_children=2,max_storage_bytes=8*1024**3)
        with patch.object(runner,'snapshot',return_value=request), \
             patch.object(runner,'idle_native_host'), \
             patch.object(runner,'inspect_progress',side_effect=inspect), \
             patch.object(runner,'check_child',side_effect=check), \
             patch.object(runner,'scenario_budget',return_value=dict(capture_timeout_seconds=1920)), \
             patch.object(runner,'run_cut',side_effect=produce) as cut, \
             patch.object(runner,'run_clean',side_effect=produce):
            first=runner.run(**args)
            self.assertEqual(first['invocation_new_children'],2)
            self.assertEqual(first['verified_children'],2)
            self.assertFalse(first['cache_eviction_verified'])
            self.assertEqual(first['status'],'NOT_RUN')
            second=runner.run(**args,resume=True)
            self.assertEqual(second['invocation_new_children'],2)
            self.assertEqual(second['verified_children'],4)
            self.assertTrue(second['cache_eviction_verified'])
            progress=matrix.load_progress(self.root)
            _,ready=inspect(self.root,request,progress,context={})
            (self.root/ready[0].name).mkdir(parents=True)
            calls=cut.call_count
            with self.assertRaisesRegex(ValueError,'preserves failed/uncredited'):
                runner.run(**args,resume=True)
            self.assertEqual(cut.call_count,calls)
            self.assertEqual(len(matrix.load_progress(self.root)['completed']),4)
            failure=matrix.sha256(self.root/'campaign-summary.json')
            with self.assertRaisesRegex(ValueError,'preserves original failed campaign'):
                runner.run(**args,resume=True)
            self.assertEqual(matrix.sha256(self.root/'campaign-summary.json'),failure)

    def test_invocation_and_progress_resource_types(self):
        import run_v16_a10_matrix_v4 as runner
        for cap in (True,0,1,17):
            with self.subTest(cap=cap),self.assertRaisesRegex(ValueError,'2..16'):
                runner.run(output=None,seed=None,prepare=None,overwrite_probe=None,source_root=None,
                    build_manifest=None,qemu_binary=None,qemu_source=None,native_lock=None,
                    max_new_children=cap,max_storage_bytes=8*1024**3)
        for value in (dict(self.progress,schema_version=True),dict(self.progress,status='PASS')):
            with self.assertRaises(ValueError):matrix.validate_progress(value)


if __name__=='__main__':
    unittest.main()
