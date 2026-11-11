"""Production diagnostic helper seams with an explicit host-owned QMP fixture."""
import copy
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
import v16_a10_cache_diagnostic_v1 as diag


class CacheDiagnostic(unittest.TestCase):
    def layout(self):
        names=['task-overrun','domain-task','control-credit','unified-service-stage','storage-boot']
        d={name:dict(pa=(i+1)*4096,size=256 if name in ('task-overrun','domain-task') else 8)
           for i,name in enumerate(names)}
        d.update({'unified-runtime':dict(pa=30000,size=16)})
        return dict(diagnostics=d,capture=dict(pa=40000,size=8),progress=dict(pa=50000,size=8),
                    consumption=dict(pa=60000,size=8))
    def test_original_periodic_path_retains_existing_overrun_and_credit_banks(self):
        calls=[]
        def save(name,pa,size):calls.append(name);return bytes(size)
        banks=diag.periodic_capture(save,self.layout())
        self.assertIn('task-overrun',banks,'old pending seam loses the actual CPU0 Budget receipt')
        self.assertIn('control-credit',banks)
        self.assertIn('pending-task-overrun.bin',calls)
    def test_hint_uses_cpu0_not_other_overrun_or_partial_publication(self):
        task=[0]*32;task[:4]=[diag.TASK_MAGIC,1,1,1]
        self.assertIsNotNone(diag.cpu0_hint({'domain-task':struct.pack('<32Q',*task)}))
        task[2]=4
        self.assertIsNone(diag.cpu0_hint({'domain-task':struct.pack('<32Q',*task)}))
        self.assertIsNone(diag.cpu0_hint({'domain-task':b'partial'}))
        over=[0]*32;over[:6]=[diag.OVERRUN_MAGIC,1,7,257,1,2_500_000]
        hint=diag.cpu0_hint({'task-overrun':struct.pack('<32Q',*over)})
        self.assertTrue(hint['live_hint_only'])
        over[0]=0
        self.assertIsNone(diag.cpu0_hint({'task-overrun':struct.pack('<32Q',*over)}))
    def test_stop_confirmation_two_reads_and_stop_related_nbd_change_are_retained(self):
        calls=[];backend=SimpleNamespace(requests=10,mutations=4,acks=10,flushes=2,fault_mutations=4,closed=False)
        class Qmp:
            def execute(self,name):
                calls.append(name)
                if name=='stop':backend.requests+=1;backend.flushes+=1;backend.mutations+=1
                else:return {'running':False,'status':'paused'}
        class Witness:
            def record(self,name,**values):calls.append((name,values))
        def save(name,pa,size):calls.append(name);return bytes(size)
        result,first=diag.stopped_capture(Qmp(),save,self.layout(),backend,Witness())
        self.assertTrue(result['stopped_banks_equal']);self.assertIsNone(result['cpu0_overrun_observation'])
        self.assertEqual(result['backend_before_stop']['flushes'],2)
        self.assertEqual(result['backend_after_pause']['flushes'],3)
        self.assertLess(calls.index('stop'),calls.index('stopped-1-task-overrun.bin'))
        self.assertEqual(result['first_sha256'],result['second_sha256'])
    def test_unconfirmed_pause_never_supplies_a_snapshot(self):
        class Qmp:
            def execute(self,name):return {'running':True,'status':'running'}
        backend=SimpleNamespace(requests=0,mutations=0,acks=0,flushes=0,fault_mutations=0,closed=False)
        with self.assertRaises(ValueError):
            diag.stopped_capture(Qmp(),lambda *a:self.fail('save before paused'),self.layout(),backend,
                                  SimpleNamespace(record=lambda *a,**k:None))
    def test_changed_or_failed_second_bank_is_not_a_complete_snapshot(self):
        class Qmp:
            def execute(self,name):return {'running':False,'status':'paused'}
        backend=SimpleNamespace(requests=0,mutations=0,acks=0,flushes=0,fault_mutations=0,closed=False)
        def save(name,pa,size):
            if name=='stopped-2-control-credit.bin':raise ValueError('original save failed')
            return b'x'*size if name=='stopped-2-domain-task.bin' else bytes(size)
        result,_=diag.stopped_capture(Qmp(),save,self.layout(),backend,
                                     SimpleNamespace(record=lambda *a,**k:None))
        self.assertFalse(result['stopped_banks_equal'])
        self.assertIn('domain-task',result['unequal_banks'])
        self.assertIn('2:control-credit',result['capture_errors'])
        self.assertNotIn('cpu0_overrun_observation',result)
    def test_c4_row_is_diagnostic_and_distinguishes_cpu_and_wall_conditions(self):
        words=[0]*32;words[:12]=[diag.OVERRUN_MAGIC,1,17,257,1,2_500_000,2_600_000,100_000_000,104_000_000,1,1,0]
        row=diag.decode_cpu0_overrun(struct.pack('<32Q',*words))
        self.assertEqual(row['thread_id'],257);self.assertTrue(row['actual_exceeds_reservation'])
        self.assertNotIn('native_acceptance_status',row)
        words[6]=2_000_000;words[8]=200_000_001
        row=diag.decode_cpu0_overrun(struct.pack('<32Q',*words))
        self.assertFalse(row['actual_exceeds_reservation']);self.assertTrue(row['finishes_after_dispatch_window'])
    def test_optional_existing_network_banks_are_stopped_only(self):
        layout=self.layout()
        with patch.object(diag,'original_profile',return_value=layout), \
             patch.object(diag,'symbol',side_effect=lambda image,name:dict(pa=90000 if 'PIECE' in name else 91000,size=512)):
            extended=diag.diagnostic_profile(b'host fixture ELF')
        self.assertIn('network-piece',extended['diagnostics'])
        self.assertIn('network-settlement',extended['diagnostics'])
        self.assertNotIn('network-piece',diag.PENDING_DIAGNOSTICS)
        with patch.object(diag,'original_profile',return_value=self.layout()), \
             patch.object(diag,'symbol',side_effect=ValueError('missing optional symbol')):
            self.assertNotIn('network-piece',diag.diagnostic_profile(b'host fixture ELF')['diagnostics'])

    def test_native_profile_admission_is_fixed_before_any_disk_or_process_access(self):
        import run_v16_a10_cache_diagnostic_v1 as producer
        for kwargs in (dict(mode=1),dict(mode=4,cut=1),dict(mode=4,reverse_replies=False),
                       dict(mode=4,sample_ms=100),dict(mode=4,phase='after-ack')):
            values=dict(mode=4,cut=0,phase='before',unflushed='drop',reverse_replies=True,sample_ms=30000)
            values.update(kwargs)
            with self.subTest(values=kwargs),patch.object(producer.subprocess,'Popen') as launch:
                with self.assertRaisesRegex(ValueError,'fixed cache diagnostic'):
                    producer.run(Path('/not-read'),Path('/not-read'),Path('/not-created'),source_root=Path.cwd(),**values)
                launch.assert_not_called()

    def test_host_resource_bounds_do_not_extend_original_native_time(self):
        inputs=dict(sample_ms=30000,capture_timeout_seconds=21720)
        limits=diag.capture_limits(inputs)
        self.assertEqual(inputs,dict(sample_ms=30000,capture_timeout_seconds=21720))
        self.assertGreaterEqual(limits['commands'],diag.poll_bound(inputs)*7+64)
        with self.assertRaises(ValueError):diag.capture_limits(dict(inputs,capture_timeout_seconds=21721))

if __name__=='__main__':unittest.main()
