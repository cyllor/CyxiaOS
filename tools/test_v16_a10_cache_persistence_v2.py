"""Actual new-runner static names and diagnostic-finally failure seams; no VM."""
import ast
import builtins
import hashlib
import json
from pathlib import Path
import symtable
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import run_v16_a10_cache_diagnostic_v1 as runner
import v16_a10_cache_diagnostic_v1 as diag


def unresolved_function_globals(source):
    root=symtable.symtable(source,'actual-diagnostic-runner.py','exec')
    available={s.get_name() for s in root.get_symbols()
               if s.is_imported() or s.is_assigned() or s.is_namespace()}
    available|=set(dir(builtins))|{'__name__','__file__','__package__','__builtins__'}
    missing={}
    def visit(table,path):
        kind=getattr(table.get_type(),'value',table.get_type())
        if kind=='function':
            unknown={s.get_name() for s in table.get_symbols()
                     if s.is_global() and s.is_referenced() and s.get_name() not in available}
            if unknown:missing[path]=sorted(unknown)
        for child in table.get_children():visit(child,path+'/'+child.get_name())
    visit(root,'module')
    return missing


class DiagnosticPersistence(unittest.TestCase):
    def test_every_actual_runner_function_has_its_referenced_global_names(self):
        source=Path(runner.__file__).read_text()
        self.assertEqual(unresolved_function_globals(source),{})
        self.assertIn('import sys\n',source)
        before=hashlib.sha256(source.encode()).hexdigest()
        old_missing_import=source.replace('import sys\n','',1)
        self.assertEqual(before,hashlib.sha256(Path(runner.__file__).read_bytes()).hexdigest())
        self.assertIn('sys',sum(unresolved_function_globals(old_missing_import).values(),[]),
                      'the audit must catch the real old nested run/sys.platform NameError')

    def test_original_cleanup_error_assignment_cannot_replace_primary(self):
        with tempfile.TemporaryDirectory() as temp:
            report=dict(error='primary native capture error')
            def original_cleanup(target):
                target['error']='QEMU wait error'
                target['error']='NBD worker error overwrites previous error'
            diag.finish_capture(original_cleanup,Path(temp),report,b'raw',b'decoded')
            self.assertEqual(report['error'],'primary native capture error')
            self.assertIn('QEMU wait error',report['cleanup_errors'])
            self.assertIn('NBD worker error overwrites previous error',report['cleanup_errors'])
            self.assertEqual((Path(temp)/'serial.bin').read_bytes(),b'raw')
            self.assertTrue(report['serial_saved']['serial.txt'])

    def test_real_legacy_cleanup_nbd_error_cannot_replace_primary(self):
        from types import SimpleNamespace
        from v13_a10_native_capture import close_capture
        with tempfile.TemporaryDirectory() as temp:
            report=dict(error='original producer error')
            server=SimpleNamespace(close=lambda:None,error='actual legacy NBD failure')
            witness=SimpleNamespace(record=lambda *a,**k:None)
            backend=SimpleNamespace(meta=dict(run_id='host-fixture-only'))
            diag.finish_capture(lambda target:close_capture(None,None,server,None,backend,witness,target),
                                Path(temp),report,b'raw',b'decoded')
            self.assertEqual(report['error'],'original producer error')
            self.assertIn('NBD worker: actual legacy NBD failure',report['cleanup_errors'])

    def test_serial_write_failure_does_not_hide_primary_or_skip_other_capture(self):
        original=Path.write_bytes
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);report=dict(error='primary original error')
            def write(path,data):
                if path.name=='serial.bin':raise OSError('disk full raw serial')
                return original(path,data)
            with patch.object(Path,'write_bytes',write):
                diag.finish_capture(lambda target:None,root,report,b'raw',b'decoded')
            self.assertEqual(report['error'],'primary original error')
            self.assertFalse(report['serial_saved']['serial.bin'])
            self.assertTrue(report['serial_saved']['serial.txt'])
            self.assertEqual((root/'serial.txt').read_bytes(),b'decoded')
            self.assertTrue(any('disk full raw serial' in e for e in report['cleanup_errors']))

    def test_inventory_failure_is_reported_and_summary_is_still_attempted(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'capture.bin').write_bytes(b'original')
            report=dict(status='NOT_RUN',error='original primary')
            with patch.object(diag,'sha256',side_effect=OSError('inventory read denied')):
                diag.finalize_diagnostic(root,report)
            self.assertFalse(report['artifact_inventory_complete'])
            self.assertTrue(report['summary_saved'])
            self.assertEqual(json.loads((root/'summary.json').read_text())['error'],'original primary')
            self.assertEqual(report['status'],'NOT_RUN')

    def test_summary_write_failure_does_not_claim_saved_or_mask_primary(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);report=dict(status='NOT_RUN',error='original primary')
            with patch.object(Path,'open',side_effect=OSError('summary disk full')):
                diag.finalize_diagnostic(root,report)
            self.assertFalse(report['summary_saved'])
            self.assertEqual(report['error'],'original primary')
            self.assertFalse((root/'summary.json').exists())
            self.assertTrue(any('summary disk full' in e for e in report['persistence_errors']))

    def test_cli_result_cannot_succeed_without_actually_saved_complete_artifacts(self):
        base=dict(stopped_banks_equal=True,summary_saved=True,artifact_inventory_complete=True,
                  cleanup_errors=[],persistence_errors=[])
        self.assertTrue(runner.diagnostic_saved(base))
        for key,value in (('summary_saved',False),('artifact_inventory_complete',False),
                          ('cleanup_errors',['cleanup failed']),('persistence_errors',['save failed']),
                          ('error','original error')):
            with self.subTest(key=key):self.assertFalse(runner.diagnostic_saved(dict(base,**{key:value})))

if __name__=='__main__':unittest.main()
