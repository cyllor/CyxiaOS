import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_v13_a10_matrix as matrix


class A10MatrixGate(unittest.TestCase):
    def test_trusted_child_projection_preserves_damaged_disk_lineage_and_subset_scope(self):
        # Synthetic coverage context only. Raw decoding and native provenance
        # have their own tests; this executes the real matrix traversal/edges.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root/'formatted.raw').write_bytes(b'formatted')
            (root/'provision.log').write_text('fresh fixture')
            (root/'source-manifest.json').write_text('{}')
            (root/'build-manifest.json').write_text('{"code_source_map":{}}')
            (root/'tools').mkdir(); (root/'tools/fixture.py').write_text('fixture data only')
            request = dict(schema_version=1, test_id='A10', specification='1.3',
                phases=list(matrix.PHASES), losses=list(matrix.LOSSES), reverse_replies=True,
                scenario_budgets=matrix.scenario_budgets(matrix.ROOT), sample_ms=30000,
                qemu_binary='/trusted/synthetic', qemu_source='/trusted/source',
                qemu_attestation=dict(qemu_pmu_patch_attested=True), filesystem_uuid='11'*16,
                overwrite_points='1', recovery_points='1', immutable_artifact_cache=None,
                build_manifest_sha256=matrix.sha(root/'build-manifest.json'),
                source_manifest_sha256=matrix.sha(root/'source-manifest.json'),
                formatted_disk_sha256=matrix.sha(root/'formatted.raw'),
                provision_log_sha256=matrix.sha(root/'provision.log'),
                tools={'fixture.py': matrix.sha(root/'tools/fixture.py')})
            (root/'matrix-input.json').write_text(json.dumps(request))

            def trusted_loader(path, **expected):
                name = path.relative_to(root).as_posix()
                if name == 'prepare': initial = 'formatted'
                elif name == 'overwrite-probe': initial = 'prepare'
                elif name == 'cache-eviction': initial = 'overwrite-probe'
                elif '/recovery/' in name:
                    initial = (name.rsplit('/',1)[0]+'/cut' if name.endswith('/final')
                               else name.split('/recovery/')[0]+'/cut')
                elif name.endswith('/recovery-probe'): initial = name.rsplit('/',1)[0]+'/cut'
                else: initial = 'prepare'
                self.assertEqual(expected['initial_sha256'], hashlib.sha256(initial.encode()).hexdigest(),
                                 'recovery must start from damaged bytes, never repaired probe output')
                path.mkdir(parents=True)
                (path/'disk.raw').write_bytes(name.encode())
                (path/'trace.bin').write_bytes(b'fixture')
                (path/'nbd').mkdir()
                (path/'nbd/start.json').write_text('{}')
                (path/'nbd/events.jsonl').write_text(json.dumps(dict(event='request', mutation=1,
                    kind=3, offset=0, length=0))+'\n')
                result = dict(binding={}, nbd_trace=dict(reordered_replies=True),
                    observation=dict(consumption_boundary=dict(present=expected['mode'] != 3),
                                     cache_eviction_verified=True, pressure_pages=4096),
                    consumption_boundary=dict(present=True))
                return result, {}

            with patch.object(matrix, 'decode', return_value={}), \
                 patch.object(matrix, 'overwrite_window', return_value=dict(points=[1])):
                result = matrix.review(root, child_loader=trusted_loader)
            self.assertEqual(result['status'], 'NOT_RUN')
            self.assertEqual(result['overwrite_cases'], 4)
            self.assertEqual(result['interrupted_recovery_cases'], 16)
            self.assertTrue(result['cache_eviction_verified'])
            self.assertFalse(result['runtime_truth_attested'])

    def rows(self):
        return [dict(mutation=1,kind=1,offset=0,length=512),
                dict(mutation=2,kind=3,offset=0,length=0),
                dict(mutation=3,kind=1,offset=512,length=512),
                dict(mutation=4,kind=3,offset=0,length=0)]

    def test_point_selection_is_exact_and_never_infers_unobserved_boundaries(self):
        rows=self.rows()
        self.assertEqual(matrix.select_points('all',rows),[1,2,3,4])
        self.assertEqual(matrix.select_points('flushes',rows),[2,4])
        self.assertEqual(matrix.select_points('1,4',rows),[1,4])
        self.assertEqual(matrix.select_points('all',rows,[2,3]),[2,3])
        for spec in ('', '2,2', '5', 'x'):
            with self.subTest(spec=spec),self.assertRaises(ValueError):
                matrix.select_points(spec,rows)
        with self.assertRaises(ValueError):matrix.select_points('all',rows,[2,5])

    def test_only_full_native_cross_product_can_claim_a10(self):
        request=dict(overwrite_points='all',recovery_points='all')
        result=matrix.result_scope(request,[10,11],[10,11],8,16,64,True,True)
        self.assertEqual(result['status'],'PASS')
        self.assertTrue(result['A10_complete'])
        variants=[
            (dict(request,overwrite_points='flushes'),[10,11],[10,11],True,True),
            (request,[10],[10,11],True,True),
            (request,[10,11],[10,11],False,True),
            (request,[10,11],[10,11],True,False),
            (request,[10,11],[10,11],True,True),
        ]
        for index,(configured,selected,window,consumed,reordered) in enumerate(variants):
            with self.subTest(configured=configured,selected=selected,consumed=consumed,reordered=reordered):
                primary=7 if index == len(variants)-1 else 4
                result=matrix.result_scope(configured,selected,window,primary,8,32,consumed,reordered)
                self.assertEqual(result['status'],'NOT_RUN')
                self.assertFalse(result['A10_complete'])
                self.assertFalse(result['runtime_truth_attested'])
        for primary,recovery,secondary in ((7,16,64),(8,7,28),(8,16,63)):
            with self.subTest(primary=primary,recovery=recovery,secondary=secondary):
                result=matrix.result_scope(request,[10,11],[10,11],primary,recovery,
                                           secondary,True,True)
                self.assertEqual(result['status'],'NOT_RUN')
                self.assertFalse(result['A10_complete'])

    def test_progress_paths_must_be_unique_relative_children(self):
        from run_v13_a10_matrix import validate_progress
        valid=dict(schema_version=1,status='RUNNING',
                   completed=['prepare','overwrite/p0001-before-drop/cut'],abandoned=[])
        self.assertEqual(validate_progress(valid),valid['completed'])
        invalid=[dict(valid,completed=['prepare','prepare']),
                 dict(valid,completed=['../prepare']),
                 dict(valid,completed=['/tmp/prepare']),
                 dict(valid,completed=[{}]),
                 dict(valid,status='FAILED')]
        for document in invalid:
            with self.subTest(document=document),self.assertRaises(ValueError):
                validate_progress(document)

    def test_resume_rejects_changed_matrix_inputs(self):
        import run_v13_a10_matrix as runner
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            build=root/'build-manifest.json'
            build.write_text('{}')
            (root/'source-manifest.json').write_text('{}')
            (root/'formatted.raw').write_bytes(b'formatted')
            (root/'provision.log').write_text('provisioned')
            qemu_binary=Path('/patched/qemu')
            qemu_source=Path('/patched/source')
            qemu_proof=dict(qemu_pmu_patch_attested=True,qemu_sha256='11'*32)
            request=dict(schema_version=1,test_id='A10',specification='1.3',
                overwrite_points='all',recovery_points='all',phases=list(matrix.PHASES),
                losses=list(matrix.LOSSES),reverse_replies=True,source_root=str(runner.ROOT),
                build_manifest_sha256=matrix.sha(build),
                source_manifest_sha256=matrix.sha(root/'source-manifest.json'),tools={},
                formatted_disk_sha256=matrix.sha(root/'formatted.raw'),
                provision_log_sha256=matrix.sha(root/'provision.log'),
                scenario_budgets=runner.scenario_budgets(runner.ROOT),
                sample_ms=30_000,qemu_binary=str(qemu_binary),
                qemu_source=str(qemu_source),qemu_attestation=qemu_proof,
                immutable_artifact_cache=None)
            (root/'matrix-input.json').write_text(json.dumps(request))
            (root/'progress.json').write_text(json.dumps(dict(
                schema_version=1,status='RUNNING',completed=[],abandoned=[])))
            loaded,_,budgets,cache=runner._resume_request(
                root,build,{}, {},overwrite_points='all',recovery_points='all',
                timeout=None,artifact_cache=None,qemu_binary=qemu_binary,
                qemu_source=qemu_source,qemu_proof=qemu_proof,sample_ms=30_000)
            self.assertEqual(loaded,request)
            self.assertEqual(budgets,request['scenario_budgets'])
            self.assertIsNone(cache)
            attempts=[dict(overwrite_points='flushes',recovery_points='all',timeout=None,
                           artifact_cache=None),
                      dict(overwrite_points='all',recovery_points='all',timeout=211,
                           artifact_cache=None),
                      dict(overwrite_points='all',recovery_points='all',timeout=None,
                           artifact_cache=root/'cache')]
            for options in attempts:
                with self.subTest(options=options),self.assertRaises(ValueError):
                    runner._resume_request(root,build,{}, {},qemu_binary=qemu_binary,
                                           qemu_source=qemu_source,qemu_proof=qemu_proof,
                                           sample_ms=30_000,**options)
            build.write_text('{"changed":true}')
            with self.assertRaises(ValueError):
                runner._resume_request(root,build,{}, {},overwrite_points='all',
                                       recovery_points='all',timeout=None,artifact_cache=None,
                                       qemu_binary=qemu_binary,qemu_source=qemu_source,
                                       qemu_proof=qemu_proof,sample_ms=30_000)

    def test_matrix_names_keep_fault_semantics_unambiguous(self):
        names={matrix._case_name(7,phase,loss)
               for phase in matrix.PHASES for loss in matrix.LOSSES}
        recovery={matrix._recovery_name(7,phase,loss)
                  for phase in matrix.PHASES for loss in matrix.LOSSES}
        self.assertEqual(len(names),4)
        self.assertEqual(len(recovery),4)
        self.assertTrue(names.isdisjoint(recovery))

    def test_child_forwards_frozen_qemu_budget_and_low_observer_sampling(self):
        import run_v13_a10_matrix as runner
        budgets = runner.scenario_budgets(runner.ROOT)
        expected = dict(status='PASS')
        with patch.object(runner, 'run_mode', return_value=expected) as invoked:
            result = runner._child(
                Path('/build.json'), Path('/initial.raw'), Path('/evidence'), mode=1,
                budgets=budgets, artifact_cache=None, qemu=Path('/patched/qemu'),
                qemu_source=Path('/patched/source'), sample_ms=30_000)
        self.assertIs(result, expected)
        arguments = invoked.call_args.kwargs
        self.assertEqual(arguments['timeout'], 1920.0)
        self.assertEqual(arguments['sample_ms'], 30_000)
        self.assertEqual(arguments['qemu'], Path('/patched/qemu'))
        self.assertEqual(arguments['qemu_source'], Path('/patched/source'))
        self.assertTrue(arguments['reverse_replies'])


if __name__ == '__main__':
    unittest.main()
