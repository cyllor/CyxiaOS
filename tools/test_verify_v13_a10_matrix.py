import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_v13_a10_matrix as matrix


class A10MatrixGate(unittest.TestCase):
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
            request=dict(schema_version=1,test_id='A10',specification='1.3',
                overwrite_points='all',recovery_points='all',phases=list(matrix.PHASES),
                losses=list(matrix.LOSSES),reverse_replies=True,source_root=str(runner.ROOT),
                build_manifest_sha256=matrix.sha(build),
                source_manifest_sha256=matrix.sha(root/'source-manifest.json'),tools={},
                formatted_disk_sha256=matrix.sha(root/'formatted.raw'),
                provision_log_sha256=matrix.sha(root/'provision.log'),timeout=210.0,
                immutable_artifact_cache=None)
            (root/'matrix-input.json').write_text(json.dumps(request))
            (root/'progress.json').write_text(json.dumps(dict(
                schema_version=1,status='RUNNING',completed=[],abandoned=[])))
            loaded,_,timeout,cache=runner._resume_request(
                root,build,{}, {},overwrite_points='all',recovery_points='all',
                timeout=None,artifact_cache=None)
            self.assertEqual(loaded,request)
            self.assertEqual(timeout,210.0)
            self.assertIsNone(cache)
            attempts=[dict(overwrite_points='flushes',recovery_points='all',timeout=None,
                           artifact_cache=None),
                      dict(overwrite_points='all',recovery_points='all',timeout=211,
                           artifact_cache=None),
                      dict(overwrite_points='all',recovery_points='all',timeout=None,
                           artifact_cache=root/'cache')]
            for options in attempts:
                with self.subTest(options=options),self.assertRaises(ValueError):
                    runner._resume_request(root,build,{}, {},**options)
            build.write_text('{"changed":true}')
            with self.assertRaises(ValueError):
                runner._resume_request(root,build,{}, {},overwrite_points='all',
                                       recovery_points='all',timeout=None,artifact_cache=None)

    def test_matrix_names_keep_fault_semantics_unambiguous(self):
        names={matrix._case_name(7,phase,loss)
               for phase in matrix.PHASES for loss in matrix.LOSSES}
        recovery={matrix._recovery_name(7,phase,loss)
                  for phase in matrix.PHASES for loss in matrix.LOSSES}
        self.assertEqual(len(names),4)
        self.assertEqual(len(recovery),4)
        self.assertTrue(names.isdisjoint(recovery))


if __name__ == '__main__':
    unittest.main()
