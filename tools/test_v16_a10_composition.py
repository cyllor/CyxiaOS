"""Behavioral checks for fixed A10 ancestry and conservative scale estimates."""
import copy
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


class CompositionTests(unittest.TestCase):
    def setUp(self):
        # Missing implementation must be an assertion failure during the RED run.
        self.assertIsNotNone(importlib.util.find_spec('v16_a10_composition'),
                             'fixed chain composition functionality is missing')
        self.api = importlib.import_module('v16_a10_composition')

    def records(self):
        common = dict(source_sha256='a'*64, build_sha256='b'*64,
                      image_sha256='c'*64, qemu={'binary_sha256': 'd'*64})
        records = []
        for name, start, version in [('cut', 10, 'a10-write-native-v2'),
                                     ('recovery', 100, 'a10-native-v1')]:
            context = dict(version=version, capture_root='/'+name,
                           initial_source='/seed' if name == 'cut' else '/cut/disk.raw',
                           backing_path='/'+name+'/disk.raw', backend_run_id=name,
                           endpoints={key: '/'+name+'/'+key for key in ('nbd','qmp','gdb')})
            identity = dict(common, initial_sha256='e'*64)
            lifecycle = {event: dict(monotonic_ns=start+i) for i,event in enumerate(
                ('identity-before','backend-open','spawn','final-disk','identity-after'))}
            summary = dict(status='NOT_RUN' if name == 'cut' else 'PASS',
                           cut_observed=name == 'cut', native_mode_verified=name != 'cut',
                           native_write_cut_custody_verified=name == 'cut',
                           nbd_trace=dict(disk_final_sha256='e'*64, reordered_replies=False))
            records.append(dict(directory='/'+name, context=context, identity=identity,
                                binding=dict(uuid='uuid'), inputs=dict(mode=3, cut=1 if name=='cut' else 0,
                                    phase='before', reverse_replies=False, initial_disk_sha256='e'*64),
                                nonce=name, lifecycle=lifecycle, summary=summary))
        return records

    def validate(self, records):
        return self.api.validate_links('/seed', 'e'*64, *records, same_host_monotonic_session=True)

    def test_supported_chain_never_grants_full_a10(self):
        result = self.validate(self.records())
        self.assertIs(result['selected_chain_verified'], True)
        self.assertEqual(result['formal_A10_status'], 'NOT_RUN')
        self.assertIs(result['A10_complete'], False)
        self.assertEqual(result['mandatory_matrix_slots_closed'], 0)
        self.assertEqual(result.get('native_acceptance_status'), 'NOT_RUN')
        self.assertIs(result.get('external_seed_native_custody_claimed'), False)
        self.assertEqual(result.get('chronology_trust'), 'caller-asserted-same-host-monotonic-session')

    def test_timestamp_comparison_requires_caller_session_acknowledgement(self):
        for value in (False, None, 1, 'true'):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'same.host.monotonic.session'):
                    self.api.validate_links('/seed', 'e'*64, *self.records(),
                                            same_host_monotonic_session=value)
        verifier=importlib.import_module('verify_v16_a10_composition')
        with self.assertRaisesRegex(ValueError, 'same.host.monotonic.session'):
            verifier.verify_chain({},source_root='/missing',build_manifest='/missing',
                qemu_binary='/missing',qemu_source='/missing',initial_disk='/missing')

    def test_same_byte_wrong_path_parent_rejected(self):
        records = self.records()
        records[1]['context']['initial_source'] = '/other-equal-disk.raw'
        with self.assertRaisesRegex(ValueError, 'initial source'):
            self.validate(records)

    def test_seed_actual_source_path_required(self):
        records = self.records()
        records[0]['context']['initial_source'] = '/same-byte-seed'
        with self.assertRaisesRegex(ValueError, 'initial source'):
            self.validate(records)

    def test_all_parent_closure_precedes_all_child_opening(self):
        for end in ('final-disk', 'identity-after'):
            for begin in ('identity-before', 'backend-open', 'spawn'):
                with self.subTest(end=end, begin=begin):
                    records = self.records()
                    records[0]['lifecycle'][end]['monotonic_ns'] = records[1]['lifecycle'][begin]['monotonic_ns']
                    with self.assertRaisesRegex(ValueError, 'chronology'):
                        self.validate(records)

    def test_reused_nonce_backend_endpoint_backing_rejected(self):
        for field in ('nonce','backend_run_id','endpoints','backing_path'):
            with self.subTest(field=field):
                records = self.records()
                if field == 'nonce':
                    records[1][field] = records[0][field]
                else:
                    records[1]['context'][field] = records[0]['context'][field]
                with self.assertRaises(ValueError):
                    self.validate(records)

    def test_changed_source_build_image_qemu_uuid_rejected(self):
        for field in ('source_sha256','build_sha256','image_sha256','qemu','uuid'):
            with self.subTest(field=field):
                records = self.records()
                target = 'binding' if field == 'uuid' else 'identity'
                records[1][target][field] = 'wrong'
                with self.assertRaises(ValueError):
                    self.validate(records)

    def test_recovery_requires_original_clean_nonreordered_mode3(self):
        for section, key, value in [('inputs','mode',2), ('inputs','cut',1),
                                    ('inputs','reverse_replies',True),
                                    ('context','version','a10-write-native-v2'),
                                    ('summary','status','NOT_RUN'),
                                    ('summary','native_mode_verified',False),
                                    ('summary','cut_observed',True)]:
            with self.subTest(key=key):
                records = self.records()
                records[1][section][key] = value
                with self.assertRaises(ValueError):
                    self.validate(records)

    def test_changed_parent_final_bytes_rejected(self):
        records = self.records()
        records[0]['summary']['nbd_trace']['disk_final_sha256'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'disk'):
            self.validate(records)

    def test_exact_eight_branches_have_211_children(self):
        result = self.api.legacy_preflight(2, [3]*8,
            assumed_recovery_count=None, observed_costs={'seconds_per_child':2, 'bytes_per_child':100},
            resource_budget={'max_children':211, 'max_runtime_seconds':422, 'max_storage_bytes':21100})
        self.assertEqual(result['exact_child_count'], 211)
        self.assertEqual(result['runtime_seconds'], 422)
        self.assertEqual(result['storage_bytes'], 21100)
        self.assertEqual(result['status'], 'ESTIMATE_WITHIN_BUDGET')
        self.assertIs(result['budget_approved'], False)
        self.assertIs(result.get('execution_authorized'), False)
        self.assertIs(result['legacy_cli_intercepted'], False)

    def test_216_assumed_84_is_conditional_582339(self):
        result = self.api.legacy_preflight(216, [], assumed_recovery_count=84,
            observed_costs={'seconds_per_child':30, 'bytes_per_child':536870912}, resource_budget={})
        self.assertIsNone(result['exact_child_count'])
        self.assertEqual(result['conditional_child_count'], 582339)
        self.assertEqual(result['unknown_branch_count'], 864)
        self.assertEqual(result['status'], 'INDETERMINATE_UNMEASURED_BRANCHES')
        self.assertIs(result['budget_approved'], False)

    def test_unknown_branches_without_assumption_remain_unknown(self):
        result = self.api.legacy_preflight(2, [3], assumed_recovery_count=None,
                                         observed_costs={}, resource_budget={})
        self.assertIsNone(result['exact_child_count'])
        self.assertIsNone(result['conditional_child_count'])
        self.assertEqual(result['status'], 'INDETERMINATE_UNMEASURED_BRANCHES')

    def test_known_lower_bound_refuses_cap_despite_unknown_branches(self):
        result = self.api.legacy_preflight(2, [3], assumed_recovery_count=None,
            observed_costs={'seconds_per_child':2,'bytes_per_child':100},
            resource_budget={'max_children':40})
        self.assertEqual(result.get('minimum_child_count'), 43)
        self.assertEqual(result['status'], 'REFUSED_RESOURCE_BUDGET')
        self.assertIsNone(result['exact_child_count'])

    def test_invalid_costs_and_caps_rejected(self):
        for costs, budget in [({'seconds_per_child':True},{}),
                              ({'seconds_per_child':float('nan')},{}),
                              ({'bytes_per_child':-1},{}), ({'made_up':1},{}),
                              ({},{'max_children':-1}), ({},{'max_children':float('inf')}),
                              ({},{'max_children':True}), ({},{'unknown_cap':1})]:
            with self.subTest(costs=costs,budget=budget):
                with self.assertRaises(ValueError):
                    self.api.legacy_preflight(2,[3]*8,assumed_recovery_count=None,
                        observed_costs=costs,resource_budget=budget)

    def test_exact_count_without_measured_costs_cannot_approve_budget(self):
        result = self.api.legacy_preflight(2,[3]*8,assumed_recovery_count=None,
                                         observed_costs={},resource_budget={'max_runtime_seconds':1})
        self.assertEqual(result['exact_child_count'],211)
        self.assertEqual(result['status'],'INDETERMINATE_UNMEASURED_COSTS')
        self.assertIs(result['budget_approved'],False)

    def test_refuses_each_explicit_resource_cap(self):
        for cap in ({'max_children':210}, {'max_runtime_seconds':421}, {'max_storage_bytes':21099}):
            with self.subTest(cap=cap):
                result = self.api.legacy_preflight(2, [3]*8, assumed_recovery_count=None,
                    observed_costs={'seconds_per_child':2, 'bytes_per_child':100}, resource_budget=cap)
                self.assertEqual(result['status'], 'REFUSED_RESOURCE_BUDGET')
                self.assertIs(result['budget_approved'], False)

    def test_invalid_preflight_values_rejected(self):
        for count, branches, assumption in [(True,[],None), (-1,[],None), (1,[1]*5,None),
                                             (1,[-1],None), (1,[],True)]:
            with self.subTest(count=count, branches=branches, assumption=assumption):
                with self.assertRaises(ValueError):
                    self.api.legacy_preflight(count, branches, assumed_recovery_count=assumption,
                                              observed_costs={}, resource_budget={})

    def plan_fixture(self, root):
        root = root.resolve()
        seed = root/'seed'; seed.write_bytes(b'seed')
        for name in ('cut','recovery'):
            (root/name).mkdir(); (root/name/'summary.json').write_text('{}')
        return seed, dict(schema_version=1, test_id='A10', profile='strict-write-cut-recovery-v1',
            external_seed={'sha256':'19b25856e1c150ca834cffc8b59b23adbd0ec0389e58eb22b3b64768098d002b'},
            cut=dict(directory=str(root/'cut'),summary_sha256='44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
                     expected_write=dict(cut=1, offset=512,length=512,data_sha256='a'*64)),
            recovery=dict(directory=str(root/'recovery'),summary_sha256='44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'))

    def test_valid_plan_reaches_fixed_native_replay(self):
        verifier=importlib.import_module('verify_v16_a10_composition')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); seed,plan=self.plan_fixture(root)
            # Replay is the expensive external boundary; real R6 is exercised
            # independently. A valid caller plan must reach this fixed checker.
            with patch.object(verifier,'verify_native_write_child',side_effect=ValueError('native replay sentinel')):
                with self.assertRaisesRegex(ValueError,'native replay sentinel'):
                    verifier.verify_chain(plan,source_root=root,build_manifest=seed,qemu_binary=seed,
                        qemu_source=root,initial_disk=seed,same_host_monotonic_session=True)

    def test_plan_binds_summaries_and_has_no_caller_checker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); seed,plan=self.plan_fixture(root)
            for mutation in ('checker','summary','selector','seed','schema','relative_directory'):
                with self.subTest(mutation=mutation):
                    changed=copy.deepcopy(plan)
                    if mutation=='checker': changed['checker']='anything.py'
                    if mutation=='summary': changed['recovery']['summary_sha256']='f'*64
                    if mutation=='selector': changed['cut']['expected_write']['extra']=1
                    if mutation=='seed': changed['external_seed']['sha256']='f'*64
                    if mutation=='schema': changed['schema_version']=True
                    if mutation=='relative_directory': changed['cut']['directory']='relative-capture'
                    with patch('verify_v16_a10_composition.verify_native_write_child', side_effect=AssertionError('must reject before replay')):
                        with self.assertRaises(ValueError):
                            importlib.import_module('verify_v16_a10_composition').verify_chain(changed,
                                source_root=root,build_manifest=seed,qemu_binary=seed,qemu_source=root,
                                initial_disk=seed,same_host_monotonic_session=True)

    def test_cli_preflight_has_no_execution_side_effect(self):
        cli = Path(__file__).with_name('verify_v16_a10_composition.py')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'costs.json'; p.write_text(json.dumps(dict(overwrite_count=2,
                recovery_point_counts=[3]*8, assumed_recovery_count=None,
                observed_costs={'seconds_per_child':2,'bytes_per_child':100}, resource_budget={'max_children':210})))
            run=subprocess.run([sys.executable,str(cli),'preflight',str(p)],capture_output=True,text=True)
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertEqual(json.loads(run.stdout)['exact_child_count'],211)
            self.assertEqual(list(Path(tmp).iterdir()),[p])


if __name__ == '__main__':
    unittest.main()
