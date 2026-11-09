"""Exact committed W8 row specimens, never a synthetic accepted label."""
import ast
import inspect
import json
from pathlib import Path
import struct
import tempfile
import unittest
import v16_a03_data_offline_v4 as offline

CAPTURE=Path('/Users/robin/CyxiaOS-V0.16/artifacts/v016-focus-a03-a10-20261109-r8/a03-coreset-preparation-progress-01')
DISK_SHA='bef16e8c47523e09804d44f08aad5ecdbad0f5f1b1c255ab81e95c9df9240580'
REFS={2:(127296,134336,'30cf416512900dff02a353974f3b6f292c4c297789a90d0c67d5ede19f82bedd'),
      3:(261632,133952,'52d49859a6d050cad32dfa62ca64d8462a936194222c33ca5cdb9e7a55d66951')}
def put(raw,at,value):struct.pack_into('<Q',raw,at,value)
def warm(raw):
    at=2048+offline.word(raw,128)*6144+offline.word(raw,136)*64+offline.word(raw,144)*128
    return bytes(raw[at:]),bytes(raw[:2048])

class ActualPrewarmRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from check_v13_disk import committed_volume,BLOCK
        from check_v13_filesystem import inspect_committed
        disk=CAPTURE/'disk.raw';assert offline.sha(disk)==DISK_SHA
        with committed_volume(disk) as (current,metadata):
            volume=inspect_committed(current,metadata)
            node=volume['files']['/lr-0000000000000001-0000']
            assert (node['inode'],node['generation'])==(4,3) and node['durable_write_seq']>0
            raw=bytearray()
            for _,start,count in node['extents']:
                assert count<=offline.MAX_FILE//BLOCK
                for block in range(start,start+count):raw+=current(block)[:min(BLOCK,node['size']-len(raw))]
            assert len(raw)==node['size'] and offline.digest(raw)==node['sha256']
        cls.sides={}
        for trial,(start,length,digest) in REFS.items():
            side=bytes(raw[start:start+length]);assert len(side)==length and offline.digest(side)==digest
            cls.sides[trial]=side
        cls.context=offline.producer_v3._schema_context(dict(json.loads((CAPTURE/'native-context.json').read_text()),boot_epoch=1))
        cls.original_summary=(CAPTURE/'summary.json').read_bytes()
        cls.control=(CAPTURE/'control.bin').read_bytes();cls.runtime=(CAPTURE/'runtime.bin').read_bytes()
    @classmethod
    def tearDownClass(cls):
        assert offline.sha(CAPTURE/'disk.raw')==DISK_SHA
        assert (CAPTURE/'summary.json').read_bytes()==cls.original_summary

    def test_actual_cpu0_rows_are_accepted_without_dropping_any_cpu(self):
        for trial,raw in self.sides.items():
            rows,header=warm(raw)
            with self.subTest(trial=trial):offline._prewarm(rows,header)
            self.assertEqual(len(rows)//64,{2:215,3:209}[trial])
            self.assertEqual(sum(offline.word(rows,i+40)-offline.word(rows,i+32) for i in range(0,len(rows),64)),offline.word(header,176))

    def test_original_strict_rejection_is_preserved_and_local_side_passes(self):
        for trial,raw in self.sides.items():
            old_failure='invalid actual CoreSet prewarm row' if trial==2 else 'candidate input action/target mismatch'
            with self.subTest(trial=trial),self.assertRaisesRegex(ValueError,old_failure):
                offline.strict_v5._side(raw,self.context)
            side=offline._side(raw,self.context)
            self.assertEqual(side['trial_id'],trial);self.assertEqual(side['sha256'],REFS[trial][2])
        self.assertEqual(json.loads(self.original_summary)['status'],'FAIL')

    def test_wrong_owner_core_generation_and_task_rows_are_rejected(self):
        rows,header=warm(self.sides[2])
        for at,value in ((0,0x5245504c434f),(0,0x5245504c5453),(0,999),(8,2),(16,1),(16,3)):
            changed=bytearray(rows);put(changed,at,value)
            with self.subTest(at=at,value=value),self.assertRaises(ValueError):offline._prewarm(changed,header)
        core_row=next(i for i in range(0,len(rows),64) if offline.word(rows,i+16)==1)
        for at,value in ((core_row,offline.OWNER),(core_row+8,2),(core_row+16,0)):
            changed=bytearray(rows);put(changed,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):offline._prewarm(changed,header)

    def test_manifest_role_generation_masks_and_missing_edges_are_rejected(self):
        rows,header=warm(self.sides[2])
        for at,value in ((616,3),(768+2*32,999),(768+2*32+8,2),(768+2*32+16,1),
                         (768+2*32+24,0),(768+2*32+24,2),(768+3*32+24,7)):
            changed=bytearray(header);put(changed,at,value)
            with self.subTest(at=at,value=value),self.assertRaises(ValueError):offline._prewarm(rows,changed)

    def test_original_time_event_reserved_order_width_and_total_rules_remain(self):
        rows,header=warm(self.sides[2]);first=offline.word(header,96);begin=offline.word(header,104)
        cases=((24,0),(64+24,offline.word(rows,24)),(32,begin-1),(40,first+1),(48,1),
               (64+32,offline.word(rows,40)-1))
        for at,value in cases:
            changed=bytearray(rows);put(changed,at,value)
            with self.subTest(at=at),self.assertRaises(ValueError):offline._prewarm(changed,header)
        bad=bytearray(header);put(bad,176,offline.word(header,176)+1)
        with self.assertRaises(ValueError):offline._prewarm(rows,bad)
        with self.assertRaises(ValueError):offline._prewarm(rows[:-1],header)

    def test_actual_direct_capacity_is_decoded_and_old_dual_word_layout_rejected(self):
        row=self.sides[3][2048:8192]
        self.assertEqual(struct.unpack_from('<2Q',row,2048+(64+8)*8),(2000,0))
        with self.assertRaises(ValueError):offline.strict_v5.encode_core_features(row,0)
        features=offline.encode_core_features(row,0)
        self.assertEqual(features[42],128)
        for capacity,padding in ((1,2000),(1,0),(0,0),(1000,0),(2000,1)):
            changed=bytearray(row);struct.pack_into('<2Q',changed,2048+(64+8)*8,capacity,padding)
            with self.subTest(capacity=capacity,padding=padding),self.assertRaises(ValueError):offline.encode_core_features(changed,0)

    def test_candidate_set_canonical_and_actual_mlp_score_mutations_still_fail(self):
        side=self.sides[3];record=bytearray(side[2048:8192]);header=offline._side(side,self.context)
        # Change the claimed CandidateSet hash in both bound locations, then
        # retain an honest new input digest. Canonical recomputation must fail.
        record[16]^=1;record[2048+160]^=1;record[48:80]=bytes.fromhex(offline.digest(record[2048:]))
        with self.assertRaisesRegex(ValueError,'CandidateSet integrity mismatch'):offline._record(record,header,self.context)
        record=bytearray(side[2048:8192]);score=struct.unpack_from('<h',record,208)[0]
        struct.pack_into('<h',record,208,score+1 if score<32767 else score-1)
        with self.assertRaisesRegex(ValueError,'MLP/first maximum mismatch'):
            offline._core_adoptions([record],side[:2048],(CAPTURE/'model.bin').read_bytes())

    def test_actual_pending_bank_is_separate_from_same_apply_archived_execution(self):
        candidate=offline._side(self.sides[3],self.context)
        with self.assertRaisesRegex(ValueError,'full MLP/publication receipt mismatch'):
            offline.strict_v5.actual_candidate_runtime(self.control,self.runtime,candidate,self.context)
        fact=offline.actual_candidate_runtime_v4(self.control,self.runtime,candidate,self.context)
        self.assertFalse(fact['bank_applied_verified']);self.assertTrue(fact['archived_applied_verified'])
        self.assertEqual(fact['candidate']['bank_state_code'],1);self.assertEqual(fact['candidate']['bank_progress_ns'],0)
        self.assertTrue(fact['candidate']['diagnostic_progress_missing']);self.assertFalse(fact['full_output_bytes_reconstructed'])
        self.assertEqual(fact['candidate']['archive_apply_id'],[1,1,921,0,0x434f5245,1])
        self.assertEqual(fact['candidate']['archive_executor_generation'],1)
        self.assertEqual(fact['zero_version_reply_count'],57);self.assertEqual(fact['zero_version_reply_classification'],'UNCLASSIFIED')
        self.assertFalse(fact['global_refusal_free_verified']);self.assertFalse(fact['full_native_runtime_verified'])

    def test_pending_without_exact_archive_identity_stamp_epoch_and_applied_fails(self):
        candidate=offline._side(self.sides[3],self.context)
        fields=((272,2),(280,2),(288,922),(296,1),(304,0x434f5246),(312,2),(320,556),
                (328,395325436001),(336,1),(344,556),(392,0),(392,2),(400,0),
                (360,395332290993),(408,395332312001),(416,395334494992),(424,0),(424,2),(432,1),(384,395334494991))
        for at,value in fields:
            changed=dict(candidate);raw=bytearray(candidate['raw_bytes']);put(raw,2048+at,value);changed['raw_bytes']=bytes(raw)
            with self.subTest(at=at,value=value),self.assertRaises(ValueError):
                offline.actual_candidate_runtime_v4(self.control,self.runtime,changed,self.context)

    def test_pending_and_mlp_caps_output_input_and_refusal_counters_fail_closed(self):
        candidate=offline._side(self.sides[3],self.context);base=(512+24*640)*8
        for index,value in ((14,0),(14,3),(14,4),(15,1),(28,1),(30,0),(19,0),(639,211),
                            (9,395332311999),(13,0),(16,2),(17,1),(10,0),(11,0),(18,1),(608,0),(32,0)):
            changed=bytearray(self.control);put(changed,base+index*8,value)
            with self.subTest(bank='control',index=index),self.assertRaises(ValueError):
                offline.actual_candidate_runtime_v4(changed,self.runtime,candidate,self.context)
        changed=bytearray(self.control);put(changed,base+12*8,490000);put(changed,base+29*8,20000)
        with self.assertRaises(ValueError):offline.actual_candidate_runtime_v4(changed,self.runtime,candidate,self.context)
        changed=bytearray(self.control);put(changed,base+10*8,2000000)
        with self.assertRaises(ValueError):offline.actual_candidate_runtime_v4(changed,self.runtime,candidate,self.context)
        for index,value in ((17,0),(17,58),(31,0),(13,743),(9,1),(15,1),(18,1),(38,1),(56,1)):
            changed=bytearray(self.runtime);put(changed,index*8,value)
            if index==15:put(changed,31*8,745)
            with self.subTest(bank='runtime',index=index),self.assertRaises(ValueError):
                offline.actual_candidate_runtime_v4(self.control,changed,candidate,self.context)

    def test_existing_applied_observation_does_not_hide_unclassified_replies(self):
        candidate=offline._side(self.sides[3],self.context);changed=bytearray(self.control);base=(512+24*640)*8
        put(changed,base+14*8,2);put(changed,base+28*8,395334500000)
        fact=offline.actual_candidate_runtime_v4(changed,self.runtime,candidate,self.context)
        self.assertTrue(fact['bank_applied_verified']);self.assertEqual(fact['zero_version_reply_count'],57)
        self.assertFalse(fact['global_refusal_free_verified']);self.assertFalse(fact['full_native_runtime_verified'])

class DispatchIdentity(unittest.TestCase):
    def test_cli_exit_zero_is_explicitly_partial_proof_not_full_status(self):
        from verify_v16_a03_data_offline_v4 import exit_code
        self.assertEqual(exit_code({'status':'OFFLINE_PARTIAL_PROTECTED_SAMPLE_VERIFIED',
            'bank_applied_verified':False,'global_refusal_free_verified':False}),0)
        for status in ('OFFLINE_VERIFIED','OFFLINE_CLOSED_WITHOUT_SAMPLE','FAIL'):
            self.assertEqual(exit_code({'status':status}),1)

    def test_side_numeric_ast_has_no_math_or_structural_changes(self):
        for name in ('_side','numeric_core_side','numeric_core_pair'):
            original=ast.parse(inspect.getsource(getattr(offline.strict_v5,name)))
            local=ast.parse(inspect.getsource(getattr(offline,name)))
            self.assertEqual(ast.dump(original),ast.dump(local),name)
            self.assertIs(getattr(offline,name).__globals__,offline.__dict__)
        self.assertIsNot(offline._prewarm,offline.strict_v5._prewarm)
        for name in ('performance','cpu_union','reward_values','select_model','_closing','_request','_execution'):
            self.assertIs(getattr(offline,name),getattr(offline.strict_v5,name))
        self.assertEqual(ast.dump(ast.parse(inspect.getsource(offline._core_adoptions))),
            ast.dump(ast.parse(inspect.getsource(offline.strict_v5._core_adoptions))))

    def test_every_function_global_is_bound_without_executing_capture(self):
        import builtins
        import symtable
        def check(table):
            for symbol in table.get_symbols():
                if symbol.is_global() and symbol.is_referenced():
                    self.assertTrue(symbol.get_name() in offline.__dict__ or hasattr(builtins,symbol.get_name()),symbol.get_name())
            for child in table.get_children():check(child)
        for name,value in vars(offline).items():
            if inspect.isfunction(value) and value.__module__==offline.__name__:
                with self.subTest(function=name):check(symtable.symtable(inspect.getsource(value),name,'exec'))
        self.assertIs(offline.strict,offline.strict_v5)
        self.assertEqual(offline.MAX_ATTEMPTS,offline.producer_v3.MAX_ATTEMPTS)

    def test_terminal_custody_and_committed_reader_dispatch_are_unchanged(self):
        for local,original in ((offline.read_committed_data,offline.producer_v3.read_committed_data),
                               (offline._verify_data_capture,offline.producer_v3.verify_data_capture)):
            left=ast.parse(inspect.getsource(local));right=ast.parse(inspect.getsource(original))
            left.body[0].name=right.body[0].name
            # Only the result claim is reduced: offline arithmetic is not authority.
            for node in ast.walk(right):
                if isinstance(node,ast.keyword) and node.arg=='native_acceptance_inferred_from_trusted_producer':node.value=ast.Constant(False)
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='actual_candidate_runtime':node.func.id='actual_candidate_runtime_v4'
            self.assertEqual(ast.dump(left),ast.dump(right))
        signature=inspect.signature(offline.verify_offline_capture)
        for name in ('producer_tools_root','expected_original_summary_sha256'):
            self.assertIs(signature.parameters[name].default,inspect.Parameter.empty)
        with self.assertRaises(ValueError):offline.require_frozen_producer_tools(None,CAPTURE)
        with self.assertRaises(ValueError):offline.require_frozen_producer_tools(CAPTURE,CAPTURE)

    def test_capacity_ast_changes_only_the_approved_native_field_reads(self):
        changes={
            '_record':(('w[at + 8] == 1 and w[at + 9] == weight.bit_count()*1000',
                        'w[at + 8] == weight.bit_count()*1000 and w[at + 9] == 0'),
                       ('canonical += bytes([1]) + words(w[at+9])','canonical += bytes([1]) + words(w[at+8])')),
            'encode_core_features':(('w[at+8]==1 and w[at+9]==mask.bit_count()*1000',
                                    'w[at+8]==mask.bit_count()*1000 and w[at+9]==0'),
                                   ('normalize(42,w[at+9],4000)','normalize(42,w[at+8],4000)'))}
        for name,replacements in changes.items():
            expected=inspect.getsource(getattr(offline.strict_v5,name))
            for old,new in replacements:
                self.assertEqual(expected.count(old),1);expected=expected.replace(old,new)
            self.assertEqual(ast.dump(ast.parse(expected)),ast.dump(ast.parse(inspect.getsource(getattr(offline,name)))))
        # This checker intentionally accepts only the historical native
        # contract. Test against its pinned raw specimen, not today's tree.
        frozen_source=CAPTURE/'source-inputs'
        offline.require_native_contract(frozen_source)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for rel in offline.NATIVE_CONTRACT_SOURCES:
                target=root/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((frozen_source/rel).read_bytes())
            offline.require_native_contract(root)
            (root/'kernel/src/domain_control.rs').write_bytes(b'changed native capacity contract')
            with self.assertRaises(ValueError):offline.require_native_contract(root)

    def test_original_fail_and_inventory_are_pinned_not_rewritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'raw.bin').write_bytes(b'actual raw fixture')
            artifacts=offline.bounded_inventory(root)
            summary=dict(version=offline.PRODUCER_VERSION,status='FAIL',capture_complete=False,
                released_pair_observed=False,error=offline.ORIGINAL_ERROR,artifacts=artifacts)
            path=root/'summary.json';path.write_text(json.dumps(summary));raw=path.read_bytes();expected=offline.sha(path)
            inventory=offline.bounded_inventory(root)
            result=offline.original_producer_failure(root,inventory,expected)
            self.assertEqual(result['status'],'FAIL');self.assertFalse(result['capture_complete']);self.assertEqual(path.read_bytes(),raw)
            with self.assertRaises(ValueError):offline.original_producer_failure(root,inventory,'0'*64)
            (root/'raw.bin').write_bytes(b'changed')
            with self.assertRaises(ValueError):offline.original_producer_failure(root,offline.bounded_inventory(root),expected)

    def test_checker_closure_contains_three_new_entries_and_no_captured_code(self):
        closure=offline.tool_closure()
        for name in ('v16_a03_data_offline_v4','verify_v16_a03_data_offline_v4','test_v16_a03_data_offline_v4'):
            self.assertIn('tools/'+name+'.py',closure)
        self.assertIn('tools/v16_a03_data.py',closure);self.assertIn('tools/v16_a03_focus.py',closure)
        self.assertTrue(all(not name.startswith('/') and '..' not in name.split('/') for name in closure))

if __name__=='__main__':unittest.main()
