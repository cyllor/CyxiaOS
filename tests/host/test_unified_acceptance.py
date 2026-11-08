"""Acceptance rejects plausible-looking partial, stale and over-budget evidence."""
import copy
import hashlib
import inspect
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from verify_unified import D8ControlDiagnostics, ROOT, attest_qemu, bind_build, capture, decode_final_diagnostics, initialize_d8_locations, profile, record_final_diagnostics, run, sha, validate, validate_rejection
from verify_domains import CONTROL_MAGIC, CONTROL_WORDS, REPLAY_MAGIC

def bundle(owner=False):
    u=[0]*512;d=[0]*512;r=[0]*1024
    u[:6]=[0x435958554e493031,1,100,1,1000,1000]
    u[30]=1
    events=[1,2,3,0x211,0x212,0x219];u[6]=len(events)
    for i,e in enumerate(events):u[32+2*i]=e
    u[8]=u[9]=int(owner);u[10]=100*int(owner);u[11]=100*int(owner);u[12]=100*int(owner)
    d[0]=0x43595844594e3133;d[1]=2
    for i,target in enumerate((6,2)):
        t=[0]*16;t[1]=i+1;t[2]=1000+i*1000;t[3]=t[2]+1;t[4]=t[5]=target;t[6]=15^target;t[9]=63;t[15]=1
        d[16+i*16:32+i*16]=t
    r[0]=0x43595852554e3133;r[2]=2;r[4]=62500000;r[14]=10;r[19]=r[20]=20;r[28]=4;r[32]=1
    return dict(UNIFIED_EVIDENCE=struct.pack('<512Q',*u),DYNAMIC_V13_EVIDENCE=struct.pack('<512Q',*d),RUNTIME_V13_EVIDENCE=struct.pack('<1024Q',*r))

def change(b,name,index,value):
    data=bytearray(b[name]);struct.pack_into('<Q',data,index*8,value);b[name]=bytes(data)

def service_events(events):
    return b''.join(f'UNIFIED_SERVICE event={event} arg1=0 arg2=0 ms={i}\n'.encode()
                    for i,event in enumerate(events))

class Acceptance(unittest.TestCase):
    def test_d8_diagnostic_initialization_and_serialization_fail_closed_without_acceptance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            diagnostic = D8ControlDiagnostics(root, interval_seconds=2.0)
            with patch('verify_unified.symbol', side_effect=ValueError('missing diagnostic symbol')):
                self.assertIsNone(initialize_d8_locations(diagnostic, [b'elf-a', b'elf-b']))
            document = diagnostic.write()
            self.assertFalse(document['acceptance_evidence'])
            self.assertFalse(document['sampling']['enabled'])
            self.assertIn('missing diagnostic symbol', document['initialization_errors'][0])

            # A malformed diagnostic value must not escape into the functional
            # runner or prevent a bounded non-acceptance JSON from being written.
            diagnostic.nodes = [{'node': 1, 'records': {}, 'counters': [],
                                 'errors': [object()]}]
            document = diagnostic.write()
            self.assertFalse(document['acceptance_evidence'])
            self.assertIn('serialization_error', document)
            self.assertEqual(
                json.loads((root / 'd8-service-batch-diagnostic.json').read_text()),
                document,
            )

    def test_d8_diagnostic_scheduling_is_after_completion_check_and_never_catches_up(self):
        diagnostic = D8ControlDiagnostics(Path('.'), interval_seconds=2.0)
        self.assertEqual(diagnostic.next_sample_at(17.5), 19.5)
        source = inspect.getsource(run)
        self.assertLess(source.index("if complete:"), source.index('d8_diagnostic.sample('))
        self.assertNotIn('while next_d8_diagnostic <=', source)

    def test_d8_diagnostic_double_reads_without_stopping_and_keeps_only_stable_records(self):
        def control(*, changed=False):
            words = [0] * CONTROL_WORDS
            words[:3] = [CONTROL_MAGIC, 1, 7]
            words[12:14] = [64, 640]
            words[32 + 5] = 11
            words[32 + 8] = 17
            words[64 + 5] = 7
            words[64 + 8] = 13
            at = 512 + 5 * 640
            record = words[at:at + 640]
            record[0:8] = [41, 41, 8, 1, 0x535643, 1, 0, 7]
            record[8:10] = [10, 20]
            record[13:18] = [9, 2, 0, 2, 1]
            record[19] = 1
            record[28] = 30
            record[30] = 1
            record[639] = 2
            native = record[32:544]
            native[8:10] = [8, 1]
            native[15] = 2
            native[64:66] = [3, 1 << 16]
            native[74:76] = [3, (4 << 16) | 1]
            record[32:544] = native
            words[at:at + 640] = record
            # A second D8 record differs between the two live reads and must
            # never be promoted into the diagnostic output.
            torn = 512 + 6 * 640
            words[torn:torn + 8] = [42, 42, 8, 1, 0x535643, 1, 0, 7]
            words[torn + 8:torn + 10] = [10, 20]
            words[torn + 13:torn + 18] = [10, 2, 0, 1, 0]
            words[torn + 19] = 1
            words[torn + 28] = 30
            words[torn + 14] = 2
            words[torn + 30] = 1
            words[torn + 639] = 2
            torn_input = words[torn + 32:torn + 544]
            torn_input[8:10] = [8, 1]
            torn_input[15] = 1
            torn_input[64:66] = [3, 1 << 16]
            words[torn + 32:torn + 544] = torn_input
            if changed:
                words[torn + 28] = 99
            return struct.pack(f'<{CONTROL_WORDS}Q', *words)

        class Qmp:
            def __init__(self):
                self.calls = []
            def execute(self, command, args):
                self.calls.append(command)
                Path(args['filename']).write_bytes(control(changed=len(self.calls) == 2))

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / 'node-1'
            folder.mkdir()
            qmp = Qmp()
            diagnostic = D8ControlDiagnostics(root, interval_seconds=2.0)
            diagnostic.sample(
                [{'qmp': qmp, 'folder': folder}],
                [{'pa': 0x1000, 'size': CONTROL_WORDS * 8}],
                elapsed_seconds=12.5,
            )
            document = diagnostic.write()

            self.assertEqual(qmp.calls, ['pmemsave', 'pmemsave'])
            self.assertFalse(any(command in qmp.calls for command in ('stop', 'cont')))
            self.assertFalse(document['acceptance_evidence'])
            self.assertEqual(document['sampling']['interval_seconds'], 2.0)
            self.assertEqual(len(document['nodes'][0]['records']), 1)
            counters = document['nodes'][0]['counters'][0]
            self.assertEqual(counters['jobs'], 17)
            self.assertEqual(counters['applied'], 13)
            self.assertEqual(len(counters['family_jobs']), 18)
            self.assertEqual(len(counters['family_applied']), 18)
            self.assertEqual((counters['family_jobs'][5], counters['family_jobs'][8]),
                             (11, 17))
            self.assertEqual((counters['family_applied'][5], counters['family_applied'][8]),
                             (7, 13))
            record = document['nodes'][0]['records'][0]
            self.assertEqual((record['sequence'], record['service_batch']), (41, 4))
            self.assertEqual(record['executor_state'], 'applied')
            self.assertEqual(record['selected_candidate'], 1)
            self.assertEqual(record['first_observed_seconds'], 12.5)
            self.assertEqual(
                json.loads((root / 'd8-service-batch-diagnostic.json').read_text()),
                document,
            )
            self.assertFalse(any(folder.glob('.d8-control-*')))

    def test_profile_captures_task_and_network_diagnostics(self):
        required = (
            'UNIFIED_EVIDENCE', 'DYNAMIC_V13_EVIDENCE', 'RUNTIME_V13_EVIDENCE',
            'UNIFIED_SERVICE_STAGE', 'DOMAIN_TASK_EVIDENCE', 'TASK_OVERRUN_EVIDENCE',
            'NETWORK_PIECE_EVIDENCE', 'NETWORK_SETTLEMENT_EVIDENCE',
            'FILE_SERVICE_EVIDENCE', 'TASK_VECTOR_EVIDENCE',
            'RUNTIME_LOOP_EVIDENCE',
            'DOMAIN_PUBLICATION_COST',
            'DOMAIN_CONTROL_EVIDENCE', 'REPLAY_V13_EVIDENCE',
            'DOMAIN_PREPARATION_CONTEXT', 'DOMAIN_PREPARATION_DETAIL',
            'DOMAIN_PREPARATION_PREFIX_DETAIL',
            'DOMAIN_PREPARATION_ENTRY_DETAIL',
            'DOMAIN_PREPARATION_REJECTIONS',
            'DOMAIN_PREPARATION_SKIP_EVIDENCE',
        )
        optional = {
            'APPLICATION_REQUEST_EVIDENCE': 6208,
            'LOCAL_REQUEST_EVIDENCE': 2112,
            'SESSION_ACTIVITY_EVIDENCE': 832,
            'DISCOVERY_EVIDENCE': 512,
            'REPLAY_QUIESCING_EVIDENCE': 512,
        }
        expected = required + tuple(optional)
        sizes = {
            'UNIFIED_EVIDENCE': 4096, 'DYNAMIC_V13_EVIDENCE': 4096,
            'RUNTIME_V13_EVIDENCE': 8192, 'UNIFIED_SERVICE_STAGE': 8,
            'DOMAIN_TASK_EVIDENCE': 256, 'TASK_OVERRUN_EVIDENCE': 256,
            'NETWORK_PIECE_EVIDENCE': 512, 'NETWORK_SETTLEMENT_EVIDENCE': 512,
            'FILE_SERVICE_EVIDENCE': 512, 'TASK_VECTOR_EVIDENCE': 512,
            'RUNTIME_LOOP_EVIDENCE': 512,
            'DOMAIN_PUBLICATION_COST': 1024,
            'DOMAIN_CONTROL_EVIDENCE': CONTROL_WORDS * 8,
            'REPLAY_V13_EVIDENCE': 512,
            'DOMAIN_PREPARATION_CONTEXT': 128,
            'DOMAIN_PREPARATION_DETAIL': 256,
            'DOMAIN_PREPARATION_PREFIX_DETAIL': 128,
            'DOMAIN_PREPARATION_ENTRY_DETAIL': 128,
            'DOMAIN_PREPARATION_REJECTIONS': 5184,
            'DOMAIN_PREPARATION_SKIP_EVIDENCE': 2048,
            **optional,
        }

        with patch('verify_unified.inspect_elf'), \
             patch('verify_unified.boot_profile', return_value={'ram_mib': 1024}), \
             patch('verify_unified.symbol', side_effect=lambda _, name: {'pa': 0, 'size': sizes[name]}):
            self.assertEqual(tuple(profile(b'elf')), expected)

        for malformed in required[-7:]:
            def located(_, name, malformed=malformed):
                return {'pa': 0, 'size': sizes[name] + int(name == malformed)}
            with self.subTest(malformed=malformed), \
                 patch('verify_unified.inspect_elf'), \
                 patch('verify_unified.boot_profile', return_value={'ram_mib': 1024}), \
                 patch('verify_unified.symbol', side_effect=located), \
                 self.assertRaisesRegex(ValueError, malformed + ' size differs'):
                profile(b'elf')

        # Optional diagnostics may be absent in older images or have an
        # incompatible layout; neither condition can discard required banks.
        for missing in optional:
            def located(_, name, missing=missing):
                if name == missing:
                    raise ValueError('fixture image has no ' + name)
                return {'pa': 0, 'size': sizes[name]}
            with self.subTest(missing_optional=missing), \
                 patch('verify_unified.inspect_elf'), \
                 patch('verify_unified.boot_profile', return_value={'ram_mib': 1024}), \
                 patch('verify_unified.symbol', side_effect=located):
                self.assertEqual(tuple(profile(b'elf')), tuple(n for n in expected if n != missing))

        for malformed in optional:
            def located(_, name, malformed=malformed):
                return {'pa': 0, 'size': sizes[name] + int(name == malformed)}
            with self.subTest(malformed_optional=malformed), \
                 patch('verify_unified.inspect_elf'), \
                 patch('verify_unified.boot_profile', return_value={'ram_mib': 1024}), \
                 patch('verify_unified.symbol', side_effect=located):
                self.assertEqual(tuple(profile(b'elf')), tuple(n for n in expected if n != malformed))

    def test_final_diagnostics_reuse_domain_decoder(self):
        evidence = bundle()
        change(evidence, 'RUNTIME_V13_EVIDENCE', 1, 3)
        task = [0] * 32
        task[:15] = [0x43595441534B0001, 123, 0, 0, 11, 22, 33, 4, 1,
                     9, 10, 3, 1, 110, 44]
        piece = list(range(64))
        settlement = list(range(64, 128))
        file_service = list(range(128, 192))
        task_vector = list(range(192, 256))
        runtime_loop = [0] * 64
        runtime_loop[:8] = [2, 0x435952544c4f4f31, 1, 1, 1, 1, 1, 0]
        runtime_loop[8:40] = [
            1, 1, 1, 100, 100, 200, 0, 0, 0,
            10, 100, 110, 20, 110, 130, 5, 110, 115,
            5, 115, 120, 10, 130, 140, 10, 140, 150,
            100, 200, 12, 0, 0,
        ]
        control = [0] * CONTROL_WORDS
        control[:3] = [CONTROL_MAGIC, 1, 1]
        control[12:14] = [64, 640]
        control[32 + 5] = 11
        control[32 + 8] = 17
        control[64 + 5] = 7
        control[64 + 8] = 13
        replay = [0] * 64
        replay[:10] = [2, REPLAY_MAGIC, 1, 8, 1, 0, 1, 3, 1, 4]
        preparation_context = list(range(16))
        preparation_detail = list(range(32))
        preparation_prefix_detail = list(range(16, 32))
        preparation_entry_detail = list(range(32, 48))
        preparation_rejections = [0] * 648
        preparation_skips = [0] * 256
        preparation_skips[:8] = [0x435950534B495031, 1, 13, 18, 16, 16, 0, 0]
        publication_cost = [0] * 128
        evidence.update(
            UNIFIED_SERVICE_STAGE=struct.pack('<Q', 7),
            DOMAIN_TASK_EVIDENCE=struct.pack('<32Q', *task),
            TASK_OVERRUN_EVIDENCE=bytes(256),
            NETWORK_PIECE_EVIDENCE=struct.pack('<64Q', *piece),
            NETWORK_SETTLEMENT_EVIDENCE=struct.pack('<64Q', *settlement),
            FILE_SERVICE_EVIDENCE=struct.pack('<64Q', *file_service),
            TASK_VECTOR_EVIDENCE=struct.pack('<64Q', *task_vector),
            RUNTIME_LOOP_EVIDENCE=struct.pack('<64Q', *runtime_loop),
            DOMAIN_PUBLICATION_COST=struct.pack('<128Q', *publication_cost),
            DOMAIN_CONTROL_EVIDENCE=struct.pack(f'<{CONTROL_WORDS}Q', *control),
            REPLAY_V13_EVIDENCE=struct.pack('<64Q', *replay),
            DOMAIN_PREPARATION_CONTEXT=struct.pack('<16Q', *preparation_context),
            DOMAIN_PREPARATION_DETAIL=struct.pack('<32Q', *preparation_detail),
            DOMAIN_PREPARATION_PREFIX_DETAIL=struct.pack(
                '<16Q', *preparation_prefix_detail),
            DOMAIN_PREPARATION_ENTRY_DETAIL=struct.pack(
                '<16Q', *preparation_entry_detail),
            DOMAIN_PREPARATION_REJECTIONS=struct.pack(
                '<648Q', *preparation_rejections),
            DOMAIN_PREPARATION_SKIP_EVIDENCE=struct.pack(
                '<256Q', *preparation_skips),
        )

        decoded = decode_final_diagnostics(evidence)
        self.assertEqual(decoded['service_stage_word'], 7)
        self.assertEqual(decoded['tasks']['probe_exit_code'], 110)
        self.assertEqual(decoded['tasks']['cpu_spent_ns'], [11, 22, 33])
        self.assertEqual(decoded['overrun_evidence'], [0] * 32)
        self.assertEqual(decoded['network_piece_evidence'], piece)
        self.assertEqual(decoded['network_settlement_evidence'], settlement)
        self.assertEqual(decoded['file_service_evidence'], file_service)
        self.assertEqual(decoded['task_vector_evidence'], task_vector)
        self.assertEqual(decoded['runtime_loop']['max_loop_gap']['duration_ns'], 0)
        self.assertEqual(decoded['runtime_loop']['segments']['ingest']['duration_ns'], 20)
        self.assertEqual(decoded['publication_cost_evidence'], publication_cost)
        self.assertEqual(decoded['publication_cost'], [])
        self.assertEqual(decoded['control']['family_jobs'][5], 11)
        self.assertEqual(decoded['control']['family_jobs'][8], 17)
        self.assertEqual(decoded['control']['family_applied'][5], 7)
        self.assertEqual(decoded['control']['family_applied'][8], 13)
        self.assertEqual(decoded['replay']['family'], [8, 1])
        self.assertEqual(decoded['replay_evidence'], replay)
        self.assertEqual(decoded['preparation_context'], preparation_context)
        self.assertEqual(decoded['preparation_detail'], preparation_detail)
        self.assertEqual(decoded['preparation_prefix_detail'],
                         preparation_prefix_detail)
        self.assertEqual(decoded['preparation_entry_detail'],
                         preparation_entry_detail)
        self.assertEqual(decoded['preparation_rejections'], preparation_rejections)
        self.assertIsNone(decoded['rejected_preparations'])
        self.assertEqual(decoded['preparation_skip_evidence'], preparation_skips)
        self.assertEqual(decoded['preparation_skips']['rows'], [])
        self.assertEqual(decoded['diagnostic_errors'], [])
        self.assertIsNone(decoded['final_parse_error'])

        with tempfile.TemporaryDirectory() as temp:
            recorded = record_final_diagnostics(Path(temp), [evidence])
            self.assertEqual(recorded, [decoded])
            self.assertEqual(json.loads((Path(temp) / 'final-diagnostics.json').read_text()),
                             [decoded])

    def test_patched_qemu_requires_exact_source_attestation(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/'qemu';binary=source/'build/qemu-system-aarch64'
            binary.parent.mkdir(parents=True);binary.write_bytes(b'qemu')
            files=('include/hw/core/cpu.h','cpu-common.c','accel/tcg/cpu-exec.c','target/arm/cpregs-pmu.c')
            for name in files:
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name)
            hashes={name:sha(source/name) for name in files}
            def output(command,**_):
                if command[-1]=='--version':return 'QEMU emulator version 10.2.2 (v10.2.2-dirty)\n'
                return 'f8ed81651e61d9c2166df6121ce2af0f44f06b3e\n'
            status=''.join(f' M {name}\n' for name in files)
            with patch('verify_unified.PATCHED_QEMU_SOURCE_SHA256',hashes), \
                 patch('verify_unified.subprocess.check_output',side_effect=output), \
                 patch('verify_unified.subprocess.run') as run:
                run.return_value.stdout=status;run.return_value.returncode=0
                proof=attest_qemu(binary,source)
                self.assertEqual(proof['qemu_source_commit'],'f8ed81651e61d9c2166df6121ce2af0f44f06b3e')
                (source/files[0]).write_text('substituted')
                with self.assertRaisesRegex(ValueError,'patched QEMU source differs'):
                    attest_qemu(binary,source)
            with patch('verify_unified.subprocess.check_output',return_value='QEMU emulator version 10.2.2 (v10.2.2-dirty)\n'):
                with self.assertRaisesRegex(ValueError,'source attestation'):
                    attest_qemu(binary,None)
    def test_joint_checks_cannot_accept_partial_evidence(self):
        original=[bundle(),bundle(True)]
        self.assertEqual(len(validate([b'',b''],original,[4,4])),2)
        for name,index,value in [('DYNAMIC_V13_EVIDENCE',1,1),('DYNAMIC_V13_EVIDENCE',25,31),('UNIFIED_EVIDENCE',36,0),('RUNTIME_V13_EVIDENCE',38,1),('RUNTIME_V13_EVIDENCE',32,2),('UNIFIED_EVIDENCE',6,201),('UNIFIED_EVIDENCE',12,625001),('UNIFIED_EVIDENCE',8,0),('UNIFIED_EVIDENCE',30,0),('UNIFIED_EVIDENCE',31,1)]:
            b=copy.deepcopy(original);change(b[1],name,index,value)
            with self.subTest(name=name,index=index),self.assertRaises(ValueError):validate([b'',b''],b,[4,4])
    def test_service_restart_requires_one_real_fault_and_a_healthy_peer(self):
        restarted=[bundle(),bundle(True)]
        events=[1,2,3,0x211,0x212,1,2,3,0x212,0x219]
        # Node b keeps its existing service context. Reconnecting authenticates
        # again, but does not re-enter _start or reconstruct the driver.
        peer_events=[1,2,3,0x211,0x212,3,0x212,0x219]
        for item,observed in zip(restarted,(events,peer_events)):
            words=list(struct.unpack('<512Q',item['UNIFIED_EVIDENCE']))
            words[6]=len(observed);words[32:]=[0]*480
            for i,event in enumerate(observed):words[32+i*2]=event
            item['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        words=list(struct.unpack('<512Q',restarted[0]['UNIFIED_EVIDENCE']))
        words[13:15]=[11,0x212];words[22]=1;words[30:32]=[2,1]
        restarted[0]['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        serial=[service_events(events[:5])+b'UNIFIED_EL0_FAULT generation=1 last_op=11 last_arg0=530 kind=7\nUNIFIED_SERVICE_RESTART boot=1 generation=2\n'+service_events(events[5:]),b'']
        self.assertEqual(len(validate(serial,restarted,[4,4],expect='service-restart')),2)
        changed=copy.deepcopy(restarted);change(changed[0],'UNIFIED_EVIDENCE',31,0)
        with self.assertRaises(ValueError):validate(serial,changed,[4,4],expect='service-restart')
        changed=copy.deepcopy(restarted);change(changed[0],'UNIFIED_EVIDENCE',14,2)
        with self.assertRaises(ValueError):validate(serial,changed,[4,4],expect='service-restart')
        changed=copy.deepcopy(restarted);change(changed[1],'UNIFIED_EVIDENCE',30,2);change(changed[1],'UNIFIED_EVIDENCE',31,1)
        with self.assertRaises(ValueError):validate(serial,changed,[4,4],expect='service-restart')
        for position in (5,6):
            changed=copy.deepcopy(restarted);change(changed[1],'UNIFIED_EVIDENCE',32+2*position,0)
            with self.subTest(missing_peer_event=peer_events[position]),self.assertRaisesRegex(ValueError,'reconcile to READY'):
                validate(serial,changed,[4,4],expect='service-restart')
    def test_no_ack_cannot_be_mislabelled_successful_handoff(self):
        with self.assertRaises(ValueError):validate([b'DYNAMIC_V13_RECONCILE']*2,[bundle(),bundle(True)],[4,4],expect='no-stop-ack')
    def test_old_ready_events_cannot_certify_a_restarted_service(self):
        restarted=[bundle(),bundle(True)]
        events=[1,2,3,0x211,0x212,1,2,3,0x212,0x219]
        for item in restarted:
            words=list(struct.unpack('<512Q',item['UNIFIED_EVIDENCE']))
            words[6]=len(events);words[32:]=[0]*480
            for i,event in enumerate(events):words[32+i*2]=event
            item['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        for index,value in ((13,11),(14,0x212),(22,1),(30,2),(31,1)):
            change(restarted[0],'UNIFIED_EVIDENCE',index,value)
        old=service_events(events)
        fault=b'UNIFIED_EL0_FAULT generation=1 last_op=11 last_arg0=530 kind=7\n'
        restart=b'UNIFIED_SERVICE_RESTART boot=1 generation=2\n'
        # A previous connection supplied all aggregate counters. Generation 2
        # has started, but has not yet authenticated or reconciled its peer.
        for after in ([],[1,2,3],[0x212,1,2,3]):
            with self.subTest(after=after),self.assertRaisesRegex(ValueError,'post-restart'):
                validate([old+fault+restart+service_events(after),old],restarted,[4,4],expect='service-restart')
        after=service_events([1,2,3,0x212])
        self.assertEqual(len(validate([old+fault+restart+after,old],restarted,[4,4],expect='service-restart')),2)
        with self.assertRaisesRegex(ValueError,'fault boundary'):
            validate([old+restart+fault+after,old],restarted,[4,4],expect='service-restart')
        with self.assertRaisesRegex(ValueError,'same-boot'):
            validate([old+fault+restart.replace(b'generation=2',b'generation=20')+after,old],restarted,[4,4],expect='service-restart')
    def test_negative_cannot_hide_admitted_authority(self):
        with self.assertRaises(ValueError):validate_rejection([b'']*2,[bundle(),bundle(True)],[4,4],'wrong-pin')
    def test_rejection_requires_initialized_custody_and_complete_budget_evidence(self):
        original=bundle()
        words=list(struct.unpack('<512Q',original['UNIFIED_EVIDENCE']))
        words[6]=3;words[32:]=[0]*480
        for i,event in enumerate((1,2,4)):words[32+i*2]=event
        original['UNIFIED_EVIDENCE']=struct.pack('<512Q',*words)
        self.assertEqual(len(validate_rejection([b'']*2,[original]*2,[4,4],'wrong-pin')),2)
        for name,index,value in [('RUNTIME_V13_EVIDENCE',2,3),('RUNTIME_V13_EVIDENCE',17,1),('RUNTIME_V13_EVIDENCE',39,625001),('UNIFIED_EVIDENCE',11,1),('UNIFIED_EVIDENCE',12,1),('UNIFIED_EVIDENCE',34,0x103),('UNIFIED_EVIDENCE',34,0x10000),('UNIFIED_EVIDENCE',34,0)]:
            mutated=copy.deepcopy(original);change(mutated,name,index,value)
            with self.subTest(name=name,index=index,value=value),self.assertRaises(ValueError):
                validate_rejection([b'']*2,[mutated]*2,[4,4],'wrong-pin')
    def test_leave_requires_durable_leave_event(self):
        with self.assertRaises(ValueError):validate([b'']*2,[bundle(),bundle(True)],[4,4],expect='leave')
    def test_build_binding_rejects_stale_source_and_substituted_images(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);names=('node-a.elf','node-b.elf','node-a.pub','node-b.pub','task.elf')
            files=[root/n for n in names]
            for i,f in enumerate(files):f.write_bytes(bytes([i+1])*32)
            nodes={n:{'node_id':sha(files[i+2]),'peer_node_id':sha(files[3-i])} for i,n in enumerate(('a','b'))}
            data=dict(schema_version=1,status='BUILT_NOT_RUN',code_source_map={'a.rs':'original'},code_source_sha256='code',builder_sha256=sha(ROOT/'tools/build_unified.py'),profiles={'fault':'normal','service_fault':'none','service_fault_nodes':{'a':'none','b':'none'},'leave':False},own_private_key_only_verified=True,nodes=nodes,artifacts={n:{'sha256':sha(f),'bytes':32} for n,f in zip(names,files)})
            manifest=root/'build.json';manifest.write_text(json.dumps(data))
            def check():return bind_build(manifest,files[0],files[1],files[2:4],files[4],'normal')
            with patch('verify_unified.code_source_map',return_value={'a.rs':'original'}):
                self.assertEqual(check()['code_source_sha256'],'code')
                files[1].write_bytes(bytes(32))
                with self.assertRaisesRegex(ValueError,'artifact differs'):check()
            with patch('verify_unified.code_source_map',return_value={'a.rs':'modified'}):
                with self.assertRaisesRegex(ValueError,'different source'):check()
    def test_build_binding_requires_the_exact_service_fault_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);names=('node-a.elf','node-b.elf','node-a.pub','node-b.pub','task.elf')
            files=[root/n for n in names]
            for i,f in enumerate(files):f.write_bytes(bytes([i+1])*32)
            nodes={n:{'node_id':sha(files[i+2]),'peer_node_id':sha(files[3-i])} for i,n in enumerate(('a','b'))}
            data=dict(schema_version=1,status='BUILT_NOT_RUN',code_source_map={'a.rs':'original'},code_source_sha256='code',builder_sha256=sha(ROOT/'tools/build_unified.py'),profiles={'fault':'normal','service_fault':'after-start','service_fault_nodes':{'a':'after-start','b':'none'},'leave':False},own_private_key_only_verified=True,nodes=nodes,artifacts={n:{'sha256':sha(f),'bytes':32} for n,f in zip(names,files)})
            manifest=root/'build.json';manifest.write_text(json.dumps(data))
            with patch('verify_unified.code_source_map',return_value={'a.rs':'original'}):
                self.assertEqual(bind_build(manifest,files[0],files[1],files[2:4],files[4],'service-restart-start')['profiles']['service_fault'],'after-start')
                with self.assertRaisesRegex(ValueError,'service-fault profile'):
                    bind_build(manifest,files[0],files[1],files[2:4],files[4],'service-restart-completion')
                data['profiles']['service_fault_nodes']={'a':'after-start','b':'after-start'}
                manifest.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError,'node scope'):
                    bind_build(manifest,files[0],files[1],files[2:4],files[4],'service-restart-start')
    def test_live_progress_retries_torn_publication_without_pausing_guest(self):
        commands=[]
        class Qmp:
            sequence=2
            def execute(self,command,args):
                commands.append(command)
                if args['size']==8:data=struct.pack('<Q',self.sequence)
                elif args['size']==8192:
                    self.sequence=4
                    words=[0]*1024;words[2]=4;words[14]=7
                    data=struct.pack('<1024Q',*words)
                else:data=bytes(args['size'])
                Path(args['filename']).write_bytes(data)
        with tempfile.TemporaryDirectory() as temp:
            locations={'UNIFIED_EVIDENCE':{'pa':0,'size':4096},
                       'DYNAMIC_V13_EVIDENCE':{'pa':4096,'size':4096},
                       'RUNTIME_V13_EVIDENCE':{'pa':8192,'size':8192},
                       'TASK_OVERRUN_EVIDENCE':{'pa':12288,'size':256},
                       'DOMAIN_CONTROL_EVIDENCE':{'pa':16384,'size':CONTROL_WORDS * 8},
                       'REPLAY_V13_EVIDENCE':{'pa':348160,'size':512},
                       'DOMAIN_PREPARATION_CONTEXT':{'pa':352256,'size':128},
                       'DOMAIN_PREPARATION_DETAIL':{'pa':356352,'size':256},
                       'DOMAIN_PREPARATION_PREFIX_DETAIL':{'pa':360448,'size':128},
                       'DOMAIN_PREPARATION_ENTRY_DETAIL':{'pa':364544,'size':128},
                       'DOMAIN_PREPARATION_REJECTIONS':{'pa':368640,'size':5184}}
            result=capture([{'qmp':Qmp(),'folder':Path(temp)}],[locations],resume=True)
            self.assertEqual(struct.unpack('<1024Q',result[0]['RUNTIME_V13_EVIDENCE'])[14],7)
            self.assertEqual(set(result[0]), {
                'UNIFIED_EVIDENCE', 'DYNAMIC_V13_EVIDENCE',
                'RUNTIME_V13_EVIDENCE',
            })
            self.assertEqual(commands,['pmemsave']*8)

if __name__=='__main__':unittest.main()
