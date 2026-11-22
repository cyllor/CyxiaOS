"""Native smoke oracle boundaries; these host checks are not native evidence."""
import copy
import struct
import unittest

import run_snapshot_probe as probe


class SnapshotProbeOracle(unittest.TestCase):
    def test_scope_is_explicit_and_never_claims_full_unified_acceptance(self):
        required = ['--build', 'build', '--output', 'output', '--qemu', 'qemu',
                    '--qemu-source', 'source']
        self.assertEqual(probe.argument_parser().parse_args(required).scope, 'full-unified')
        selected = probe.argument_parser().parse_args(required + ['--scope', 'local-filesystem'])
        self.assertEqual(selected.scope, 'local-filesystem')
        for scope in probe.SCOPES:
            evidence = probe.scope_evidence(scope)
            self.assertEqual(evidence['scope'], scope)
            self.assertIs(evidence['full_unified_accepted'], False)
            self.assertEqual(evidence['peer_network_enabled'], scope == 'full-unified')
        with self.assertRaisesRegex(ValueError, 'unknown native smoke scope'):
            probe.scope_evidence('anything')

    def test_local_nics_have_no_socket_peer_or_host_backend(self):
        for number in (1, 2):
            self.assertEqual(probe.network_backend('local-filesystem', number),
                             'hubport,id=net0,hubid=0')
        self.assertEqual(probe.network_backend('full-unified', 1, 23456),
                         'socket,id=net0,listen=127.0.0.1:23456')
        self.assertEqual(probe.network_backend('full-unified', 2, 23456),
                         'socket,id=net0,connect=127.0.0.1:23456')
        with self.assertRaisesRegex(ValueError, 'peer socket port'):
            probe.network_backend('full-unified', 1)
        with self.assertRaisesRegex(ValueError, 'invalid native network profile'):
            probe.network_backend('unknown', 1, 23456)
        with self.assertRaisesRegex(ValueError, 'invalid native network profile'):
            probe.network_backend('local-filesystem', 3)

    def evidence(self, first=(41, 2, 1, 0), second=(42, 3, 1, 0)):
        words = [probe.PROBE_MAGIC, probe.PROBE_SCHEMA] + [0] * 14
        words[4:8], words[8:12] = first, second
        return struct.pack('<16Q', *words)

    def test_two_distinct_completed_real_actors_are_required(self):
        observed = probe.decode_probe(self.evidence(), final=True)
        self.assertTrue(observed['complete'])
        self.assertEqual([actor['task_id'] for actor in observed['actors']], [41, 42])
        pending = self.evidence(second=(42, 3, 0, 0))
        self.assertFalse(probe.decode_probe(pending)['complete'])
        with self.assertRaisesRegex(ValueError, 'both snapshot actors'):
            probe.decode_probe(pending, final=True)
        with self.assertRaisesRegex(ValueError, 'identities alias'):
            probe.decode_probe(self.evidence(second=(41, 2, 1, 0)), final=True)

    def test_nonzero_recovery_exit_and_unbound_success_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, 'role 2 exited with code 312'):
            probe.decode_probe(self.evidence(second=(42, 3, 1, 312)))
        with self.assertRaisesRegex(ValueError, 'lacks task identity'):
            probe.decode_probe(self.evidence(first=(0, 0, 1, 0)), final=True)
        self.assertIsNone(probe.decode_probe(bytes(probe.PROBE_BYTES)))
        with self.assertRaisesRegex(ValueError, 'identity'):
            probe.decode_probe(bytes(probe.PROBE_BYTES), final=True)

    def test_budget_failure_and_partial_publication_cannot_pass(self):
        words = list(struct.unpack('<16Q', self.evidence()))
        words[12:] = [701, 88, 3_000_000, 2_500_000]
        for final in (False, True):
            with self.subTest(final=final):
                with self.assertRaisesRegex(ValueError,
                        'CPU0 budget failure: stage=701, sequence=88, '
                        'actual_ns=3000000, reserved_ns=2500000'):
                    probe.decode_probe(struct.pack('<16Q', *words), final=final)
        words[13] = 0  # Sequence is the producer's final publication field.
        self.assertIsNone(probe.decode_probe(struct.pack('<16Q', *words)))
        with self.assertRaisesRegex(ValueError, 'incomplete CPU0 budget'):
            probe.decode_probe(struct.pack('<16Q', *words), final=True)
        words[12:] = [0] * 4
        words[1] = 1  # The source-bound diagnostic profile uses schema 2.
        with self.assertRaisesRegex(ValueError, 'identity'):
            probe.decode_probe(struct.pack('<16Q', *words), final=True)

    def fixture(self):
        uuid = '07' * 16
        key = dict(snapshot_id=3, slot=6, slot_generation=1)
        files = {probe.VALUE: dict(size=16, sha256=probe.BEFORE_SHA256),
                 probe.KEY_FILE: dict(size=0)}
        snapshots = [dict(slot=0, snapshot_id=1, slot_generation=1, state=1),
                     dict(slot=3, snapshot_id=2, slot_generation=1, state=1),
                     dict(key, state=1, captured_live_view_epoch=1,
                          files=copy.deepcopy(files))]
        checked = dict(format_version=2, uuid=uuid, boot_epoch=1, files=files,
            snapshots=snapshots, control=dict(live_view_epoch=2, business_write_gate=0,
                                             restore_phase=0, gc_phase=0))
        records = []
        for slot, sequence, operation in ((0, 1, 0x20), (15, 2, 0x23), (15, 3, 0x29)):
            records.append(dict(client_slot=slot, client_generation=1, request_seq=sequence,
                operation=operation, state=2, result_code=0, snapshot_key=key,
                old_epoch=1, new_epoch=2))
        return checked, records, uuid

    def test_stopped_v2_disk_requires_matching_history_and_durable_receipts(self):
        checked, records, uuid = self.fixture()
        outcome = probe.validate_snapshot_outcome(checked, records, uuid)
        self.assertTrue(outcome['original_history_preserved'])
        self.assertEqual(outcome['business_write_gate'], 'OPEN')
        for field, value in [('format_version', 1), ('uuid', '08' * 16), ('boot_epoch', 2)]:
            with self.subTest(field=field):
                altered = copy.deepcopy(checked)
                altered[field] = value
                with self.assertRaises(ValueError):
                    probe.validate_snapshot_outcome(altered, records, uuid)
        for offset in range(3):
            with self.subTest(record=offset):
                altered = copy.deepcopy(records)
                altered[offset]['state'] = 1
                with self.assertRaisesRegex(ValueError, 'durable request'):
                    probe.validate_snapshot_outcome(checked, altered, uuid)
        wrong_operation = copy.deepcopy(records)
        wrong_operation[1]['operation'] = 0x22  # DELETE cannot stand in for RESTORE.
        with self.assertRaisesRegex(ValueError, 'durable request 15:2:0x23'):
            probe.validate_snapshot_outcome(checked, wrong_operation, uuid)

    def test_old_live_bytes_wrong_snapshot_or_still_frozen_gate_cannot_pass(self):
        checked, records, uuid = self.fixture()
        for mutation in ('live_bytes', 'history_bytes', 'ready_name', 'gate', 'epoch', 'source'):
            with self.subTest(mutation=mutation):
                altered, receipts = copy.deepcopy(checked), copy.deepcopy(records)
                if mutation == 'live_bytes':
                    altered['files'][probe.VALUE]['sha256'] = '00' * 32
                elif mutation == 'history_bytes':
                    altered['snapshots'][2]['files'][probe.VALUE]['sha256'] = '00' * 32
                elif mutation == 'ready_name':
                    altered['files'][probe.READY] = dict(size=0)
                elif mutation == 'gate':
                    altered['control']['business_write_gate'] = 1
                elif mutation == 'epoch':
                    receipts[1]['new_epoch'] = 1
                else:
                    receipts[1]['snapshot_key'] = dict(snapshot_id=4, slot=7, slot_generation=1)
                with self.assertRaises(ValueError):
                    probe.validate_snapshot_outcome(altered, receipts, uuid)


if __name__ == '__main__':
    unittest.main()
