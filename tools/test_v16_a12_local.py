"""Portable Local-bank integrity tests, never native executions or A12 PASS.

The small fixtures contain only public u64 observations. Complete native
acceptance additionally requires the outer verifier's source/image/custody,
actor and other A12 predicates; these tests exercise only parsing and joins.
"""
from pathlib import Path
import struct
import unittest

import v16_a12_local as local


FIXTURES = Path(__file__).parent / 'fixtures' / 'v16_a12'


def mutated(data, changes):
    words = list(struct.unpack(f'<{len(data) // 8}Q', data))
    for index, value in changes.items():
        words[index] = value(words[index]) if callable(value) else value
    return struct.pack(f'<{len(words)}Q', *words)


class LocalBankIntegrity(unittest.TestCase):
    def setUp(self):
        self.application = (FIXTURES / 'application.bin').read_bytes()
        self.local = (FIXTURES / 'local.bin').read_bytes()

    def joins(self, application=None, broker=None):
        _, applications = local._applications(
            self.application if application is None else application)
        _, brokers = local._locals(self.local if broker is None else broker)
        return local._join_records(applications, brokers)

    def reject(self, *, application=None, broker=None, pattern=None):
        if pattern is None:
            with self.assertRaises(ValueError):
                self.joins(application, broker)
        else:
            with self.assertRaisesRegex(ValueError, pattern):
                self.joins(application, broker)

    def test_four_public_observation_joins_preserve_full_identities(self):
        joins = self.joins()
        self.assertEqual(len(joins), 4)
        self.assertEqual([r['request'] for r in joins],
                         [[4097, 1], [4098, 1], [4099, 1], [4100, 1]])
        self.assertEqual([r['target_task'] for r in joins],
                         [[4097, 11], [4097, 5], [4097, 7], [4097, 9]])
        self.assertEqual([r['actor'] for r in joins], [[4096, 4]] * 4)
        self.assertEqual([r['spawn_id'] for r in joins], [1, 2, 3, 4])
        self.assertTrue(all(r['submitted_ns'] <= r['completion_ns'] for r in joins))
        # No fixture is promoted to an execution/acceptance verdict by joining.
        self.assertTrue(all('native_acceptance_status' not in r for r in joins))

    def test_both_decoders_reject_torn_wrong_schema_or_replaced_banks(self):
        for decoder, data in ((local._applications, self.application),
                              (local._locals, self.local)):
            for changes in ({0: lambda n: n + 1}, {1: 0}, {2: 2},
                            {3: 99}, {4: 99}, {5: lambda n: n + 1},
                            {6: 1}, {7: 1}):
                with self.subTest(decoder=decoder.__name__, changes=changes):
                    with self.assertRaises(ValueError):
                        decoder(mutated(data, changes))

    def test_both_decoders_require_exact_length_and_real_publication(self):
        for decoder, data in ((local._applications, self.application),
                              (local._locals, self.local)):
            for invalid in (data[:-1], data + bytes(8), bytes(len(data))):
                with self.subTest(decoder=decoder.__name__, length=len(invalid)):
                    with self.assertRaises(ValueError):
                        decoder(invalid)

    def test_nonzero_unused_slots_and_duplicate_requests_rejected(self):
        for changes in ({8 + 31 * 24 + 23: 1}, {8 + 24: 4097}):
            self.reject(application=mutated(self.application, changes),
                        pattern='duplicate/empty request')
        self.reject(broker=mutated(self.local, {8 + 7 * 32 + 31: 1}),
                    pattern='duplicate/empty request')

    def test_wrong_request_slot_rejected(self):
        self.reject(application=mutated(self.application, {8: lambda n: n + 5}),
                    pattern='request slot')
        self.reject(broker=mutated(self.local, {8 + 2: 8}),
                    pattern='identity/slot')

    def test_actual_actor_requires_full_nonzero_task_identity(self):
        for changes in ({8 + 2: 44}, {8 + 3: 0}):
            self.reject(application=mutated(self.application, changes),
                        pattern='actor full task identity')

    def test_nonzero_actor_generation_is_preserved_for_outer_task_check(self):
        joins = self.joins(application=mutated(self.application, {8 + 3: 5}))
        self.assertEqual(joins[0]['actor'], [4096, 5])
        self.assertNotEqual(joins[0]['actor'], [4096, 4])
        # Only the outer protected Task bank knows the expected actor. The
        # Local bank has no actor column and must not invent that third fact.

    def test_original_deadline_is_preserved_for_outer_completion_check(self):
        joins = self.joins(broker=mutated(self.local, {8 + 15: 1}))
        self.assertEqual(joins[0]['original_deadline_ns'], 1)
        self.assertGreater(joins[0]['completion_ns'], joins[0]['original_deadline_ns'])
        # Joining identities alone is not the outer deadline acceptance gate.

    def test_duplicate_actor_sequence_rejected(self):
        self.reject(application=mutated(self.application, {8 + 24 + 4: 1}),
                    pattern='duplicate actor/sequence')

    def test_mixed_application_boot_generation_rejected(self):
        self.reject(application=mutated(self.application, {8 + 1: 2}),
                    pattern='boot generation')

    def test_wrong_local_request_id_or_generation_rejected(self):
        for changes in ({8: lambda n: n + 32}, {8 + 1: 2}):
            self.reject(broker=mutated(self.local, changes),
                        pattern='same full request')

    def test_wrong_target_generation_rejected(self):
        self.reject(broker=mutated(self.local, {8 + 11: lambda n: n + 1}),
                    pattern='cross-bank')

    def test_completion_timestamp_must_match_other_bank(self):
        self.reject(broker=mutated(self.local, {8 + 28: lambda n: n + 1}),
                    pattern='cross-bank')

    def test_created_without_acknowledgment_is_insufficient(self):
        self.reject(broker=mutated(self.local, {8 + 14: 0}), pattern='completion/ack')

    def test_created_without_retained_success_is_insufficient(self):
        self.reject(broker=mutated(self.local,
                    {8 + 13: 0, 8 + 14: 0, 8 + 27: 0, 8 + 28: 0}),
                    pattern='completion/ack')

    def test_owner_error_does_not_become_successful_created(self):
        self.reject(broker=mutated(self.local,
                    {8 + 7: 1, 8 + 23: 11, 8 + 24: 2**64 - 1, 8 + 25: 1}),
                    pattern='Created/no-error')

    def test_broker_completion_reserved_words_are_checked(self):
        for offset in (30, 31):
            self.reject(broker=mutated(self.local, {8 + offset: 1}),
                        pattern='completion/reserved')

    def test_duplicate_created_target_cannot_serve_two_requests(self):
        target = {8 + 10: 4097, 8 + 11: 5}
        self.reject(application=mutated(self.application, target),
                    broker=mutated(self.local, target), pattern='duplicate target')

    def test_remote_application_is_not_local_admission(self):
        self.reject(application=mutated(self.application,
                    {8 + i * 24 + 9: 3 for i in range(4)}), pattern='no genuine Local')

    def test_application_local_status_alone_is_insufficient(self):
        _, applications = local._applications(self.application)
        with self.assertRaisesRegex(ValueError, 'same full request'):
            local._join_records(applications, {})

    def test_created_broker_status_alone_is_insufficient(self):
        _, brokers = local._locals(self.local)
        with self.assertRaisesRegex(ValueError, 'no genuine Local'):
            local._join_records({}, brokers)

    def test_publication_accounting_cannot_omit_observations(self):
        for decoder, data in ((local._applications, self.application),
                              (local._locals, self.local)):
            with self.subTest(decoder=decoder.__name__):
                with self.assertRaisesRegex(ValueError, 'publication accounting'):
                    decoder(mutated(data, {0: lambda n: n + 2, 5: lambda n: n + 1}))


if __name__ == '__main__':
    unittest.main()
