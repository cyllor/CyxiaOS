"""Transcript contract tests only; these fixtures are not guest evidence."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import os_cosmic_config as subject


def transcript(lines, code=0, pid=7):
    return (f'posix exec cosmic-config-check\r\nELF pid={pid} started; ABI=Linux-x86_64-subset\r\n'.encode()
            + b'\r\n'.join(lines) + f'\r\nUSER pid={pid} Exited code={code} free_pages=64\r\n'.encode())


DEFAULTS = b'COSMIC_CONFIG DEFAULTS PASS bindings=123 actions=25 rules=35'
EXERCISE = [DEFAULTS, b'COSMIC_CONFIG NOTIFIED value=false', b'COSMIC_CONFIG NOTIFIED value=true',
            b'COSMIC_CONFIG VALUES_RECOVERED PASS', b'COSMIC_CONFIG RECOVERED PASS',
            b'COSMIC_CONFIG EXERCISE PASS']


class CosmicConfigTranscript(unittest.TestCase):
    def test_exercise_requires_both_notifications_in_order_and_clean_exit(self):
        parsed = subject.validate_transcript(transcript(EXERCISE), 7, 'check')
        self.assertEqual(parsed['defaults'], {'bindings': 123, 'actions': 25, 'rules': 35})
        for data in (transcript(EXERCISE, code=1), transcript(EXERCISE, pid=8),
                     transcript(EXERCISE[:1] + EXERCISE[2:]),
                     transcript([EXERCISE[0], EXERCISE[2], EXERCISE[1], *EXERCISE[3:]]),
                     transcript(EXERCISE + [b'COSMIC_CONFIG FAIL: unexpected']),
                     transcript(EXERCISE).replace(b'bindings=123', b'bindings=0')):
            with self.subTest(data=data), self.assertRaises(ValueError):
                subject.validate_transcript(data, 7, 'check')

    def test_malformed_init_requires_parse_failure_and_must_not_claim_readiness(self):
        lines = [DEFAULTS, b'COSMIC_CONFIG FAIL: RonSpanned(SpannedError { code: ExpectedMapEnd })']
        parsed = subject.validate_transcript(transcript(lines, code=1), 7, 'init', custom='malformed')
        self.assertEqual(parsed['exit_code'], 1)
        for bad in (transcript(lines), transcript(lines + [b'COSMIC_CONFIG READY'], code=1),
                    transcript([DEFAULTS, b'COSMIC_CONFIG FAIL: Io(NotFound)'], code=1)):
            with self.subTest(data=bad), self.assertRaises(ValueError):
                subject.validate_transcript(bad, 7, 'init', custom='malformed')

    def test_created_and_preserved_are_distinct_claims(self):
        for custom in ('created', 'preserved'):
            lines = [DEFAULTS, ('COSMIC_CONFIG CUSTOM_' + custom.upper()).encode(), b'COSMIC_CONFIG READY']
            subject.validate_transcript(transcript(lines), 7, 'init', custom=custom)
            with self.assertRaises(ValueError):
                subject.validate_transcript(transcript(lines), 7, 'init',
                                            custom='created' if custom == 'preserved' else 'preserved')

    def test_markers_after_exit_or_before_launch_cannot_satisfy_a_run(self):
        launch = b'ELF pid=7 started; ABI=Linux-x86_64-subset\r\n'
        ended = b'USER pid=7 Exited code=0 free_pages=64\r\n'
        marker = b'COSMIC_CONFIG VALUES_RECOVERED PASS\r\nCOSMIC_CONFIG RECOVERED PASS\r\n'
        for data in (marker + launch + ended, launch + ended + marker, launch + launch + marker + ended):
            with self.subTest(data=data), self.assertRaises(ValueError):
                subject.validate_transcript(data, 7, 'verify')

    def test_recovery_never_initializes_writes_or_exercises(self):
        for library, alias in ((False, 'verify'), (True, 'values')):
            with self.subTest(library=library), \
                 patch.object(subject, 'run_client', return_value={'alias': alias}) as run, \
                 patch.object(subject, 'readback', side_effect=lambda c, path, value: {'path': path, 'value': value}) as read:
                report = subject.checks(object(), recover=True, library=library)
            self.assertEqual([call.args[1] for call in run.call_args_list], [alias])
            self.assertTrue(report['recovered'])
            self.assertEqual(read.call_count, 3)

    def test_durable_values_do_not_certify_directory_cleanup(self):
        values = [b'COSMIC_CONFIG VALUES_RECOVERED PASS']
        clean = values + [b'COSMIC_CONFIG RECOVERED PASS']
        subject.validate_transcript(transcript(values), 7, 'values')
        subject.validate_transcript(transcript(clean), 7, 'verify')
        for lines, alias in ((values, 'verify'), (clean, 'values'),
                             (list(reversed(clean)), 'verify'), (clean[1:], 'verify')):
            with self.subTest(lines=lines, alias=alias), self.assertRaises(ValueError):
                subject.validate_transcript(transcript(lines), 7, alias)

    def test_library_exercise_retains_notification_and_runtime_cleanup_checks(self):
        subject.validate_transcript(transcript(EXERCISE), 7, 'raw')
        for missing in (b'COSMIC_CONFIG VALUES_RECOVERED PASS', b'COSMIC_CONFIG RECOVERED PASS'):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                subject.validate_transcript(transcript([line for line in EXERCISE if line != missing]), 7, 'raw')


if __name__ == '__main__':
    unittest.main()
