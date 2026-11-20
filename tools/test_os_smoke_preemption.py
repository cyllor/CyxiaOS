"""Check that the native smoke observes a real timer preemption of its own task."""
import re
import unittest
from unittest.mock import patch

import os_smoke


class ConsoleFixture:
    def __init__(self, statuses, fail_status=False):
        self.raw = bytearray()
        self.statuses = iter(statuses)
        self.commands = []
        self.fail_status = fail_status

    def command(self, command, expected=()):
        self.commands.append(command)
        at = len(self.raw)
        if command == 'posix spawn spin':
            self.raw.extend(b'USER pid=5 started; memory AI_DIRECT\r\n')
        elif command == 'posix status':
            if self.fail_status:
                raise OSError('console disconnected')
            pid, count = next(self.statuses)
            self.raw.extend(f'POSIX subset EL0 UserStatus {{ pid: {pid}, state: Running, preemptions: {count}, code: 0 }}\r\n'.encode())
        elif command == 'posix kill 5':
            self.raw.extend(b'pid=5 killed; pages reclaimed\r\n')
        else:
            raise AssertionError(command)
        for pattern in expected:
            assert re.search(pattern, self.raw[at:])
        return at

    def until(self, pattern, start=0):
        match = re.search(pattern, self.raw[start:])
        assert match is not None
        return match


class TimerPreemptionSmoke(unittest.TestCase):
    def observe(self, console, times):
        with patch.object(os_smoke.time, 'monotonic', side_effect=times), \
             patch.object(os_smoke.time, 'sleep'):
            return os_smoke.preemption_check(console)

    def test_waits_for_own_live_process_counter_and_reclaims_it(self):
        console = ConsoleFixture([(4, 90), (5, 0), (5, 2)])
        result = self.observe(console, [0, 1, 2, 3, 3.5])
        self.assertEqual(result, {'pid': 5, 'preemptions': 2, 'source': 'syscall-free spin'})
        self.assertEqual(console.commands.count('posix status'), 3)
        self.assertEqual(console.commands[-1], 'posix kill 5')

    def test_never_accepts_zero_or_another_process_counter(self):
        for statuses in [[(5, 0), (5, 0)], [(4, 90), (4, 90)]]:
            console = ConsoleFixture(statuses)
            with self.assertRaisesRegex(TimeoutError, 'timer preemption'):
                self.observe(console, [0, 1, 2, 6])
            self.assertEqual(console.commands[-1], 'posix kill 5')

    def test_console_failure_still_reclaims_the_probe(self):
        console = ConsoleFixture([], fail_status=True)
        with self.assertRaisesRegex(OSError, 'console disconnected'):
            self.observe(console, [0, 1])
        self.assertEqual(console.commands[-1], 'posix kill 5')

    def test_late_nonzero_counter_does_not_pass_the_deadline(self):
        console = ConsoleFixture([(5, 1)])
        with self.assertRaisesRegex(TimeoutError, 'timer preemption.*pid=5 preemptions=1'):
            self.observe(console, [0, 1, 6])
        self.assertEqual(console.commands[-1], 'posix kill 5')


if __name__ == '__main__':
    unittest.main()
