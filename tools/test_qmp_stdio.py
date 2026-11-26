"""QMP commands over owned child pipes retain framing, deadlines and EOF."""
import subprocess
import sys
import time
import unittest

from tools.qmp_stdio import PipeTransport
from tools.run_qemu import Qmp


class StdioQmpTests(unittest.TestCase):
    def child(self, code):
        proc = subprocess.Popen([sys.executable, "-u", "-c", code],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, bufsize=0)
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
        self.addCleanup(cleanup)
        return proc

    def test_qmp_command_preserves_arguments_ids_and_event_framing(self):
        proc = self.child('''
import json, sys
request = json.loads(sys.stdin.buffer.readline())
sys.stdout.buffer.write(b'{"event":"STOP"}\\n')
sys.stdout.buffer.write(json.dumps({"id": request["id"], "return": request}).encode() + b'\\n')
sys.stdout.buffer.flush()
''')
        qmp = Qmp(PipeTransport(proc))
        self.assertEqual(qmp.execute("pmemsave", {"val": 4096, "size": 4096}),
                         {"execute": "pmemsave", "arguments": {"val": 4096, "size": 4096}, "id": 1})
        self.assertEqual(qmp.transcript[1]["message"], {"event": "STOP"})

    def test_silent_child_obeys_receive_deadline(self):
        proc = self.child("import sys; sys.stdin.buffer.read()")
        transport = PipeTransport(proc)
        transport.settimeout(0.01)
        with self.assertRaises(TimeoutError):
            transport.recv(64)

    def test_exited_child_is_eof_not_an_infinite_poll(self):
        proc = self.child("pass")
        proc.wait(timeout=5)
        transport = PipeTransport(proc)
        transport.settimeout(1)
        self.assertEqual(transport.recv(64), b"")
        with self.assertRaisesRegex(RuntimeError, "QMP disconnected"):
            Qmp(transport).receive(time.monotonic() + 1)


if __name__ == "__main__":
    unittest.main()
