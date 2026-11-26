"""Bounded QMP transport over an owned subprocess's standard pipes.

This is an explicit alternative for executors without Unix sockets. It changes
only the host transport; QMP framing and all guest acceptance checks stay in
the existing runner. It never opens a listening socket or changes permissions.
"""
import os
import select
import time


class PipeTransport:
    def __init__(self, process):
        if process.stdin is None or process.stdout is None:
            raise ValueError("QMP requires owned stdin/stdout pipes")
        self.reader = process.stdout
        self.writer = process.stdin
        self.timeout = 5.0
        os.set_blocking(self.reader.fileno(), False)
        os.set_blocking(self.writer.fileno(), False)

    def settimeout(self, seconds):
        self.timeout = seconds

    def recv(self, size):
        if not select.select([self.reader], [], [], self.timeout)[0]:
            raise TimeoutError("QMP pipe receive timeout")
        return os.read(self.reader.fileno(), size)

    def sendall(self, data):
        end = time.monotonic() + self.timeout
        pending = memoryview(data)
        while pending:
            left = end - time.monotonic()
            if left <= 0 or not select.select([], [self.writer], [], left)[1]:
                raise TimeoutError("QMP pipe send timeout")
            count = os.write(self.writer.fileno(), pending)
            if count == 0:
                raise RuntimeError("QMP pipe disconnected")
            pending = pending[count:]

    def close(self):
        self.reader.close()
        self.writer.close()
