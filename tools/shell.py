"""CyxiaOS serial console bridge. Commands run inside the ARM guest.
The host only transports framed UART bytes through a local socket; it does not implement files or AI.
"""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import termios
import time
import tty
from doctor import ROOT, env
from run_qemu import Qmp
from transport import FrameDecoder
from check_elf import boot_profile


class Guest:
    def __init__(self, elf, output, graphics=False, display="none", rng=False, disk=None, disk_readonly=False):
        self.graphics = graphics
        self.rng = rng
        self.display = display
        self.elf = Path(elf).resolve()
        self.boot_profile = boot_profile(self.elf.read_bytes())
        self.disk = Path(disk).resolve() if disk is not None else None
        self.disk_readonly = disk_readonly
        if self.disk is not None and (not self.disk.is_file() or self.disk.stat().st_size < 2*1024*1024):
            raise ValueError('Dedicated CyxiaOS raw disk must be an existing regular file of at least 2 MiB')
        self.output = Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.decoder = FrameDecoder()
        self.proc = self.sock = self.uart = self.qmp = self.temp = self.err = None
        self.text = bytearray()
        self.raw = bytearray()

    def __enter__(self):
        try:
            self.temp = tempfile.TemporaryDirectory(prefix='cyxs-')
            socket_path = str(Path(self.temp.name) / 'q.sock')
            uart_path = str(Path(self.temp.name) / 'uart.sock')
            self.err = (self.output / 'qemu-stderr.log').open('wb')
            args = [shutil.which('qemu-system-aarch64', path=env()['PATH']),
                    '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                    '-cpu', 'cortex-a53', '-smp', '1', '-m', f"{self.boot_profile['ram_mib']}M", '-accel', 'tcg',
                    '-display', self.display, '-monitor', 'none', '-nic', 'none',
                    '-chardev', f'socket,id=cyxlog,path={uart_path},server=on,wait=on', '-serial', 'chardev:cyxlog',
                    '-qmp', f'unix:{socket_path},server=on,wait=off', '-kernel', str(self.elf), '-no-reboot']
            if self.graphics:
                args += ["-global", "virtio-mmio.force-legacy=false",
                         "-device", "virtio-gpu-device",
                         "-device", "virtio-keyboard-device",
                         "-device", "virtio-mouse-device"]
            if self.rng:
                if not self.graphics:
                    args += ["-global", "virtio-mmio.force-legacy=false"]
                args += ["-object", "rng-random,id=cyxentropy,filename=/dev/urandom",
                         "-device", "virtio-rng-device,rng=cyxentropy"]
            if self.disk is not None:
                if not self.graphics and not self.rng:
                    args += ["-global", "virtio-mmio.force-legacy=false"]
                args += ["-blockdev", json.dumps({"driver": "file", "node-name": "cyxfile", "filename": str(self.disk), "read-only": self.disk_readonly}),
                         "-blockdev", json.dumps({"driver": "raw", "node-name": "cyxdisk", "file": "cyxfile", "read-only": self.disk_readonly}),
                         "-device", "virtio-blk-device,drive=cyxdisk"]
            (self.output / "qemu-command.json").write_text(json.dumps(args, indent=2))
            self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=self.err, env=env())
            self.uart = socket.socket(socket.AF_UNIX)
            deadline = time.monotonic() + 10
            while True:
                try:
                    self.uart.connect(uart_path)
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if self.proc.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('QEMU failed to start')
                    time.sleep(.01)
            self.uart.setblocking(False)
            self.sock = socket.socket(socket.AF_UNIX)
            while True:
                try:
                    self.sock.connect(socket_path)
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if self.proc.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('QMP failed to start')
                    time.sleep(.01)
            self.qmp = Qmp(self.sock)
            if 'QMP' not in self.qmp.receive(deadline):
                raise RuntimeError('Missing QMP greeting')
            self.qmp.execute('qmp_capabilities')
            self.state('running', args=args)
            return self
        except BaseException:
            self.close()
            raise

    def state(self, status, **extra):
        (self.output / 'state.json').write_text(json.dumps(dict(
            state=status, pid=self.proc.pid if self.proc else None,
            elf=str(self.elf), **extra), indent=2))

    def poll(self):
        try:
            raw = self.uart.recv(65536)
            if not raw:
                raise RuntimeError('UART disconnected')
        except BlockingIOError:
            raw = b''
        data = b''.join(self.decoder.feed(raw))
        self.raw.extend(raw)
        self.text.extend(data)
        if len(self.raw) > 8 * 1024 * 1024:
            # Keep manual sessions bounded without losing new output or transport state.
            del self.raw[:-4 * 1024 * 1024]
            del self.text[:-4 * 1024 * 1024]
        if self.decoder.corrupt or self.decoder.loss:
            raise RuntimeError('UART transport lost/corrupted output; session stopped')
        if self.proc.poll() is not None:
            raise RuntimeError('QEMU exited')
        # Avoid unbounded QMP transcript growth during an interactive session.
        if len(self.qmp.transcript) > 1024:
            del self.qmp.transcript[:-512]
        return data

    def send(self, data):
        if len(data) > 8:
            raise ValueError('UART input batch exceeds 8 bytes')
        # Tiny batches; bounded socket backpressure. Never drop a partial write.
        view = memoryview(data)
        deadline = time.monotonic() + 2
        while view:
            if time.monotonic() >= deadline:
                raise TimeoutError('UART input stalled')
            _, writable, _ = select.select([], [self.uart], [], .01)
            if writable:
                try:
                    sent = self.uart.send(view)
                except BlockingIOError:
                    continue
                if not sent:
                    raise RuntimeError('UART disconnected')
                view = view[sent:]

    def until(self, marker, timeout=10):
        data = bytearray()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data.extend(self.poll())
            if marker in data:
                return bytes(data)
            time.sleep(.01)
        raise TimeoutError(f'Missing guest output: {marker!r}; tail={bytes(data[-300:])!r}')

    def command(self, command, prompt=b'cyxia:/> '):
        data = bytearray()
        payload = command.encode('utf-8') + b'\r'
        for start in range(0, len(payload), 8):
            self.send(payload[start:start + 8])
            time.sleep(.01)
            data.extend(self.poll())
        if b"\r\n" + prompt not in data:
            data.extend(self.until(prompt))
        return bytes(data)

    def close(self):
        if self.proc:
            if self.proc.poll() is None:
                try:
                    if self.qmp:
                        self.qmp.execute('quit')
                except Exception:
                    pass
                try:
                    self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.proc.terminate()
                    try:
                        self.proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
                        self.proc.wait(timeout=2)
            self.state('stopped', exit_code=self.proc.returncode)
        if self.sock:
            self.sock.close()
        if self.uart:
            self.uart.close()
        if self.err:
            self.err.close()
        if self.temp:
            self.temp.cleanup()
        (self.output / 'console.txt').write_bytes(self.text)
        (self.output / 'serial.bin').write_bytes(self.raw)

    def __exit__(self, *_):
        self.close()


class InputQueue:
    """Reject a whole damaged paste line; never interpret its tail as a new command."""
    def __init__(self):
        self.pending = bytearray()
        self.discarding = False

    def feed(self, incoming):
        cancelled = False
        while True:
            if self.discarding:
                end = next((i for i, byte in enumerate(incoming) if byte in (10, 13)), None)
                if end is None:
                    return cancelled
                incoming = incoming[end + 1:]
                self.discarding = False
            if len(self.pending) + len(incoming) <= 4096:
                self.pending.extend(incoming)
                return cancelled
            self.pending.clear()
            self.discarding = True
            cancelled = True

    def take(self):
        data = bytes(self.pending[:8])
        del self.pending[:8]
        return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf', type=Path)
    parser.add_argument('--disk', type=Path, help='Existing dedicated raw disk; save with guest storage checkpoint')
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts' / ('shell-' + str(time.time_ns())))
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.error('Open in an interactive terminal; use verify_shell.py for scripted tests')
    if args.elf:
        elf = args.elf
    else:
        from build import build
        elf = build('release', selftest=False)
    print('CyxiaOS ARM guest console. Ctrl+] exits QEMU. Use storage checkpoint to save to an attached disk.', flush=True)
    with Guest(elf, args.output, disk=args.disk) as guest:
        boot = guest.until(b'cyxia:/> ')
        guest.state('running', shell_ready=True)
        sys.stdout.buffer.write(boot)
        sys.stdout.buffer.flush()
        previous = termios.tcgetattr(sys.stdin.fileno())
        inputs = InputQueue()
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                readable, _, _ = select.select([sys.stdin], [], [], .01)
                if readable:
                    incoming = os.read(sys.stdin.fileno(), 256)
                    if not incoming or b'\x1d' in incoming:
                        break
                    if inputs.feed(incoming):
                        guest.send(b'\x03')
                        sys.stdout.buffer.write(b'\r\nPaste overflow; discarding through next line ending.\r\n')
                pending = inputs.take()
                if pending:
                    guest.send(pending)
                    time.sleep(.01)
                sys.stdout.buffer.write(guest.poll())
                sys.stdout.buffer.flush()
        finally:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, previous)
            print('\r\nCyxiaOS stopped.')


if __name__ == '__main__':
    main()
