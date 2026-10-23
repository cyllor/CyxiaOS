"""Actual EL0 C execution, syscall semantics and protection/recovery in ARM QEMU."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from shell import Guest
from doctor import ROOT, llvm_dir, env
from check_elf import inspect_elf
from verify_m1 import inspect_instructions


def verify(elf, output):
    elf = Path(elf).resolve()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = elf.read_bytes()
    report = dict(status='FAIL', elf_sha256=hashlib.sha256(binary).hexdigest(), checks=[], programs=[])
    try:
        layout = inspect_elf(binary)
        report['kernel_bytes'] = max(s['pa']+s['mem'] for s in layout['loads'])-0x40200000
        assembly = subprocess.run([str(llvm_dir()/'llvm-objdump'), '--disassemble', '--no-show-raw-insn', str(elf)], env=env(), capture_output=True, text=True, check=True, timeout=30).stdout
        report['inspected_instructions'] = inspect_instructions(assembly, allow_user_context=True)
        report['checks'].append('production ELF bounds; integer kernel outside FP context save/restore')
        with Guest(elf, output/'session') as guest:
            guest.until(b'cyxia:/> ')
            def command(text, expected=b''):
                result = guest.command(text)
                if expected not in result or b'FAIL unexpected exception' in result or b'FAIL panic' in result:
                    raise AssertionError((text, expected, result))
                report['checks'].append(text)
                return result
            def run(mode, state, code):
                # Previous status is still visible until kernel accepts the queued launch.
                start = len(guest.text)
                command('posix run '+mode, b'EL0 launch queued:')
                deadline = time.monotonic()+5
                while time.monotonic() < deadline:
                    time.sleep(.025)
                    result = command('posix status')
                    match = re.search(rb'UserStatus \{ ([^}]+)\}', result)
                    if match and b'state: '+state in match[1]:
                        fields = match[1]
                        if not re.search(rb'code: '+str(code).encode()+rb',', fields) or b'free_pages: 64' not in fields:
                            raise AssertionError(fields)
                        report['programs'].append(dict(mode=mode, status=fields.decode()))
                        return fields, bytes(guest.text[start:])
                raise TimeoutError((mode, result))
            fields, transcript = run('demo', b'Exited', 0)
            if b'POSIX EL0 C program: PASS\r\n' not in transcript or b'POSIX CHECK FAILED' in transcript:
                raise AssertionError(transcript)
            command('cat /posix-result', b'hello from EL0\r\n')
            fields, transcript = run('preempt', b'Exited', 0)
            if b'EL0 REGISTERS PASS\r\n' not in transcript or not re.search(rb'preemptions: [1-9]\d*', fields):
                raise AssertionError(('IRQ context preservation not observed', fields))
            for mode, ec in [('fault',0x24), ('readonly',0x24), ('execdata',0x20), ('kernel',0x24), ('guard',0x24)]:
                fields, _ = run(mode, b'Fault', 139)
                esr = int(re.search(rb'esr: (\d+)', fields)[1])
                if esr >> 26 != ec:
                    raise AssertionError((mode, 'wrong exception class', esr))
                command('pwd', b'/\r\n')
            fields, _ = run('spin', b'Timeout', 124)
            if not re.search(rb'preemptions: [1-9]\d*', fields) or b'last_slice_ms: 4' not in fields or b'cpu_model: 12290' not in fields:
                raise AssertionError(('preemption and CPU model not observed',fields))
            # Concurrent EL1 work causes the actual user model to select a shorter slice.
            r = command('proc spawn compute 1000000 1 1', b'spawned pid=')
            pid = int(re.search(rb'spawned pid=(\d+)',r)[1])
            command('posix run spin', b'EL0 launch queued:')
            r = command('posix status', b'state: Running')
            if b'last_slice_ms: 1' not in r:
                raise AssertionError(('competing task not reflected in user budget',r))
            command('posix kill')
            command('posix status', b'state: Killed')
            command(f'proc kill {pid}')
            command(f'proc reap {pid}')
            command('mem status', b'free=32 used=0')
            # A fresh image after all faults proves descriptor/page cleanup and re-entry.
            fields, transcript = run('demo', b'Exited', 0)
            if b'POSIX EL0 C program: PASS\r\n' not in transcript:
                raise AssertionError(transcript)
            command('cat /posix-result', b'hello from EL0\r\n')
            command('write /shell-regression shell-still-works')
            command('cat /shell-regression', b'shell-still-works\r\n')
            report['frames'] = guest.decoder.frames
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf', required=True)
    parser.add_argument('--output', default=str(ROOT/'artifacts/posix-verification'))
    args = parser.parse_args()
    result = verify(args.elf, args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
