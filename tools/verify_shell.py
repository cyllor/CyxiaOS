"""Exercise the actual production ARM shell, RAM filesystem and local model via UART."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from shell import Guest
from doctor import ROOT, llvm_dir, env
from check_elf import inspect_elf
from verify_m1 import inspect_instructions

TRACE = [0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1]


def verify(elf, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status='FAIL', elf_sha256=hashlib.sha256(Path(elf).read_bytes()).hexdigest(), checks=[])
    try:
        layout = inspect_elf(Path(elf).read_bytes())
        report['kernel_bytes'] = max(x['pa'] + x['mem'] for x in layout['loads']) - 0x40200000
        disassembly = subprocess.run([str(llvm_dir() / 'llvm-objdump'), '--disassemble',
                                     '--no-show-raw-insn', str(elf)], env=env(),
                                    capture_output=True, text=True, check=True, timeout=30).stdout
        report['inspected_instructions'] = inspect_instructions(disassembly, allow_user_context=True)
        report['checks'].append('production ELF; integer kernel outside FP context save/restore')
        with Guest(elf, output / 'session') as guest:
            guest.until(b'cyxia:/> ')
            def check(command, expected=b'', error=False, prompt=b'cyxia:/> '):
                reply = guest.command(command, prompt)
                if expected not in reply or (not error and b'error:' in reply):
                    raise AssertionError((command, expected, reply))
                report['checks'].append(command)
                return reply
            check('help', b'write PATH TEXT')
            check('mkdir /docs')
            check('cd /docs', prompt=b'cyxia:/docs> ')
            check('write note hello', prompt=b'cyxia:/docs> ')
            check('append note world', prompt=b'cyxia:/docs> ')
            check('cat note', b'helloworld\r\n', prompt=b'cyxia:/docs> ')
            check('cat note', b'helloworld\r\n', prompt=b'cyxia:/docs> ')
            check('ai status', b'cache hits=1 misses=1', prompt=b'cyxia:/docs> ')
            check('write note updated', prompt=b'cyxia:/docs> ')
            check('cat note', b'updated\r\n', prompt=b'cyxia:/docs> ')
            check('cd /')
            check('rmdir /docs', b'error: NotEmpty', error=True)
            check('rm /docs/note')
            check('rmdir /docs')
            check('cat /docs/note', b'error: NotFound', error=True)
            check('write /hot unchanged')
            check('write /cold cold')
            for choice in TRACE:
                check('cat /hot' if choice == 0 else 'cat /cold', b'unchanged' if choice == 0 else b'cold')
            check('ai train', b'candidate validated')
            check('ai status', b'model v1')
            check('ai apply', b'model activated')
            check('ai status', b'model v2')
            check('cat /hot', b'unchanged\r\n')
            check('ai rollback', b'model rolled back')
            check('ai status', b'model v3')
            check('write /limit ' + 'x' * 1024)
            for _ in range(3): check('append /limit ' + 'x' * 1024)
            check('append /limit overflow', b'error: TooLarge', error=True)
            check('stat /limit', b'bytes=4096')
            check('write /overflow ' + 'x' * 1152, b'command discarded', error=True)
            check('stat /overflow', b'NotFound', error=True)
            check('df', b'persistent=no')
            report['frames'] = guest.decoder.frames
        with Guest(elf, output / 'reboot') as guest:
            guest.until(b'cyxia:/> ')
            if b'error: NotFound' not in guest.command('stat /hot'):
                raise AssertionError('RAM reset contract failed')
            report['checks'].append('reboot clears RAM files')
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output / 'summary.json').write_text(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf', required=True)
    parser.add_argument('--output', default=str(ROOT / 'artifacts' / 'shell-verification'))
    args = parser.parse_args()
    result = verify(args.elf, args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
