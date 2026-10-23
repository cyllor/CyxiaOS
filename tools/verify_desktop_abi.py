"""Verify musl directory/event, signal and socket programs on the supplied kernel."""
import argparse
import hashlib
import json
from pathlib import Path
from doctor import ROOT
from shell import Guest
from check_elf import inspect_elf, boot_profile
from verify_x11 import wait
from verify_ported import parse_processes


def verify(elf, output):
    image = elf.read_bytes()
    inspect_elf(image)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status='FAIL', kernel_sha256=hashlib.sha256(image).hexdigest(),
                  programs={}, checks=[])
    cases = [('desktop-api-probe', ['EVENT', 'DIRECTORY', 'IDENTITY']),
             ('pipe-probe', ['ATOMIC', 'VECTOR', 'LIFETIME', 'SIGNAL', 'ROLLBACK']),
             ('file-probe', ['RENAME', 'ATOMIC_ERRORS']),
             ('signal-probe', ['MASK_PENDING', 'FP_TLS_UCONTEXT', 'FAULT_RECOVERY',
                               'NODEFER_RESETHAND', 'IGNORE_UNSUPPORTED']),
             ('socket-probe', []), ('xau-probe', [])]
    try:
        for name, _ in cases:
            data = (ROOT/'artifacts/sysroot/aarch64-musl'/(name+'.elf')).read_bytes()
            assert image.count(data) == 1, f'{name} exact image missing'
            report['programs'][name] = hashlib.sha256(data).hexdigest()
        with Guest(elf, output/'session', rng=True) as guest:
            guest.until(b'cyxia:/> ')
            for pid, (name, stages) in enumerate(cases, 1):
                prefix = name.upper().replace('-', '_')
                start = len(guest.text)
                guest.command('posix exec '+name)
                wait(guest, start, f'EL0 pid={pid} Exited code=0'.encode(), 20)
                data = bytes(guest.text[start:])
                assert f'{prefix} PASS'.encode() in data and b' FAIL ' not in data, data
                for stage in stages: assert f'{prefix} {stage} PASS'.encode() in data, data
                row = parse_processes(guest.command('posix list'))[pid]
                assert row['heap_pages'] == 0 and row['image_pages'] == 0 and row['free_pages'] == 64, row
                assert row['heap_free'] == boot_profile(image)['heap_pages'] and row['image_free'] == 4096 and row['ai_selections'] > 0, row
                report['checks'].append(dict(program=name, stages=stages, process=row))
            (output/'qmp.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in guest.qmp.transcript))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report['kernel_sha256']
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    finally:
        (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/desktop-abi')
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
