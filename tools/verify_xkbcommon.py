"""Exercise genuine libxkbcommon keymap/state parsing in a CyxiaOS ARM guest.

The fixture is embedded; this does not test full desktop layout data, a physical
keyboard driver, or delivery through a COSMIC compositor.
"""
import argparse
import hashlib
import json
from pathlib import Path

from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import wait


EXPECTED = [
    b'XKBCOMMON_PROBE KEYMAP parsed=1 base=a',
    b'XKBCOMMON_PROBE SHIFT down=A release=a',
    b'XKBCOMMON_PROBE CAPS lock=A shift_with_lock=a unlock=a',
    b'XKBCOMMON_PROBE CTRL utf8=01 release=a',
    b'XKBCOMMON_PROBE SERIALIZE reparse=1 invalid_rejected=1',
    b'XKBCOMMON_PROBE PASS upstream=1.13.2 checks=24 layouts=embedded full_desktop=false',
]


def verify(elf, output, runs=3):
    output.mkdir(parents=True, exist_ok=True)
    report = {'status': 'FAIL', 'scope': 'upstream core keymap/state; embedded layout fixture', 'runs': []}
    try:
        image = elf.read_bytes()
        inspect_elf(image)
        report['kernel_sha256'] = hashlib.sha256(image).hexdigest()
        profile = report['profile'] = boot_profile(image)
        program = (ROOT / 'artifacts/sysroot/aarch64-musl/xkbcommon-probe.elf').read_bytes()
        assert image.count(program) == 1, 'Exact xkbcommon probe ELF is not embedded'
        report['probe_sha256'] = hashlib.sha256(program).hexdigest()
        with Guest(elf, output / 'session', rng=True) as guest:
            guest.until(b'cyxia:/> ')
            for pid in range(1, runs + 1):
                start = len(guest.text)
                guest.command('posix exec xkbcommon-probe')
                wait(guest, start, f'EL0 pid={pid} Exited code='.encode(), 30)
                data = bytes(guest.text[start:])
                assert f'EL0 pid={pid} Exited code=0'.encode() in data, data
                actual = [line for line in data.splitlines() if line.startswith(b'XKBCOMMON_PROBE')]
                assert actual == EXPECTED, data
                process = parse_processes(guest.command('posix list'))[pid]
                expected = dict(state='Exited', code=0, free_pages=64,
                                heap_pages=0, heap_free=profile['heap_pages'],
                                image_pages=0, image_free=4096, thread_count=0,
                                thread_peak=1, thread_admissions=0, thread_denials=0,
                                rank_model=12289)
                assert all(process.get(key) == value for key, value in expected.items()), process
                assert process['ai_selections'] > 0, process
                report['runs'].append({'pid': pid, 'markers': [line.decode() for line in actual],
                                       'process': process})
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report['kernel_sha256']
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    finally:
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/xkbcommon')
    parser.add_argument('--runs', type=int, choices=range(1, 11), default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), args.runs)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
