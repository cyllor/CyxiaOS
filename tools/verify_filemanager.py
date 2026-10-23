"""Exercise upstream PCManFM against the guest RAM filesystem via real input."""
import argparse
import hashlib
import json
from pathlib import Path
import time

from check_elf import inspect_elf
from desktop_session import embedded_programs, wait_window, windows
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import button, key, move, pump, wait


def chord(guest, *keys):
    for code in keys: key(guest, code, True)
    for code in reversed(keys): key(guest, code, False)


def type_text(guest, text):
    codes = {'/': 'slash', '.': 'dot', '-': 'minus', ' ': 'spc'}
    for char in text:
        code = codes.get(char, char.lower())
        if char.isupper(): key(guest, 'shift', True)
        chord(guest, code)
        if char.isupper(): key(guest, 'shift', False)


def click(guest, x, y):
    move(guest, -10000, -10000)
    move(guest, x, y)
    pump(guest, .4)
    button(guest, True); button(guest, False)


def navigate(guest, path):
    chord(guest, 'ctrl', 'l')
    chord(guest, 'ctrl', 'a')
    type_text(guest, path)
    chord(guest, 'ret')
    pump(guest, 1)


def capture(guest, output, name):
    guest.qmp.execute('screendump', {'filename': str(output/(name+'.ppm'))})


def verify(elf, output):
    output.mkdir(parents=True, exist_ok=True)
    image = elf.read_bytes()
    inspect_elf(image)
    result = dict(status='FAIL', scope='PCManFM local file operations; not complete D3',
                  kernel_sha256=hashlib.sha256(image).hexdigest(), checks=[])
    try:
        result['programs'] = embedded_programs(elf, ('Xcyxia', 'openbox', 'pcmanfm', 'x11-inspect'))
        with Guest(elf, output/'session', graphics=True, rng=True) as guest:
            try:
                guest.until(b'cyxia:/> ')
                guest.command('mkdir /work')
                guest.command('write /work/note.txt cyxia-gui-preserved-content')
                guest.command('posix exec xorg')
                wait(guest, 0, b'CYXIA_XORG_READY')
                guest.command('posix exec openbox')
                wait_window(guest)
                guest.command('posix exec pcmanfm')
                view = wait_window(guest, 'Pcmanfm')[0]
                result['initial_window'] = view
                capture(guest, output, '01-mapped')
                result['checks'].append('real upstream PCManFM mapped a managed GTK window')
                click(guest, view['x']+view['width']//2, view['y']+40)
                navigate(guest, '/work')
                capture(guest, output, '02-work')
                # New-folder accelerator belongs to libfm's actual folder view.
                chord(guest, 'ctrl', 'shift', 'n')
                pump(guest, .7)
                chord(guest, 'ctrl', 'a')
                type_text(guest, 'gui-folder')
                chord(guest, 'ret')
                pump(guest, 1)
                folder = guest.command('stat /work/gui-folder')
                assert b'Directory' in folder, folder
                result['checks'].append('keyboard created a real directory through libfm/GIO and guest VFS')
                # Select the existing file in an otherwise empty folder. The
                # filename search uses PCManFM's ordinary type-ahead selection.
                click(guest, view['x']+view['width']-35, view['y']+view['height']//2)
                type_text(guest, 'note.txt')
                chord(guest, 'esc')
                chord(guest, 'f2')
                pump(guest, .7)
                capture(guest, output, '03-rename-dialog')
                chord(guest, 'ctrl', 'a')
                type_text(guest, 'renamed.txt')
                chord(guest, 'ret')
                pump(guest, 1)
                renamed = guest.command('cat /work/renamed.txt')
                assert b'cyxia-gui-preserved-content' in renamed, renamed
                original = guest.command('stat /work/note.txt')
                assert b'NotFound' in original, original
                result['checks'].append('GUI rename retained exact original bytes and removed the old path')
                capture(guest, output, '04-renamed')
                chord(guest, 'alt', 'f4')
                pump(guest, 1)
                assert not [w for w in (windows(guest) or []) if w['class'].casefold() == 'pcmanfm']
                rows = parse_processes(guest.command('posix list'))
                live = [pid for pid, row in rows.items() if row['state'] in ('Running', 'Waiting')]
                for pid in reversed(live):
                    marker = len(guest.text)
                    guest.command(f'posix kill {pid}')
                    wait(guest, marker, f'EL0 pid={pid} killed; pages reclaimed'.encode())
                result['final_processes'] = parse_processes(guest.command('posix list'))
                assert all(r['free_pages'] == 64 and r['heap_pages'] == 0 and r['image_pages'] == 0
                           for r in result['final_processes'].values())
                result['checks'].append('window closed; all process image/heap grants reclaimed')
            finally:
                capture(guest, output, 'final')
                (output/'qmp.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in guest.qmp.transcript))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == result['kernel_sha256']
        result['status'] = 'PASS'
    except Exception as error:
        result['error'] = repr(error)
    (output/'summary.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/filemanager-verified')
    args = parser.parse_args()
    report = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)
