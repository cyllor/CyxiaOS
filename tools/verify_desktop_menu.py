"""Physical LXPanel menu launch, PCManFM rename and durable GUI save/reboot."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from check_elf import inspect_elf, boot_profile
from desktop_session import embedded_programs, wait_window, windows
from doctor import ROOT
from shell import Guest
from storage import create_disk
from verify_filemanager import chord, click, type_text
from verify_panel import launch, assert_reclaimed
from verify_ported import parse_processes
from verify_x11 import event, move, pump, wait


def wait_panel_menu(guest, name, selected=None, timeout=15):
    """Observe the pinned GTK popup/selection before sending the next key.

    A mapped LXPanel window is not evidence that its popup has finished mapping
    and acquiring the keyboard grab. The pinned 1024x768 profile has three menu
    rows; sample their margins, away from text, through the actual guest scanout.
    A white popup and its blue selected row are different from the desktop/panel.
    """
    path = guest.output / (name + '.ppm')
    white, blue = b'\xff\xff\xff', bytes((53, 132, 228))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        guest.qmp.execute('screendump', {'filename': str(path)})
        with path.open('rb') as stream:
            assert stream.readline() == b'P6\n'
            assert stream.readline() == b'1024 768\n'
            assert stream.readline() == b'255\n'
            pixels = stream.read()
        assert len(pixels) == 1024 * 768 * 3
        rows = [[pixels[(y * 1024 + x) * 3:(y * 1024 + x) * 3 + 3]
                 for x in (4, 115)] for y in (668, 694, 719)]
        visible = all(color in (white, blue) for row in rows for color in row)
        selection = selected is None or all(
            row == [blue, blue] if index == selected else row == [white, white]
            for index, row in enumerate(rows))
        if visible and selection:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        pump(guest, .1)
    raise TimeoutError(f'LXPanel popup did not become ready: selected={selected}, rows={rows}')


def menu(guest, last=False):
    """Use the real icon-only menu and GTK's first/last-item key navigation."""
    assert any(w['class'].casefold() == 'lxpanel' for w in windows(guest) or []), 'LXPanel exited before menu interaction'
    label = 'save' if last else 'files'
    click(guest, 16, 752)
    popup = wait_panel_menu(guest, 'panel-' + label + '-popup')
    chord(guest, 'end' if last else 'home')
    selected = wait_panel_menu(guest, 'panel-' + label + '-selected', 2 if last else 0)
    chord(guest, 'ret')
    return {'popup_sha256': popup, 'selection_sha256': selected}


def file_window(guest, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clients = windows(guest)
        matches = [w for w in clients or [] if w['class'].casefold() == 'pcmanfm' and w['width'] < 1024]
        if matches:
            return matches[0]
        pump(guest, .25)
    raise TimeoutError('Menu did not open a real PCManFM directory window')


def no_file_window(guest, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clients = windows(guest)
        if clients is not None and not any(
                w['class'].casefold() == 'pcmanfm' and w['width'] < 1024 for w in clients):
            return clients
        pump(guest, .25)
    raise TimeoutError('Existing PCManFM directory window did not close')


def titled_file_window(guest, title, window_id=None, timeout=20):
    """Wait for the guest's completed navigation/dialog, not elapsed host time.

    PCManFM maps its directory window before asynchronous navigation finishes.
    Typing the next operation too early can target the location entry instead
    of the file view. Only a complete X11 observation of the requested title
    allows the next input sequence; no action is retried or synthesized.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clients = windows(guest)
        matches = [w for w in clients or [] if w['class'].casefold() == 'pcmanfm'
                   and w['title'] == title and (window_id is None or w['id'] == window_id)]
        if len(matches) == 1:
            return matches[0]
        pump(guest, .25)
    raise TimeoutError(f'PCManFM did not show {title!r}, window={window_id}')


def location_entry_state(path, view):
    """Inspect the pinned GTK toolbar, excluding its text and pointer cursor.

    A mapped directory window can precede GTK's actual entry focus. Its blue
    focus border and selected text are separate observations: neither a title
    nor elapsed host time establishes where the next accelerator will land.
    """
    with path.open('rb') as stream:
        assert stream.readline() == b'P6\n'
        assert stream.readline() == b'1024 768\n'
        assert stream.readline() == b'255\n'
        pixels = stream.read()
    assert len(pixels) == 1024 * 768 * 3
    assert view['width'] == 640 and view['height'] == 480, view
    x, y = view['x'], view['y']
    assert 0 <= x and x + 600 < 1024 and 0 <= y and y + 60 < 768, view
    blue = bytes((53, 132, 228))

    def pixel(px, py):
        return pixels[(py * 1024 + px) * 3:(py * 1024 + px) * 3 + 3]

    focused = all(pixel(x + dx, y + 29) == blue for dx in (270, 350, 500))
    selected = sum(pixel(px, py) == blue for py in range(y + 35, y + 55)
                   for px in range(x + 264, x + 590))
    return dict(focused=focused, selected_pixels=selected,
                screenshot_sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def wait_location_entry(guest, view, name, selected=None, timeout=15):
    path = guest.output / ('location-' + name + '.ppm')
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        guest.qmp.execute('screendump', {'filename': str(path)})
        state = location_entry_state(path, view)
        selection_ready = selected is None or (
            state['selected_pixels'] >= 8 if selected else state['selected_pixels'] == 0)
        if state['focused'] and selection_ready:
            return state
        pump(guest, .1)
    raise TimeoutError(f'PCManFM location entry not ready: selected={selected}, state={state}')


def navigate_menu_directory(guest, view):
    # Ctrl+L focuses the entry and selects its existing path. PCManFM also has
    # a global Ctrl+A folder-view action; sending it here can select all files
    # and take focus away again. Observe the selection produced by Ctrl+L.
    chord(guest, 'ctrl', 'l')
    selected = wait_location_entry(guest, view, 'selected', True)
    type_text(guest, '/menu-check')
    # Right accepts GTK's inline completion and dismisses its popup without
    # replacing the typed prefix (Escape can reject it). Observe the resulting
    # focused, unselected entry before issuing Return exactly once.
    chord(guest, 'right')
    ready = wait_location_entry(guest, view, 'ready', False)
    chord(guest, 'ret')
    return dict(selected=selected, ready=ready)


def chooser_window(guest, timeout=20):
    # The shipped libfm app-chooser.ui names this real GtkDialog. The warning
    # occurs inside its constructor, before gtk_dialog_run maps the window.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clients = windows(guest)
        matches = [w for w in clients or [] if w['class'].casefold() == 'pcmanfm'
                   and w['title'] == 'Choose Application']
        if len(matches) == 1:
            return matches[0]
        pump(guest, .25)
    raise TimeoutError('Application chooser warning was not followed by its real mapped dialog')


def gone_window(guest, window_id, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        clients = windows(guest)
        if clients is not None and not any(w['id'] == window_id for w in clients):
            return clients
        pump(guest, .25)
    raise TimeoutError(f'Cancelled chooser {window_id} did not unmap')


def spawned_child(data, parent):
    records = re.findall(
        rb'(?m)^SPAWN_CHILD pid,parent AI_DIRECT model=8193 image_model=8195\r?\n'
        rb'([0-9a-f]{16})\r?\n([0-9a-f]{16})\r?$', data)
    assert len(records) == 1, ('Expected one complete child admission', data[-2000:])
    child, actual_parent = (int(value, 16) for value in records[0])
    assert actual_parent == parent and child > parent > 0, (child, actual_parent, parent)
    return child


def storage_status(guest):
    data = guest.command('storage status')
    match = re.search(
        rb'STORAGE_STATUS state=(\w+) generation=(\d+) free_pages=(\d+) '
        rb'ai_grants=(\d+) io_plan_decisions=(\d+) io_submitted=(\d+) deferred_polls=(\d+) '
        rb'reads=(\d+) writes=(\d+) flushes=(\d+) budget_unit=new_operations_per_8ms', data)
    assert match, data
    names = ('generation', 'free_pages', 'ai_grants', 'io_plan_decisions',
             'io_submitted', 'deferred_polls', 'reads', 'writes', 'flushes')
    return dict(state=match[1].decode(), **dict(zip(names, map(int, match.groups()[1:]))))


def durable_save(data, before, after):
    storage = re.search(rb'(?m)^STORAGE_DURABLE generation=1 slot=[01] bytes=\d+ '
                        rb'flushes=(\d+) MECHANISM\r?$', data)
    dialog = re.search(rb'(?m)^CYXIA_SAVE DURABLE generation=1\r?$', data)
    assert storage and dialog and storage.start() < dialog.start(), data[-3000:]
    assert re.search(rb'STORAGE_CHECKPOINT_BEGIN .*io_model=20481 '
                     rb'trigger=OPERATOR memory_source=AI_DIRECT '
                     rb'budget_unit=new_operations_per_8ms', data), data[-3000:]
    assert re.search(rb'STORAGE_BUDGET model=20481 plan=\d+ runnable=[0-8] '
                     rb'operations=[14] window_ms=8 AI_DIRECT', data), data[-3000:]
    assert before['state'] == after['state'] == 'Ready', (before, after)
    assert before['generation'] == 0 and after['generation'] == 1, (before, after)
    assert before['flushes'] == 0 and after['flushes'] == int(storage[1]) == 2, (before, after)
    assert before['free_pages'] == after['free_pages'] == 128, (before, after)
    assert after['ai_grants'] == before['ai_grants'] + 1, (before, after)
    assert after['io_plan_decisions'] > before['io_plan_decisions'], (before, after)
    assert after['io_submitted'] > before['io_submitted'], (before, after)
    assert after['io_submitted'] - before['io_submitted'] == (
        after['writes'] - before['writes'] + after['flushes'] - before['flushes']), (before, after)
    assert after['deferred_polls'] >= before['deferred_polls'], (before, after)


def capture(guest, output, name):
    path = output / (name + '.ppm')
    guest.qmp.execute('screendump', {'filename': str(path)})
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_saved_file(guest):
    # The command echo contains only the path. The content match plus its exact
    # length rejects prefixed/suffixed corruption instead of accepting a substring.
    assert b'menu-checkpoint-value' in guest.command('cat /menu-check/saved.txt')
    data = guest.command('stat /menu-check/saved.txt')
    assert re.search(rb'(?m)^/menu-check/saved\.txt File bytes=21 reads=\d+ cached=(true|false)\r?$', data), data


def verify(elf, output):
    output.mkdir(parents=True, exist_ok=True)
    image = elf.read_bytes()
    inspect_elf(image)
    report = {'status': 'FAIL', 'scope': 'Physical static menu, real file-manager launch/rename, GUI disk save and reboot recovery',
              'kernel_sha256': hashlib.sha256(image).hexdigest(),
              'verifier_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'profile': boot_profile(image), 'checks': []}
    try:
        report['programs'] = embedded_programs(elf, ('Xcyxia', 'openbox', 'pcmanfm', 'lxpanel', 'cyxia-save', 'x11-inspect'))
        disk = create_disk(output / 'cyxia-menu.raw')
        with Guest(elf, output / 'session', graphics=True, rng=True, disk=disk) as guest:
            try:
                boot = guest.until(b'cyxia:/> ', timeout=30)
                assert b'STORAGE_READY VIRTIO_BLOCK FLUSH' in boot and b'STORAGE_EMPTY' in boot, boot
                assert b'error:' not in guest.command('mkdir /menu-check')
                assert b'error:' not in guest.command('write /menu-check/note.txt menu-checkpoint-value')
                launch(guest, 'xorg')
                wait(guest, 0, b'CYXIA_XORG_READY')
                wm_pid = launch(guest, 'openbox')
                wait_window(guest)
                launch(guest, 'pcmanfm-desktop')
                background = wait_window(guest, 'Pcmanfm', 45)
                assert any(w['width'] == 1024 for w in background), background
                panel_pid = launch(guest, 'lxpanel')
                wait_window(guest, 'Lxpanel', 45)
                pump(guest, 1)
                assert not [w for w in windows(guest) if w['class'].casefold() == 'pcmanfm' and w['width'] < 1024]
                start = len(guest.text)
                report['files_menu_evidence'] = menu(guest)
                view = file_window(guest)
                report['files_child_pid'] = spawned_child(bytes(guest.text[start:]), panel_pid)
                report['file_window'] = view
                report['checks'].append('physical LXPanel Files menu created a real AI-admitted catalog child and PCManFM opened a directory window')
                click(guest, view['x'] + view['width']//2, view['y'] + 40)
                report['location_entry_evidence'] = navigate_menu_directory(guest, view)
                view = titled_file_window(guest, 'menu-check', view['id'])
                report['navigated_window'] = view
                report['navigation_screenshot_sha256'] = capture(guest, output, 'directory-menu-check')
                click(guest, view['x'] + view['width'] - 35, view['y'] + view['height']//2)
                type_text(guest, 'note.txt')
                chord(guest, 'esc'); chord(guest, 'f2')
                rename = titled_file_window(guest, 'Rename File')
                assert rename['id'] != view['id'], (rename, view)
                report['rename_dialog'] = rename
                report['rename_screenshot_sha256'] = capture(guest, output, 'rename-dialog')
                chord(guest, 'ctrl', 'a')
                type_text(guest, 'saved.txt')
                chord(guest, 'ret')
                report['rename_closed_snapshot'] = gone_window(guest, rename['id'])
                exact_saved_file(guest)
                assert b'NotFound' in guest.command('stat /menu-check/note.txt')
                report['checks'].append('the launched PCManFM window renamed a real guest file while preserving its bytes')
                start = len(guest.text)
                chord(guest, 'ret')
                wait(guest, start, b'menu-cached is unavailable; application menu cannot be loaded', 20)
                chooser = chooser_window(guest)
                report['chooser_window'] = chooser
                capture(guest, output, 'application-chooser-unavailable')
                click(guest, chooser['x'] + chooser['width']//2, chooser['y'] + 25)
                chord(guest, 'esc')
                after_cancel = gone_window(guest, chooser['id'])
                assert any(w['id'] == view['id'] for w in after_cancel), after_cancel
                report['chooser_closed_snapshot'] = after_cancel
                report['checks'].append('unavailable application-menu service reported a real failure without terminating PCManFM; the chooser was cancelled')
                # Close the directory first: an unchanged old window cannot
                # serve as evidence that the root-menu Files command worked.
                click(guest, view['x'] + view['width']//2, view['y'] + 40)
                chord(guest, 'alt', 'f4')
                report['file_closed_snapshot'] = no_file_window(guest)
                # PCManFM forwards blank-desktop right-click to Openbox's
                # genuine static root menu. Execute its first item too.
                start = len(guest.text)
                move(guest, -10000, -10000)
                move(guest, 950, 100)
                event(guest, [{'type': 'btn', 'data': {'button': 'right', 'down': True}}])
                event(guest, [{'type': 'btn', 'data': {'button': 'right', 'down': False}}])
                pump(guest, .5)
                capture(guest, output, 'desktop-root-menu')
                chord(guest, 'home'); chord(guest, 'ret')
                wait(guest, start, b'SPAWN_CHILD pid,parent AI_DIRECT model=8193 image_model=8195', 15)
                root_view = file_window(guest)
                # XIDs can be reused. The complete window-set absence barrier
                # above plus this new parent-bound spawn and mapped client are
                # the lifecycle evidence; numerical inequality is not required.
                report['root_files_child_pid'] = spawned_child(bytes(guest.text[start:]), wm_pid)
                report['root_file_window'] = root_view
                report['checks'].append('blank-desktop right-click opened the real Openbox root menu and Files executed through its GLib spawn path')
                before_save = storage_status(guest)
                start = len(guest.text)
                report['save_menu_evidence'] = menu(guest, last=True)
                wait(guest, start, b'CYXIA_SAVE DURABLE generation=1', 30)
                # Do not type an inspector command while the asynchronous
                # kernel durable receipt is being written to the same UART.
                # Keep its full-line ordering proof intact before inspection.
                save = wait_window(guest, 'CyxiaSave', 30)[0]
                save_pid = spawned_child(bytes(guest.text[start:]), panel_pid)
                after_save = storage_status(guest)
                durable_save(bytes(guest.text[start:]), before_save, after_save)
                report['save_pid'] = save_pid
                report['save_window'] = save
                report['screenshot_sha256'] = capture(guest, output, 'desktop-saved')
                report['storage_before'] = before_save
                report['storage_status'] = after_save
                report['checks'].append('physical Save Files menu launched the guest X11 save dialog and reported durable only after actual VirtIO flush completion')
                start = len(guest.text)
                click(guest, save['x'] + 430, save['y'] + 140)
                wait(guest, start, f'EL0 pid={save_pid} Exited code=0'.encode())
                guest.command('write /menu-check/unsaved not-checkpointed')
                rows = parse_processes(guest.command('posix list'))
                for pid, row in sorted(rows.items(), reverse=True):
                    if row['state'] in ('Running', 'Waiting'):
                        start = len(guest.text)
                        guest.command(f'posix kill {pid}')
                        wait(guest, start, f'EL0 pid={pid} killed; pages reclaimed'.encode())
                rows = parse_processes(guest.command('posix list'))
                assert_reclaimed(rows, report['profile'])
                report['final_processes'] = rows
                report['window_inspection_retries'] = getattr(guest, 'window_inspection_retries', 0)
            finally:
                if not (output/'desktop-saved.ppm').exists():
                    capture(guest, output, 'desktop-failure')
                (output/'qmp.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in guest.qmp.transcript))
        with Guest(elf, output / 'reboot', disk=disk) as guest:
            boot = guest.until(b'cyxia:/> ', timeout=30)
            assert b'STORAGE_RECOVERED generation=1' in boot, boot
            exact_saved_file(guest)
            assert b'NotFound' in guest.command('stat /menu-check/note.txt')
            assert b'NotFound' in guest.command('stat /menu-check/unsaved')
        report['checks'].append('a fresh VM recovered the GUI-renamed saved file and exact text; post-save changes were absent')
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report['kernel_sha256'], 'kernel changed during gate'
        report['disk_sha256'] = hashlib.sha256(disk.read_bytes()).hexdigest()
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = repr(error)
    (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'artifacts/desktop-menu-verified')
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
