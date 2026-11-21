#!/usr/bin/env python3
"""Real pointer actions plus an independent read-only compositor-state observer.

Optional workspace-list testing uses an explicitly customized user panel; the
original default identities/assets must remain installed and unchanged.
"""
import argparse
from pathlib import Path
import re
import sys
import time

import os_cosmic_startup_probe as startup
import os_cosmic_bg_probe as background
import os_cosmic_time_probe as clock
import os_x86
import os_cosmic_pointer_probe as pointer_probe

pc = os_x86.pc


def compare_shared_resources(baseline, current):
    usage = {'objects', 'pages', 'mappings', 'description_refs', 'mapping_refs',
             'grant_reserved', 'grant_used'}
    capacity = {'metadata_capacity', 'page_capacity'}
    fields = usage | capacity | {'free_pages'}
    same_fields = set(baseline) == set(current) == fields
    valid = same_fields and all(type(row[key]) is int and row[key] >= 0
                                for row in (baseline, current) for key in fields)
    deltas = {key: current[key] - baseline[key] for key in sorted(fields)} if valid else {}
    return dict(rule='each_usage_nonincreasing_free_pages_nondecreasing_capacity_unchanged',
        same_fields=same_fields, valid_counters=valid, baseline_equal=valid and baseline == current,
        deltas=deltas, nonincreasing=bool(valid
            and all(deltas[key] <= 0 for key in usage)
            and all(deltas[key] == 0 for key in capacity) and deltas['free_pages'] >= 0))


def popup_recovered(recovery):
    return (recovery.get('matched') is True and recovery.get('popup_hidden') is True
            and recovery.get('resource_comparison', {}).get('nonincreasing') is True)


def cursor_matches(data, position, mask):
    x, y = position
    white, black = mask
    if not white or not black: return False
    def pixel(dx, dy):
        if not (0 <= x + dx < pointer_probe.WIDTH and 0 <= y + dy < pointer_probe.HEIGHT): return None
        at = 3 * ((y + dy) * pointer_probe.WIDTH + x + dx)
        return data[at:at + 3]
    return (all((value := pixel(dx, dy)) is not None and min(value) >= 250 for dx, dy in white)
            and all((value := pixel(dx, dy)) is not None and max(value) <= 5 for dx, dy in black))


def interaction(console, qmp, output, **options):
    result = dict(status='FAIL', full_os_verified=False, cosmic_session_verified=False)
    try:
        return _interaction(console, qmp, output, _result=result, **options)
    except Exception as error:
        result.update(status='FAIL', error=str(error))
        raise
    finally:
        pc.write_json(output / 'workspace-result.json', result)
        pc.write_json(output / 'workspace-qmp.json', qmp.transcript)


def _interaction(console, qmp, output, *, workspace_x=None, workspace_first_x=28, tiling_x=1004, toggle_x=985, toggle_y=64,
                 repeat_tiling=False, notifications_applet=False, _result):
    result = _result
    result.update(status='FAIL', full_os_verified=False, cosmic_session_verified=False,
                  scope='original_applet_pointer_actions_and_independent_compositor_state')
    result['hardware_memory'] = qmp.execute('query-memory-size-summary')
    result['hardware_cpus'] = len(qmp.execute('query-cpus-fast'))
    pc.require(result['hardware_memory']['base-memory'] == 1024**3 and result['hardware_cpus'] == 4,
               'Applet regression requires the actual one-GiB four-core guest')
    result['input_coordinates'] = dict(workspace_x=workspace_x, workspace_first_x=workspace_first_x,
                                      tiling_x=tiling_x, toggle_x=toggle_x, toggle_y=toggle_y)
    def pump(seconds):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            console.pump(); time.sleep(.01)
    def capture(name):
        path = output / (name + '.ppm')
        qmp.execute('screendump', {'filename': str(path.resolve())})
        return dict(path=path.name, sha256=pc.sha(path))
    pointer = [0, 0]
    cursor_mask = None
    result['pointer_actions'] = []
    qmp.execute('input-send-event', {'events': [
        {'type': 'rel', 'data': {'axis': 'x', 'value': -4096}},
        {'type': 'rel', 'data': {'axis': 'y', 'value': -4096}}]})
    pump(.5)
    def move_pointer(x, y):
        nonlocal cursor_mask
        # Keep popup pointer focus: homing through the panel's outside region
        # between every action can dismiss its popup before the actual click.
        started = time.monotonic()
        events = [dict(type='rel', data=dict(axis=axis, value=value))
                  for axis, value in [('x', x - pointer[0]), ('y', y - pointer[1])] if value]
        if events: qmp.execute('input-send-event', {'events': events})
        pointer[:] = [x, y]
        path = output / ('pointer-action-' + str(len(result['pointer_actions'])) + '.ppm')
        while True:
            pump(.2)
            qmp.execute('screendump', {'filename': str(path.resolve())})
            data = pointer_probe.pixels(path)
            ink = pointer_probe.cursor_ink(data, (x, y))
            if cursor_mask is None:
                if ink >= pointer_probe.COMPLETE_CURSOR_PIXELS:
                    white, black = [], []
                    for dy in range(32):
                        for dx in range(24):
                            at = 3 * ((y + dy) * pointer_probe.WIDTH + x + dx)
                            pixel = data[at:at + 3]
                            if min(pixel) == 255: white.append((dx, dy))
                            if max(pixel) == 0: black.append((dx, dy))
                    pc.require(white and black, 'Missing opaque native cursor shape')
                    cursor_mask = white, black
                    result['cursor_reference'] = dict(target=[x, y], complete_cursor_pixels=ink,
                        opaque_white=white, opaque_black=black, sha256=pc.sha(path))
                    break
            elif cursor_matches(data, (x, y), cursor_mask): break
            pc.require(time.monotonic() - started < 15, 'Complete cursor did not reach click target')
        result['pointer_actions'].append(dict(target=[x, y], elapsed_seconds=round(time.monotonic() - started, 3),
            cursor_pixels=ink, opaque_cursor_matched=cursor_mask is not None,
            scanout=dict(path=path.name, sha256=pc.sha(path))))
    def click(x, y):
        move_pointer(x, y)
        for down in (True, False):
            qmp.execute('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': down}}]})
            pump(.15)
    def open_tiling(label):
        started = time.monotonic()
        move_pointer(tiling_x, 18); pump(.5)
        pressed = time.monotonic()
        path = output / (label + '.ppm')
        matched = False
        qmp.execute('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
        try:
            while time.monotonic() - started < 15:
                pump(.25)
                qmp.execute('screendump', {'filename': str(path.resolve())})
                raw = path.read_bytes()
                header = clock.ink(raw, (680, 45, 1008, 90))
                footer = clock.ink(raw, (680, 370, 1008, 420))
                if header >= 200 and footer >= 400:
                    matched = True; break
        finally:
            qmp.execute('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': False}}]})
            held = round(time.monotonic() - pressed, 3)
            pump(.15)
        elapsed = round(time.monotonic() - started, 3)
        result[label] = dict(matched=matched, elapsed_seconds=elapsed, pressed_seconds=held,
            deadline_seconds=15, within_deadline=matched and elapsed <= 15,
            gesture='press_until_original_popup_present_then_release',
            scanout=dict(path=path.name, sha256=pc.sha(path)))
        pc.write_json(output / 'workspace-partial-result.json', result)
        pc.require(matched, 'Original tiling popup did not appear within opening budget')
    def state():
        at = console.program('posix exec workspace-state-probe', b'WORKSPACE_STATE PASS')
        rows = re.findall(rb'WORKSPACE_STATE workspace name_hex=([0-9a-f]*) active=(\d) tiling=(\d)', console.raw[at:])
        active = [dict(name_hex=name.decode(), tiling=int(tiling)) for name, active, tiling in rows if active == b'1']
        pc.require(len(active) == 1, 'Missing independent active workspace state')
        return dict(active=active[0], workspaces=len(rows), serial_offset=at)
    def transition(label, action, expected):
        started = time.monotonic(); action()
        input_scanout = capture(label + '-input')
        matched = False; snapshots = []
        while time.monotonic() - started < 60:
            snapshot = state(); snapshots.append(snapshot)
            if expected(snapshot):
                matched = True; break
            pump(.5)
        elapsed = round(time.monotonic() - started, 3)
        result[label] = dict(matched=matched, elapsed_seconds=elapsed, deadline_seconds=15,
                             within_deadline=matched and elapsed <= 15, observations=snapshots,
                             input_scanout=input_scanout,
                             scanout=capture(label))
        return matched
    start = len(console.raw)
    result['initial_scanout'] = capture('workspace-initial')
    at = console.command('posix list')
    rows = re.findall(rb'EL0 UserStatus \{ pid: (\d+), parent_pid: (\d+),[^\r\n]*?state: (?:Running|Waiting), code: 0,', console.raw[at:])
    active = {int(pid) for pid, _ in rows}
    children = {int(pid) for pid, parent in rows if parent == b'6'}
    result['panel_children'] = sorted(children)
    # Establish the full 140-pixel cursor on empty background. On controls,
    # antialiased edge colors vary with their background, so require every
    # opaque white/black reference pixel instead of reusing an empty-scene sum.
    move_pointer(500, 400)
    result['shared_before'] = clock.shared_state(console, compact=True)
    expected_children = 2 + int(workspace_x is not None) + int(notifications_applet)
    pc.require({1, 2, 3, 4, 5, 6} <= active and len(children) == expected_children,
               'Not the original core plus expected real applet processes: children=' + repr(sorted(children)))
    before = state(); result['before'] = before
    open_tiling('tiling_open')
    result['popup_scanout'] = capture('tiling-popup')
    original = before['active']
    if transition('tiling_changed', lambda: click(toggle_x, toggle_y),
                  lambda s: s['active'] == {**original, 'tiling': 1 - original['tiling']}):
        transition('tiling_restored', lambda: click(toggle_x, toggle_y), lambda s: s['active'] == original)
    def close_and_recover(label, baseline):
        started = time.monotonic()
        move_pointer(tiling_x, 18); pump(.5)
        pressed = time.monotonic()
        hidden = False
        qmp.execute('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
        try:
            while time.monotonic() - started < 60:
                pump(.25); scanout = capture(label)
                raw = (output / scanout['path']).read_bytes()
                hidden = clock.ink(raw, (680, 45, 1008, 90)) < 100 and clock.ink(raw, (680, 370, 1008, 420)) < 100
                if hidden: break
        finally:
            qmp.execute('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': False}}]})
            held = round(time.monotonic() - pressed, 3); pump(.15)
        recovery = []
        while True:
            snapshot = clock.shared_state(console, compact=True); recovery.append(snapshot)
            scanout = capture(label)
            raw = (output / scanout['path']).read_bytes()
            hidden = clock.ink(raw, (680, 45, 1008, 90)) < 100 and clock.ink(raw, (680, 370, 1008, 420)) < 100
            comparison = compare_shared_resources(baseline, snapshot)
            if (hidden and comparison['nonincreasing']) or time.monotonic() - started >= 60: break
            pump(.5)
        elapsed = round(time.monotonic() - started, 3)
        matched = hidden and comparison['nonincreasing']
        return snapshot, dict(matched=matched, elapsed_seconds=elapsed, deadline_seconds=15,
            observation_limit_seconds=60, pressed_seconds=held,
            within_deadline=matched and elapsed <= 15, popup_hidden=hidden,
            resource_comparison=comparison,
            gesture='press_parent_icon_until_hidden_then_release', observations=recovery, scanout=scanout)
    result['shared_after_tiling'], result['tiling_recovery'] = close_and_recover('tiling-closed', result['shared_before'])
    result['tiling_shared_recovered'] = popup_recovered(result['tiling_recovery'])
    if repeat_tiling:
        # Diagnose cold growth separately. Keep the original cold recovery
        # verdict even if a second cycle proves a stable warm allocation.
        warm = result['shared_after_tiling']
        pc.require(result['tiling_recovery']['popup_hidden'], 'First popup still visible; repeated cycle cannot be trusted')
        open_tiling('repeat_tiling_open')
        if transition('repeat_tiling_changed', lambda: click(toggle_x, toggle_y),
                      lambda s: s['active'] == {**original, 'tiling': 1 - original['tiling']}):
            transition('repeat_tiling_restored', lambda: click(toggle_x, toggle_y), lambda s: s['active'] == original)
        after, recovery = close_and_recover('repeat-tiling-closed', warm)
        result['repeat_tiling'] = dict(before=warm, after=after, recovery=recovery,
            shared_resources_stable=warm == after,
            shared_resources_nonincreasing=recovery['resource_comparison']['nonincreasing'])
    if workspace_x is not None:
        # The original compositor has one empty dynamic workspace. Occupy it
        # with a separate real xdg client; the observer never creates/activates
        # workspaces and only the genuine applet drives the switches below.
        at = console.command('posix exec workspace-window-probe')
        pid = console.until(rb'ELF pid=(\d+) started;', at).group(1)
        console.until(rb'WORKSPACE_WINDOW READY', at)
        result['workspace_window_pid'] = int(pid)
        end = time.monotonic() + 15
        while time.monotonic() < end:
            observed = state()
            if observed['workspaces'] >= 2: break
            pump(.5)
        else: raise RuntimeError('Real xdg window did not create a second dynamic workspace')
        result['before_workspace_input'] = observed
        pump(2); result['workspace_list_scanout'] = capture('workspace-list')
        if transition('workspace_changed', lambda: click(workspace_x, 18),
                      lambda s: s['active']['name_hex'] != original['name_hex']):
            transition('workspace_restored', lambda: click(workspace_first_x, 18),
                       lambda s: s['active']['name_hex'] == original['name_hex'])
        console.command('posix kill ' + pid.decode(), [rb'killed; pages reclaimed'])
        pump(2)
    result['shared_after'] = clock.shared_state(console, compact=True)
    # Reuse the original calendar's real two-cycle checks and deadlines. Its
    # original single-child default remains unchanged for the historical gate.
    qmp.execute('input-send-event', {'events': [
        {'type': 'rel', 'data': {'axis': 'x', 'value': -4096}},
        {'type': 'rel', 'data': {'axis': 'y', 'value': -4096}}]})
    pump(.3)
    result['calendar'] = clock.interaction(console, qmp, output, expected_panel_children=len(children), compact_objects=True)
    after = console.command('posix list')
    alive = {int(pid) for pid in re.findall(rb'EL0 UserStatus \{ pid: (\d+),[^\r\n]*?state: (?:Running|Waiting), code: 0,', console.raw[after:])}
    result['original_processes_alive'] = ({1, 2, 3, 4, 5, 6} | children) <= alive
    result['abnormal_exits'] = [dict(pid=int(p), code=int(c)) for p, c in re.findall(
        rb'USER pid=(\d+) (?:Exited|Fault) code=(\d+)\b', console.raw[start:]) if int(c)]
    checks = ['tiling_changed', 'tiling_restored']
    if repeat_tiling: checks += ['repeat_tiling_changed', 'repeat_tiling_restored']
    if workspace_x is not None: checks += ['workspace_changed', 'workspace_restored']
    passed = all(result.get(key, {}).get('within_deadline') for key in checks)
    result['shared_recovered'] = result['shared_before'] == result['shared_after']
    # Always end all users and check real grants/backings/descriptions reach zero.
    for _ in range(3):
        at = console.command('posix list')
        pids = sorted({int(pid) for pid in re.findall(
            rb'EL0 UserStatus \{ pid: (\d+),[^\r\n]*?state: (?:Running|Waiting),', console.raw[at:])}, reverse=True)
        if not pids: break
        for pid in pids: console.command('posix kill ' + str(pid), [rb'killed; pages reclaimed'])
    else: raise RuntimeError('Desktop process teardown exceeded bounded retries')
    shared = clock.shared_state(console, compact=True)
    pc.require(shared['metadata_capacity'] == (48 if notifications_applet else 32),
               'Shared object capacity differs from the active applet profile')
    pc.require(all(shared[k] == 0 for k in ('objects', 'pages', 'mappings', 'description_refs',
               'mapping_refs', 'grant_reserved', 'grant_used')), 'Shared resources retained after teardown')
    at = console.command('ai objects'); console.until(rb'AI_OBJECTS_END\r?\n', at)
    raw = console.raw[at:]
    pc.require(re.search(rb'^ANON_POOL [^\r\n]*\bused=0\b', raw, re.MULTILINE)
               and re.search(rb'^OFD_OBJECTS live=0 references=0\b', raw, re.MULTILINE),
               'Anonymous frames or open descriptions retained after teardown')
    domains = {}
    for name, fields in re.findall(rb'^AI_DOMAIN name=(shared_\w+) ([^\r\n]+)', raw, re.MULTILINE):
        pc.require(name.decode() not in domains, 'Duplicate shared admission receipt')
        domains[name.decode()] = {key.decode(): int(value) for key, value in re.findall(rb'(\w+)=(\d+)', fields)}
    expected_models = dict(shared_pages=8194, shared_objects=8205 if notifications_applet else 8203,
                           shared_mappings=8204)
    pc.require(set(domains) == set(expected_models), 'Incomplete shared admission receipts')
    for name, model in expected_models.items():
        row = domains[name]
        pc.require(row['last_model'] == model and row['denied'] == row['failed'] == 0
                   and row['grant_units'] == row['release_units'], 'Shared admission or release mismatch: ' + name)
    result['shared_admission'] = domains
    unix_rows = re.findall(rb'^UNIX_POOL ([^\r\n]+)', raw, re.MULTILINE)
    pc.require(len(unix_rows) == 1, 'Missing Unix pool teardown receipt')
    unix = {key.decode(): int(value) for key, value in re.findall(rb'(\w+)=(\d+)', unix_rows[0])}
    pc.require(unix['endpoints'] == unix['free_endpoints'] == 128
               and unix['connections'] == unix['free_connections'] == 64, 'Unix endpoints or connections retained')
    result['complete_teardown'] = dict(shared=shared, anonymous_used=0, open_descriptions=0, unix=unix)
    controls = (all(result.get(key, {}).get('matched') for key in checks)
        and result['original_processes_alive']
        and result['calendar']['status'] == 'PASS' and not result['abnormal_exits'])
    result['controls_status'] = 'PASS' if controls else 'FAIL'
    functional = (controls and result['tiling_shared_recovered']
        and (not repeat_tiling or popup_recovered(result['repeat_tiling']['recovery'])))
    result['functional_status'] = 'PASS' if functional else 'FAIL'
    result['all_actions_within_15_seconds'] = (passed and result['tiling_open']['within_deadline']
        and result['tiling_recovery']['within_deadline'] and result['calendar']['all_interactions_within_15_seconds']
        and (not repeat_tiling or result['repeat_tiling_open']['within_deadline']
             and result['repeat_tiling']['recovery']['within_deadline']))
    result['status'] = 'PASS' if functional and result['all_actions_within_15_seconds'] else 'FAIL'
    pc.write_json(output / 'workspace-qmp.json', qmp.transcript)
    pc.write_json(output / 'workspace-result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--workspace-x', type=int)
    parser.add_argument('--workspace-first-x', type=int, default=28)
    parser.add_argument('--tiling-x', type=int, default=1004)
    parser.add_argument('--toggle-x', type=int, default=985)
    parser.add_argument('--toggle-y', type=int, default=64)
    parser.add_argument('--repeat-tiling', action='store_true')
    args, remaining = parser.parse_known_args()
    sys.argv = [sys.argv[0], *remaining]
    build = Path(remaining[remaining.index('--build') + 1])
    manifest = os_x86.validate_build(build)
    output = Path(remaining[remaining.index('--output') + 1])
    producers = os_x86.producer_sources(__file__)
    snapshot = {name: (pc.ROOT / name).read_bytes() for name in producers}
    def check(console, qmp, output):
        if os_x86.WALLPAPER_FEATURES.intersection(manifest['features']):
            # Match the flat compositor background used by the cursor reference.
            background.solid_background(console, qmp, output, rgb=(39, 41, 42))
        return interaction(
            console, qmp, output,
            notifications_applet=bool(os_x86.NOTIFICATIONS_OBJECT_FEATURES.intersection(manifest['features'])),
            **vars(args))
    try:
        return startup.main(after_observation=check)
    finally:
        if output.is_dir():
            pc.require(os_x86.producer_sources(__file__) == producers, 'Interaction producer changed during capture')
            for name, raw in snapshot.items():
                path = output / 'producer-sources' / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw); pc.require(pc.sha(path) == producers[name], 'Capture producer snapshot changed')
            pc.write_json(output / 'interaction-producers.json', dict(status='CAPTURE_PRODUCERS_PRESERVED',
                producers=producers, full_os_verified=False, cosmic_session_verified=False))


if __name__ == '__main__':
    raise SystemExit(main())
