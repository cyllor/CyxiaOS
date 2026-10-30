#!/usr/bin/env python3
"""Independently replay the bounded A02 scheduler-capture wire contract.

This decoder alone cannot attest native execution. run_v13_a02.py captures the
instrumented unified runtime and its build/launch provenance. Successful raw
parsing therefore remains NOT_RUN without that independent execution chain.
Host fixtures, serial PASS markers, and producer verdicts never close A02.

Wire versions 1/2 use unsigned little-endian u64 words; unused words must be zero.
Version 2 matches actual native trap boundaries: registration can precede each
task generation's first dispatch, and deferred binding events name that task's
last return and original CPU, even if another task is running there while the
broker handles the trapped caller. Same-generation ownership events describe DRAIN/suspect
changes; they must change the masks. Existing in-flight work may finish on a
draining/suspect original owner, but no new dispatch may enter there.
TRACE = 64-word header followed by count * 16-word records (no ring wrapping):
  0 magic=0x4359584130325452, 1 version=1, 2 record_words=16, 3 count,
  4 dropped=0, 5 nonzero even seal_sequence, 6 boot_epoch, 7..8 run_nonce,
  9 start_tick, 10 end_tick, 11 ticks_per_second, 12 initial_core_generation,
  13..18 initial C/B/T/Q/draining/suspect masks, 19 cpu_count=4,
  20..23 initial EL0-entry counters=0,
  24..27 image SHA256, 28..31 frozen input SHA256, 32..35 source-manifest SHA256
  (hashes are 32 bytes in ordinary digest order, not four encoded hex integers).
Each event contains seq,tick,kind,cpu,task_id,task_generation,core_generation,
then nine payload words. Sequence begins at 1 and cannot skip or wrap. CPU=4
means a global event. Task identities and roles come from protected kernel data.
  1 REGISTER: cpu=4, payload role(1 business/2 control), initial affinity.
              Register the fixed task roster before the first EL0 entry.
  2 OWNER: cpu=4, task fields=0, next core_generation, payload C/B/T/Q/drain/suspect.
  3 ENTER: real EL0 entry; payload per-CPU slice number beginning at 1.
  4 EXIT: real EL0 return; same task and slice, strictly later tick.
  5 BIND_REQUEST: currently executing caller; payload request number, requested mask.
  6 BIND_RESULT: same caller; payload request number, 0 success/1 E_AUTH.
              Request numbers are global, contiguous, and begin at 1. A denied
              request retains affinity. Admission uses the current ownership.
COUNTERS is a separate fixed 64-word protected snapshot, not derived from TRACE:
  0 magic=0x4359584130324354, 1 version=1, 2 seal_sequence, 3 boot_epoch,
  4..5 run_nonce, 6 end_tick, 7 event_count, 8 dropped=0, 9 final_core_generation,
  10..15 final C/B/T/Q/draining/suspect,
  16..19 per-CPU EL0 entries, 20..23 per-CPU exits,
  24 bind requests, 25 denied binds, 26 accepted binds, 27 registered tasks,
  28..31 image SHA256, 32..35 input SHA256, 36..39 source-manifest SHA256,
  40..43 per-CPU sum of EXIT.tick - ENTER.tick.

Native integration: reserve an EL1-only bounded trace and separate accounting
page before the first user dispatch. Instrument every actual EL0 enter/return
site, the ownership publication linearization point, and the protected affinity
syscall's request/admission points. Snapshot the kernel's immutable task roles.
Use a total-order sequence at the linearization points (not UART arrival order),
and record overflow instead of dropping or overwriting events. Counter updates
must live at the underlying scheduler/admission sites, not be computed by the
trace writer. Run an ordinary EL0 task that requests a currently controlled
CPU, alongside business and control progress. Quiesce all tasks, finish pending
admissions, seal both pages, stop the VM, and save both with QMP pmemsave.

The runner must additionally preserve the launch/build/DTB/toolchain and input
artifacts required by sections 1.2/14.4, establish hash and capture provenance,
and demonstrate that all dispatch paths are instrumented. Hash agreement alone
does not attest that these bytes came from execution. Only then may a reviewed
native receipt adapter be registered in check_v13_evidence; it is absent today.
Version 1 has a fixed task roster; version 2 records dynamic task generations.
Neither version certifies A04 migration fault handling or host-core isolation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct
import sys

from check_prototype_evidence import _pairs, read_json, require, safe_path, sha256

TRACE_MAGIC = 0x4359584130325452
COUNTER_MAGIC = 0x4359584130324354
MAX_EVENTS = 65536
HEADER_BYTES = 512
EVENT_BYTES = 128


def execution_flags(verified: bool) -> dict:
    """Local execution verification is never a signed runtime attestation."""
    require(type(verified) is bool, 'invalid verification flag')
    return dict(native_execution_verified=verified, runtime_truth_attested=False)


def native_document(root: Path, name: str):
    return read_json(safe_path(root, name))


def read_native_qmp(root: Path) -> list[dict]:
    path = safe_path(root, 'qmp.jsonl')
    require(path.stat().st_size <= 16 * 1024 * 1024, 'QMP transcript exceeds bounded size')
    def invalid_number(value):
        raise ValueError('Invalid number ' + value)
    rows = []
    for line in path.read_text(encoding='utf-8').splitlines():
        require(len(line) <= 4 * 1024 * 1024, 'QMP frame exceeds bounded size')
        row = json.loads(line, object_pairs_hook=_pairs, parse_constant=invalid_number)
        require(type(row) is dict and row.keys() == {'direction', 'message'}
                and row['direction'] in ('send', 'receive') and type(row['message']) is dict,
                'invalid QMP transcript entry')
        rows.append(row)
    return rows


def verify_stopped_status(statuses: list[dict]):
    # QEMU 10.2 omits the deprecated singlestep field. When present, it must
    # still affirm a normal paused capture, never a debugger single-step.
    require(len(statuses) == 1, 'missing or duplicate stopped VM status')
    status = statuses[0]
    require(type(status) is dict and status.keys() in
            ({'status', 'running'}, {'status', 'running', 'singlestep'})
            and status['status'] == 'paused' and status['running'] is False
            and status.get('singlestep', False) is False, 'invalid stopped VM status')


def verify_native_qemu(tools: dict, binary: Path, *, qemu_source: Path | None = None) -> None:
    """Recheck the local binary; a dirty version string alone is never trusted.

    Legacy stock captures retain their original hash/version contract. Patched
    captures must match the repository's fixed commit, complete tracked diff,
    source digests, patch and binary again during independent receipt replay.
    """
    from verify_unified import attest_qemu
    version = tools.get('qemu_version', '')
    require(isinstance(version, str) and version.splitlines(), 'missing QEMU version')
    require(isinstance(tools.get('qemu_sha256'), str)
            and re.fullmatch('[0-9a-f]{64}', tools['qemu_sha256'])
            and sha256(Path(binary)) == tools['qemu_sha256'], 'QEMU binary identity changed')
    clean = ('QEMU emulator version 10.2.2', 'QEMU emulator version 10.2.2 (v10.2.2)')
    if version.splitlines()[0] in clean:
        require(tools.get('qemu_pmu_patch_attested', False) is False,
                'stock QEMU cannot claim the PMU patch')
        return
    source = tools.get('qemu_source_directory')
    require(tools.get('qemu_pmu_patch_attested') is True and isinstance(source, str)
            and Path(source).is_absolute(), 'patched QEMU source attestation missing')
    # Never run git in an archive-selected directory. The replay caller must
    # explicitly select the trusted emulator checkout, just like the runner.
    require(qemu_source is not None and qemu_source.resolve(strict=True)
            == Path(source).resolve(strict=True), 'explicit trusted QEMU source required')
    trusted = qemu_source.resolve(strict=True)
    built = trusted / 'build/qemu-system-aarch64'
    require(built.is_file() and sha256(built) == sha256(binary),
            'receipt binary differs from explicit trusted source build')
    # The receipt chooses no executable either: run --version only on the
    # caller-selected source build, after binding the archived binary digest.
    actual = attest_qemu(built.resolve(strict=True), trusted)
    require(actual.get('qemu_pmu_patch_attested') is True
            and all(tools.get(key) == value for key, value in actual.items()),
            'patched QEMU attestation changed')


def verify_capture_revision(runner_sha256: str, verifier_sha256: str):
    project = Path(__file__).resolve().parents[1]
    current = tuple(sha256(project / 'tools' / name)
                    for name in ('run_v13_a02.py', 'verify_v13_a02.py'))
    # Exact archived tools of the real 2026-10-26 v4 run, independently replayed
    # before enrolment. Preserve replay after verifier maintenance without ever
    # importing/executing archive code or trusting a manifest-selected checker.
    reviewed_v4 = ('55ad61d89cc3abbcafcbb77ed49768e37dcfe7ba7560928325860f4a0b9a1db3',
                   'b59af78493b056a8ece7911584d7dc91cb55af3e17309aea81c3bb4b000631ef')
    require((runner_sha256, verifier_sha256) in (current, reviewed_v4),
            'unreviewed runner/verifier revision')


def _ownership(masks):
    c, b, t, q, draining, suspect = masks
    require(all(value <= 15 for value in masks) and c and b
            and c | b | t | q == 15 and c + b + t + q == 15,
            'invalid ownership partition')
    require((draining | suspect) & ~(c | b) == 0,
            'draining/suspect must retain original C/B owner')
    return masks


def _allowed(role, cpu, masks):
    bit = 1 << cpu
    require(not bit & (masks[4] | masks[5]), 'dispatch on draining/suspect core')
    if role == 1:
        require(bit & masks[1], 'business dispatch on protected C/T/Q core')
    else:
        require(bit & masks[0], 'control dispatch outside C')


def verify(trace: bytes, counters: bytes, *, image_sha256: str,
           input_sha256: str, source_sha256: str) -> dict:
    """Check raw observations and expected artifact identities; never attest origin."""
    require(len(trace) >= HEADER_BYTES, 'incomplete trace length')
    require(len(counters) == HEADER_BYTES, 'invalid counter snapshot length')
    h = struct.unpack_from('<64Q', trace)
    s = struct.unpack('<64Q', counters)
    require(h[0] == TRACE_MAGIC and h[1] in (1, 2) and h[2] == 16
            and s[:2] == (COUNTER_MAGIC, h[1]),
            'unsupported A02 capture format')
    version = h[1]
    require(1 <= h[3] <= MAX_EVENTS and len(trace) == HEADER_BYTES + h[3] * EVENT_BYTES,
            'invalid trace length/event count')
    require(h[4] == s[8] == 0, 'dropped scheduler events')
    require(h[5] > 0 and h[5] % 2 == 0, 'unsealed scheduler capture')
    require(h[6] > 0 and any(h[7:9]) and 0 < h[9] < h[10] and h[11] >= 1000
            and h[12] > 0 and h[19] == 4, 'invalid boot/run/clock/platform identity')
    require(not any(h[20:24]), 'capture must start before first dispatch')
    require(not any(h[36:]) and not any(s[44:]), 'nonzero reserved capture fields')
    require(s[2:8] == (h[5], h[6], h[7], h[8], h[10], h[3]),
            'counter snapshot belongs to different boot/run/capture')
    for digest, trace_at, counter_at in ((image_sha256, 24, 28),
                                         (input_sha256, 28, 32),
                                         (source_sha256, 32, 36)):
        require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest)
                and digest != '0' * 64, 'invalid expected artifact identity')
        expected = bytes.fromhex(digest)
        require(trace[trace_at*8:(trace_at+4)*8] == expected
                and counters[counter_at*8:(counter_at+4)*8] == expected,
                'capture artifact identity mismatch')

    masks = _ownership(h[13:19])
    core_generation = h[12]
    tasks = {}
    running = [None] * 4
    returned = {}
    entries = [0] * 4
    exits = [0] * 4
    elapsed = [0] * 4
    pending = {}
    requested = denied = accepted = control_denials = publications = registered = 0
    previous_tick = h[9]
    entered_roles = set()
    for index in range(h[3]):
        row = struct.unpack_from('<16Q', trace, HEADER_BYTES + index * EVENT_BYTES)
        seq, tick, kind, cpu, task, generation, owner = row[:7]
        payload = row[7:]
        require(seq == index + 1, 'event sequence gap/reordering')
        require(previous_tick <= tick <= h[10], 'event clock regression/outside capture')
        previous_tick = tick
        require(kind in (1, 2, 3, 4, 5, 6), 'unknown scheduler event kind')
        used = {1: 2, 2: 6, 3: 1, 4: 1, 5: 2, 6: 2}[kind]
        require(not any(payload[used:]), 'nonzero reserved event payload')
        require(owner == core_generation if kind != 2 else
                (owner == core_generation + 1 or (version == 2 and owner == core_generation
                                                 and payload[:6] != masks)),
                'stale/skipped core generation')
        if kind == 1:
            role, affinity = payload[:2]
            fresh = task not in tasks or (version == 2 and generation > tasks[task][0]
                    and not any(item is not None and item[0] == task for item in running))
            require(cpu == 4 and task > 0 and generation > 0 and fresh
                    and (version == 2 or not any(entries)) and role in (1, 2) and 0 < affinity <= 15,
                    'invalid/late/duplicate task registration')
            allowed = masks[1 if role == 1 else 0] & ~(masks[4] | masks[5])
            require(affinity & ~allowed == 0, 'registered affinity exceeds role ownership')
            tasks[task] = [generation, role, affinity]
            registered += 1
            continue
        if kind == 2:
            require(cpu == 4 and task == generation == 0, 'invalid ownership event identity')
            masks = _ownership(payload[:6])
            core_generation = owner
            publications += 1
            for running_cpu, active in enumerate(running):
                if active is not None:
                    active_masks = masks if version == 1 else (*masks[:4], 0, 0)
                    _allowed(tasks[active[0]][1], running_cpu, active_masks)
            continue
        require(cpu < 4, 'invalid dispatch CPU')
        require(task in tasks and generation == tasks[task][0], 'unknown/stale task generation')
        role, affinity = tasks[task][1:]
        active = running[cpu]
        if kind == 3:
            require(active is None, 'overlapping dispatch on CPU')
            require(not any(item is not None and item[0] == task for item in running),
                    'concurrent task execution on different CPUs')
            _allowed(role, cpu, masks)
            require(affinity & (1 << cpu), 'dispatch violates admitted affinity')
            require(payload[0] == entries[cpu] + 1, 'skipped/duplicate dispatch slice')
            running[cpu] = (task, generation, payload[0], tick)
            returned.pop((task, generation), None)
            entries[cpu] += 1
            entered_roles.add(role)
            continue
        if kind == 4 or version == 1:
            require(active is not None and active[:2] == (task, generation),
                    'event does not identify running caller')
        else:
            require(returned.get((task, generation)) == cpu
                    and not any(item is not None and item[:2] == (task, generation) for item in running),
                    'event does not identify returned caller')
        if kind == 4:
            require(payload[0] == active[2] and tick > active[3], 'invalid dispatch exit/duration')
            require(not any(request[0] == task for request in pending.values()),
                    'dispatch exited with unfinished binding request')
            exits[cpu] += 1
            elapsed[cpu] += tick - active[3]
            running[cpu] = None
            returned[(task, generation)] = cpu
            continue
        request_id, value = payload[:2]
        if kind == 5:
            require(request_id == requested + 1 and 0 < value <= 15
                    and not any(request[0] == task for request in pending.values()),
                    'invalid/duplicate binding request')
            pending[request_id] = (task, generation, cpu, value)
            requested += 1
            continue
        require(request_id in pending and pending[request_id][:3] == (task, generation, cpu)
                and value in (0, 1), 'unmatched/invalid binding result')
        requested_mask = pending.pop(request_id)[3]
        allowed = masks[1 if role == 1 else 0] & ~(masks[4] | masks[5])
        if version == 2:
            allowed &= affinity
        forbidden = requested_mask & ~allowed
        if forbidden:
            require(value == 1, 'accepted forbidden affinity')
        else:
            require(value == 0, 'E_AUTH without forbidden affinity')
        if value == 1:
            denied += 1
            if role == 1 and requested_mask & masks[0]:
                control_denials += 1
        else:
            accepted += 1
            tasks[task][2] = requested_mask
        if version == 2:
            returned.pop((task, generation))

    require(not any(running), 'unfinished dispatch at capture seal')
    require(not pending, 'unfinished binding request at capture seal')
    require(entered_roles == {1, 2}, 'capture lacks actual business/control execution')
    require(control_denials > 0, 'missing business-to-control affinity denial')
    require(s[9] == core_generation and s[10:16] == masks,
            'final ownership snapshot disagrees with trace')
    require(s[16:20] == tuple(entries) and s[20:24] == tuple(exits),
            'independent dispatch counters disagree with complete trace')
    require(s[24:28] == (requested, denied, accepted, registered),
            'independent admission/registration counters disagree with trace')
    require(s[40:44] == tuple(elapsed), 'independent elapsed counters disagree with trace')
    return dict(test_id='A02', verifier_version=f'a02-scheduler-v{version}',
                raw_contract_valid=True, native_acceptance_status='NOT_RUN',
                **execution_flags(False), native_runner_available=True,
                events=h[3], boot_epoch=h[6], dispatches_per_cpu=entries,
                elapsed_ticks_per_cpu=elapsed, binding_requests=requested,
                accepted_bindings=accepted, denied_bindings=denied,
                business_control_bind_denials=control_denials,
                ownership_publications=publications,
                scope='Raw capture contract only; use the native runner and its provenance for execution evidence.')


def verify_native_receipt(directory: Path, *, source_root: Path | None = None,
                          qemu_source: Path | None = None) -> dict:
    """Replay known native evidence, ignoring the producer's PASS boolean.

    This is process/launch/capture provenance, not a hardware attestation or a
    signature from QEMU. Its trust base is the reviewed local runner and source
    build, not arbitrary manifest-supplied executable code. Only the caller may
    explicitly select a frozen source checkout; receipt fields cannot select it.
    """
    from check_elf import boot_profile, inspect_elf, symbol
    from verify_v13_model import loaded_bytes
    from check_v13_disk import inspect as inspect_disk
    from build_unified import code_source_map
    root = Path(directory).resolve(strict=True)
    project = Path(source_root if source_root is not None else Path(__file__).resolve().parents[1]).resolve(strict=True)
    def path(name):
        return safe_path(root, name)
    def document(name):
        return native_document(root, name)
    receipt = document('summary.json')
    artifacts = receipt.get('artifacts')
    mandatory = {'trace.bin', 'counters.bin', 'node-a.elf', 'service-a.elf', 'task.elf',
        'build-manifest.json', 'source-manifest.json', 'input.json', 'config.bin', 'config-observed.bin',
        'platform.dtb', 'dtb-header.bin', 'model.bin', 'control-header.bin', 'qmp.jsonl',
        'tools.json', 'launch.json', 'platform.json', 'disk.raw', 'run_v13_a02.py', 'verify_v13_a02.py',
        'control-credit.bin', 'task-overrun.bin', 'config-injection.json', 'build-inputs/Cargo.lock', 'build-inputs/Cargo.toml',
        'build-inputs/.cargo/config.toml'}
    require(type(artifacts) is dict and mandatory <= artifacts.keys(), 'incomplete native artifact inventory')
    for name, digest in artifacts.items():
        require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest)
                and sha256(path(name)) == digest, 'changed native artifact: ' + name)
    source = document('source-manifest.json')
    build = document('build-manifest.json')
    require(build.get('schema_version') == 1 and build.get('status') == 'BUILT_NOT_RUN'
            and build['profiles']['fault'] == 'normal' and build['profiles']['selftest'] is True
            and build['code_source_map'] == source == code_source_map(project), 'native build/source mismatch')
    for name in ('node-a.elf', 'service-a.elf', 'task.elf'):
        require(build['artifacts'][name]['sha256'] == sha256(path(name)), 'native build artifact mismatch')
    require(build['builder_sha256'] == sha256(safe_path(project, 'tools/build_unified.py')),
            'native builder revision changed')
    verify_capture_revision(sha256(path('run_v13_a02.py')), sha256(path('verify_v13_a02.py')))
    require({'cargo', 'rustc', 'clang'} <= build['tools'].keys(), 'missing build tools')
    tools = document('tools.json')
    require(tools['build_tools'] == build['tools'], 'unverified native toolchain')
    image = path('node-a.elf').read_bytes()
    inspect_elf(image)
    require(boot_profile(image)['ram_mib'] == 1024, 'wrong native image RAM profile')
    config_symbol = symbol(image, 'A02_CONFIG')
    capture_symbol = symbol(image, 'A02_CAPTURE')
    layout_symbol = symbol(image, 'A02_CAPTURE_LAYOUT')
    layout = struct.unpack('<8Q', loaded_bytes(image, layout_symbol['va'], layout_symbol['size']))
    require(config_symbol['size'] == 512 and layout[0] == 2 and 0 < layout[1] <= MAX_EVENTS
            and layout[3:5] == (512, 128) and layout[5] == 512 + layout[1] * 128
            and layout[6] == 512 and layout[7] == capture_symbol['size'], 'invalid native layout')
    config = path('config.bin').read_bytes()
    require(len(config) == 512 and struct.unpack_from('<2Q', config) == (0x4359584130324346, 2)
            and any(config[16:32]) and not any(config[128:])
            and config == path('config-observed.bin').read_bytes(), 'invalid observed preboot config')
    expected = b''.join(bytes.fromhex(sha256(path(name))) for name in
                        ('node-a.elf', 'input.json', 'source-manifest.json'))
    require(config[32:128] == expected, 'wrong preboot artifact identity')
    injection = document('config-injection.json')
    payload = f'M{config_symbol["pa"]:x},200:{config.hex()}'.encode('ascii')
    packet = b'$' + payload + f'#{sum(payload) % 256:02x}'.encode('ascii')
    require(injection['request_hex'] == packet.hex() and injection['ack_hex'] == '2b'
            and bytes.fromhex(injection['received_hex']).lstrip(b'+') == b'$OK#9a',
            'preboot injection changed bytes outside the exact config range')
    inputs = document('input.json')
    require(inputs['test_id'] == 'A02' and inputs['seed'] == config[16:32].hex()
            and inputs['clock'] == 'wallclock' and inputs['max_trace_events'] == layout[1],
            'wrong frozen scenario/run identity')
    trace, counters = path('trace.bin').read_bytes(), path('counters.bin').read_bytes()
    observed = verify(trace, counters, image_sha256=sha256(path('node-a.elf')),
                      input_sha256=sha256(path('input.json')), source_sha256=sha256(path('source-manifest.json')))
    require(struct.unpack_from('<Q', trace, 8)[0] == 2 and trace[56:72] == config[16:32],
            'wrong native wire version/run nonce')
    platform = document('platform.json')
    require(len(platform['cpus']) == 4 and platform['memory']['base-memory'] == 1024 ** 3,
            'wrong captured platform')
    dtb = path('platform.dtb').read_bytes()
    require(len(dtb) >= 40 and struct.unpack_from('>2I', dtb) == (0xd00dfeed, len(dtb))
            and dtb[:40] == path('dtb-header.bin').read_bytes(), 'invalid native DTB')
    model_symbol = symbol(image, 'A02_BOOT_MODEL')
    require(path('model.bin').read_bytes() == loaded_bytes(image, model_symbol['va'], model_symbol['size']),
            'model artifact differs from built model')
    control = path('control-header.bin').read_bytes()
    words = struct.unpack_from('<25Q', control)
    require(words[0] == 0x435958444f4d3031 and words[2] == observed['boot_epoch']
            and control[128:160].hex() == sha256(path('model.bin'))
            and control[160:192].hex() == source['crates/prototype/src/features.rs'],
            'runtime model/schema/boot mismatch')
    require(inspect_disk(path('disk.raw'))['boot_epoch'] == observed['boot_epoch'], 'durable boot mismatch')
    launch = document('launch.json')['argv']
    require(type(launch) is list and len(launch) > 1 and all(type(v) is str for v in launch), 'invalid launch')
    options = {}
    i = 1
    while i < len(launch):
        key = launch[i]
        require(key.startswith('-'), 'invalid launch option')
        if key in ('-S', '-no-reboot'):
            options.setdefault(key, []).append(True); i += 1
        else:
            require(i + 1 < len(launch), 'missing launch value')
            options.setdefault(key, []).append(launch[i + 1]); i += 2
    expected_keys = {'-machine', '-cpu', '-smp', '-m', '-accel', '-S', '-display', '-monitor', '-global',
        '-drive', '-device', '-netdev', '-object', '-chardev', '-serial', '-qmp', '-gdb', '-kernel', '-no-reboot'}
    require(set(options) == expected_keys, 'unexpected native launch option')
    for key, value in {'-machine': 'virt-10.2,gic-version=2,secure=off,virtualization=off',
        '-cpu': 'cortex-a53', '-smp': '4', '-m': '1024M', '-accel': 'tcg,thread=multi',
        '-display': 'none', '-monitor': 'none', '-global': 'virtio-mmio.force-legacy=false',
        '-kernel': str(path('node-a.elf')), '-S': True, '-no-reboot': True}.items():
        require(options[key] == [value], 'wrong native launch parameter: ' + key)
    expected_devices = {'virtio-blk-device,drive=disk0',
        'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
        'virtio-rng-device,rng=rng0'}
    require(set(options['-device']) == expected_devices and len(options['-device']) == 3,
            'unexpected native loader/device')
    require(options['-drive'] == [f'if=none,id=disk0,format=raw,file={path("disk.raw")},cache=writeback'],
            'wrong native disk attachment')
    verify_native_qemu(tools, Path(launch[0]), qemu_source=qemu_source)
    transcript = read_native_qmp(root)
    requests, responses = [], {}
    for item in transcript:
        message = item['message']
        if item['direction'] == 'send': requests.append(message)
        elif 'id' in message:
            require('return' in message and 'error' not in message and message['id'] not in responses,
                    'failed/duplicate QMP reply')
            responses[message['id']] = message['return']
    allowed = {'qmp_capabilities', 'query-cpus-fast', 'query-memory-size-summary', 'pmemsave',
               'cont', 'ringbuf-read', 'stop', 'query-status', 'quit'}
    require(all(request['execute'] in allowed and request['id'] in responses for request in requests),
            'unanswered or forbidden QMP command')
    commands = [request['execute'] for request in requests]
    for command, expected in (('query-cpus-fast', platform['cpus']),
                               ('query-memory-size-summary', platform['memory'])):
        actual = [responses[request['id']] for request in requests if request['execute'] == command]
        require(actual == [expected], 'platform summary differs from native QMP observation')
    require(commands.count('cont') == commands.count('stop') == 1
            and commands.index('cont') < commands.index('stop'), 'missing uninterrupted execution/capture stop')
    stop = commands.index('stop')
    statuses = [responses[request['id']] for request in requests[stop + 1:] if request['execute'] == 'query-status']
    verify_stopped_status(statuses)
    required_saves = {'trace.bin': (capture_symbol['pa'], len(trace)),
        'counters.bin': (capture_symbol['pa'] + layout[5], 512),
        'control-header.bin': (symbol(image, 'DOMAIN_CONTROL_EVIDENCE')['pa'], 4096)}
    for name, (address, size) in required_saves.items():
        matches = [request for request in requests[stop + 1:] if request['execute'] == 'pmemsave'
                   and request.get('arguments') == dict(val=address, size=size, filename=str(path(name)))]
        require(len(matches) == 1, 'missing exact stopped native memory capture: ' + name)
    for name, address, size in (('config-observed.bin', config_symbol['pa'], 512),
                               ('platform.dtb', 0x40000000, len(dtb))):
        require(any(request['execute'] == 'pmemsave' and request.get('arguments')
                    == dict(val=address, size=size, filename=str(path(name)))
                    for request in requests[:commands.index('cont')]), 'missing preboot capture provenance')
    observed.update(native_acceptance_status='PASS', **execution_flags(True),
                    verifier_version='a02-native-v4', scope='Native A02 only; other v1.3 cases remain separate.')
    return observed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ('trace', 'counters', 'image', 'input', 'source-manifest'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        require(args.trace.stat().st_size <= HEADER_BYTES + MAX_EVENTS * EVENT_BYTES,
                'trace exceeds capture bound')
        require(args.counters.stat().st_size == HEADER_BYTES, 'invalid counter snapshot length')
        result = verify(args.trace.read_bytes(), args.counters.read_bytes(),
                        image_sha256=sha256(args.image), input_sha256=sha256(args.input),
                        source_sha256=sha256(args.source_manifest))
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, TypeError, struct.error) as error:
        print(f'a02-evidence: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
