#!/usr/bin/env python3
"""Verify real concurrent xdg clients, overlap, hit testing, focus and isolated close.

The host injects only physical input and reads actual QMP scanout. The expected
pixels are independently reconstructed here from client frame identities.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import tomllib

from build_cosmic import tree_identity
from build_sysroot import inspect_elf as inspect_program
from check_elf import boot_profile, inspect_elf
from doctor import ROOT, RUST_BIN, env
from shell import Guest
from verify_edge import DOMAINS
from verify_ported import parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import event
from verify_smithay_xdg import bind_inputs, digest, rows

WIDTH, HEIGHT = 128, 96
X, Y = 32, 48
# Each entry gives A frame, B frame, bottom-to-top identities and keyboard focus.
SCENES = ((0, 0, (1, 2), 2), (0, 1, (1, 2), 2),
          (1, 1, (2, 1), 1), (2, 1, (2, 1), 1),
          (3, 1, (2, 1), 1), (3, 2, (1, 2), 2),
          (3, 3, (1, 2), 2), (3, None, (1,), 1),
          (4, None, (1,), 1), (None, None, (), 0))
SEEDS = {1: (0, 272, 48, 273, 32), 2: (0, 30, 272, 46)}
ORIGINS = {1: (8, 8), 2: (40, 24)}
TRANSITIONS = ((2, 0, "key", 30), (1, 0, "button", 272),
               (1, 1, "key", 48), (1, 2, "button", 273),
               (2, 1, "button", 272), (2, 2, "key", 46),
               (2, 3, "key", 16), (1, 3, "key", 32),
               (1, 4, "key", 16))
READY = "SMITHAY_MULTI READY wayland=1 gles=1 native=1 xdg=1 windows=2"
CANVAS = "SMITHAY_MULTI CANVAS x=32 y=48 width=128 height=96"
TOTAL = "SMITHAY_MULTI TOTAL clients=2 cfg=7 acks=7 closes=2 cosmic=0"
SUCCESS = "SMITHAY_MULTI RESULT PASS scenes=10 commits=9 pixels=122880"
FATAL = (b"SMITHAY_MULTI FAIL", b"MULTI_CLIENT FAIL", b"KERNEL_FAULT",
         b"panicked", b"EL0 start failed", b"ELF start failed", b"CHECK_FAILED", b"SERVICE_PANIC",
         b"FAIL unexpected exception", b"GRAPHICS_GPU_ERROR")


def check_console(data):
    assert not any(word in data for word in FATAL), data[-6000:]
    assert not re.search(rb"EL0 pid=\d+ (?:Fault|Killed|Exited) code=(?!0\b)\d+", data), data[-6000:]


def scene_ready(scene):
    _, _, stack, focus = SCENES[scene]
    label = lambda identity: {0: "none", 1: "A", 2: "B"}[identity]
    return (f"SMITHAY_MULTI SCENE n={scene} "
            f"top={label(stack[-1] if stack else 0)} focus={label(focus)} windows={len(stack)}")


def wire(expected):
    """Compact an expected semantic marker; never repair observed UART bytes.

    All actual markers remain exact complete records of at most 64 bytes,
    including their newline, matching the existing console write boundary.
    """
    if expected.startswith("SMITHAY_MULTI "):
        return expected.replace(" CONFIGURE ", " CONFIG ").replace(" sequence=", " n=").replace(
            " width=64 height=48 activated=", " w=64 h=48 a=").replace(" INPUT_FORWARDED ", " INPUT ")
    if not expected.startswith("MULTI_CLIENT "):
        return expected
    expected = expected.replace(" libwayland=1.24.0 xdg_shell=1", "")
    expected = expected.replace(" KEYMAP PASS ", " KEYMAP ").replace(" CONFIGURE ", " CONFIG ")
    expected = expected.replace("KEYBOARD_ENTER", "K_ENTER").replace("KEYBOARD_LEAVE", "K_LEAVE")
    expected = expected.replace("POINTER_ENTER", "P_ENTER").replace("POINTER_LEAVE", "P_LEAVE")
    expected = expected.replace(" FRAME PASS ", " FRAME ").replace(" callback=1 after_import_write=1", "")
    expected = expected.replace(" frame=", " f=").replace(" width=", " w=").replace(" height=", " h=")
    expected = expected.replace(" activated=", " active=").replace(" keysym=", " sym=")
    expected = expected.replace(" x_fixed=", " x=").replace(" y_fixed=", " y=")
    expected = expected.replace(" index=", " seq=" if " CONFIG " in expected or " ACK " in expected else " n=")
    if " CONFIG " in expected:
        expected = expected.replace(" serial=", " s=")
    if " RELEASE " in expected:
        expected = expected.replace(" count=1", "")
    else:
        expected = expected.replace(" count=1", " n=1")
    return expected


def expected_pixel(scene, x, y):
    first, second, stack, _ = SCENES[scene]
    for identity in reversed(stack):
        ox, oy = ORIGINS[identity]
        local_x, local_y = x-ox, y-oy
        if 0 <= local_x < 64 and 0 <= local_y < 48:
            frame = (first, second)[identity-1]
            seed = SEEDS[identity][frame]
            return bytes(((3*local_x+local_y+29*identity+47*frame+seed) & 255,
                          (local_x+5*local_y+11*identity+31*frame+3*seed) & 255,
                          (7*(local_x ^ local_y)+13*identity+19*frame+5*seed) & 255))
    return bytes(3)


def scanout(path, scene):
    with path.open("rb") as stream:
        assert stream.readline() == b"P6\n", "Not a QMP PPM"
        assert stream.readline() == b"1024 768\n", "Unexpected physical scanout"
        assert stream.readline() == b"255\n"
        pixels = stream.read()
    assert len(pixels) == 1024*768*3, "Incomplete or oversized scanout"
    canvas = bytearray()
    for y in range(HEIGHT):
        for x in range(WIDTH):
            at = ((Y+y)*1024+X+x)*3
            actual, expected = pixels[at:at+3], expected_pixel(scene, x, y)
            assert actual == expected, (scene, x, y, actual.hex(), expected.hex())
            canvas.extend(actual)
    return dict(path=str(path), sha256=digest(path), canvas_sha256=hashlib.sha256(canvas).hexdigest(),
                pixels=WIDTH*HEIGHT, scene=scene, x=X, y=Y, width=WIDTH, height=HEIGHT)


def scene_waiting(data, scene):
    check_console(data)
    server = [line for line, _ in rows(data, "SMITHAY_MULTI")]
    assert server.count(scene_ready(scene)) == 1
    assert not any(line.startswith(f"SMITHAY_MULTI SCENE n={later} ")
                   for later in range(scene+1, len(SCENES)) for line in server)
    if scene == 9:
        return
    identity, frame, kind, code = TRANSITIONS[scene]
    assert not any(line.startswith(f"SMITHAY_MULTI INPUT scene={scene} ") for line in server)
    client = [line for line, _ in rows(data, "MULTI_CLIENT")]
    assert not any(line.startswith(wire(f"MULTI_CLIENT {kind.upper()} id={identity} frame={frame} code={code} "))
                   for line in client), "Native input was received before host injection"
    pointer_marker = {
        1: "MULTI_CLIENT POINTER_ENTER id=1 index=0 ",
        3: "MULTI_CLIENT MOTION id=1 frame=2 ",
        4: "MULTI_CLIENT POINTER_ENTER id=2 index=1 ",
    }.get(scene)
    assert pointer_marker is None or not any(line.startswith(wire(pointer_marker)) for line in client), \
        "Pointer moved before physical host injection"
    if scene in (1, 4):
        prefix = f"SMITHAY_MULTI CONFIGURE id=1 sequence={1 if scene == 1 else 2} "
        assert not any(line.startswith(wire(prefix)) for line in server), "Focus changed before physical click"
    if scene in (6, 8):
        assert f"SMITHAY_MULTI CLOSE id={identity}" not in server
    else:
        assert f"SMITHAY_MULTI COMMIT id={identity} frame={frame+1} seed={SEEDS[identity][frame+1]}" not in server


def capture(guest, start, path, scene, timeout=3):
    deadline, attempts = time.monotonic()+timeout, 0
    while True:
        guest.poll()
        scene_waiting(bytes(guest.text[start:]), scene)
        guest.qmp.execute("screendump", {"filename": str(path.resolve())})
        attempts += 1
        try:
            witness = scanout(path, scene)
            witness["capture_attempts"] = attempts
            return witness
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.01)


def validate_live(processes):
    assert set(processes) == {1, 2, 3}, processes
    for pid, row in processes.items():
        assert row["parent_pid"] == (0 if pid == 1 else 1), row
        assert row["state"] in ("Running", "Waiting"), row
        assert row["code"] == row["exit_signal"] == row["esr"] == row["far"] == 0, row
        assert row["image_pages"] > 0 and row["heap_pages"] > 0, row
        assert row["ai_selections"] > 0 and row["syscalls"] > 0, row
        assert row["rank_model"] == 12289 and row["cpu_model"] == 12290, row
        assert row["guard_selections"] == row["thread_guard_selections"] == 0, row


def client_done(identity):
    configs = 4 if identity == 1 else 3
    return f"MULTI_CLIENT RESULT PASS id={identity} configures={configs} acks={configs} close=1"


def client_counts(identity):
    frames, events = (5, 10) if identity == 1 else (4, 8)
    return f"MULTI_CLIENT COUNTS id={identity} f={frames} cb={frames} rel={frames} ev={events}"


def validate(data):
    """Match both independent protocol streams and their causal dependencies.

    Cross-client scheduling and early copied-SHM release order are intentionally
    unconstrained. Ownership, input causality and every exact event are required.
    """
    check_console(data)
    server, client = rows(data, "SMITHAY_MULTI"), rows(data, "MULTI_CLIENT")
    assert len({line for line, _ in server}) == len(server), "Duplicate server marker"
    assert len({line for line, _ in client}) == len(client), "Duplicate client marker"
    positions = dict(server + client)
    assert all(len(line.encode())+1 <= 64 for line, _ in server+client), "Oversized telemetry is not an atomic console write"
    expected_server = {READY, CANVAS, TOTAL, SUCCESS}
    expected_client, configs, keymap_sizes, configure_serials = set(), {}, [], []
    frame_scenes = {1: (0, 2, 3, 4, 8), 2: (0, 1, 5, 6)}

    def before(*lines):
        lines = tuple(wire(line) for line in lines)
        assert all(line in positions for line in lines), ("Missing required marker", lines)
        values = [positions[line] for line in lines]
        assert values == sorted(set(values)), ("Causal order", lines, values)

    def between(scene, *lines):
        before(scene_ready(scene), *lines, scene_ready(scene+1))

    for identity in (1, 2):
        expected_server.add(f"SMITHAY_MULTI SPAWN id={identity} child={identity+1}")
        start = f"MULTI_CLIENT START id={identity} pid={identity+1} fd=3 libwayland=1.24.0 xdg_shell=1"
        expected_client.add(start)
        before(READY, start)
        maps = [line for line, _ in client if line.startswith(f"MULTI_CLIENT KEYMAP id={identity} ")]
        assert len(maps) == 1, maps
        match = re.fullmatch(rf"MULTI_CLIENT KEYMAP id={identity} bytes=(\d+)", maps[0])
        assert match and 1 < int(match[1]) <= 65536, maps
        keymap_sizes.append(int(match[1]))
        expected_client.add(maps[0])
        before(start, maps[0])
        states = (0, 1, 0, 1) if identity == 1 else (1, 0, 1)
        for sequence, activated in enumerate(states):
            prefix = f"SMITHAY_MULTI CONFIG id={identity} n={sequence} "
            candidates = [line for line, _ in server if line.startswith(prefix)]
            assert len(candidates) == 1, candidates
            match = re.fullmatch(re.escape(prefix)+rf"serial=(\d+) w=64 h=48 a={activated}", candidates[0])
            assert match and 0 < int(match[1]) <= 0xffffffff, candidates
            serial = int(match[1])
            assert serial not in configure_serials, ("Reused serial", serial)
            configure_serials.append(serial)
            config = candidates[0]
            ack = f"SMITHAY_MULTI ACK id={identity} sequence={sequence} serial={serial}"
            client_config = f"MULTI_CLIENT CONFIGURE id={identity} index={sequence} serial={serial} width=64 height=48 activated={activated}"
            client_ack = f"MULTI_CLIENT ACK id={identity} index={sequence} serial={serial}"
            expected_server.update((config, ack))
            expected_client.update((client_config, client_ack))
            configs[identity, sequence] = (config, client_config, client_ack, ack)
            before(*configs[identity, sequence])
            if sequence == 0:
                before(maps[0], config, ack, f"SMITHAY_MULTI COMMIT id={identity} frame=0 seed=0", scene_ready(0))
            else:
                transition = {1: (1, 4, 6), 2: (1, 4)}[identity][sequence-1]
                between(transition, config, ack)
                before(configs[identity, sequence-1][-1], config)
        for frame, scene in enumerate(frame_scenes[identity]):
            seed = SEEDS[identity][frame]
            commit = f"SMITHAY_MULTI COMMIT id={identity} frame={frame} seed={seed}"
            callback = f"MULTI_CLIENT CALLBACK id={identity} frame={frame} time={scene}"
            complete = (f"MULTI_CLIENT FRAME PASS id={identity} frame={frame} width=64 height=48 "
                        f"seed={seed} callback=1 after_import_write=1")
            release = f"MULTI_CLIENT RELEASE id={identity} frame={frame} count=1"
            expected_server.add(commit)
            expected_client.update((callback, complete, release))
            before(commit, scene_ready(scene), callback, complete, client_done(identity))
            # A renderer may release SHM as soon as it has copied the buffer.
            before(commit, release, client_counts(identity), client_done(identity))
            if frame:
                previous = (f"MULTI_CLIENT FRAME PASS id={identity} frame={frame-1} width=64 height=48 "
                            f"seed={SEEDS[identity][frame-1]} callback=1 after_import_write=1")
                before(previous, commit)
        expected_server.update((f"SMITHAY_MULTI CLOSE id={identity}", f"SMITHAY_MULTI UNMAP id={identity}",
                                f"SMITHAY_MULTI EXIT id={identity} child={identity+1} status=0"))
        expected_client.update((f"MULTI_CLIENT CLOSE id={identity} count=1", client_done(identity)))
        pointers = 1 if identity == 1 else 2
        counts = client_counts(identity)
        focus_counts = f"MULTI_CLIENT FOCUS id={identity} ke=2 kl=1 pe={pointers} pl=1"
        expected_client.update((counts, focus_counts))
        before(f"MULTI_CLIENT CLOSE id={identity} count=1", counts, focus_counts, client_done(identity))
        for index in (0, 1):
            expected_client.add(f"MULTI_CLIENT KEYBOARD_ENTER id={identity} index={index}")
        for device in ("KEYBOARD", "POINTER"):
            normal_leave = f"MULTI_CLIENT {device}_LEAVE id={identity} index=0 closing=0"
            expected_client.add(normal_leave)
            closing_leave = f"MULTI_CLIENT {device}_LEAVE id={identity} index=0 closing=1"
            if wire(closing_leave) in positions:
                assert not (identity == 1 and device == "POINTER"), \
                    "A's pointer focus ended when B was raised; it cannot leave again at close"
                expected_client.add(closing_leave)
                before(f"MULTI_CLIENT CLOSE id={identity} count=1", closing_leave,
                       client_counts(identity), client_done(identity))
        enter = f"MULTI_CLIENT POINTER_ENTER id={identity} index=0 x_fixed=2048 y_fixed=2048"
        expected_client.add(enter)
        if identity == 2:
            expected_client.add("MULTI_CLIENT POINTER_ENTER id=2 index=1 x_fixed=14336 y_fixed=10240")
    assert keymap_sizes[0] == keymap_sizes[1]
    for scene in range(10):
        expected_server.add(scene_ready(scene))
        if scene:
            before(scene_ready(scene-1), scene_ready(scene))
    for scene, (identity, frame, kind, code) in enumerate(TRANSITIONS):
        forwarded = f"SMITHAY_MULTI INPUT_FORWARDED scene={scene} target={identity} kind={kind} code={code}"
        expected_server.add(forwarded)
        between(scene, forwarded)
        events = []
        for state in (1, 0):
            if kind == "key":
                symbol = {30: 97, 48: 98, 46: 99, 32: 100, 16: 113}[code]
                line = f"MULTI_CLIENT KEY id={identity} frame={frame} code={code} state={state} keysym={symbol}"
            else:
                x, y = (8, 8) if scene == 1 else ((48, 32) if scene == 3 else (56, 40))
                line = (f"MULTI_CLIENT BUTTON id={identity} frame={frame} code={code} state={state} "
                        f"x_fixed={x*256} y_fixed={y*256}")
            events.append(line)
            expected_client.add(line)
        between(scene, *events)
        current_done = (f"MULTI_CLIENT FRAME PASS id={identity} frame={frame} width=64 height=48 "
                        f"seed={SEEDS[identity][frame]} callback=1 after_import_write=1")
        before(current_done, events[0])
        active_sequence = {0: 0, 1: 1, 2: 1, 3: 1, 4: 2, 5: 2, 6: 2, 7: 3, 8: 3}[scene]
        before(configs[identity, active_sequence][2], events[0])
        enter_index = 0 if scene <= 3 else 1
        before(f"MULTI_CLIENT KEYBOARD_ENTER id={identity} index={enter_index}", events[0])
        if scene in (6, 8):
            close = f"SMITHAY_MULTI CLOSE id={identity}"
            received_close = f"MULTI_CLIENT CLOSE id={identity} count=1"
            before(forwarded, close, received_close, client_done(identity), scene_ready(scene+1))
            before(events[-1], received_close)
        else:
            commit = f"SMITHAY_MULTI COMMIT id={identity} frame={frame+1} seed={SEEDS[identity][frame+1]}"
            before(events[-1], commit)
            before(forwarded, commit)
    motion = "MULTI_CLIENT MOTION id=1 frame=2 x_fixed=12288 y_fixed=8192"
    expected_client.add(motion)
    between(3, motion, "MULTI_CLIENT BUTTON id=1 frame=2 code=273 state=1 x_fixed=12288 y_fixed=8192")
    focuses = ((0, 2, "initial", None), (2, 1, "click", 1), (1, 2, "click", 4),
               (2, 1, "unmap", 6), (1, 0, "unmap", 8))
    for previous, current, reason, scene in focuses:
        line = f"SMITHAY_MULTI FOCUS previous={previous} current={current} reason={reason}"
        expected_server.add(line)
        if scene is None:
            before("SMITHAY_MULTI COMMIT id=1 frame=0 seed=0", line, scene_ready(0))
            before("SMITHAY_MULTI COMMIT id=2 frame=0 seed=0", line)
        else:
            between(scene, line)
            if reason == "unmap":
                before(f"MULTI_CLIENT CLOSE id={previous} count=1", line)
    for identity, index, scene in ((2, 0, None), (1, 0, 1), (2, 1, 4), (1, 1, 6)):
        line = f"MULTI_CLIENT KEYBOARD_ENTER id={identity} index={index}"
        if scene is None:
            before(configs[identity, 0][-1], line,
                   "MULTI_CLIENT KEY id=2 frame=0 code=30 state=1 keysym=97")
        elif identity == 1 and index == 1:
            before(scene_ready(scene), line,
                   "MULTI_CLIENT KEY id=1 frame=3 code=32 state=1 keysym=100")
        else:
            between(scene, line)
    for identity, scene in ((2, 1), (1, 4)):
        for device in ("KEYBOARD", "POINTER"):
            between(scene, f"MULTI_CLIENT {device}_LEAVE id={identity} index=0 closing=0")
    before("SMITHAY_MULTI FOCUS previous=0 current=2 reason=initial",
           "MULTI_CLIENT POINTER_ENTER id=2 index=0 x_fixed=2048 y_fixed=2048",
           "MULTI_CLIENT KEY id=2 frame=0 code=30 state=1 keysym=97")
    between(1, "MULTI_CLIENT POINTER_ENTER id=1 index=0 x_fixed=2048 y_fixed=2048")
    between(4, "MULTI_CLIENT POINTER_ENTER id=2 index=1 x_fixed=14336 y_fixed=10240")
    expected_server = {wire(line) for line in expected_server}
    expected_client = {wire(line) for line in expected_client}
    assert set(line for line, _ in server) == expected_server, ("Unexpected/missing server markers", set(line for line, _ in server) ^ expected_server)
    assert set(line for line, _ in client) == expected_client, ("Unexpected/missing client markers", set(line for line, _ in client) ^ expected_client)
    endings = rows(data, "EL0 pid=")
    expected_exits = [f"EL0 pid={pid} Exited code=0 free_pages={free} esr=0x0 far=0x0"
                      for pid, free in ((3, 48), (2, 56), (1, 64))]
    assert [line for line, _ in endings] == expected_exits, endings
    for identity, end in ((2, endings[0][1]), (1, endings[1][1])):
        exit_marker = f"SMITHAY_MULTI EXIT id={identity} child={identity+1} status=0"
        before(f"MULTI_CLIENT CLOSE id={identity} count=1", f"SMITHAY_MULTI UNMAP id={identity}",
               client_done(identity))
        assert positions[client_done(identity)] < end < positions[exit_marker]
        before(exit_marker, scene_ready(7 if identity == 2 else 9))
    before(scene_ready(7), "MULTI_CLIENT KEY id=1 frame=3 code=32 state=1 keysym=100", scene_ready(8))
    before(READY, CANVAS, scene_ready(0))
    before(scene_ready(9), TOTAL, SUCCESS)
    assert positions[SUCCESS] < endings[2][1]
    return dict(server_markers=[line for line, _ in server], client_markers=[line for line, _ in client],
                configure_serials=configure_serials, keymap_bytes=keymap_sizes,
                exit_records=expected_exits, scenes=10, commits=9, pixels=122880,
                configures=7, acknowledgements=7, closes=2, concurrent_clients=2,
                focus_transitions=5, physical_input_events=18)


def validate_resources(before, after, processes, heap_pages):
    reclaimed(before)
    reclaimed(after)
    assert 1 in processes and set(processes) <= {1, 2, 3}, processes
    for pid, row in processes.items():
        for name, value in dict(parent_pid=0 if pid == 1 else 1, state="Exited", code=0,
                                exit_signal=0, esr=0, far=0, free_pages=64, heap_pages=0,
                                heap_free=heap_pages, image_pages=0, image_free=4096,
                                thread_count=0, thread_peak=1, thread_admissions=0,
                                guard_selections=0, thread_guard_selections=0,
                                rank_model=12289, cpu_model=12290).items():
            assert row.get(name) == value, (name, value, row)
        assert row["ai_selections"] > 0 and row["syscalls"] > 0, row
    for domain in DOMAINS:
        old, new = before["ai"][domain], after["ai"][domain]
        assert new["requests"] == sum(new[k] for k in ("committed", "denied", "capacity", "invalid", "failed")), (domain, new)
        assert new["ai"] <= new["approved"] <= new["proposals"] <= new["requests"], (domain, new)
        assert new["grant_units"] == new["release_units"], (domain, new)
        for name in ("requests", "committed", "denied", "capacity", "invalid", "failed",
                     "proposals", "approved", "ai", "grant_units", "release_units"):
            assert new[name] >= old[name], (domain, name, old, new)
        for name in ("denied", "capacity", "invalid", "failed"):
            assert new[name] == old[name], ("Unexpected admission rejection", domain, name, old, new)
        if domain in ("process", "anonymous", "elf", "unix", "spawn_receipt",
                      "shared_objects", "shared_pages", "shared_mappings",
                      "ancillary_messages", "ancillary_references"):
            assert new["ai"] > old["ai"] and new["committed"] > old["committed"], (domain, old, new)
            if domain != "unix":
                assert new["grant_units"] > old["grant_units"], (domain, old, new)
    old, new = before["ai"]["display"], after["ai"]["display"]
    assert new["available"] == "true" and new["model"] == 24577 and new["phase"] == "Idle", new
    assert new["failed"] == old["failed"] == 0, new
    assert new["admitted"] == new["submitted"] == new["completed"], new
    assert new["admitted"] == new["ai_admitted"] + new["guard_admitted"], new
    assert new["guard_admitted"] == old["guard_admitted"], ("Display bypassed local AI", old, new)
    assert new["ai_admitted"] - old["ai_admitted"] == new["completed"] - old["completed"] == 30, new


def provenance(elf, server, client):
    kernel = elf.read_bytes()
    layout = inspect_elf(kernel)
    inputs = {elf: digest(elf), server: digest(server), client: digest(client)}
    for program in (server, client):
        binary = program.read_bytes()
        assert kernel.count(binary) == 1, ("Exact program missing/duplicated", program)
        assert any(binary in kernel[load["offset"]:load["offset"]+load["size"]]
                   for load in layout["loads"] if not load["flags"] & 2), program
    manifest_path = elf.parent / "kernel-source-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert "kernel/src/user/shared_memory.rs" in manifest and "crates/posix/src/epoll.rs" in manifest
    inputs[manifest_path] = digest(manifest_path)
    bind_inputs(inputs, {ROOT / name: value for name, value in manifest.items()})
    for program, kind in ((server, "probe"), (client, "client")):
        path = program.parent / "build-report.json"
        report = json.loads(path.read_text())
        assert report["status"] == "cross-built" and report[kind]["sha256"] == digest(program), path
        assert inspect_program(program) == report[kind], ("ELF layout differs from build evidence", program)
        inputs[path] = digest(path)
        if kind == "client":
            assert report["protocol"] == dict(
                fd=3, compositor_version=4, seat_version=7, shm_format="ARGB8888",
                identities=[1, 2], xdg_wm_base_version=1, window_size=[64, 48],
                frame_seeds={"1": [0, 272, 48, 273, 32], "2": [0, 30, 272, 46]},
                input_codes={"1": [272, 48, 273, 32, 16], "2": [30, 272, 46, 16]},
                activation={"1": [False, True, False, True], "2": [True, False, True]},
                shared_pixels_written_after_import=True, final_key=16)
            assert {str(ROOT / name) for name in (
                "user/ported/smithay_multi_client.c", "tools/build_smithay_multi_client.py",
                "tools/build_smithay_wayland_client.py", "ports/cosmic/smithay-multi-client-source.json")
            } <= set(report["inputs_sha256"])
            bind_inputs(inputs, {Path(p): value for p, value in report["inputs_sha256"].items()})
            assert set(report["generated"]) == {"xdg-shell.xml", "xdg-shell-client-protocol.h",
                                                 "xdg-shell-protocol.c"}
            for name, generated in report["generated"].items():
                generated_path = program.parent / "generated" / name
                assert generated["path"] == str(generated_path)
                assert str(generated_path) in report["inputs_sha256"]
                bind_inputs(inputs, {generated_path: generated["sha256"]})
            symbols = Path(report["symbols"]["file"])
            assert inspect_program(symbols) == report["symbols"]
            bind_inputs(inputs, {symbols: report["symbols"]["sha256"]})
            continue
        base = program.parent
        assert report["build_profile"] == dict(
            manifest=str(ROOT / "ports/cosmic/smithay-multi-source.json"),
            source=str(ROOT / "ports/cosmic/smithay-multi/main.rs"), binary_stem="smithay-multi", lto="fat")
        assert str(ROOT / "tools/build_smithay_multi.py") in report["helper_sha256"]
        assert set(report["modules_sha256"]) == {str(ROOT / name) for name in (
            "ports/cosmic/smithay-wayland/native.rs", "ports/cosmic/smithay-wayland/us.xkb",
            "ports/cosmic/smithay-multi/scene.rs")}, "All compiled native/keymap/scene modules must be bound"
        source_paths = {
            "ports/cosmic/smithay-multi-source.json": "manifest_sha256",
            "ports/cosmic/smithay-multi/main.rs": "source_sha256",
            "ports/cosmic/smithay-wayland.Cargo.lock": "cargo_lock_sha256",
            "tools/build_smithay_wayland.py": "builder_sha256",
            "artifacts/cosmic-sources/cosmic-comp-epoch/Cargo.lock": "cosmic_lock_sha256",
        }
        for name, field in source_paths.items():
            inputs[ROOT / name] = report[field]
            inputs[base / "provenance" / Path(name).name] = report[field]
        inputs[base / "source/src/main.rs"] = report["source_sha256"]
        inputs[base / "source/Cargo.lock"] = report["cargo_lock_sha256"]
        for name, value in report["modules_sha256"].items():
            inputs[Path(name)] = value
            inputs[base / "provenance" / Path(name).name] = value
            inputs[base / "source/src" / Path(name).name] = value
        for name, value in report["patches_sha256"].items():
            inputs[ROOT / name] = value
            inputs[base / "provenance" / Path(name).name] = value
        for name in ("cargo_inputs_sha256", "generated_bindings", "compiled_artifacts_sha256"):
            bind_inputs(inputs, {base / p: value for p, value in report[name].items()})
        for name in ("static_inputs_sha256", "helper_sha256"):
            bind_inputs(inputs, {Path(p): value for p, value in report[name].items()})
        for name in ("mesa", "xkbcommon"):
            inputs[base / (name + "-build-report.json")] = report[name + "_report_sha256"]
        assert tree_identity(base / "source/smithay")["sha256"] == report["patched_source_tree_sha256"]
        assert tree_identity(base / "vendor")["sha256"] == report["vendor_tree_sha256"]
        pages = len({page for header in report["probe"]["program_headers"]
                     if header["type"] == 1 and header["memsz"]
                     for page in range(header["vaddr"] // 4096,
                                       (header["vaddr"] + header["memsz"] + 4095) // 4096)})
        assert report["stack_pages"] == 64 and report["image_pages"] == pages
        assert report["admission_pages"] == pages + 64 <= 4096
        release = tomllib.loads((base / "source/Cargo.toml").read_text())["profile"]["release"]
        assert release["lto"] == "fat" and release["opt-level"] == "s" and release["codegen-units"] == 1
        model_paths = [ROOT / name for name in (
            "Cargo.toml", "Cargo.lock", ".cargo/config.toml", "rust-toolchain.toml")]
        for name in ("ai-runtime", "kernel-core", "contracts"):
            directory = ROOT / "crates" / name
            model_paths += [directory / "Cargo.toml", *sorted(directory.rglob("*.rs"))]
        assert set(report["model_inputs_sha256"]) == {str(path) for path in model_paths}
        for model_path in model_paths:
            value = report["model_inputs_sha256"][str(model_path)]
            relative = model_path.relative_to(ROOT)
            if str(relative) in manifest:
                assert manifest[str(relative)] == value, ("Kernel/preflight model disagreement", relative)
            bind_inputs(inputs, {model_path: value, base / "provenance/model" / relative: value})
        expected_decision = dict(free=4096, requested=pages+64, allowed=True, model=8195)
        assert report["model_preflight"] == expected_decision, "Existing local AI must admit this ELF"
        assert json.loads((base / "logs/model-preflight.log").read_text()) == expected_decision
        model_program = "target/debug/examples/check_exec_admission"
        assert set(report["model_preflight_executable_sha256"]) == {model_program}
        model_hash = report["model_preflight_executable_sha256"][model_program]
        bind_inputs(inputs, {base / model_program: model_hash})
        assert digest(base / model_program) == model_hash
        decision = subprocess.check_output([str(base / model_program), "4096", str(pages+64)],
                                           env=env(), text=True, timeout=10)
        assert json.loads(decision) == expected_decision, "Actual compiled local model differs from receipt"
        assert report["manifest_projection"]["retained_mandatory_dependencies"] is True
        assert {"wayland_frontend", "backend_egl_static", "renderer_gl",
                "cyxia_sync_shm_drop", "cyxia_precompiled_keymap"} <= set(report["features"])
        names = {p["id"]: p["name"] for p in report["resolved_packages"]}
        resolved = [features for identity, features in report["resolved_features"].items()
                    if names[identity] == "smithay"]
        assert len(resolved) == 1 and set(report["features"]) <= set(resolved[0])
        bind_inputs(inputs, {base / "logs" / p: value for p, value in report["logs"].items()})
        bind_inputs(inputs, {base / "provenance" / Path(p).name: value
                       for p, value in report["helper_sha256"].items()})
        inputs[Path(report["symbols"]["file"])] = report["symbols"]["sha256"]
        inputs[base / "native/libunwind.a"] = report["rust_unwind_sha256"]
        target_lib = Path(subprocess.check_output(
            [str(RUST_BIN / "rustc"), "--print", "target-libdir", "--target", "aarch64-unknown-linux-musl"],
            env=env(), text=True, timeout=10).strip())
        bind_inputs(inputs, {target_lib / p: value for p, value in report["rust_target_rlibs_sha256"].items()})
        inputs[target_lib / "self-contained/libunwind.a"] = report["rust_unwind_sha256"]
        inputs[ROOT / "artifacts/sysroot/aarch64-musl/bin/aarch64-linux-musl-cc"] = report["target_driver_sha256"]
    for name in ("verify_smithay_multi.py", "verify_smithay_xdg.py", "verify_shared_objects.py", "verify_edge.py",
                 "verify_ported.py", "verify_x11.py", "build_cosmic.py", "check_elf.py",
                 "verify_ai_system.py", "build_sysroot.py", "shell.py", "transport.py", "doctor.py", "run_qemu.py"):
        path = ROOT / "tools" / name
        bind_inputs(inputs, {path: digest(path)})
    for path, expected in inputs.items():
        assert digest(path) == expected, ("Changed evidence input", path)
    return dict(inputs_sha256={str(path): value for path, value in inputs.items()},
                kernel_sha256=digest(elf), server_sha256=digest(server), client_sha256=digest(client),
                profile=boot_profile(kernel), kernel_source_count=len(manifest))


def wait_marker(guest, start, marker, timeout=120):
    deadline = time.monotonic() + timeout
    pattern = re.compile(rb"(?m)^(?:cyxia:/> )?" + re.escape(marker) + rb"\r?$\n")
    data = b""
    while time.monotonic() < deadline:
        guest.poll()
        data = bytes(guest.text[start:])
        check_console(data)
        if pattern.search(data):
            return data
        time.sleep(.01)
    raise TimeoutError((marker, data[-6000:]))


def wait_input_target(guest, start, scene, timeout=120):
    """Observe the client's callback handling before injecting its next event.

    One libwayland dispatch can consume a frame callback and input together;
    the main loop's FRAME receipt proves it has returned from that dispatch.
    """
    if scene == 9:
        return
    identity, frame, _, _ = TRANSITIONS[scene]
    marker = wire(f"MULTI_CLIENT FRAME PASS id={identity} frame={frame} width=64 height=48 "
                  f"seed={SEEDS[identity][frame]} callback=1 after_import_write=1")
    wait_marker(guest, start, marker.encode(), timeout)


def input_events(scene):
    if scene == 9:
        return []
    if scene in (1, 3, 4):
        dx, dy = (-32, -16) if scene == 1 else (40, 24)
        button = "right" if scene == 3 else "left"
        return [[{"type": "rel", "data": {"axis": "x", "value": dx}},
                 {"type": "rel", "data": {"axis": "y", "value": dy}}],
                *[[{"type": "btn", "data": {"button": button, "down": state}}]
                  for state in (True, False)]]
    key = {0: "a", 2: "b", 5: "c", 6: "q", 7: "d", 8: "q"}[scene]
    return [[{"type": "key", "data": {"key": {"type": "qcode", "data": key},
                                        "down": state}}] for state in (True, False)]


def validate_qmp(transcript, scanouts):
    """Require each real screenshot before the exact physical transition."""
    commands = [row["message"] for row in transcript if row["direction"] == "send"]
    assert commands and commands[0]["execute"] == "qmp_capabilities"
    assert commands[-1]["execute"] == "quit", "Missing final actual guest shutdown"
    assert sum(row["execute"] == "qmp_capabilities" for row in commands) == 1
    assert sum(row["execute"] == "quit" for row in commands) == 1
    assert [row["id"] for row in commands] == list(range(1, len(commands)+1))
    replies = [(index, row["message"]) for index, row in enumerate(transcript)
               if row["direction"] == "receive" and "id" in row["message"]]
    assert len(replies) == len(commands), "Missing or duplicate QMP completion"
    for command in commands:
        sends = [index for index, row in enumerate(transcript)
                 if row["direction"] == "send" and row["message"]["id"] == command["id"]]
        responses = [(index, row) for index, row in replies if row["id"] == command["id"]]
        assert len(sends) == len(responses) == 1
        index, response = responses[0]
        assert response == {"return": {}, "id": command["id"]} and index > sends[0], response
    assert all(row["execute"] in ("qmp_capabilities", "screendump", "input-send-event", "quit")
               for row in commands), "Unexpected host operation"
    relevant = [row for row in commands if row["execute"] in ("screendump", "input-send-event")]
    assert [w["scene"] for w in scanouts] == list(range(10))
    cursor, input_count = 0, 0
    for witness in scanouts:
        attempts = witness["capture_attempts"]
        assert 1 <= attempts <= 300
        captures = relevant[cursor:cursor+attempts]
        assert len(captures) == attempts
        assert all(row["execute"] == "screendump" and
                   row["arguments"] == {"filename": str(Path(witness["path"]).resolve())}
                   for row in captures)
        assert captures[-1]["id"] == witness["capture_qmp_id"]
        cursor += attempts
        expected = input_events(witness["scene"])
        inputs = relevant[cursor:cursor+len(expected)]
        assert [row["execute"] for row in inputs] == ["input-send-event"]*len(expected)
        assert [row["arguments"] for row in inputs] == [{"events": events} for events in expected]
        if expected:
            assert inputs[0]["id"] == witness["input_first_qmp_id"] > witness["capture_qmp_id"]
            assert inputs[-1]["id"] == witness["input_last_qmp_id"]
            assert witness["captured_at"] <= witness["input_started_at"] <= witness["input_finished_at"]
        else:
            assert not any(name in witness for name in
                           ("input_first_qmp_id", "input_last_qmp_id", "input_started_at", "input_finished_at"))
        cursor += len(expected)
        input_count += len(expected)
    assert cursor == len(relevant), "Unaccounted host input or scanout"
    assert input_count == 21
    return dict(scanouts=10, input_commands=input_count, qmp_commands=len(commands))


def verify(elf, server, client, output, iterations=3):
    if output.exists():
        raise FileExistsError("Preserve prior evidence; select a fresh directory")
    output.mkdir(parents=True)
    report = dict(status="FAIL", scope="Bounded real concurrent xdg clients, composition and input focus; not COSMIC desktop",
                  smithay_multi_verified=False, full_cosmic_port=False, cosmic_runtime_verified=False,
                  iterations=iterations, runs=[])
    guest = None
    try:
        assert 1 <= iterations <= 5
        report["provenance"] = provenance(elf, server, client)
        for iteration in range(1, iterations+1):
            run = dict(iteration=iteration, scanouts=[])
            report["runs"].append(run)
            with Guest(elf, output / f"run-{iteration}", graphics=True, rng=True) as guest:
                guest.until(b"cyxia:/> ")
                run["before"] = before = snapshot(guest)
                reclaimed(before)
                start = len(guest.text)
                guest.command("posix exec smithay-multi-probe")
                for scene in range(10):
                    wait_marker(guest, start, scene_ready(scene).encode())
                    wait_input_target(guest, start, scene)
                    if scene == 0:
                        # Both clients have consumed their real frame callbacks
                        # before UART echo can be introduced by the shell query.
                        for identity in (1, 2):
                            wait_marker(guest, start,
                                wire(f"MULTI_CLIENT FRAME PASS id={identity} frame=0 width=64 height=48 "
                                     "seed=0 callback=1 after_import_write=1").encode())
                        wait_marker(guest, start,
                                    wire("MULTI_CLIENT POINTER_ENTER id=2 index=0 x_fixed=2048 y_fixed=2048").encode())
                        run["concurrent_processes"] = parse_processes(guest.command("posix list"))
                        validate_live(run["concurrent_processes"])
                    path = output / f"run-{iteration}" / f"scene-{scene}.ppm"
                    witness = capture(guest, start, path, scene)
                    witness["capture_qmp_id"] = guest.qmp.seq
                    witness["captured_at"] = time.monotonic()
                    guest.poll()
                    scene_waiting(bytes(guest.text[start:]), scene)
                    witness["serial_bytes_before_input"] = len(guest.text) - start
                    run["scanouts"].append(witness)
                    events = input_events(scene)
                    if events:
                        witness["input_started_at"] = time.monotonic()
                        witness["input_first_qmp_id"] = guest.qmp.seq+1
                        for batch in events:
                            event(guest, batch)
                        witness["input_finished_at"] = time.monotonic()
                        witness["input_last_qmp_id"] = guest.qmp.seq
                        witness["input"] = events
                wait_marker(guest, start, b"EL0 pid=1 Exited code=0 free_pages=64 esr=0x0 far=0x0", 60)
                run["observations"] = validate(bytes(guest.text[start:]))
                run["processes"] = processes = parse_processes(guest.command("posix list"))
                run["after"] = after = snapshot(guest)
                validate_resources(before, after, processes, report["provenance"]["profile"]["heap_pages"])
            run["qmp_observations"] = validate_qmp(guest.qmp.transcript, run["scanouts"])
            (guest.output / "qmp.jsonl").write_text("".join(json.dumps(row) + "\n" for row in guest.qmp.transcript))
            run["evidence_sha256"] = {str(path): digest(path) for path in sorted(
                (output / f"run-{iteration}").iterdir()) if path.is_file()}
        assert provenance(elf, server, client) == report["provenance"], "Verification inputs changed"
        report.update(status="PASS", smithay_multi_verified=True)
    except Exception as error:
        report["error"] = repr(error)
        if guest is not None and guest.qmp is not None:
            (guest.output / "qmp.jsonl").write_text("".join(json.dumps(row) + "\n" for row in guest.qmp.transcript))
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("elf", "server", "client", "output"):
        parser.add_argument("--"+name, required=True, type=Path)
    parser.add_argument("--iterations", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.server.resolve(), args.client.resolve(), args.output.resolve(), args.iterations)
    print(json.dumps(result, indent=2))
    raise SystemExit(result["status"] != "PASS")


