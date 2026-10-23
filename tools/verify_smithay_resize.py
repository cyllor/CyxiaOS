#!/usr/bin/env python3
"""Verify anchored top/left resize commits and owner-unmap pointer-grab cancellation."""
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
from verify_smithay_multi import bind_inputs, digest, rows, validate_live

WIDTH, HEIGHT = 128, 96
X, Y = 32, 48
# Bottom-to-top (identity, frame, x, y, width, height). The host paints these
# independently from native compositor geometry and renderer implementations.
B = (2, 0, 40, 24, 64, 48)
SCENES = (
    ((1, 0, 24, 16, 64, 48), B),
    (B, (1, 1, 24, 16, 64, 48)),
    (B, (1, 2, 16, 12, 72, 52)),
    (B, (1, 3, 28, 20, 60, 44)),
    (B, (1, 4, 28, 20, 60, 44)),
    (B, (1, 5, 28, 20, 60, 44)),
    (B, (1, 6, 28, 20, 60, 44)),
    (B, (1, 7, 12, 20, 76, 44)),
    (B,), (B,), ((2, 1, 40, 24, 64, 48),), (),
)
SEEDS = {1: (0, 272, 272, 272, 272, 32, 273, 273), 2: (0, 32)}
GRABS = ("none", "resize", "resize", "resize", "none", "none", "resize", "resize", "none", "none", "none", "none")
READY = "SMITHAY_RS READY wayland=1 gles=1 native=1 xdg=1 windows=2"
CANVAS = "SMITHAY_RS CANVAS x=32 y=48 width=128 height=96"
TOTAL = "SMITHAY_RS TOTAL clients=2 cfg=11 acks=11 closes=2 rejected=0"
SUCCESS = "SMITHAY_RS RESULT PASS scenes=12 commits=10 pixels=147456"
CONFIGS = {
    1: ((64, 48, 0, 0), (64, 48, 1, 0), (64, 48, 1, 1),
        (72, 52, 1, 1), (60, 44, 1, 1), (60, 44, 1, 0),
        (60, 44, 1, 1), (76, 44, 1, 1)),
    2: ((64, 48, 1, 0), (64, 48, 0, 0), (64, 48, 1, 0)),
}
FRAME_SCENES = {1: (0, 1, 2, 3, 4, 5, 6, 7), 2: (0, 10)}
FATAL = (b"SMITHAY_RS FAIL", b"RS_CLIENT FAIL", b"KERNEL_FAULT",
         b"panicked", b"EL0 start failed", b"ELF start failed", b"CHECK_FAILED", b"SERVICE_PANIC",
         b"FAIL unexpected exception", b"GRAPHICS_GPU_ERROR")


def check_console(data):
    assert not any(word in data for word in FATAL), data[-6000:]
    assert not re.search(rb"EL0 pid=\d+ (?:Fault|Killed|Exited) code=(?!0\b)\d+", data), data[-6000:]


def scene_ready(scene):
    stack = SCENES[scene]
    top = {0: "none", 1: "A", 2: "B"}[stack[-1][0] if stack else 0]
    return f"SMITHAY_RS SCENE n={scene} top={top} focus={top} win={len(stack)} grab={GRABS[scene]}"


def geometry(scene, window):
    identity, _, x, y, width, height = window
    return f"SMITHAY_RS GEOM n={scene} id={identity} x={x} y={y} w={width} h={height}"


def expected_pixel(scene, x, y):
    for identity, frame, ox, oy, width, height in reversed(SCENES[scene]):
        px, py = x-ox, y-oy
        if 0 <= px < width and 0 <= py < height:
            seed = SEEDS[identity][frame]
            return bytes(((3*px+py+29*identity+47*frame+seed) & 255,
                          (px+5*py+11*identity+31*frame+3*seed) & 255,
                          (7*(px ^ py)+13*identity+19*frame+5*seed) & 255))
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


def frame_ready(identity, frame):
    window = next(window for window in SCENES[FRAME_SCENES[identity][frame]] if window[0] == identity)
    return f"RS_CLIENT FRAME id={identity} f={frame} w={window[4]} h={window[5]} seed={SEEDS[identity][frame]}"


def client_counts(identity):
    frames, keys, buttons, requests = (8, 4, 2, 2) if identity == 1 else (2, 4, 0, 0)
    return f"RS_CLIENT COUNTS id={identity} f={frames} cb={frames} rel={frames} keys={keys} btn={buttons} req={requests}"


def client_done(identity):
    configs = 8 if identity == 1 else 3
    return f"RS_CLIENT RESULT PASS id={identity} cfg={configs} ack={configs} close=1"


def validate(data):
    """Require ACK-bound anchors, real owner removal and physical release drain."""
    check_console(data)
    server, client = rows(data, "SMITHAY_RS"), rows(data, "RS_CLIENT")
    assert all(len(line.encode())+1 <= 64 for line, _ in server+client), "Non-atomic telemetry"
    assert len({line for line, _ in server}) == len(server), "Duplicate server record"
    assert len({line for line, _ in client}) == len(client), "Duplicate client record"
    positions = dict(server+client)
    expected_server, expected_client = {READY, CANVAS, TOTAL, SUCCESS}, set()
    configure_serials, input_serials, configs, buttons, keys, keymaps = [], [], {}, {}, {}, []
    applications = {}

    def before(*lines):
        assert all(line in positions for line in lines), ("Missing causal marker", lines)
        values = [positions[line] for line in lines]
        assert values == sorted(set(values)), ("Invalid causal order", lines, values)

    def between(scene, *lines):
        before(scene_ready(scene), *lines, scene_ready(scene+1))

    def take(prefix, pattern, records, expected):
        found = [line for line, _ in records if line.startswith(prefix)]
        assert len(found) == 1, (prefix, found)
        match = re.fullmatch(pattern, found[0])
        assert match, ("Malformed record", found[0])
        expected.add(found[0])
        return found[0], match

    def serial(value, seen):
        value = int(value)
        assert 0 < value <= 0xffffffff and value not in seen, ("Invalid/reused serial", value)
        seen.append(value)
        return value

    for scene, stack in enumerate(SCENES):
        expected_server.add(scene_ready(scene))
        if scene:
            before(scene_ready(scene-1), scene_ready(scene))
        for window in stack:
            line = geometry(scene, window)
            expected_server.add(line)
            before(line, scene_ready(scene))
            if scene:
                before(scene_ready(scene-1), line)
    for identity in (1, 2):
        spawned = f"SMITHAY_RS SPAWN id={identity} child={identity+1}"
        start = f"RS_CLIENT START id={identity} pid={identity+1} fd=3"
        expected_server.add(spawned)
        expected_client.add(start)
        keymap, match = take(f"RS_CLIENT KEYMAP id={identity} ",
                             rf"RS_CLIENT KEYMAP id={identity} bytes=(\d+)", client, expected_client)
        assert 1 < int(match[1]) <= 65536
        keymaps.append(int(match[1]))
        before(READY, start, keymap)
        for index, (width, height, active, resizing) in enumerate(CONFIGS[identity]):
            prefix = f"SMITHAY_RS CONFIG id={identity} n={index} "
            configured, match = take(prefix, re.escape(prefix)+rf"s=(\d+) w={width} h={height} a={active} r={resizing}",
                                     server, expected_server)
            number = serial(match[1], configure_serials)
            ack = f"SMITHAY_RS ACK id={identity} n={index} s={number}"
            received = f"RS_CLIENT CFG id={identity} n={index} s={number} w={width} h={height} a={active} r={resizing}"
            sent = f"RS_CLIENT ACK id={identity} n={index} s={number}"
            configs[identity, index] = (configured, received, sent, ack, number)
            expected_server.add(ack)
            expected_client.update((received, sent))
            before(configured, received, sent, ack)
            if index == 0:
                before(READY, spawned, configured)
                before(keymap, configured, ack, f"SMITHAY_RS COMMIT id={identity} frame=0 seed=0", scene_ready(0))
            else:
                scene = {1: (0, 0, 1, 2, 3, 5, 6), 2: (0, 7)}[identity][index-1]
                between(scene, configured, ack)
                before(configs[identity, index-1][3], configured)
        for frame, scene in enumerate(FRAME_SCENES[identity]):
            commit = f"SMITHAY_RS COMMIT id={identity} frame={frame} seed={SEEDS[identity][frame]}"
            callback = f"RS_CLIENT CALLBACK id={identity} f={frame} time={scene}"
            release = f"RS_CLIENT RELEASE id={identity} f={frame}"
            window = next(w for w in SCENES[scene] if w[0] == identity)
            config_index = {1: (0, 2, 3, 4, 5, None, 6, 7), 2: (0, 2)}[identity][frame]
            number = 0 if config_index is None else configs[identity, config_index][4]
            anchor = int(identity == 1 and frame in (1, 2, 3, 4, 6, 7))
            applied = f"SMITHAY_RS APPLY id={identity} s={number} anchor={anchor} x={window[2]} y={window[3]}"
            applications[identity, frame] = applied
            expected_server.update((applied, commit))
            expected_client.update((callback, release, frame_ready(identity, frame)))
            before(applied, commit, scene_ready(scene), callback, frame_ready(identity, frame), client_counts(identity))
            before(commit, release, client_counts(identity))
            if config_index is not None:
                before(configs[identity, config_index][3], applied)
            if frame:
                before(frame_ready(identity, frame-1), applied)
                before(scene_ready(scene-1), applied)
        expected_server.update((f"SMITHAY_RS CLOSE id={identity}", f"SMITHAY_RS UNMAP id={identity}",
                                f"SMITHAY_RS EXIT id={identity} child={identity+1} status=0"))
        focus = ("RS_CLIENT FOCUS id=1 ke=1 kl=0 pe=2 pl=2" if identity == 1 else
                 "RS_CLIENT FOCUS id=2 ke=2 kl=1 pe=0 pl=0")
        expected_client.update((f"RS_CLIENT CLOSE id={identity} n=1", client_counts(identity), focus, client_done(identity)))
        before(f"RS_CLIENT CLOSE id={identity} n=1", f"SMITHAY_RS UNMAP id={identity}",
               client_counts(identity), focus, client_done(identity))
        closing = f"RS_CLIENT K_LEAVE id={identity} n=0 closing=1"
        if closing in positions:
            expected_client.add(closing)
            before(f"RS_CLIENT CLOSE id={identity} n=1", closing, client_counts(identity))
    assert keymaps[0] == keymaps[1]
    for scene, identity, code, state in ((0, 1, 272, 1), (3, 1, 272, 0), (5, 1, 273, 1), (8, 0, 273, 0)):
        prefix = f"SMITHAY_RS BUTTON n={scene} id={identity} code={code} state={state} "
        line, match = take(prefix, re.escape(prefix)+r"s=(\d+)", server, expected_server)
        number = serial(match[1], input_serials)
        buttons[scene] = (line, number)
        completed = f"SMITHAY_RS INPUT n={scene} kind=button code={code} state={state}"
        expected_server.add(completed)
        between(scene, line, completed)
        if state:
            received = f"RS_CLIENT BUTTON id=1 n={0 if scene == 0 else 1} s={number} code={code} state=1"
            expected_client.add(received)
            between(scene, line, received)
            before(configs[1, 1][2], received)
    for scene, identity, frame, code, symbol in ((4, 1, 4, 32, 100), (7, 1, 7, 16, 113),
                                               (9, 2, 0, 32, 100), (10, 2, 1, 16, 113)):
        pairs = []
        for state in (1, 0):
            prefix = f"SMITHAY_RS KEY n={scene} id={identity} code={code} state={state} "
            line, match = take(prefix, re.escape(prefix)+r"s=(\d+)", server, expected_server)
            serial(match[1], input_serials)
            received = f"RS_CLIENT KEY id={identity} f={frame} code={code} state={state} sym={symbol}"
            expected_client.add(received)
            between(scene, line, received)
            pairs.append((line, received))
        before(pairs[0][0], pairs[1][0])
        before(frame_ready(identity, frame), pairs[0][1], pairs[1][1])
        completed = f"SMITHAY_RS INPUT n={scene} kind=key code={code}"
        expected_server.add(completed)
        between(scene, pairs[1][0], completed)
        keys[scene] = pairs
        if code == 16:
            before(completed, f"SMITHAY_RS CLOSE id={identity}", f"RS_CLIENT CLOSE id={identity} n=1")
            before(pairs[1][1], f"RS_CLIENT CLOSE id={identity} n=1", client_done(identity), scene_ready(scene+1))
        else:
            before(pairs[1][1], applications[identity, frame+1], f"SMITHAY_RS COMMIT id={identity} frame={frame+1} seed=32")
    assert set(configure_serials).isdisjoint(input_serials), "Configure/input serial collision"
    reqs = {}
    for number, scene, edge, config_index in ((0, 0, 5, 2), (1, 5, 4, 6)):
        pressed_serial = buttons[scene][1]
        sent = f"RS_CLIENT REQ id=1 n={number} kind=resize s={pressed_serial} edge={edge}"
        received = f"SMITHAY_RS REQUEST id=1 n={number} kind=resize s={pressed_serial} edge={edge}"
        auth = f"SMITHAY_RS AUTH id=1 n={number} s={pressed_serial} held={pressed_serial} owner=1"
        grabbed = f"SMITHAY_RS GRAB id=1 kind=resize s={pressed_serial}"
        expected_client.add(sent)
        expected_server.update((received, auth, grabbed))
        before(f"RS_CLIENT BUTTON id=1 n={number} s={pressed_serial} code={272 if number == 0 else 273} state=1",
               sent, received, auth, configs[1, config_index][0], grabbed)
        between(scene, sent, grabbed)
        reqs[number] = grabbed
    for scene, x, y, width, height, config_index in ((1, 16, 12, 72, 52, 3),
                                                   (2, 28, 20, 60, 44, 4), (6, 12, 20, 76, 44, 7)):
        dx, dy = {1: (-8, -4), 2: (12, 8), 6: (-16, 0)}[scene]
        motion = f"SMITHAY_RS MOTION n={scene} dx={dx} dy={dy}"
        drag = f"SMITHAY_RS DRAG id=1 kind=resize n={scene} x={x} y={y} w={width} h={height}"
        completed = f"SMITHAY_RS INPUT n={scene} kind=motion dx={dx} dy={dy}"
        expected_server.update((motion, drag, completed))
        between(scene, motion, drag, completed)
        before(reqs[int(scene == 6)], motion, configs[1, config_index][0], drag)
    ended = f"SMITHAY_RS END id=1 kind=resize s={buttons[3][1]}"
    expected_server.add(ended)
    between(3, buttons[3][0], configs[1, 5][0], ended, "SMITHAY_RS INPUT n=3 kind=button code=272 state=0")
    cancelled = "SMITHAY_RS CANCEL id=1 reason=unmap"
    quarantine = "SMITHAY_RS POINTER n=8 grabbed=1 held=1 focus=0"
    drained = "SMITHAY_RS POINTER n=9 grabbed=0 held=0 focus=0"
    expected_server.update((cancelled, quarantine, drained))
    before(reqs[1], frame_ready(1, 7), keys[7][0][0], "RS_CLIENT CLOSE id=1 n=1",
           cancelled, quarantine, "SMITHAY_RS UNMAP id=1", scene_ready(8))
    between(8, buttons[8][0], drained, "SMITHAY_RS INPUT n=8 kind=button code=273 state=0")
    for previous, current, reason, scene in ((0, 2, "initial", None), (2, 1, "click", 0),
                                            (1, 2, "unmap", 7), (2, 0, "unmap", 10)):
        line = f"SMITHAY_RS FOCUS previous={previous} current={current} reason={reason}"
        expected_server.add(line)
        if scene is None:
            before("SMITHAY_RS COMMIT id=1 frame=0 seed=0", line, scene_ready(0))
            before("SMITHAY_RS COMMIT id=2 frame=0 seed=0", line)
        else:
            between(scene, line)
            if reason == "unmap":
                before(f"RS_CLIENT CLOSE id={previous} n=1", line)
    for identity, number in ((1, 0), (2, 0), (2, 1)):
        expected_client.add(f"RS_CLIENT K_ENTER id={identity} n={number}")
    expected_client.add("RS_CLIENT K_LEAVE id=2 n=0 closing=0")
    before("SMITHAY_RS FOCUS previous=0 current=2 reason=initial", "RS_CLIENT K_ENTER id=2 n=0")
    before("SMITHAY_RS FOCUS previous=2 current=1 reason=click", "RS_CLIENT K_ENTER id=1 n=0")
    before("SMITHAY_RS FOCUS previous=2 current=1 reason=click", "RS_CLIENT K_LEAVE id=2 n=0 closing=0")
    before("SMITHAY_RS FOCUS previous=1 current=2 reason=unmap", "RS_CLIENT K_ENTER id=2 n=1")
    before("RS_CLIENT K_ENTER id=2 n=0", "RS_CLIENT K_LEAVE id=2 n=0 closing=0", "RS_CLIENT K_ENTER id=2 n=1")
    between(0, "RS_CLIENT K_ENTER id=1 n=0", f"RS_CLIENT BUTTON id=1 n=0 s={buttons[0][1]} code=272 state=1")
    between(0, "RS_CLIENT K_LEAVE id=2 n=0 closing=0")
    for number in (0, 1):
        enter = f"RS_CLIENT P_ENTER id=1 n={number} x=2048 y=2048"
        leave = f"RS_CLIENT P_LEAVE id=1 n={number} closing=0"
        expected_client.update((enter, leave))
        if number == 0:
            before("SMITHAY_RS FOCUS previous=0 current=2 reason=initial", enter, buttons[0][0])
        else:
            before(ended, enter, keys[4][0][0])
        before(reqs[number], leave, f"SMITHAY_RS MOTION n={1 if number == 0 else 6} dx={-8 if number == 0 else -16} dy={-4 if number == 0 else 0}")
    for scene in range(11):
        dx, dy = {1: (-8, -4), 2: (12, 8), 6: (-16, 0)}.get(scene, (0, 0))
        first_native = (buttons[scene][0] if scene in buttons else keys[scene][0][0] if scene in keys else
                        f"SMITHAY_RS MOTION n={scene} dx={dx} dy={dy}")
        for receipt in input_receipts(scene):
            before(receipt, first_native)
    assert set(line for line, _ in server) == expected_server, ("Unexpected/missing server records", set(line for line, _ in server)^expected_server)
    assert set(line for line, _ in client) == expected_client, ("Unexpected/missing client records", set(line for line, _ in client)^expected_client)
    endings = rows(data, "EL0 pid=")
    expected_exits = [f"EL0 pid={pid} Exited code=0 free_pages={free} esr=0x0 far=0x0"
                      for pid, free in ((2, 48), (3, 56), (1, 64))]
    assert [line for line, _ in endings] == expected_exits, endings
    for identity, ending, scene in ((1, endings[0][1], 8), (2, endings[1][1], 11)):
        exited = f"SMITHAY_RS EXIT id={identity} child={identity+1} status=0"
        assert positions[client_done(identity)] < ending < positions[exited]
        before(exited, scene_ready(scene))
    before(READY, CANVAS, scene_ready(0))
    before(scene_ready(11), TOTAL, SUCCESS)
    assert positions[SUCCESS] < endings[2][1]
    return dict(server_markers=[line for line, _ in server], client_markers=[line for line, _ in client],
                configure_serials=configure_serials, native_input_serials=input_serials, keymap_bytes=keymaps,
                resize_serials=[buttons[0][1], buttons[5][1]], resize_edges=[5, 4],
                scenes=12, commits=10, pixels=147456, configures=11, acknowledgements=11,
                accepted_grabs=2, cancelled_grabs=1, drained_releases=1, closes=2, concurrent_clients=2,
                exit_records=expected_exits)


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
    assert new["ai_admitted"] - old["ai_admitted"] == new["completed"] - old["completed"] == 36, new


def client_protocol():
    return dict(fd=3, compositor_version=4, seat_version=7, shm_format="ARGB8888",
                identities=[1, 2], xdg_wm_base_version=1,
                frame_sizes={"1": [[64, 48], [64, 48], [72, 52], [60, 44], [60, 44],
                                   [60, 44], [60, 44], [76, 44]],
                             "2": [[64, 48], [64, 48]]},
                frame_seeds={str(identity): list(seeds) for identity, seeds in SEEDS.items()},
                configure_states={str(identity): [list(row) for row in configs] for identity, configs in CONFIGS.items()},
                request_edges={"1": [5, 4], "2": []}, cancellation="owner-unmap-while-button-held",
                ordinary_repaint_after_anchored_resize=True, shared_pixels_written_after_import=True, final_key=16)


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
            assert report["protocol"] == client_protocol()
            assert {str(ROOT / name) for name in (
                "user/ported/smithay_resize_client.c", "tools/build_smithay_resize_client.py",
                "tools/build_smithay_wayland_client.py", "ports/cosmic/smithay-resize-client-source.json")
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
            manifest=str(ROOT / "ports/cosmic/smithay-resize-source.json"),
            source=str(ROOT / "ports/cosmic/smithay-resize/main.rs"), binary_stem="smithay-resize", lto="fat")
        assert str(ROOT / "tools/build_smithay_resize.py") in report["helper_sha256"]
        assert set(report["modules_sha256"]) == {str(ROOT / name) for name in (
            "ports/cosmic/smithay-wayland/native.rs", "ports/cosmic/smithay-wayland/us.xkb",
            "ports/cosmic/smithay-multi/scene.rs", "ports/cosmic/smithay-resize/geometry.rs")}, "All compiled native/keymap/scene modules must be bound"
        source_paths = {
            "ports/cosmic/smithay-resize-source.json": "manifest_sha256",
            "ports/cosmic/smithay-resize/main.rs": "source_sha256",
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
    for name in ("verify_smithay_resize.py", "verify_smithay_multi.py", "verify_smithay_xdg.py", "verify_shared_objects.py", "verify_edge.py",
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


def input_receipts(scene):
    """Real client dispatch barriers before the next native input action."""
    return {
        0: (frame_ready(1, 0), frame_ready(2, 0), "RS_CLIENT P_ENTER id=1 n=0 x=2048 y=2048",
            "RS_CLIENT K_ENTER id=2 n=0"),
        1: (frame_ready(1, 1), "RS_CLIENT P_LEAVE id=1 n=0 closing=0"),
        2: (frame_ready(1, 2),), 3: (frame_ready(1, 3),),
        4: (frame_ready(1, 4), "RS_CLIENT P_ENTER id=1 n=1 x=2048 y=2048"),
        5: (frame_ready(1, 5),),
        6: (frame_ready(1, 6), "RS_CLIENT P_LEAVE id=1 n=1 closing=0"),
        7: (frame_ready(1, 7),), 8: ("RS_CLIENT K_ENTER id=2 n=1",),
        9: ("RS_CLIENT K_ENTER id=2 n=1",), 10: (frame_ready(2, 1),),
    }.get(scene, ())


def wait_input_target(guest, start, scene, timeout=120):
    for marker in input_receipts(scene):
        wait_marker(guest, start, marker.encode(), timeout)


def input_events(scene):
    if scene == 11:
        return []
    if scene in (0, 3, 5, 8):
        return [[{"type": "btn", "data": {"button": "left" if scene < 5 else "right",
                                            "down": scene in (0, 5)}}]]
    if scene in (1, 2, 6):
        dx, dy = {1: (-8, -4), 2: (12, 8), 6: (-16, 0)}[scene]
        return [[{"type": "rel", "data": {"axis": "x", "value": dx}},
                 {"type": "rel", "data": {"axis": "y", "value": dy}}]]
    key = "d" if scene in (4, 9) else "q"
    return [[{"type": "key", "data": {"key": {"type": "qcode", "data": key},
                                        "down": state}}] for state in (True, False)]


def scene_waiting(data, scene):
    check_console(data)
    server = [line for line, _ in rows(data, "SMITHAY_RS")]
    assert server.count(scene_ready(scene)) == 1
    assert not any(line.startswith(f"SMITHAY_RS SCENE n={later} ")
                   for later in range(scene+1, len(SCENES)) for line in server)
    if scene == 11:
        return
    kind = "BUTTON" if scene in (0, 3, 5, 8) else ("MOTION" if scene in (1, 2, 6) else "KEY")
    assert not any(line.startswith(f"SMITHAY_RS {kind} n={scene} ") for line in server), \
        "Native transition preceded its physical host input"


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
        following_sends = [i for i, row in enumerate(transcript) if row["direction"] == "send" and i > sends[0]]
        assert not following_sends or index < following_sends[0], "QMP action began before prior completion"
    assert all(row["execute"] in ("qmp_capabilities", "screendump", "input-send-event", "quit")
               for row in commands), "Unexpected host operation"
    relevant = [row for row in commands if row["execute"] in ("screendump", "input-send-event")]
    assert [w["scene"] for w in scanouts] == list(range(12))
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
    assert input_count == 15
    return dict(scanouts=12, input_commands=input_count, qmp_commands=len(commands))


def verify(elf, server, client, output, iterations=3):
    if output.exists():
        raise FileExistsError("Preserve prior evidence; select a fresh directory")
    output.mkdir(parents=True)
    report = dict(status="FAIL", scope="Native anchored top/left resize and owner-unmap cancellation; not COSMIC desktop",
                  smithay_resize_verified=False, full_cosmic_port=False, cosmic_runtime_verified=False,
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
                guest.command("posix exec smithay-resize-probe")
                for scene in range(12):
                    wait_marker(guest, start, scene_ready(scene).encode())
                    wait_input_target(guest, start, scene)
                    if scene == 0:
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
        report.update(status="PASS", smithay_resize_verified=True)
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

