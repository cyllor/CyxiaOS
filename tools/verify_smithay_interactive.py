#!/usr/bin/env python3
"""Verify actual xdg move/resize grabs, serial authorization and two-client recovery."""
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
    ((1, 0, 8, 8, 64, 48), B),
    (B, (1, 0, 8, 8, 64, 48)),
    (B, (1, 0, 16, 12, 64, 48)),
    (B, (1, 0, 24, 16, 64, 48)),
    (B, (1, 1, 24, 16, 64, 48)),
    (B, (1, 2, 24, 16, 64, 48)),
    (B, (1, 3, 24, 16, 72, 52)),
    (B, (1, 4, 24, 16, 68, 56)),
    (B, (1, 5, 24, 16, 68, 56)),
    (B,), ((2, 1, 40, 24, 64, 48),), (),
)
SEEDS = {1: (0, 272, 273, 273, 273, 273), 2: (0, 32)}
GRABS = ("none", "move", "move", "move", "none", "resize", "resize", "resize", "none", "none", "none", "none")
READY = "SMITHAY_INT READY wayland=1 gles=1 native=1 xdg=1 windows=2"
CANVAS = "SMITHAY_INT CANVAS x=32 y=48 width=128 height=96"
TOTAL = "SMITHAY_INT TOTAL clients=2 cfg=9 acks=9 closes=2 rejected=3"
SUCCESS = "SMITHAY_INT RESULT PASS scenes=12 commits=8 pixels=147456"
CONFIGS = {
    1: ((64, 48, 0, 0), (64, 48, 1, 0), (64, 48, 1, 1),
        (72, 52, 1, 1), (68, 56, 1, 1), (68, 56, 1, 0)),
    2: ((64, 48, 1, 0), (64, 48, 0, 0), (64, 48, 1, 0)),
}
FRAME_SCENES = {1: (0, 4, 5, 6, 7, 8), 2: (0, 10)}
FATAL = (b"SMITHAY_INT FAIL", b"INT_CLIENT FAIL", b"KERNEL_FAULT",
         b"panicked", b"EL0 start failed", b"ELF start failed", b"CHECK_FAILED", b"SERVICE_PANIC",
         b"FAIL unexpected exception", b"GRAPHICS_GPU_ERROR")


def check_console(data):
    assert not any(word in data for word in FATAL), data[-6000:]
    assert not re.search(rb"EL0 pid=\d+ (?:Fault|Killed|Exited) code=(?!0\b)\d+", data), data[-6000:]


def scene_ready(scene):
    stack = SCENES[scene]
    top = {0: "none", 1: "A", 2: "B"}[stack[-1][0] if stack else 0]
    return f"SMITHAY_INT SCENE n={scene} top={top} focus={top} win={len(stack)} grab={GRABS[scene]}"


def geometry(scene, window):
    identity, _, x, y, width, height = window
    return f"SMITHAY_INT GEOM n={scene} id={identity} x={x} y={y} w={width} h={height}"


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
    return f"INT_CLIENT FRAME id={identity} f={frame} w={window[4]} h={window[5]} seed={SEEDS[identity][frame]}"


def client_counts(identity):
    frames, keys, buttons, requests = (6, 2, 2, 4) if identity == 1 else (2, 4, 0, 1)
    return f"INT_CLIENT COUNTS id={identity} f={frames} cb={frames} rel={frames} keys={keys} btn={buttons} req={requests}"


def client_done(identity):
    configs = 6 if identity == 1 else 3
    return f"INT_CLIENT RESULT PASS id={identity} cfg={configs} ack={configs} close=1 peer=1"


def validate(data):
    """Require genuine current-serial authority, wire ACKs and independent clients."""
    check_console(data)
    server, client = rows(data, "SMITHAY_INT"), rows(data, "INT_CLIENT")
    assert all(len(line.encode())+1 <= 64 for line, _ in server+client), "Non-atomic telemetry"
    assert len({line for line, _ in server}) == len(server), "Duplicate server record"
    assert len({line for line, _ in client}) == len(client), "Duplicate client record"
    positions = dict(server+client)
    expected_server, expected_client = {READY, CANVAS, TOTAL, SUCCESS}, set()
    configure_serials, input_serials, configs, buttons, keys, keymaps = [], [], {}, {}, {}, []

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
        spawned = f"SMITHAY_INT SPAWN id={identity} child={identity+1}"
        expected_server.add(spawned)
        start = f"INT_CLIENT START id={identity} pid={identity+1} fd=3 peer=4"
        expected_client.add(start)
        keymap, match = take(f"INT_CLIENT KEYMAP id={identity} ",
                             rf"INT_CLIENT KEYMAP id={identity} bytes=(\d+)", client, expected_client)
        assert 1 < int(match[1]) <= 65536
        keymaps.append(int(match[1]))
        before(READY, start, keymap)
        for index, (width, height, active, resizing) in enumerate(CONFIGS[identity]):
            prefix = f"SMITHAY_INT CONFIG id={identity} n={index} "
            configured, match = take(prefix, re.escape(prefix)+rf"s=(\d+) w={width} h={height} a={active} r={resizing}",
                                     server, expected_server)
            number = serial(match[1], configure_serials)
            ack = f"SMITHAY_INT ACK id={identity} n={index} s={number}"
            received = f"INT_CLIENT CFG id={identity} n={index} s={number} w={width} h={height} a={active} r={resizing}"
            sent = f"INT_CLIENT ACK id={identity} n={index} s={number}"
            configs[identity, index] = (configured, received, sent, ack)
            expected_server.add(ack)
            expected_client.update((received, sent))
            before(configured, received, sent, ack)
            if index == 0:
                before(READY, spawned, configured)
                before(keymap, configured, ack, f"SMITHAY_INT COMMIT id={identity} frame=0 seed=0", scene_ready(0))
            else:
                scene = {1: (0, 4, 5, 6, 7), 2: (0, 8)}[identity][index-1]
                between(scene, configured, ack)
                before(configs[identity, index-1][-1], configured)
        for frame, scene in enumerate(FRAME_SCENES[identity]):
            commit = f"SMITHAY_INT COMMIT id={identity} frame={frame} seed={SEEDS[identity][frame]}"
            callback = f"INT_CLIENT CALLBACK id={identity} f={frame} time={scene}"
            release = f"INT_CLIENT RELEASE id={identity} f={frame}"
            expected_server.add(commit)
            expected_client.update((callback, release, frame_ready(identity, frame)))
            before(commit, scene_ready(scene), callback, frame_ready(identity, frame), client_counts(identity))
            before(commit, release, client_counts(identity))
            if frame:
                before(frame_ready(identity, frame-1), commit)
            if identity == 1 and frame >= 2:
                before(configs[1, frame][-1], commit)
        expected_server.update((f"SMITHAY_INT CLOSE id={identity}", f"SMITHAY_INT UNMAP id={identity}",
                                f"SMITHAY_INT EXIT id={identity} child={identity+1} status=0"))
        focus = (f"INT_CLIENT FOCUS id=1 ke=1 kl=0 pe=3 pl=2" if identity == 1 else
                 "INT_CLIENT FOCUS id=2 ke=2 kl=1 pe=0 pl=0")
        expected_client.update((f"INT_CLIENT CLOSE id={identity} n=1", client_counts(identity), focus, client_done(identity)))
        before(f"INT_CLIENT CLOSE id={identity} n=1", f"SMITHAY_INT UNMAP id={identity}",
               client_counts(identity), focus, client_done(identity))
        for device in ("K", "P"):
            closing = f"INT_CLIENT {device}_LEAVE id={identity} n=0 closing=1"
            if closing in positions:
                assert not (identity == 2 and device == "P"), "B never had pointer focus"
                expected_client.add(closing)
                before(f"INT_CLIENT CLOSE id={identity} n=1", closing, client_counts(identity))
    assert keymaps[0] == keymaps[1]
    for scene, code, state in ((0, 272, 1), (3, 272, 0), (4, 273, 1), (7, 273, 0)):
        prefix = f"SMITHAY_INT BUTTON n={scene} id=1 code={code} state={state} "
        line, match = take(prefix, re.escape(prefix)+r"s=(\d+)", server, expected_server)
        number = serial(match[1], input_serials)
        buttons[scene] = (line, number)
        completed = f"SMITHAY_INT INPUT n={scene} kind=button code={code} state={state}"
        expected_server.add(completed)
        between(scene, line, completed)
        if state:
            received = f"INT_CLIENT BUTTON id=1 n={0 if scene == 0 else 1} s={number} code={code} state=1"
            expected_client.add(received)
            between(scene, line, received)
            before(configs[1, 1][2], received)
            before(frame_ready(1, 0 if scene == 0 else 1), received)
    for scene, identity, frame, code, symbol in ((8, 1, 5, 16, 113), (9, 2, 0, 32, 100), (10, 2, 1, 16, 113)):
        pairs = []
        for state in (1, 0):
            prefix = f"SMITHAY_INT KEY n={scene} id={identity} code={code} state={state} "
            line, match = take(prefix, re.escape(prefix)+r"s=(\d+)", server, expected_server)
            serial(match[1], input_serials)
            received = f"INT_CLIENT KEY id={identity} f={frame} code={code} state={state} sym={symbol}"
            expected_client.add(received)
            between(scene, line, received)
            pairs.append((line, received))
        before(pairs[0][0], pairs[1][0])
        before(frame_ready(identity, frame), pairs[0][1], pairs[1][1])
        before(configs[identity, 5 if identity == 1 else 2][2], pairs[0][1])
        completed = f"SMITHAY_INT INPUT n={scene} kind=key code={code}"
        expected_server.add(completed)
        between(scene, pairs[1][0], completed)
        keys[scene] = pairs
        if code == 16:
            before(completed, f"SMITHAY_INT CLOSE id={identity}", f"INT_CLIENT CLOSE id={identity} n=1")
            before(pairs[1][1], f"INT_CLIENT CLOSE id={identity} n=1", client_done(identity), scene_ready(scene+1))
        else:
            before(pairs[1][1], "SMITHAY_INT COMMIT id=2 frame=1 seed=32")
    assert set(configure_serials).isdisjoint(input_serials), "Configure/input serial collision"
    move_serial, resize_serial = buttons[0][1], buttons[4][1]
    requests = ((1, 0, "move", 0, 0, 0, 0, "serial"),
                (2, 0, "move", move_serial, 0, move_serial, 1, "owner"),
                (1, 1, "move", move_serial, 0, move_serial, 1, None),
                (1, 2, "move", move_serial, 0, 0, 0, "serial"),
                (1, 3, "resize", resize_serial, 10, resize_serial, 1, None))
    reqs = {}
    for identity, number, kind, requested, edge, held, owner, rejection in requests:
        sent = f"INT_CLIENT REQ id={identity} n={number} kind={kind} s={requested}"+(f" edge={edge}" if kind == "resize" else "")
        received = f"SMITHAY_INT REQUEST id={identity} n={number} kind={kind} s={requested} edge={edge}"
        auth = f"SMITHAY_INT AUTH id={identity} n={number} s={requested} held={held} owner={owner}"
        expected_client.add(sent)
        expected_server.update((received, auth))
        before(sent, received, auth)
        outcome = (f"SMITHAY_INT REJECT id={identity} n={number} why={rejection}" if rejection else
                   f"SMITHAY_INT GRAB id={identity} kind={kind} s={requested}")
        expected_server.add(outcome)
        before(auth, outcome)
        reqs[identity, number] = (sent, received, auth, outcome)
    before("SMITHAY_INT COMMIT id=1 frame=0 seed=0", reqs[1, 0][1], reqs[1, 0][-1], scene_ready(0))
    before(scene_ready(0), reqs[2, 0][0], reqs[2, 0][-1], reqs[1, 1][0], reqs[1, 1][-1], scene_ready(1))
    before(scene_ready(3), reqs[1, 2][0], reqs[1, 2][-1], scene_ready(4))
    before(scene_ready(4), reqs[1, 3][0], reqs[1, 3][-1], scene_ready(5))
    before(reqs[1, 3][2], configs[1, 2][0], reqs[1, 3][-1])
    peer = {(identity, op): f"INT_CLIENT PEER id={identity} op={op} s={move_serial}"
            for identity, ops in ((1, ("send", "recv", "close")), (2, ("recv", "sync", "send", "close"))) for op in ops}
    expected_client.update(peer.values())
    # A successful four-byte write can wake the peer before the sender logs its
    # completion. Check each process's sequence and the real sync dependency,
    # without inventing a total order between independent runnable processes.
    pressed = f"INT_CLIENT BUTTON id=1 n=0 s={move_serial} code=272 state=1"
    before(pressed, peer[1, "send"], peer[1, "recv"], peer[1, "close"], reqs[1, 1][0])
    before(pressed, peer[2, "recv"], reqs[2, 0][0], reqs[2, 0][-1], peer[2, "sync"],
           peer[2, "send"], peer[2, "close"], client_counts(2))
    before(frame_ready(2, 0), peer[2, "recv"])
    before(peer[2, "sync"], peer[1, "recv"])
    stale_sync = f"INT_CLIENT STALE_SYNC id=1 s={move_serial}"
    expected_client.add(stale_sync)
    before(reqs[1, 2][-1], stale_sync, "SMITHAY_INT COMMIT id=1 frame=1 seed=272", scene_ready(4))
    for scene, kind, x, y, width, height in ((1, "move", 16, 12, 64, 48), (2, "move", 24, 16, 64, 48),
                                           (5, "resize", 24, 16, 72, 52), (6, "resize", 24, 16, 68, 56)):
        dx = -4 if scene == 6 else 8
        motion = f"SMITHAY_INT MOTION n={scene} dx={dx} dy=4"
        drag = f"SMITHAY_INT DRAG id=1 kind={kind} n={scene} x={x} y={y} w={width} h={height}"
        completed = f"SMITHAY_INT INPUT n={scene} kind=motion dx={dx} dy=4"
        expected_server.update((motion, drag, completed))
        between(scene, motion, drag, completed)
        before(reqs[1, 1 if kind == "move" else 3][-1], motion)
        if kind == "resize":
            before(motion, configs[1, scene-2][0], drag)
    for scene, kind in ((3, "move"), (7, "resize")):
        ended = f"SMITHAY_INT END id=1 kind={kind} s={buttons[scene][1]}"
        expected_server.add(ended)
        between(scene, buttons[scene][0], ended,
                f"SMITHAY_INT INPUT n={scene} kind=button code={272 if scene == 3 else 273} state=0")
        if kind == "resize":
            before(buttons[scene][0], configs[1, 5][0], ended)
    for previous, current, reason, scene in ((0, 2, "initial", None), (2, 1, "click", 0),
                                            (1, 2, "unmap", 8), (2, 0, "unmap", 10)):
        line = f"SMITHAY_INT FOCUS previous={previous} current={current} reason={reason}"
        expected_server.add(line)
        if scene is None:
            before("SMITHAY_INT COMMIT id=1 frame=0 seed=0", line, scene_ready(0))
            before("SMITHAY_INT COMMIT id=2 frame=0 seed=0", line)
        else:
            between(scene, line)
            if reason == "unmap":
                before(f"INT_CLIENT CLOSE id={previous} n=1", line)
    for identity, number in ((1, 0), (2, 0), (2, 1)):
        expected_client.add(f"INT_CLIENT K_ENTER id={identity} n={number}")
    expected_client.add("INT_CLIENT K_LEAVE id=2 n=0 closing=0")
    before("SMITHAY_INT FOCUS previous=0 current=2 reason=initial", "INT_CLIENT K_ENTER id=2 n=0")
    before("SMITHAY_INT FOCUS previous=2 current=1 reason=click", "INT_CLIENT K_ENTER id=1 n=0")
    before("SMITHAY_INT FOCUS previous=2 current=1 reason=click", "INT_CLIENT K_LEAVE id=2 n=0 closing=0")
    before("SMITHAY_INT FOCUS previous=1 current=2 reason=unmap", "INT_CLIENT K_ENTER id=2 n=1")
    before("INT_CLIENT K_ENTER id=2 n=0", "INT_CLIENT K_LEAVE id=2 n=0 closing=0", "INT_CLIENT K_ENTER id=2 n=1")
    between(0, "INT_CLIENT K_ENTER id=1 n=0", f"INT_CLIENT BUTTON id=1 n=0 s={move_serial} code=272 state=1")
    between(0, "INT_CLIENT K_LEAVE id=2 n=0 closing=0")
    before(scene_ready(8), "INT_CLIENT K_ENTER id=2 n=1", keys[9][0][1])
    for number, x, y in ((0, 2048, 2048), (1, 2048, 2048), (2, 3072, 4096)):
        enter = f"INT_CLIENT P_ENTER id=1 n={number} x={x} y={y}"
        expected_client.add(enter)
        if number == 0:
            before("SMITHAY_INT FOCUS previous=0 current=2 reason=initial", enter,
                   f"INT_CLIENT BUTTON id=1 n=0 s={move_serial} code=272 state=1")
        elif number == 1:
            before(f"SMITHAY_INT END id=1 kind=move s={buttons[3][1]}", enter, reqs[1, 2][0])
        else:
            before(f"SMITHAY_INT END id=1 kind=resize s={buttons[7][1]}", enter, keys[8][0][1])
    for number, scene, kind in ((0, 0, "move"), (1, 4, "resize")):
        leave = f"INT_CLIENT P_LEAVE id=1 n={number} closing=0"
        expected_client.add(leave)
        before(reqs[1, 1 if kind == "move" else 3][-1], leave,
               f"SMITHAY_INT MOTION n={scene+1} dx=8 dy=4")
    for scene in range(11):
        first_native = (buttons[scene][0] if scene in buttons else keys[scene][0][0] if scene in keys else
                        f"SMITHAY_INT MOTION n={scene} dx={-4 if scene == 6 else 8} dy=4")
        for receipt in input_receipts(scene):
            before(receipt, first_native)
    assert set(line for line, _ in server) == expected_server, ("Unexpected/missing server records", set(line for line, _ in server)^expected_server)
    assert set(line for line, _ in client) == expected_client, ("Unexpected/missing client records", set(line for line, _ in client)^expected_client)
    endings = rows(data, "EL0 pid=")
    expected_exits = [f"EL0 pid={pid} Exited code=0 free_pages={free} esr=0x0 far=0x0"
                      for pid, free in ((2, 48), (3, 56), (1, 64))]
    assert [line for line, _ in endings] == expected_exits, endings
    for identity, ending, scene in ((1, endings[0][1], 9), (2, endings[1][1], 11)):
        exited = f"SMITHAY_INT EXIT id={identity} child={identity+1} status=0"
        assert positions[client_done(identity)] < ending < positions[exited]
        before(exited, scene_ready(scene))
    before(READY, CANVAS, scene_ready(0))
    before(scene_ready(11), TOTAL, SUCCESS)
    assert positions[SUCCESS] < endings[2][1]
    return dict(server_markers=[line for line, _ in server], client_markers=[line for line, _ in client],
                configure_serials=configure_serials, native_input_serials=input_serials,
                move_serial=move_serial, resize_serial=resize_serial, keymap_bytes=keymaps,
                scenes=12, commits=8, pixels=147456, configures=9, acknowledgements=9,
                accepted_grabs=2, rejected_requests=3, closes=2, concurrent_clients=2,
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
                peer_fd=4, peer_serial_bytes=4, peer_sync_before_valid_move=True,
                fd=3, compositor_version=4, seat_version=7, shm_format="ARGB8888",
                identities=[1, 2], xdg_wm_base_version=1,
                frame_sizes={"1": [[64, 48], [64, 48], [64, 48], [72, 52], [68, 56], [68, 56]],
                             "2": [[64, 48], [64, 48]]},
                frame_seeds={"1": [0, 272, 273, 273, 273, 273], "2": [0, 32]},
                stale_sync_before_repaint=True,
                configure_states={str(identity): [list(row) for row in configs] for identity, configs in CONFIGS.items()},
                request_kinds={"1": ["forged_move", "move", "stale_move", "resize_bottom_right"],
                               "2": ["foreign_owner_move"]}, resize_edge=10,
                shared_pixels_written_after_import=True, final_key=16)
            assert {str(ROOT / name) for name in (
                "user/ported/smithay_interactive_client.c", "tools/build_smithay_interactive_client.py",
                "tools/build_smithay_wayland_client.py", "ports/cosmic/smithay-interactive-client-source.json")
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
            manifest=str(ROOT / "ports/cosmic/smithay-interactive-source.json"),
            source=str(ROOT / "ports/cosmic/smithay-interactive/main.rs"), binary_stem="smithay-interactive", lto="fat")
        assert str(ROOT / "tools/build_smithay_interactive.py") in report["helper_sha256"]
        assert set(report["modules_sha256"]) == {str(ROOT / name) for name in (
            "ports/cosmic/smithay-wayland/native.rs", "ports/cosmic/smithay-wayland/us.xkb",
            "ports/cosmic/smithay-multi/scene.rs", "ports/cosmic/smithay-interactive/interaction.rs")}, "All compiled native/keymap/scene modules must be bound"
        source_paths = {
            "ports/cosmic/smithay-interactive-source.json": "manifest_sha256",
            "ports/cosmic/smithay-interactive/main.rs": "source_sha256",
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
    for name in ("verify_smithay_interactive.py", "verify_smithay_multi.py", "verify_smithay_xdg.py", "verify_shared_objects.py", "verify_edge.py",
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
    """Actual client dispatch barriers required before each next host action."""
    return {
        0: (frame_ready(1, 0), frame_ready(2, 0), "INT_CLIENT P_ENTER id=1 n=0 x=2048 y=2048",
            "INT_CLIENT K_ENTER id=2 n=0"),
        1: ("INT_CLIENT P_LEAVE id=1 n=0 closing=0",),
        4: (frame_ready(1, 1), "INT_CLIENT P_ENTER id=1 n=1 x=2048 y=2048"),
        5: (frame_ready(1, 2), "INT_CLIENT P_LEAVE id=1 n=1 closing=0"),
        6: (frame_ready(1, 3),), 7: (frame_ready(1, 4),),
        8: (frame_ready(1, 5), "INT_CLIENT P_ENTER id=1 n=2 x=3072 y=4096"),
        9: ("INT_CLIENT K_ENTER id=2 n=1",), 10: (frame_ready(2, 1),),
    }.get(scene, ())
def wait_input_target(guest, start, scene, timeout=120):
    """Wait for real client dispatch receipts before the next physical event."""
    for marker in input_receipts(scene):
        wait_marker(guest, start, marker.encode(), timeout)


def input_events(scene):
    if scene == 11:
        return []
    if scene in (0, 3, 4, 7):
        return [[{"type": "btn", "data": {"button": "left" if scene < 4 else "right",
                                            "down": scene in (0, 4)}}]]
    if scene in (1, 2, 5, 6):
        return [[{"type": "rel", "data": {"axis": "x", "value": -4 if scene == 6 else 8}},
                 {"type": "rel", "data": {"axis": "y", "value": 4}}]]
    key = "d" if scene == 9 else "q"
    return [[{"type": "key", "data": {"key": {"type": "qcode", "data": key},
                                        "down": state}}] for state in (True, False)]


def scene_waiting(data, scene):
    check_console(data)
    server = [line for line, _ in rows(data, "SMITHAY_INT")]
    assert server.count(scene_ready(scene)) == 1
    assert not any(line.startswith(f"SMITHAY_INT SCENE n={later} ")
                   for later in range(scene+1, len(SCENES)) for line in server)
    if scene == 11:
        return
    kind = "BUTTON" if scene in (0, 3, 4, 7) else ("MOTION" if scene in (1, 2, 5, 6) else "KEY")
    assert not any(line.startswith(f"SMITHAY_INT {kind} n={scene} ") for line in server), \
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
    assert input_count == 14
    return dict(scanouts=12, input_commands=input_count, qmp_commands=len(commands))


def verify(elf, server, client, output, iterations=3):
    if output.exists():
        raise FileExistsError("Preserve prior evidence; select a fresh directory")
    output.mkdir(parents=True)
    report = dict(status="FAIL", scope="Native xdg move/resize authorization with two independent clients; not COSMIC desktop",
                  smithay_interactive_verified=False, full_cosmic_port=False, cosmic_runtime_verified=False,
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
                guest.command("posix exec smithay-interactive-probe")
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
        report.update(status="PASS", smithay_interactive_verified=True)
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

