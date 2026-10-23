#!/usr/bin/env python3
"""Verify independent named-socket clients, capacity rejection, slot reuse and abrupt cleanup."""
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
from verify_smithay_multi import bind_inputs, digest, rows

WIDTH, HEIGHT = 128, 96
X, Y = 32, 48
# Bottom-to-top (identity, frame, x, y, width, height). The host paints these
# independently from native compositor geometry and renderer implementations.
SCENES = (
    (), ((1, 0, 8, 8, 64, 48),), ((1, 1, 8, 8, 64, 48),),
    ((1, 1, 8, 8, 64, 48), (2, 0, 40, 24, 64, 48)),
    ((1, 1, 8, 8, 64, 48), (2, 1, 40, 24, 64, 48)),
    ((1, 1, 8, 8, 64, 48),), ((1, 2, 8, 8, 64, 48),),
    ((1, 2, 8, 8, 64, 48), (3, 0, 48, 16, 64, 48)),
    ((1, 2, 8, 8, 64, 48), (3, 1, 48, 16, 64, 48)),
    ((1, 2, 8, 8, 64, 48),), ((1, 3, 8, 8, 64, 48),), (),
)
SEEDS = {1: (0, 32, 32, 32), 2: (0, 32), 3: (0, 32)}
READY = "SMITHAY_DYN READY wayland=1 gles=1 native=1 xdg=1 capacity=2"
CANVAS = "SMITHAY_DYN CANVAS x=32 y=48 width=128 height=96"
LISTEN = "SMITHAY_DYN LISTEN path=/tmp/cyxia-wayland-0"
TOTAL = "SMITHAY_DYN TOTAL clients=3 cfg=7 acks=7 graceful=2 abrupt=1"
SUCCESS = "SMITHAY_DYN RESULT PASS scenes=12 commits=8 pixels=147456"
CONFIGS = {1: (1, 0, 1, 0, 1), 2: (1,), 3: (1,)}
FRAME_SCENES = {1: (1, 2, 6, 10), 2: (3, 4), 3: (7, 8)}
PIDS = {0: 4, 1: 2, 2: 3, 3: 5}
FATAL = (b"SMITHAY_DYN FAIL", b"DYN_CLIENT FAIL", b"KERNEL_FAULT",
         b"panicked", b"EL0 start failed", b"ELF start failed", b"CHECK_FAILED", b"SERVICE_PANIC",
         b"FAIL unexpected exception", b"GRAPHICS_GPU_ERROR")


def check_console(data):
    assert not any(word in data for word in FATAL), data[-6000:]
    assert not re.search(rb"EL0 pid=\d+ (?:Fault|Killed|Exited) code=(?!0\b)\d+", data), data[-6000:]


def scene_ready(scene):
    stack = SCENES[scene]
    top = {0: "none", 1: "A", 2: "B", 3: "C"}[stack[-1][0] if stack else 0]
    return f"SMITHAY_DYN SCENE n={scene} top={top} focus={top} win={len(stack)}"


def geometry(scene, window):
    identity, _, x, y, width, height = window
    return f"SMITHAY_DYN GEOM n={scene} id={identity} x={x} y={y} w={width} h={height}"


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
    return f"DYN_CLIENT FRAME id={identity} f={frame} w={window[4]} h={window[5]} seed={SEEDS[identity][frame]}"


def client_counts(identity):
    frames, keys = (4, 8) if identity == 1 else (2, 4)
    return f"DYN_CLIENT COUNTS id={identity} f={frames} cb={frames} rel={frames} keys={keys}"


def client_done(identity):
    configs = 5 if identity == 1 else 1
    return f"DYN_CLIENT RESULT PASS id={identity} cfg={configs} ack={configs} close=1"


def validate(data):
    """Bind real peers, generations, wire lifecycle and independent shell launches."""
    check_console(data)
    server, client = rows(data, "SMITHAY_DYN"), rows(data, "DYN_CLIENT")
    assert all(len(line.encode())+1 <= 64 for line, _ in server+client), "Non-atomic telemetry"
    assert len({line for line, _ in server}) == len(server), "Duplicate server record"
    assert len({line for line, _ in client}) == len(client), "Duplicate client record"
    positions = dict(server+client)
    expected_server = {READY, CANVAS, LISTEN, TOTAL, SUCCESS, "SMITHAY_DYN REBIND PASS", "SMITHAY_DYN SOCKET CLEAN"}
    expected_client = set()
    configs, config_serials, input_serials, keymaps, keys = {}, [], [], [], {}

    def before(*lines):
        assert all(line in positions for line in lines), ("Missing causal marker", lines)
        values = [positions[line] for line in lines]
        assert values == sorted(set(values)), ("Invalid causal order", lines, values)

    def between(scene, *lines):
        before(scene_ready(scene), *lines, scene_ready(scene+1))

    def take(prefix, pattern, records, expected):
        found = [line for line, _ in records if line.startswith(prefix)]
        assert len(found) == 1, (prefix, found)
        match = re.fullmatch(pattern, found[0]);assert match, found[0]
        expected.add(found[0]);return found[0], match

    def serial(value, seen):
        number = int(value)
        assert 0 < number <= 0xffffffff and number not in seen, ("Reused/invalid serial", number)
        seen.append(number);return number

    for scene, stack in enumerate(SCENES):
        expected_server.add(scene_ready(scene))
        if scene: before(scene_ready(scene-1), scene_ready(scene))
        for window in stack:
            line = geometry(scene, window);expected_server.add(line)
            before(line, scene_ready(scene))
            if scene: before(scene_ready(scene-1), line)
    for identity in (0, 1, 2, 3):
        environment = f"DYN_CLIENT ENV id={identity} ws=0 fd3=closed"
        path = f"DYN_CLIENT PATH id={identity} /tmp/cyxia-wayland-0"
        start = f"DYN_CLIENT START id={identity} pid={PIDS[identity]} fd=3"
        peer = f"DYN_CLIENT PEER id={identity} pid=1 uid=0 gid=0"
        expected_client.update((environment, path, start, peer))
        before(LISTEN, environment, path, start, peer)
        if identity == 0: continue
        slot, generation = {1: (0, 1), 2: (1, 1), 3: (1, 2)}[identity]
        accepted = f"SMITHAY_DYN ACCEPT id={identity} slot={slot} gen={generation} pid={PIDS[identity]}"
        credentials = f"SMITHAY_DYN PEER id={identity} uid=0 gid=0"
        expected_server.update((accepted, credentials))
        before(accepted, credentials)
        launch_scene = {1: 0, 2: 2, 3: 6}[identity]
        between(launch_scene, accepted)
        keymap, match = take(f"DYN_CLIENT KEYMAP id={identity} ", rf"DYN_CLIENT KEYMAP id={identity} bytes=(\d+)", client, expected_client)
        assert 1 < int(match[1]) <= 65536;keymaps.append(int(match[1]))
        before(peer, keymap)
        before(credentials, keymap)
        for index, active in enumerate(CONFIGS[identity]):
            prefix = f"SMITHAY_DYN CONFIG id={identity} n={index} "
            configured, match = take(prefix, re.escape(prefix)+rf"s=(\d+) w=64 h=48 a={active}", server, expected_server)
            number = serial(match[1], config_serials)
            ack = f"SMITHAY_DYN ACK id={identity} n={index} s={number}"
            received = f"DYN_CLIENT CFG id={identity} n={index} s={number} w=64 h=48 a={active}"
            sent = f"DYN_CLIENT ACK id={identity} n={index} s={number}"
            configs[identity, index] = (configured, received, sent, ack, number)
            expected_server.add(ack);expected_client.update((received, sent))
            before(configured, received, sent, ack)
            scene = (launch_scene if index == 0 else (2, 4, 6, 8)[index-1])
            between(scene, configured, ack)
            if index == 0:
                before(keymap, configured, ack, f"SMITHAY_DYN COMMIT id={identity} frame=0 seed=0")
            else: before(configs[identity, index-1][3], configured)
        for frame, scene in enumerate(FRAME_SCENES[identity]):
            commit = f"SMITHAY_DYN COMMIT id={identity} frame={frame} seed={SEEDS[identity][frame]}"
            callback = f"DYN_CLIENT CALLBACK id={identity} f={frame} time={scene}"
            expected_server.add(commit);expected_client.update((callback, frame_ready(identity, frame)))
            before(commit, scene_ready(scene), callback, frame_ready(identity, frame))
            before(scene_ready(scene-1), commit)
            config_index = (0, 0, 2, 4)[frame] if identity == 1 else 0
            before(configs[identity, config_index][3], commit)
            if frame: before(frame_ready(identity, frame-1), commit)
            if identity != 3 or frame == 0:
                release = f"DYN_CLIENT RELEASE id={identity} f={frame}";expected_client.add(release)
                terminal = "DYN_CLIENT ABORT id=3 f=2 cb=2 rel=1 keys=4" if identity == 3 else client_counts(identity)
                before(commit, release, terminal)
            if identity != 3: before(frame_ready(identity, frame), client_counts(identity))
        if identity == 3: continue
        focus = f"DYN_CLIENT FOCUS id={identity} ke={3 if identity == 1 else 1} kl={2 if identity == 1 else 0}"
        close = f"DYN_CLIENT CLOSE id={identity} n=1"
        closing_leave = f"DYN_CLIENT K_LEAVE id={identity} n=0 closing=1"
        expected_client.update((close, closing_leave, client_counts(identity), focus, client_done(identity)))
        unmap = f"SMITHAY_DYN UNMAP id={identity}"
        retire = f"SMITHAY_DYN RETIRED id={identity} why=graceful"
        expected_server.update((f"SMITHAY_DYN CLOSE id={identity}", unmap, retire))
        before(close, unmap, retire, scene_ready(11 if identity == 1 else 5))
        before(close, closing_leave, client_counts(identity), focus, client_done(identity))
        before(unmap, client_counts(identity))
    assert len(set(keymaps)) == 1
    rejected = "SMITHAY_DYN REJECT why=full pid=4 uid=0 gid=0"
    eof = "DYN_CLIENT PROBE id=0 eof=1 bytes=0"
    probe_done = "DYN_CLIENT RESULT PASS id=0 eof=1"
    expected_server.add(rejected);expected_client.update((eof, probe_done))
    between(4, rejected, eof, probe_done)
    before("DYN_CLIENT PEER id=0 pid=1 uid=0 gid=0", eof)
    stale = "SMITHAY_DYN STALE old=2 slot=1 gen=1 rejected=1"
    expected_server.add(stale)
    before("SMITHAY_DYN RETIRED id=2 why=graceful", "SMITHAY_DYN ACCEPT id=3 slot=1 gen=2 pid=5",
           "SMITHAY_DYN PEER id=3 uid=0 gid=0", stale, configs[3, 0][0])
    for scene, identity, frame, code in ((1, 1, 0, 32), (3, 2, 0, 32), (4, 2, 1, 16),
                                        (5, 1, 1, 32), (7, 3, 0, 32), (8, 3, 1, 45),
                                        (9, 1, 2, 32), (10, 1, 3, 16)):
        symbol = {32: 100, 16: 113, 45: 120}[code];pairs=[]
        for state in (1, 0):
            prefix = f"SMITHAY_DYN KEY n={scene} id={identity} code={code} state={state} "
            native, match = take(prefix, re.escape(prefix)+r"s=(\d+)", server, expected_server)
            number = serial(match[1], input_serials)
            received = f"DYN_CLIENT KEY id={identity} f={frame} s={number} c={code} v={state} sym={symbol}"
            expected_client.add(received);between(scene, native, received);pairs.append((native, received))
        before(pairs[0][0], pairs[1][0]);before(frame_ready(identity, frame), pairs[0][1], pairs[1][1])
        completed = f"SMITHAY_DYN INPUT n={scene} kind=key code={code}";expected_server.add(completed)
        between(scene, pairs[1][0], completed);keys[scene]=pairs
        if code == 16:
            before(completed, f"SMITHAY_DYN CLOSE id={identity}", f"DYN_CLIENT CLOSE id={identity} n=1")
            before(pairs[1][1], f"DYN_CLIENT CLOSE id={identity} n=1")
        elif code == 32:
            before(pairs[1][1], f"SMITHAY_DYN COMMIT id={identity} frame={frame+1} seed=32")
    assert set(config_serials).isdisjoint(input_serials), "Configure/input serial collision"
    abort = "DYN_CLIENT ABORT id=3 f=2 cb=2 rel=1 keys=4"
    disconnect = "DYN_CLIENT DISCONNECT id=3 mode=abrupt"
    removed = "SMITHAY_DYN REMOVE id=3 why=disconnect"
    retired = "SMITHAY_DYN RETIRED id=3 why=abrupt"
    expected_client.update((abort, disconnect));expected_server.update((removed, retired))
    before(keys[8][1][1], abort, disconnect)
    before(abort, removed, retired, scene_ready(9))
    # Closing the socket may wake the server before the disconnect completion
    # log is written. Do not invent an order between these runnable processes.
    transitions = ((0, 1, "map", 0), (1, 2, "map", 2), (2, 1, "unmap", 4),
                   (1, 3, "map", 6), (3, 1, "disconnect", 8), (1, 0, "unmap", 10))
    focus_events={}
    for previous,current,reason,scene in transitions:
        line=f"SMITHAY_DYN FOCUS previous={previous} current={current} reason={reason}"
        expected_server.add(line);between(scene,line);focus_events[scene]=line
    before(removed, focus_events[8], retired)
    for identity,number,scene in ((1,0,0),(2,0,2),(1,1,4),(3,0,6),(1,2,8)):
        line=f"DYN_CLIENT K_ENTER id={identity} n={number}";expected_client.add(line)
        before(focus_events[scene],line)
        next_key={0:1,2:3,4:5,6:7,8:9}[scene];before(line,keys[next_key][0][0])
    for number,scene in ((0,2),(1,6)):
        line=f"DYN_CLIENT K_LEAVE id=1 n={number} closing=0";expected_client.add(line)
        before(focus_events[scene],line)
    before("DYN_CLIENT K_ENTER id=1 n=0", "DYN_CLIENT K_LEAVE id=1 n=0 closing=0",
           "DYN_CLIENT K_ENTER id=1 n=1", "DYN_CLIENT K_LEAVE id=1 n=1 closing=0", "DYN_CLIENT K_ENTER id=1 n=2")
    for scene in range(11):
        first = keys[scene][0][0] if scene in keys else {0:"SMITHAY_DYN ACCEPT id=1 slot=0 gen=1 pid=2",2:"SMITHAY_DYN ACCEPT id=2 slot=1 gen=1 pid=3",6:"SMITHAY_DYN ACCEPT id=3 slot=1 gen=2 pid=5"}[scene]
        for receipt in input_receipts(scene):before(receipt,first)
    assert set(line for line,_ in server)==expected_server,("Unexpected/missing server records",set(line for line,_ in server)^expected_server)
    assert set(line for line,_ in client)==expected_client,("Unexpected/missing client records",set(line for line,_ in client)^expected_client)
    before(LISTEN,READY,CANVAS,scene_ready(0))
    before(scene_ready(11),"SMITHAY_DYN REBIND PASS","SMITHAY_DYN SOCKET CLEAN",TOTAL,SUCCESS)
    launches=rows(data,"ELF pid=");endings=rows(data,"EL0 pid=")
    launched={};exited={};active=set()
    for line,position in sorted(launches+endings,key=lambda pair:pair[1]):
        if line.startswith("ELF"):
            match=re.fullmatch(r"ELF pid=(\d+) started; ABI=Linux-AArch64-subset image AI_DIRECT model=8195 pages=(\d+)",line)
            assert match,line
            pid,pages=map(int,match.groups());assert pid not in launched and pid==len(launched)+1 and 64<pages<=4096
            launched[pid]=(position,pages);active.add(pid)
        else:
            match=re.fullmatch(r"EL0 pid=(\d+) Exited code=0 free_pages=(\d+) esr=0x0 far=0x0",line);assert match,line
            pid,free=map(int,match.groups());assert pid in active and pid not in exited
            active.remove(pid);assert free==64-8*len(active),(pid,free,active);exited[pid]=position
    assert set(launched)==set(exited)=={1,2,3,4,5} and not active
    assert launched[1][0]<positions[READY]
    for identity in (0,1,2,3):assert launched[PIDS[identity]][0]<positions[f"DYN_CLIENT ENV id={identity} ws=0 fd3=closed"]
    assert positions[probe_done]<exited[4]<positions[keys[4][0][0]]
    assert positions[client_done(2)]<exited[3]<positions[keys[5][0][0]]<launched[5][0]
    assert positions[disconnect]<exited[5]<positions[keys[9][0][0]]
    assert positions[client_done(1)]<exited[2] and positions[SUCCESS]<exited[1]
    return dict(server_markers=[line for line,_ in server],client_markers=[line for line,_ in client],
                configure_serials=config_serials,native_input_serials=input_serials,keymap_bytes=keymaps,
                launches={str(pid):{"pages":v[1]} for pid,v in launched.items()},exit_records=[line for line,_ in endings],
                scenes=12,commits=8,pixels=147456,configures=7,acknowledgements=7,admitted_clients=3,
                capacity_rejections=1,reused_slots=1,stale_keys_rejected=1,graceful_closes=2,abrupt_disconnects=1,
                independently_launched_processes=5)


def validate_resources(before, after, processes, heap_pages):
    reclaimed(before)
    reclaimed(after)
    assert set(processes) == {1, 2, 4, 5}, processes
    for pid, row in processes.items():
        for name, value in dict(parent_pid=0, state="Exited", code=0,
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
        if domain in ("process", "anonymous", "elf", "unix",
                      "shared_objects", "shared_pages", "shared_mappings",
                      "ancillary_messages", "ancillary_references"):
            assert new["ai"] > old["ai"] and new["committed"] > old["committed"], (domain, old, new)
            if domain != "unix":
                assert new["grant_units"] > old["grant_units"], (domain, old, new)
    assert after["ai"]["spawn_receipt"] == before["ai"]["spawn_receipt"], "Independent launches created spawn receipts"
    for name in ("requests", "committed", "ai"):
        assert after["ai"]["process"][name]-before["ai"]["process"][name] == 5, name
    old, new = before["ai"]["display"], after["ai"]["display"]
    assert new["available"] == "true" and new["model"] == 24577 and new["phase"] == "Idle", new
    assert new["failed"] == old["failed"] == 0, new
    assert new["admitted"] == new["submitted"] == new["completed"], new
    assert new["admitted"] == new["ai_admitted"] + new["guard_admitted"], new
    assert new["guard_admitted"] == old["guard_admitted"], ("Display bypassed local AI", old, new)
    assert new["ai_admitted"] - old["ai_admitted"] == new["completed"] - old["completed"] == 36, new


def client_protocol():
    return dict(connection="wl_display_connect(NULL)", inherited_socket=False,
                environment={"XDG_RUNTIME_DIR": "/tmp", "WAYLAND_DISPLAY": "cyxia-wayland-0", "WAYLAND_SOCKET": None},
                socket_path="/tmp/cyxia-wayland-0", peer_credentials="SO_PEERCRED",
                capacity_probe_identity=0, capacity_probe="connect-without-requests-then-EOF",
                compositor_version=4, seat_version=7, shm_format="ARGB8888", identities=[1, 2, 3], xdg_wm_base_version=1,
                frame_sizes={"1": [[64, 48]]*4, "2": [[64, 48]]*2, "3": [[64, 48]]*2},
                frame_seeds={str(i): list(s) for i, s in SEEDS.items()},
                configure_states={str(i): [[64, 48, a] for a in states] for i, states in CONFIGS.items()},
                callback_scenes={str(i): list(s) for i, s in FRAME_SCENES.items()},
                keyboard_focus_counts={"1": [3, 2], "2": [1, 0], "3": [1, 0]}, pointer_bound=False,
                normal_close_identities=[1, 2], final_key=16, abrupt_identity=3, abrupt_key=45,
                abrupt_teardown="wl_display_disconnect-then-_exit-with-live-objects",
                shared_pixels_written_after_import=True)


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
                "user/ported/smithay_dynamic_client.c", "tools/build_smithay_dynamic_client.py",
                "tools/build_smithay_wayland_client.py", "ports/cosmic/smithay-dynamic-client-source.json")
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
            manifest=str(ROOT / "ports/cosmic/smithay-dynamic-source.json"),
            source=str(ROOT / "ports/cosmic/smithay-dynamic/main.rs"), binary_stem="smithay-dynamic", lto="fat")
        assert str(ROOT / "tools/build_smithay_dynamic.py") in report["helper_sha256"]
        assert set(report["modules_sha256"]) == {str(ROOT / name) for name in (
            "ports/cosmic/smithay-wayland/native.rs", "ports/cosmic/smithay-wayland/us.xkb",
            "ports/cosmic/smithay-multi/scene.rs", "ports/cosmic/smithay-dynamic/clients.rs")}, "All compiled native/keymap/scene modules must be bound"
        source_paths = {
            "ports/cosmic/smithay-dynamic-source.json": "manifest_sha256",
            "ports/cosmic/smithay-dynamic/main.rs": "source_sha256",
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
    for name in ("verify_smithay_dynamic.py", "verify_smithay_multi.py", "verify_smithay_xdg.py", "verify_shared_objects.py", "verify_edge.py",
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
    return {
        1: (frame_ready(1, 0), "DYN_CLIENT K_ENTER id=1 n=0"),
        2: (frame_ready(1, 1),),
        3: (frame_ready(2, 0), "DYN_CLIENT K_ENTER id=2 n=0", "DYN_CLIENT K_LEAVE id=1 n=0 closing=0"),
        4: (frame_ready(2, 1),),
        5: ("DYN_CLIENT K_ENTER id=1 n=1", "DYN_CLIENT RESULT PASS id=2 cfg=1 ack=1 close=1"),
        6: (frame_ready(1, 2),),
        7: (frame_ready(3, 0), "DYN_CLIENT K_ENTER id=3 n=0", "DYN_CLIENT K_LEAVE id=1 n=1 closing=0"),
        8: (frame_ready(3, 1),),
        9: ("DYN_CLIENT K_ENTER id=1 n=2", "DYN_CLIENT DISCONNECT id=3 mode=abrupt"),
        10: (frame_ready(1, 3),),
    }.get(scene, ())


def wait_input_target(guest, start, scene, timeout=120):
    for marker in input_receipts(scene):
        wait_marker(guest, start, marker.encode(), timeout)


def input_events(scene):
    if scene in (0, 2, 6, 11):
        return []
    key = "q" if scene in (4, 10) else "x" if scene == 8 else "d"
    return [[{"type": "key", "data": {"key": {"type": "qcode", "data": key}, "down": state}}]
            for state in (True, False)]


def scene_waiting(data, scene):
    check_console(data)
    server = [line for line, _ in rows(data, "SMITHAY_DYN")]
    assert server.count(scene_ready(scene)) == 1
    assert not any(line.startswith(f"SMITHAY_DYN SCENE n={later} ")
                   for later in range(scene+1, len(SCENES)) for line in server)
    assert not any(line.startswith(f"SMITHAY_DYN KEY n={scene} ") for line in server), "Input before host injection"
    if scene in (0, 2, 6):
        identity = {0: 1, 2: 2, 6: 3}[scene]
        assert not any(line.startswith(f"SMITHAY_DYN ACCEPT id={identity} ") for line in server), "Admission before shell launch"


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



class DynamicGuest(Guest):
    """Record successful physical UART batches without changing the transport."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.input_writes, self.host_commands = [], []

    def send(self, data):
        started = time.monotonic()
        console_bytes = len(self.text)
        super().send(data)
        self.input_writes.append(dict(index=len(self.input_writes), hex=bytes(data).hex(),
                                      started_at=started, finished_at=time.monotonic(), console_bytes=console_bytes))

    def command(self, command, prompt=b"cyxia:/> "):
        record = dict(command=command, started_at=time.monotonic(), console_start=len(self.text),
                      write_first=len(self.input_writes))
        self.host_commands.append(record)
        result = super().command(command, prompt)
        record.update(finished_at=time.monotonic(), console_end=len(self.text), write_end=len(self.input_writes))
        return result

    def close(self):
        super().close()
        (self.output / "uart-input.jsonl").write_text("".join(json.dumps(row)+"\n" for row in self.input_writes))
        (self.output / "host-commands.json").write_text(json.dumps(self.host_commands, indent=2)+"\n")


PHASES = {
    "a_alive": ({1, 2}, set(), 2), "full_before_probe": ({1, 2, 3}, set(), 4),
    "full_after_probe": ({1, 2, 3}, {4}, 4), "b_retired": ({1, 2}, {3, 4}, 5),
    "c_alive": ({1, 2, 5}, {4}, 8), "c_retired": ({1, 2}, {4, 5}, 9),
}
LAUNCH_COMMANDS = ["posix exec smithay-dynamic-"+name for name in ("probe", "a", "b", "reject", "c")]


def validate_process_phase(processes, phase, heap_pages):
    alive, dead, _ = PHASES[phase]
    assert set(processes) == alive | dead, (phase, processes)
    for pid, row in processes.items():
        assert row["pid"] == pid and row["parent_pid"] == 0, (phase, row)
        assert row["state"] in (("Running", "Waiting") if pid in alive else ("Exited",)), (phase, row)
        assert row["code"] == row["exit_signal"] == row["esr"] == row["far"] == 0, row
        assert row["rank_model"] == 12289 and row["cpu_model"] == 12290, row
        assert row["guard_selections"] == row["thread_guard_selections"] == 0, row
        assert row["ai_selections"] > 0 and row["syscalls"] > 0, row
        assert row["free_pages"] == 64-8*len(alive), row
        if pid in alive:
            assert row["image_pages"] > 0 and row["heap_pages"] > 0 and row["thread_count"] == 1, row
        else:
            assert row["image_pages"] == row["heap_pages"] == row["thread_count"] == 0, row
            assert row["heap_free"] == heap_pages and row["image_free"] == 4096, row


def wait_exit(guest, start, pid, timeout=60):
    deadline = time.monotonic()+timeout
    pattern = re.compile(rb"(?m)^EL0 pid="+str(pid).encode()+rb" Exited code=0 free_pages=\d+ esr=0x0 far=0x0\r?$\n")
    while time.monotonic() < deadline:
        guest.poll()
        data = bytes(guest.text[start:]);check_console(data)
        if pattern.search(data):return
        time.sleep(.01)
    raise TimeoutError(("Missing actual process exit", pid))


def validate_commands(commands, writes, console, start, scanouts, capacity, process_phases):
    """Reconstruct every UART command and bind launch barriers to received bytes."""
    expected = ["ai system", *LAUNCH_COMMANDS[:2], "posix list", LAUNCH_COMMANDS[2], "posix list",
                LAUNCH_COMMANDS[3], "posix list", "posix list", LAUNCH_COMMANDS[4],
                "posix list", "posix list", "posix list", "ai system"]
    assert [row["command"] for row in commands] == expected, "Unexpected shell commands"
    cursor, previous_end, previous_time = 0, 0, 0
    for command in commands:
        begin, end = command["console_start"], command["console_end"]
        assert previous_end <= begin < end <= len(console)
        assert previous_time <= command["started_at"] <= command["finished_at"]
        assert command["write_first"] == cursor < command["write_end"] <= len(writes)
        batches = writes[cursor:command["write_end"]]
        assert b"".join(bytes.fromhex(row["hex"]) for row in batches) == command["command"].encode()+b"\r"
        assert (command["command"]+"\r\n").encode() in console[begin:end], "Missing actual shell echo"
        for index,row in enumerate(batches,cursor):
            assert row["index"] == index and 1 <= len(bytes.fromhex(row["hex"])) <= 8
            assert command["started_at"] <= row["started_at"] <= row["finished_at"] <= command["finished_at"]
            assert begin <= row["console_bytes"] <= end
            if index>cursor:assert writes[index-1]["finished_at"] <= row["started_at"]
        cursor, previous_end, previous_time = command["write_end"], end, command["finished_at"]
    assert cursor == len(writes), "Unaccounted UART bytes"
    assert commands[1]["console_start"] == start
    for number, command_index, prior_scene in ((1,1,None),(2,2,0),(3,4,2),(4,6,4),(5,9,6)):
        command = commands[command_index]
        region = console[command["console_start"]:command["console_end"]]
        assert re.search(rb"(?m)^(?:cyxia:/> )?ELF pid="+str(number).encode()+rb" started; ",region)
        if prior_scene is not None:
            witness=scanouts[prior_scene]
            assert witness["captured_at"] <= command["started_at"]
            assert start+witness["serial_bytes_before_input"] <= command["console_start"]
            scene_waiting(console[start:command["console_start"]],prior_scene)
            for receipt in input_receipts(prior_scene):assert receipt.encode() in console[start:command["console_start"]]
    probe_command=commands[6]
    assert probe_command["finished_at"] <= capacity["captured_at"] <= scanouts[4]["input_started_at"]
    prefix=console[start:start+capacity["serial_bytes_before_input"]]
    assert b"DYN_CLIENT PROBE id=0 eof=1 bytes=0\r\n" in prefix
    assert b"EL0 pid=4 Exited code=0 free_pages=40 esr=0x0 far=0x0\r\n" in prefix
    for phase,command_index in zip(PHASES,(3,5,7,8,10,11)):
        saved=process_phases[phase];command=commands[command_index]
        assert saved["command_index"] == command_index
        assert parse_processes(console[command["console_start"]:command["console_end"]]) == saved["processes"]
        scene_waiting(console[start:command["console_start"]],PHASES[phase][2])
    return dict(shell_commands=len(commands), uart_batches=len(writes), independent_launches=5,
                process_snapshots=7, argv_roles=[1,2,0,3])


def validate_qmp(transcript, scanouts, capacity):
    commands=[row["message"] for row in transcript if row["direction"]=="send"]
    assert commands and commands[0]["execute"]=="qmp_capabilities" and commands[-1]["execute"]=="quit"
    assert sum(row["execute"]=="qmp_capabilities" for row in commands)==sum(row["execute"]=="quit" for row in commands)==1
    assert [row["id"] for row in commands]==list(range(1,len(commands)+1))
    replies=[(i,row["message"]) for i,row in enumerate(transcript) if row["direction"]=="receive" and "id" in row["message"]]
    assert len(replies)==len(commands)
    for command in commands:
        sends=[i for i,row in enumerate(transcript) if row["direction"]=="send" and row["message"]["id"]==command["id"]]
        responses=[(i,row) for i,row in replies if row["id"]==command["id"]]
        assert len(sends)==len(responses)==1
        index,response=responses[0]
        assert response=={"return":{},"id":command["id"]} and index>sends[0]
        following=[i for i,row in enumerate(transcript) if row["direction"]=="send" and i>sends[0]]
        assert not following or index<following[0],"QMP operation before previous completion"
    assert all(row["execute"] in ("qmp_capabilities","screendump","input-send-event","quit") for row in commands)
    relevant=[row for row in commands if row["execute"] in ("screendump","input-send-event")]
    assert [w["scene"] for w in scanouts]==list(range(12)) and capacity["scene"]==4
    assert capacity["canvas_sha256"]==scanouts[4]["canvas_sha256"],"Capacity rejection changed physical canvas"
    cursor=inputs=0
    for witness in scanouts:
        for capture_witness in ([witness,capacity] if witness["scene"]==4 else [witness]):
            attempts=capture_witness["capture_attempts"];assert 1<=attempts<=300
            captures=relevant[cursor:cursor+attempts]
            assert len(captures)==attempts and all(row["execute"]=="screendump" and row["arguments"]=={"filename":str(Path(capture_witness["path"]).resolve())} for row in captures)
            assert captures[-1]["id"]==capture_witness["capture_qmp_id"]
            cursor+=attempts
        expected=input_events(witness["scene"])
        actual=relevant[cursor:cursor+len(expected)]
        assert [row["execute"] for row in actual]==["input-send-event"]*len(expected)
        assert [row["arguments"] for row in actual]==[{"events":events} for events in expected]
        if expected:
            latest=capacity if witness["scene"]==4 else witness
            assert actual[0]["id"]==witness["input_first_qmp_id"]>latest["capture_qmp_id"]
            assert actual[-1]["id"]==witness["input_last_qmp_id"]
            assert latest["captured_at"]<=witness["input_started_at"]<=witness["input_finished_at"]
        else:assert not any(name in witness for name in ("input_first_qmp_id","input_last_qmp_id","input_started_at","input_finished_at"))
        cursor+=len(expected);inputs+=len(expected)
    assert cursor==len(relevant) and inputs==16
    return dict(scanouts=12,capacity_scanouts=1,input_commands=inputs,qmp_commands=len(commands))


def verify(elf, server, client, output, iterations=3):
    if output.exists():raise FileExistsError("Preserve prior evidence; select a fresh directory")
    output.mkdir(parents=True)
    report=dict(status="FAIL",scope="Native independently launched named-socket clients, bounded admission and disconnect cleanup; not COSMIC desktop",
                smithay_dynamic_verified=False,full_cosmic_port=False,cosmic_runtime_verified=False,iterations=iterations,runs=[])
    guest=None
    try:
        assert 1<=iterations<=5
        report["provenance"]=provenance(elf,server,client)
        heap_pages=report["provenance"]["profile"]["heap_pages"]
        for iteration in range(1,iterations+1):
            run=dict(iteration=iteration,scanouts=[],process_phases={});report["runs"].append(run)
            with DynamicGuest(elf,output/f"run-{iteration}",graphics=True,rng=True) as guest:
                guest.until(b"cyxia:/> ")
                run["before"]=before=snapshot(guest);reclaimed(before)
                run["console_start"]=start=len(guest.text)
                guest.command(LAUNCH_COMMANDS[0])
                def process_snapshot(phase):
                    index=len(guest.host_commands)
                    processes=parse_processes(guest.command("posix list"))
                    validate_process_phase(processes,phase,heap_pages)
                    run["process_phases"][phase]=dict(command_index=index,processes=processes)
                def capture_witness(scene,path):
                    witness=capture(guest,start,path,scene)
                    witness.update(capture_qmp_id=guest.qmp.seq,captured_at=time.monotonic())
                    guest.poll();scene_waiting(bytes(guest.text[start:]),scene)
                    witness["serial_bytes_before_input"]=len(guest.text)-start
                    return witness
                for scene in range(12):
                    wait_marker(guest,start,scene_ready(scene).encode());wait_input_target(guest,start,scene)
                    if scene in (5,9):wait_exit(guest,start,{5:3,9:5}[scene])
                    phase={2:"a_alive",4:"full_before_probe",5:"b_retired",8:"c_alive",9:"c_retired"}.get(scene)
                    if phase:process_snapshot(phase)
                    witness=capture_witness(scene,guest.output/f"scene-{scene}.ppm");run["scanouts"].append(witness)
                    if scene in (0,2,6):guest.command(LAUNCH_COMMANDS[{0:1,2:2,6:4}[scene]])
                    if scene==4:
                        guest.command(LAUNCH_COMMANDS[3])
                        wait_marker(guest,start,b"DYN_CLIENT RESULT PASS id=0 eof=1");wait_exit(guest,start,4)
                        process_snapshot("full_after_probe")
                        run["capacity_scanout"]=capture_witness(4,guest.output/"scene-4-after-capacity.ppm")
                    events=input_events(scene)
                    if events:
                        witness.update(input_started_at=time.monotonic(),input_first_qmp_id=guest.qmp.seq+1)
                        for batch in events:event(guest,batch)
                        witness.update(input_finished_at=time.monotonic(),input_last_qmp_id=guest.qmp.seq,input=events)
                wait_exit(guest,start,2);wait_exit(guest,start,1)
                run["observations"]=validate(bytes(guest.text[start:]))
                run["processes"]=processes=parse_processes(guest.command("posix list"))
                run["after"]=after=snapshot(guest)
                validate_resources(before,after,processes,heap_pages)
                run["host_observations"]=validate_commands(guest.host_commands,guest.input_writes,bytes(guest.text),start,
                                                            run["scanouts"],run["capacity_scanout"],run["process_phases"])
            run["qmp_observations"]=validate_qmp(guest.qmp.transcript,run["scanouts"],run["capacity_scanout"])
            (guest.output/"qmp.jsonl").write_text("".join(json.dumps(row)+"\n" for row in guest.qmp.transcript))
            run["evidence_sha256"]={str(path):digest(path) for path in sorted(guest.output.iterdir()) if path.is_file()}
        assert provenance(elf,server,client)==report["provenance"],"Verification inputs changed"
        report.update(status="PASS",smithay_dynamic_verified=True)
    except Exception as error:
        report["error"]=repr(error)
        if guest is not None and guest.qmp is not None:
            (guest.output/"qmp.jsonl").write_text("".join(json.dumps(row)+"\n" for row in guest.qmp.transcript))
    finally:(output/"summary.json").write_text(json.dumps(report,indent=2)+"\n")
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

