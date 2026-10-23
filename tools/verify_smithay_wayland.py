#!/usr/bin/env python3
"""Verify genuine Smithay surface rendering, physical scanout and seat input."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from build_cosmic import tree_identity
from build_sysroot import inspect_elf as inspect_program
from check_elf import boot_profile, inspect_elf
from doctor import ROOT, RUST_BIN, env
from shell import Guest
from verify_edge import DOMAINS
from verify_ported import parse_processes
from verify_shared_objects import reclaimed, snapshot
from verify_x11 import button, key, move

WIDTH, HEIGHT = 128, 96
X, Y = 32, 48
SUCCESS = "SMITHAY_WAYLAND RESULT PASS rounds=2 frames=6 pixels=73728 native=1 input=1 cosmic=0"
FATAL = (b"SMITHAY_WAYLAND FAIL", b"SMITHAY_CLIENT FAIL", b"KERNEL_FAULT",
         b"panicked", b"EL0 start failed", b"CHECK_FAILED", b"SERVICE_PANIC",
         b"FAIL unexpected exception", b"GRAPHICS_GPU_ERROR")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bind_inputs(inputs, candidates):
    for path, expected in candidates.items():
        assert path not in inputs or inputs[path] == expected, ("Conflicting input provenance", path)
        inputs[path] = expected


def frame_ready(round_number, frame):
    width, height = (96, 64) if frame == 2 else (64, 48)
    return (f"SMITHAY_WAYLAND FRAME_READY round={round_number} frame={frame} x=32 y=48 "
            f"width=128 height=96 surface_width={width} surface_height={height} seed={[0, 30, 272][frame]}")


def expected_pixel(round_number, frame, x, y):
    width, height = (96, 64) if frame == 2 else (64, 48)
    if x >= width or y >= height:
        return bytes(3)
    seed = [0, 30, 272][frame]
    return bytes(((3*x+y+29*round_number+47*frame+seed) & 255,
                  (x+5*y+11*round_number+31*frame+3*seed) & 255,
                  (7*(x ^ y)+13*round_number+19*frame+5*seed) & 255))


def scanout(path, round_number, frame):
    """Only consume actual QMP PPM output; compare every canvas pixel."""
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
            actual = pixels[at:at+3]
            expected = expected_pixel(round_number, frame, x, y)
            assert actual == expected, (round_number, frame, x, y, actual.hex(), expected.hex())
            canvas.extend(actual)
    return dict(path=str(path), sha256=digest(path), canvas_sha256=hashlib.sha256(canvas).hexdigest(),
                pixels=WIDTH*HEIGHT, round=round_number, frame=frame, x=X, y=Y,
                width=WIDTH, height=HEIGHT)


def check_console(data):
    assert not any(word in data for word in FATAL), data[-6000:]
    assert not re.search(rb"EL0 pid=\d+ (?:Fault|Killed|Exited) code=(?!0\b)\d+", data), data[-6000:]


def frame_waiting(data, round_number, frame):
    """Do not accept input or callbacks already produced before host injection."""
    check_console(data)
    ready = frame_ready(round_number, frame)
    assert [line for line, _ in rows(data, "SMITHAY_WAYLAND")].count(ready) == 1
    for prefix in (f"SMITHAY_WAYLAND INPUT_FORWARDED round={round_number} frame={frame}",
                   *(f"SMITHAY_CLIENT {kind} round={round_number} frame={frame}"
                     for kind in ("KEY", "BUTTON", "MOTION", "CALLBACK", "FRAME PASS"))):
        assert prefix.encode() not in data, ("Premature input/callback", prefix)


def capture(guest, start, path, round_number, frame, timeout=3):
    # A fenced RESOURCE_FLUSH can precede QEMU's host display refresh. Every
    # attempt is a real scanout; never modify pixels or inject input to advance it.
    deadline = time.monotonic() + timeout
    attempts = 0
    while True:
        guest.poll()
        frame_waiting(bytes(guest.text[start:]), round_number, frame)
        guest.qmp.execute("screendump", {"filename": str(path.resolve())})
        attempts += 1
        try:
            witness = scanout(path, round_number, frame)
            witness["capture_attempts"] = attempts
            return witness
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.01)


def rows(data, prefix):
    matches = list(re.finditer(rb"(?m)^(?:cyxia:/> )?(" + prefix.encode() + rb"[^\r\n]*)\r?$", data))
    assert data.count(prefix.encode()) == len(matches), ("Malformed/interleaved marker", prefix)
    return [(m[1].decode(), m.start()) for m in matches]


def validate(data):
    """Independent client/server order plus cross-process frame/input barriers."""
    check_console(data)
    server = rows(data, "SMITHAY_WAYLAND")
    client = rows(data, "SMITHAY_CLIENT")
    expected_server = ["SMITHAY_WAYLAND READY frontend=upstream renderer=upstream native=1"]
    expected_client = []
    keymap_sizes = []
    for round_number in (1, 2):
        expected_server.append(f"SMITHAY_WAYLAND SPAWN round={round_number} child={round_number+1}")
        expected_client.append(f"SMITHAY_CLIENT START round={round_number} pid={round_number+1} fd=3 libwayland=1.24.0")
        keymaps = [line for line, _ in client if line.startswith(f"SMITHAY_CLIENT KEYMAP PASS round={round_number} ")]
        assert len(keymaps) == 1, keymaps
        match = re.fullmatch(rf"SMITHAY_CLIENT KEYMAP PASS round={round_number} bytes=(\d+)", keymaps[0])
        assert match and 1 < int(match[1]) <= 65536, keymaps
        keymap_sizes.append(int(match[1]))
        expected_client.append(keymaps[0])
        for frame in range(3):
            expected_server.extend([frame_ready(round_number, frame),
                                    f"SMITHAY_WAYLAND INPUT_FORWARDED round={round_number} frame={frame}"])
            if frame == 1:
                expected_client.append(f"SMITHAY_CLIENT MOTION round={round_number} frame=1 x_fixed=5120 y_fixed=4864 dx=4 dy=3")
                expected_client.extend(f"SMITHAY_CLIENT BUTTON round={round_number} frame=1 code=272 state={state}"
                                       for state in (1, 0))
            else:
                code, keysym = (30, 97) if frame == 0 else (16, 113)
                expected_client.extend(f"SMITHAY_CLIENT KEY round={round_number} frame={frame} code={code} state={state} keysym={keysym}"
                                       for state in (1, 0))
            expected_client.append(f"SMITHAY_CLIENT CALLBACK round={round_number} frame={frame} time={round_number*100+frame}")
            width, height = (96, 64) if frame == 2 else (64, 48)
            expected_client.append(f"SMITHAY_CLIENT FRAME PASS round={round_number} frame={frame} width={width} height={height} "
                                   f"seed={[0, 30, 272][frame]} callback=1 release=1 after_import_write=1")
        expected_client.append(f"SMITHAY_CLIENT RESULT PASS round={round_number} frames=3 callbacks=3 releases=3 input=1")
        expected_server.append(f"SMITHAY_WAYLAND ROUND_PASS round={round_number} frames=3 surfaces=0")
    expected_server.append(SUCCESS)
    assert [line for line, _ in server] == expected_server, server
    assert [line for line, _ in client] == expected_client, client
    assert keymap_sizes[0] == keymap_sizes[1], keymap_sizes
    positions = dict(server + client)
    for round_number in (1, 2):
        keymap = next(pos for line, pos in client if line.startswith(f"SMITHAY_CLIENT KEYMAP PASS round={round_number} "))
        assert keymap < positions[frame_ready(round_number, 0)]
        for frame in range(3):
            ready = positions[frame_ready(round_number, frame)]
            first_input = next(pos for line, pos in client if
                               line.startswith(f"SMITHAY_CLIENT {'MOTION' if frame == 1 else 'KEY'} round={round_number} frame={frame} "))
            callback = positions[f"SMITHAY_CLIENT CALLBACK round={round_number} frame={frame} time={round_number*100+frame}"]
            assert ready < first_input < callback
            assert ready < positions[f"SMITHAY_WAYLAND INPUT_FORWARDED round={round_number} frame={frame}"]
            if frame < 2:
                complete = next(pos for line, pos in client if
                                line.startswith(f"SMITHAY_CLIENT FRAME PASS round={round_number} frame={frame} "))
                assert complete < positions[frame_ready(round_number, frame+1)]
    endings = rows(data, "EL0 pid=")
    expected_exits = [f"EL0 pid={pid} Exited code=0 free_pages={56 if pid != 1 else 64} esr=0x0 far=0x0"
                      for pid in (2, 3, 1)]
    assert [line for line, _ in endings] == expected_exits, endings
    for index, round_number in enumerate((1, 2)):
        done = positions[f"SMITHAY_CLIENT RESULT PASS round={round_number} frames=3 callbacks=3 releases=3 input=1"]
        assert done < endings[index][1] < positions[f"SMITHAY_WAYLAND ROUND_PASS round={round_number} frames=3 surfaces=0"]
    assert positions[SUCCESS] < endings[-1][1]
    return dict(server_markers=expected_server, client_markers=expected_client,
                keymap_bytes=keymap_sizes, exit_records=expected_exits, frames=6, pixels=73728)


def validate_resources(before, after, processes, heap_pages):
    reclaimed(before)
    reclaimed(after)
    assert 1 in processes and set(processes) <= {1, 2, 3}, processes
    for pid, row in processes.items():
        for name, value in dict(parent_pid=0 if pid == 1 else 1, state="Exited", code=0,
                                exit_signal=0, esr=0, far=0, free_pages=64, heap_pages=0,
                                heap_free=heap_pages, image_pages=0, image_free=4096,
                                thread_count=0, thread_peak=1, thread_admissions=0,
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
    assert new["ai_admitted"] > old["ai_admitted"] and new["completed"] - old["completed"] >= 18, new


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
            bind_inputs(inputs, {Path(p): value for p, value in report["inputs_sha256"].items()})
            continue
        base = program.parent
        source_paths = {
            "ports/cosmic/smithay-wayland-source.json": "manifest_sha256",
            "ports/cosmic/smithay-wayland/main.rs": "source_sha256",
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
        pages = sum(((p["vaddr"] + p["memsz"] + 4095) // 4096 - p["vaddr"] // 4096)
                    for p in report["probe"]["program_headers"] if p["type"] == 1)
        assert report["stack_pages"] == 64 and report["image_pages"] == pages
        assert report["admission_pages"] == pages + 64 <= 4096
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
    for name in ("verify_smithay_wayland.py", "verify_shared_objects.py", "verify_edge.py",
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


def input_events(frame):
    if frame == 1:
        return [[{"type": "rel", "data": {"axis": "x", "value": 4}},
                 {"type": "rel", "data": {"axis": "y", "value": 3}}],
                *[[{"type": "btn", "data": {"button": "left", "down": state}}]
                  for state in (True, False)]]
    return [[{"type": "key", "data": {"key": {"type": "qcode", "data": "a" if frame == 0 else "q"},
                                        "down": state}}] for state in (True, False)]


def validate_qmp(transcript, scanouts):
    """Bind every actual screenshot to the exact subsequent physical input."""
    commands = [row["message"] for row in transcript if row["direction"] == "send"]
    assert all(row["execute"] in ("qmp_capabilities", "screendump", "input-send-event", "quit")
               for row in commands), "Unexpected host operation"
    relevant = [row for row in commands if row["execute"] in ("screendump", "input-send-event")]
    assert [(w["round"], w["frame"]) for w in scanouts] == [(r, f) for r in (1, 2) for f in range(3)]
    cursor = 0
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
        expected = input_events(witness["frame"])
        inputs = relevant[cursor:cursor+len(expected)]
        assert [row["execute"] for row in inputs] == ["input-send-event"]*len(expected)
        assert [row["arguments"] for row in inputs] == [{"events": events} for events in expected]
        assert inputs[0]["id"] == witness["input_first_qmp_id"] > witness["capture_qmp_id"]
        assert inputs[-1]["id"] == witness["input_last_qmp_id"]
        assert witness["captured_at"] <= witness["input_started_at"] <= witness["input_finished_at"]
        cursor += len(expected)
    assert cursor == len(relevant), "Unaccounted host input or scanout"
    return dict(scanouts=len(scanouts), input_commands=14, qmp_commands=len(commands))


def verify(elf, server, client, output, iterations=3):
    if output.exists():
        raise FileExistsError("Preserve prior evidence; select a fresh directory")
    output.mkdir(parents=True)
    report = dict(status="FAIL", scope="Bounded upstream Smithay Wayland frontend/GLES/native scanout/input",
                  smithay_wayland_verified=False, full_cosmic_port=False, cosmic_runtime_verified=False,
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
                guest.command("posix exec smithay-wayland-probe")
                for round_number in (1, 2):
                    for frame in range(3):
                        marker = frame_ready(round_number, frame).encode()
                        wait_marker(guest, start, marker)
                        path = output / f"run-{iteration}" / f"round-{round_number}-frame-{frame}.ppm"
                        witness = capture(guest, start, path, round_number, frame)
                        witness["capture_qmp_id"] = guest.qmp.seq
                        witness["captured_at"] = time.monotonic()
                        guest.poll()
                        frame_waiting(bytes(guest.text[start:]), round_number, frame)
                        witness["serial_bytes_before_input"] = len(guest.text) - start
                        witness["input_started_at"] = time.monotonic()
                        witness["input_first_qmp_id"] = guest.qmp.seq+1
                        run["scanouts"].append(witness)
                        if frame == 1:
                            move(guest, 4, 3)
                            button(guest, True)
                            button(guest, False)
                            witness["input"] = ["rel(4,3)", "left-down", "left-up"]
                        else:
                            code = "a" if frame == 0 else "q"
                            key(guest, code, True)
                            key(guest, code, False)
                            witness["input"] = [code+"-down", code+"-up"]
                        witness["input_finished_at"] = time.monotonic()
                        witness["input_last_qmp_id"] = guest.qmp.seq
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
        report.update(status="PASS", smithay_wayland_verified=True)
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
