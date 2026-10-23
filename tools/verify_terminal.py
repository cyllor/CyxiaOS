"""Exercise the real LXPanel -> Xlib terminal -> PTY -> EL0 shell desktop path."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from check_elf import boot_profile
from desktop_session import embedded_programs, wait_window
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import button, key, move, pump, wait


def point(guest, x, y):
    move(guest, -10000, -10000)
    move(guest, x, y)


def click(guest, x, y):
    point(guest, x, y)
    pump(guest, .4)
    button(guest, True)
    button(guest, False)


def chord(guest, *codes):
    for code in codes:
        key(guest, code, True)
    for code in reversed(codes):
        key(guest, code, False)


def type_text(guest, text):
    special = {" ": "spc", "\n": "ret", "/": "slash", ".": "dot", "-": "minus", "'": "apostrophe"}
    for character in text:
        code = special.get(character, character)
        if not (character.isascii() and (character.islower() or character.isdigit() or character in special)):
            raise ValueError("Unsupported gate input: " + repr(character))
        guest.qmp.execute("input-send-event", {"events": [
            {"type": "key", "data": {"key": {"type": "qcode", "data": code}, "down": down}}
            for down in (True, False)]})
        pump(guest, .04)


def drag_resize(guest, window):
    point(guest, window["x"] + window["width"] - 30, window["y"] + window["height"] - 30)
    pump(guest, .4)
    key(guest, "alt", True)
    try:
        guest.qmp.execute("input-send-event", {"events": [{"type": "btn", "data": {"button": "right", "down": True}}]})
        pump(guest, .2)
        for _ in range(4):
            move(guest, 30, 16)
    finally:
        guest.qmp.execute("input-send-event", {"events": [{"type": "btn", "data": {"button": "right", "down": False}}]})
        key(guest, "alt", False)


def read_file(guest, path, expected, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = guest.command("cat " + path)
        if expected in data:
            return data.decode(errors="replace")
        pump(guest, .15)
    raise AssertionError(f"Guest file did not contain {expected!r}: {data!r}")


def settled_resize(guest, original, start, timeout=15):
    """Observe completed WM geometry and the matching client PTY resize."""
    deadline = time.monotonic() + timeout
    last = None
    stable = 0
    observations = []
    while time.monotonic() < deadline:
        window = wait_window(guest, "CyxiaTerminal")[0]
        geometry = tuple(window[name] for name in ("x", "y", "width", "height"))
        observations.append(dict(monotonic=time.monotonic(), window=window))
        stable = stable + 1 if geometry == last else 0
        last = geometry
        columns = (window["width"] - 16) // ((original["width"] - 16) // 80)
        lines = (window["height"] - 16) // ((original["height"] - 16) // 24)
        marker = f"CYXIA_TERMINAL RESIZE cols={columns} rows={lines}".encode()
        changed = (window["width"], window["height"]) != (original["width"], original["height"])
        if changed and stable >= 2 and marker in guest.text[start:]:
            return window, dict(cols=columns, rows=lines), observations
        pump(guest, .3)
    raise AssertionError(f"WM geometry and PTY did not settle together: {observations!r}")


def sleeping_shell(guest, child, previous, timeout=3):
    """Witness a new wait that stays parked before any queued command."""
    deadline = time.monotonic() + timeout
    observations = []
    last = None
    while time.monotonic() < deadline:
        row = parse_processes(guest.command("posix list"))[child]
        observations.append(dict(monotonic=time.monotonic(), process=row))
        if (row["state"] == "Waiting" and row["waits"] > previous["waits"]
                and last is not None and last["state"] == "Waiting"
                and row["syscalls"] == last["syscalls"] and row["waits"] == last["waits"]):
            return row, observations
        last = row
        pump(guest, .25)
    raise AssertionError(f"Shell did not enter a new stable sleep wait: {observations!r}")


def launch(guest, output):
    start = len(guest.text)
    click(guest, 16, 752)
    pump(guest, .7)
    guest.qmp.execute("screendump", {"filename": str(output / "terminal-menu.ppm")})
    chord(guest, "home")
    chord(guest, "down")
    chord(guest, "ret")
    data = wait(guest, start, b"CYXIA_TERMINAL READY", 30)
    child = int(re.search(rb"CYXIA_TERMINAL READY child=(\d+)", data)[1])
    window = wait_window(guest, "CyxiaTerminal")[0]
    rows = parse_processes(guest.command("posix list"))
    parent = rows[child]["parent_pid"]
    assert rows[parent]["state"] in ("Running", "Waiting") and rows[child]["state"] in ("Running", "Waiting"), rows
    click(guest, window["x"] + 40, window["y"] + 60)
    pump(guest, .5)
    return window, parent, child


def verify(elf, output):
    if (output / "summary.json").exists():
        raise FileExistsError("Select fresh terminal evidence; preserve previous reports")
    output.mkdir(parents=True, exist_ok=True)
    image = elf.read_bytes()
    report = dict(status="FAIL", kernel_sha256=hashlib.sha256(image).hexdigest(),
                  verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  profile=boot_profile(image), checks=[])
    try:
        report["programs"] = embedded_programs(elf, ["Xcyxia", "openbox", "pcmanfm", "lxpanel", "cyxia-terminal", "cyxia-sh", "x11-inspect"])
        with Guest(elf, output / "session", graphics=True, rng=True) as guest:
            try:
                guest.until(b"cyxia:/> ")
                guest.command("mkdir /Desktop")
                guest.command("posix exec xorg")
                wait(guest, 0, b"CYXIA_XORG_READY")
                guest.command("posix exec openbox")
                wait_window(guest)
                guest.command("posix exec pcmanfm-desktop")
                wait_window(guest, "Pcmanfm")
                guest.command("posix exec lxpanel")
                wait_window(guest, "lxpanel")
                pump(guest, 1.5)
                window, parent, child = launch(guest, output)
                report["initial_window"] = window
                report["terminal_pid"] = parent
                report["shell_pid"] = child
                report["checks"].append("LXPanel static menu spawned a real terminal and independent shell")
                type_text(guest, "mkdir /terminal-test\n")
                type_text(guest, "write /terminal-test/note.txt 'real keyboard through pty'\n")
                report["written_file"] = read_file(guest, "/terminal-test/note.txt", b"real keyboard through pty")
                type_text(guest, "cat /terminal-test/note.txt\n")
                pump(guest, .8)
                capture = output / "terminal-file.ppm"
                guest.qmp.execute("screendump", {"filename": str(capture)})
                report["file_screenshot_sha256"] = hashlib.sha256(capture.read_bytes()).hexdigest()
                report["checks"].append("physical keyboard mkdir/write/cat traversed XKB, Xlib, PTY and the real filesystem")
                # Openbox's explicit Alt+right-drag binding changes client
                # geometry; wait for the WM/client exchange before inspecting.
                resize_start = len(guest.text)
                drag_resize(guest, window)
                resized, pty_size, observations = settled_resize(guest, window, resize_start)
                report["resized_window"] = resized
                report["resize_convergence"] = observations
                report["pty_resize_readback"] = pty_size
                assert pty_size != {"cols": 80, "rows": 24}
                click(guest, resized["x"] + 40, resized["y"] + 60)
                # A completed physical-keyboard command proves focus has
                # returned after Openbox releases its resize input grab.
                type_text(guest, "write /terminal-test/focus.txt ready\n")
                report["focus_after_resize"] = read_file(guest, "/terminal-test/focus.txt", b"ready")
                previous = parse_processes(guest.command("posix list"))[child]
                sleep_started = time.monotonic()
                type_text(guest, "sleep 10\n")
                sleeping, observations = sleeping_shell(guest, child, previous)
                report["sleep_wait_evidence"] = observations
                # Queue a command behind sleep and prove it cannot run before
                # interruption. A broken/no-op sleep must fail this check.
                type_text(guest, "write /sleep-queued premature\n")
                pump(guest, 1)
                before_interrupt = guest.command("stat /sleep-queued")
                assert b"NotFound" in before_interrupt, before_interrupt
                blocked = parse_processes(guest.command("posix list"))[child]
                assert blocked["state"] == "Waiting", blocked
                assert blocked["syscalls"] == sleeping["syscalls"] and blocked["waits"] == sleeping["waits"], (sleeping, blocked)
                report["sleep_queued_process"] = blocked
                report["sleep_blocked_evidence"] = before_interrupt.decode(errors="replace")
                interrupted_at = time.monotonic()
                report["sleep_before_interrupt_seconds"] = interrupted_at - sleep_started
                assert interrupted_at - sleep_started < 8, "Harness exhausted the ten-second sleep window"
                capture = output / "terminal-sleep-queued.ppm"
                guest.qmp.execute("screendump", {"filename": str(capture)})
                report["sleep_queued_screenshot_sha256"] = hashlib.sha256(capture.read_bytes()).hexdigest()
                chord(guest, "ctrl", "c")
                type_text(guest, "write /terminal-test/after.txt interrupted\n")
                report["after_interrupt_file"] = read_file(guest, "/terminal-test/after.txt", b"interrupted", timeout=5)
                after_interrupt = time.monotonic()
                report["interrupt_response_seconds"] = after_interrupt - interrupted_at
                report["sleep_to_after_file_seconds"] = after_interrupt - sleep_started
                # Independent pre/post limits could accidentally accept natural
                # expiration. The file must exist before this ten-second sleep
                # could finish without Ctrl-C, including all harness overhead.
                assert after_interrupt - sleep_started < 8, "sleep did not wake before its natural deadline"
                assert b"NotFound" in guest.command("stat /sleep-queued"), "VINTR did not flush pending input"
                report["checks"].append("Openbox Alt+right-drag changed actual terminal geometry and PTY size; Ctrl-C interrupted a proven-blocking sleep")
                pump(guest, .8)
                guest.qmp.execute("screendump", {"filename": str(output / "terminal-resized.ppm")})
                start = len(guest.text)
                type_text(guest, "exit\n")
                wait(guest, start, b"CYXIA_TERMINAL EXIT child-status=0", 15)
                wait(guest, start, f"EL0 pid={parent} Exited code=0".encode(), 15)
                rows = parse_processes(guest.command("posix list"))
                for pid in (parent, child):
                    assert rows[pid]["state"] == "Exited" and rows[pid]["heap_pages"] == rows[pid]["image_pages"] == rows[pid]["thread_count"] == 0, rows
                report["normal_exit"] = {pid: rows[pid] for pid in (parent, child)}
                _, parent, child = launch(guest, output)
                start = len(guest.text)
                chord(guest, "alt", "f4")
                wait(guest, start, b"CYXIA_TERMINAL EXIT child-status=1", 15)
                wait(guest, start, f"EL0 pid={parent} Exited code=0".encode(), 15)
                rows = parse_processes(guest.command("posix list"))
                assert rows[child]["exit_signal"] == 1 and rows[child]["code"] == 129, rows
                for pid in (parent, child):
                    assert rows[pid]["heap_pages"] == rows[pid]["image_pages"] == rows[pid]["thread_count"] == 0, rows
                report["window_close"] = {pid: rows[pid] for pid in (parent, child)}
                report["checks"].append("shell exit and Openbox window close both reap child processes; window close delivers real SIGHUP")
                for pid, row in sorted(rows.items(), reverse=True):
                    if row["state"] in ("Running", "Waiting"):
                        start = len(guest.text)
                        guest.command(f"posix kill {pid}")
                        wait(guest, start, f"EL0 pid={pid} killed; pages reclaimed".encode())
                rows = parse_processes(guest.command("posix list"))
                assert all(row["state"] in ("Exited", "Killed") and row["free_pages"] == 64
                           and row["heap_pages"] == row["image_pages"] == row["thread_count"] == 0
                           and row["heap_free"] == report["profile"]["heap_pages"]
                           and row["image_free"] == 4096 for row in rows.values()), rows
                report["final_processes"] = rows
                report["checks"].append("all process, image, heap and thread grants reclaimed; serial shell remains responsive")
            finally:
                guest.qmp.execute("screendump", {"filename": str(output / "last-screen.ppm")})
                (output / "qmp.jsonl").write_text("".join(json.dumps(v) + "\n" for v in guest.qmp.transcript))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report["kernel_sha256"]
        assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == report["verifier_sha256"]
        report["status"] = "PASS"
    except Exception as error:
        report["error"] = repr(error)
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/terminal")
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
