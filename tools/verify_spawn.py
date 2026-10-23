"""Exercise independent ELF children, cross-process pipes, wait and real GLib APIs."""
import argparse
import hashlib
import json
from pathlib import Path

from check_elf import boot_profile
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import wait


def verify(elf, output, glib=True):
    image = elf.read_bytes()
    profile = boot_profile(image)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status="FAIL", kernel_sha256=hashlib.sha256(image).hexdigest(),
                  profile=profile, programs={}, checks=[])
    cases = [("spawn-probe", ["PIPE_ENV_CWD", "WAIT_SIGNAL", "ATOMIC_ERRORS", "LIFETIME", "RECEIPTS"])]
    if glib:
        cases.append(("glib-spawn-probe", ["SYNC", "CHILD_WATCH", "ERRORS"]))
    try:
        for name, stages in cases:
            data = (ROOT / "artifacts/sysroot/aarch64-musl" / (name + ".elf")).read_bytes()
            assert image.count(data) == 1, "Exact ELF missing: " + name
            report["programs"][name] = hashlib.sha256(data).hexdigest()
            with Guest(elf, output / name, rng=True) as guest:
                guest.until(b"cyxia:/> ")
                start = len(guest.text)
                guest.command("posix exec " + name)
                wait(guest, start, b"EL0 pid=1 Exited code=0", 30)
                data = bytes(guest.text[start:])
                prefix = name.upper().replace("-", "_")
                actual = [line for line in data.splitlines() if line.startswith(prefix.encode())]
                expected = [f"{prefix} {stage} PASS".encode() for stage in stages] + [f"{prefix} PASS".encode()]
                assert actual == expected, data
                rows = parse_processes(guest.command("posix list"))
                assert len(rows) > 1, rows
                for row in rows.values():
                    assert row["state"] == "Exited" and row["free_pages"] == 64, row
                    assert row["heap_pages"] == row["image_pages"] == row["thread_count"] == 0, row
                    assert row["heap_free"] == profile["heap_pages"] and row["image_free"] == 4096, row
                    assert row["rank_model"] == 12289 and row["ai_selections"] > 0, row
                if name == "glib-spawn-probe":
                    assert rows[1]["thread_peak"] >= 2, rows
                report["checks"].append(dict(program=name, stages=stages, processes=list(rows.values())))
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == report["kernel_sha256"]
        report["status"] = "PASS"
    except Exception as error:
        report["error"] = repr(error)
    finally:
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/spawn")
    parser.add_argument("--syscall-only", action="store_true", help="Skip the optional spawn-test GLib image")
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), not args.syscall_only)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
