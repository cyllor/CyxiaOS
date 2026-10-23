"""Exercise the event/stream ABI in an ARM guest, including failure atomicity."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from check_elf import boot_profile, inspect_elf
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import wait


def verify(elf, output):
    image = elf.read_bytes()
    inspect_elf(image)
    profile = boot_profile(image)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status="FAIL", kernel_sha256=hashlib.sha256(image).hexdigest())
    try:
        probe = (ROOT / "artifacts/sysroot/aarch64-musl/event-probe.elf").read_bytes()
        assert image.count(probe) == 1, "Exact event-probe ELF is not embedded"
        report["probe_sha256"] = hashlib.sha256(probe).hexdigest()
        with Guest(elf, output / "session", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            start = len(guest.text)
            guest.command("posix exec event-probe")
            wait(guest, start, b"EL0 pid=1 Exited code=0", 30)
            data = bytes(guest.text[start:])
            matches = re.findall(rb"(?m)^EVENT_PROBE PASS checks=(\d+) fd_transport=false level_epoll=true\r?$", data)
            assert len(matches) == 1 and int(matches[0]) >= 35 and b"EVENT_PROBE FAIL" not in data, data
            report["checks"] = int(matches[0])
            row = parse_processes(guest.command("posix list"))[1]
            for field, expected in dict(state="Exited", code=0, free_pages=64,
                    heap_pages=0, heap_free=profile["heap_pages"], image_pages=0,
                    image_free=4096, thread_count=0, thread_peak=2).items():
                assert row.get(field) == expected, (field, row)
            report["process"] = row
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
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/events")
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
