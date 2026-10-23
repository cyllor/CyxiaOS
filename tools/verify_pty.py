"""Run real PTY and spawned-shell target probes and verify process reclamation."""
import argparse
import hashlib
import json
from pathlib import Path

from check_elf import boot_profile
from doctor import ROOT
from shell import Guest
from verify_ported import parse_processes
from verify_x11 import wait


def verify(elf, output, runs=3):
    image = elf.read_bytes()
    profile = boot_profile(image)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status="FAIL", kernel_sha256=hashlib.sha256(image).hexdigest(), profile=profile, runs=[])
    try:
        program = (ROOT / "artifacts/sysroot/aarch64-musl/pty-probe.elf").read_bytes()
        assert image.count(program) == 1, "Exact PTY probe missing from kernel"
        report["probe_sha256"] = hashlib.sha256(program).hexdigest()
        for iteration in range(runs):
            with Guest(elf, output / f"run-{iteration + 1}", rng=True) as guest:
                guest.until(b"cyxia:/> ")
                start = len(guest.text)
                guest.command("posix exec pty-probe")
                wait(guest, start, b"EL0 pid=1 Exited code=", 30)
                data = bytes(guest.text[start:])
                assert b"EL0 pid=1 Exited code=0" in data, data
                actual = [line for line in data.splitlines() if line.startswith(b"PTY_PROBE")]
                expected = [f"PTY_PROBE {stage} PASS".encode() for stage in ("RAW_BOUNDS", "CANONICAL_CHILD", "SIGNALS_EOF", "LIFETIME", "SHELL")]
                assert actual == expected + [b"PTY_PROBE PASS"], data
                rows = parse_processes(guest.command("posix list"))
                assert len(rows) >= 2, rows
                for row in rows.values():
                    assert row["state"] == "Exited" and row["free_pages"] == 64, row
                    assert row["heap_pages"] == row["image_pages"] == row["thread_count"] == 0, row
                    assert row["heap_free"] == profile["heap_pages"] and row["image_free"] == 4096, row
                    assert row["rank_model"] == 12289 and row["ai_selections"] > 0, row
                report["runs"].append(dict(stages=[line.decode() for line in actual], processes=list(rows.values()), pty_admissions=data.count(b"PTY_ADMISSION AI_DIRECT model=8193")))
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
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/pty")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve(), args.runs)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
