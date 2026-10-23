"""Check actual EL0 execution receipts and cumulative admission/release accounting.

Uses the supplied ARM ELF unchanged. No host decisions substitute for guest models.
"""
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


CPU = ("cpu_process", "cpu_thread", "cpu_quantum")
RESOURCES = ("process", "thread", "anonymous", "elf", "spawn_receipt")


def snapshot(guest):
    start = len(guest.text)
    guest.command("ai system")
    wait(guest, start, b"AI_SYSTEM_END", 10)
    data = bytes(guest.text[start:])
    blocks = re.findall(rb"AI_SYSTEM schema=.*?AI_SYSTEM_END", data, re.S)
    assert len(blocks) == 1, data
    rows = {}
    for line in blocks[0].splitlines():
        if not line.startswith(b"AI_DOMAIN name="):
            continue
        fields = dict(item.decode().split("=", 1) for item in line.split()[1:])
        name = fields.pop("name")
        if name in CPU + RESOURCES:
            assert name not in rows, name
            rows[name] = {key: int(value) for key, value in fields.items()}
    assert set(rows) == set(CPU + RESOURCES), rows
    return rows


def settled(rows):
    for name in CPU:
        c = rows[name]
        assert c["committed"] == c["ai"] + c["guard"], (name, c)
        assert c["proposals"] == c["committed"] + c["cancelled"], (name, c)
    assert rows["cpu_process"]["committed"] == rows["cpu_quantum"]["committed"], rows
    c = rows["cpu_quantum"]
    assert c["enters"] == c["returns"] >= c["committed"], c
    for name in RESOURCES:
        c = rows[name]
        assert c["requests"] == sum(c[key] for key in ("committed", "denied", "capacity", "invalid", "failed")), (name, c)
        assert c["committed"] <= c["approved"] <= c["proposals"] <= c["requests"], (name, c)
        assert c["grant_units"] == c["release_units"], (name, c)


def verify(elf, output):
    image = elf.read_bytes()
    inspect_elf(image)
    profile = boot_profile(image)
    output.mkdir(parents=True, exist_ok=True)
    report = dict(status="FAIL", kernel_sha256=hashlib.sha256(image).hexdigest(),
                  profile=profile, snapshots=[], programs={}, checks=[])
    try:
        for name in ("thread-probe", "spawn-probe"):
            probe = (ROOT / "artifacts/sysroot/aarch64-musl" / (name + ".elf")).read_bytes()
            assert image.count(probe) == 1, "Exact probe is not embedded: " + name
            report["programs"][name] = hashlib.sha256(probe).hexdigest()
        with Guest(elf, output / "session", rng=True) as guest:
            guest.until(b"cyxia:/> ")
            initial = snapshot(guest)
            settled(initial)
            assert all(row["requests"] == 0 for row in initial.values()), initial
            report["snapshots"].append(dict(stage="initial", domains=initial))

            # Every timed spin is selected once more after its lifetime expires.
            # That choice has no user-context entry, and must not become execution.
            start = len(guest.text)
            guest.command("posix run spin")
            wait(guest, start, b"EL0 pid=1 Timeout code=124", 15)
            status = parse_processes(guest.command("posix list"))[1]
            assert status["ai_selections"] + status["guard_selections"] == status["ai_slices"], status
            assert status["thread_ai_selections"] + status["thread_guard_selections"] == status["ai_slices"], status
            before = snapshot(guest)
            settled(before)
            assert before["cpu_process"]["cancelled"] >= 1, before
            assert before["cpu_thread"]["cancelled"] >= 1, before
            report["checks"].append("expired lifetime cancels selection without inventing context execution")
            report["snapshots"].append(dict(stage="timeout", domains=before, process=status))

            for pid in (2, 3):
                start = len(guest.text)
                guest.command("posix exec thread-probe")
                wait(guest, start, f"EL0 pid={pid} Exited code=0".encode(), 40)
                data = bytes(guest.text[start:])
                stages = ("BASIC", "SYNC", "SIGNAL", "FUTEX", "LIMIT_REUSE", "GROUP_EXIT")
                actual = [line for line in data.splitlines() if line.startswith(b"THREAD_PROBE")]
                expected = [f"THREAD_PROBE {stage} PASS".encode() for stage in stages] + [b"THREAD_PROBE PASS"]
                assert actual == expected, data
                after = snapshot(guest)
                settled(after)
                assert after["thread"]["committed"] - before["thread"]["committed"] == 47, after
                assert after["thread"]["capacity"] - before["thread"]["capacity"] == 1, after
                assert after["thread"]["denied"] == before["thread"]["denied"], after
                for domain in CPU + RESOURCES:
                    for field in ("requests", "proposals", "approved", "committed", "grant_units", "release_units"):
                        assert after[domain][field] >= before[domain][field], (domain, field)
                report["snapshots"].append(dict(stage=f"thread-{pid - 1}", domains=after))
                before = after
            report["checks"].append("two real pthread probes preserve cumulative counts across slot reuse and distinguish hard thread limit")

            start = len(guest.text)
            guest.command("posix exec spawn-probe")
            wait(guest, start, b"EL0 pid=4 Exited code=0", 40)
            data = bytes(guest.text[start:])
            stages = ("PIPE_ENV_CWD", "WAIT_SIGNAL", "ATOMIC_ERRORS", "LIFETIME", "RECEIPTS")
            actual = [line for line in data.splitlines() if line.startswith(b"SPAWN_PROBE")]
            expected = [f"SPAWN_PROBE {stage} PASS".encode() for stage in stages] + [b"SPAWN_PROBE PASS"]
            assert actual == expected, data
            processes = parse_processes(guest.command("posix list"))
            assert all(row["state"] not in ("Running", "Waiting") for row in processes.values()), processes
            assert all(row["heap_pages"] == row["image_pages"] == row["thread_count"] == 0 for row in processes.values()), processes
            final = snapshot(guest)
            settled(final)
            assert final["spawn_receipt"]["committed"] > 0, final
            assert final["spawn_receipt"]["denied"] > 0, final
            for name, model in (("process", 8193), ("thread", 8193), ("anonymous", 8194), ("elf", 8195), ("spawn_receipt", 8193)):
                assert final[name]["last_model"] == model, (name, final[name])
                assert final[name]["granted"] > 0, (name, final[name])
            report["snapshots"].append(dict(stage="spawn", domains=final, processes=processes))
            report["checks"].append("spawn receipt denial, orphan/reap lifetime, memory release and models are real guest outcomes")
            assert b"FAIL panic" not in guest.text and b"FAIL unexpected exception" not in guest.text, guest.text[-2000:]
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
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/ai-accounting")
    args = parser.parse_args()
    result = verify(args.elf.resolve(), args.output.resolve())
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
