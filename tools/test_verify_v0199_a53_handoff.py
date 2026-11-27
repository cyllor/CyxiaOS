"""Synthetic archive checks. These cases do not represent board observations."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

if __package__:
    from . import verify_v0199_verdicts as verdicts
    from .verify_v0199_a53_handoff import validate_handoff
else:
    import verify_v0199_verdicts as verdicts
    from verify_v0199_a53_handoff import validate_handoff


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dtb(compatible=b"fixture,a53-board\0", cpu_affinity=1, boot_cpu=0):
    strings = bytearray()
    names = {}
    tree = bytearray()

    def word(*values):
        return struct.pack(">" + "I" * len(values), *values)

    def emit(data):
        tree.extend(data)
        tree.extend(bytes(-len(data) % 4))

    def node(name, props, children=()):
        emit(word(1) + name.encode() + b"\0")
        for key, value in props.items():
            if key not in names:
                names[key] = len(strings)
                strings.extend(key.encode() + b"\0")
            emit(word(3, len(value), names[key]) + value)
        for child in children:
            node(*child)
        emit(word(2))

    cpu = {"device_type": b"cpu\0", "compatible": b"arm,cortex-a53\0"}
    node("", {"compatible": compatible, "#address-cells": word(2), "#size-cells": word(2)}, (
        ("cpus", {"#address-cells": word(2), "#size-cells": word(0)}, (
            ("cpu@0", dict(cpu, reg=word(0, 0))),
            ("cpu@1", dict(cpu, reg=word(cpu_affinity >> 32, cpu_affinity & 0xffffffff))),
        )),
        ("memory@40000000", {"device_type": b"memory\0", "reg": word(0, 0x40000000, 0, 0x40000000)}),
        ("serial@1000", {"compatible": b"arm,pl011\0"}),
    ))
    emit(word(9))
    strings_at = 56 + len(tree)
    return (word(0xd00dfeed, strings_at + len(strings), 56, strings_at, 40, 17, 16, boot_cpu,
                 len(strings), len(tree)) + bytes(16) + tree + strings)


def elf(machine=183):
    entry = 0x40200000
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01", 2, machine, 1,
                         entry, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 5, 120, entry, entry, 4, 4, 4)
    return header + segment + b"\0\0\0\0"


class HandoffTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.lock = {
            "schema": "cyxia-a53-platform-lock/v1",
            "source": "physical-board",
            "source_commit": "a" * 40,
            "board": {
                "vendor": "Synthetic",
                "model": "A53 test shape",
                "serial": "SYNTHETIC-01",
                "pcb_revision": "fixture-rev",
                "soc": "Synthetic SoC",
                "dt_compatible": "fixture,a53-board",
            },
            "cpus": [
                {"index": 0, "mpidr_el1": 0x80000000, "midr_el1": 0x410fd034},
                {"index": 1, "mpidr_el1": 0x80000001, "midr_el1": 0x410fd035},
            ],
            "ram": [[0x40000000, 0x40000000]],
            "firmware": self.write("firmware.bin", b"synthetic firmware"),
            "boot_image": self.write("kernel.elf", elf()),
            "dtb": self.write("board.dtb", dtb()),
        }
        self.lock["devices"] = [{
            "node": "/serial@1000",
            "compatible": "arm,pl011",
            "driver": {"id": "pl011", "version": "test", "artifact": self.lock["boot_image"]},
        }]
        self.capture()

    def write(self, name, data):
        (self.root / name).write_bytes(data)
        return {"path": name, "bytes": len(data), "sha256": sha(data)}

    def capture(self):
        lines = [
            "startup output preserved",
            "CYX_A53_BOARD " + self.lock["board"]["serial"],
            "CYX_A53_SOURCE " + self.lock["source_commit"],
            "CYX_A53_FIRMWARE " + self.lock["firmware"]["sha256"],
            "CYX_A53_IMAGE " + self.lock["boot_image"]["sha256"],
            "CYX_A53_DTB " + self.lock["dtb"]["sha256"],
            *(f"CYX_A53_CPU {c['index']} 0x{c['mpidr_el1']:016x} 0x{c['midr_el1']:08x}"
              for c in self.lock["cpus"]),
        ]
        self.lock["raw_capture"] = self.write("capture.raw", ("\n".join(lines) + "\n").encode())

    def validate(self):
        raw = json.dumps(self.lock).encode()
        return validate_handoff(raw, sha(raw), self.root)

    def test_checks_structure_without_hardware_verdict(self):
        original = (self.root / "capture.raw").read_bytes()
        result = self.validate()
        self.assertEqual(result["status"], "STRUCTURE_VALID")
        self.assertEqual(result["ARCH_A53"], "NOT_RUN")
        self.assertEqual(result["source_commit"], self.lock["source_commit"])
        self.assertEqual(result["manifest_sha256"], sha(json.dumps(self.lock).encode()))
        self.assertEqual(result["boot_image_sha256"], self.lock["boot_image"]["sha256"])
        self.assertEqual(result["raw_capture_sha256"], sha(original))
        self.assertEqual((self.root / "capture.raw").read_bytes(), original)

    def test_g5_archive_cli_keeps_missing_proofs_not_run_after_handoff(self):
        platform = json.dumps(self.lock).encode()
        lock_record = self.write("platform.json", platform)
        _, _, _, inventory_hash = verdicts.inventory()
        run = json.dumps({"schema": "cyxia-frozen-verdict-run/v1", "run_id": 1,
                          "inventory_sha256": inventory_hash, "proofs": []}).encode()
        run_record = self.write("run.json", run)
        output = self.root / "result.json"
        process = subprocess.run([
            sys.executable, "-B", "-m", "tools.verify_v0199_verdicts", "--scope", "g5",
            "--manifest", str(self.root / run_record["path"]), "--manifest-sha256", run_record["sha256"],
            "--evidence-root", str(self.root), "--output", str(output),
            "--a53-manifest", str(self.root / lock_record["path"]),
            "--a53-manifest-sha256", lock_record["sha256"], "--a53-evidence-root", str(self.root),
        ], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
        self.assertEqual((process.returncode, process.stderr), (1, ""))
        report = json.loads(output.read_bytes())
        self.assertEqual(report["a53_platform_lock_sha256"], lock_record["sha256"])
        self.assertEqual(report["ARCH_A53"]["counts"]["NOT_RUN"], 26)
        self.assertEqual(report["G4_QEMU"]["counts"]["NOT_RUN"], 262)

    def test_operator_pin_and_ambiguous_json(self):
        raw = json.dumps(self.lock).encode()
        with self.assertRaisesRegex(ValueError, "locked"):
            validate_handoff(raw, "b" * 64, self.root)
        raw = raw.replace(b'"source":', b'"source":"physical-board","source":')
        with self.assertRaisesRegex(ValueError, "[Dd]uplicate"):
            validate_handoff(raw, sha(raw), self.root)

    def test_known_emulator_is_rejected_even_with_a53_cpu_nodes(self):
        self.lock["dtb"] = self.write("board.dtb", dtb(b"linux,dummy-virt\0"))
        self.lock["board"]["dt_compatible"] = "linux,dummy-virt"
        self.capture()
        with self.assertRaisesRegex(ValueError, "emulat"):
            self.validate()

    def test_wrong_a53_part_is_rejected_even_with_matching_capture(self):
        self.lock["cpus"][1]["midr_el1"] = 0x410fd073
        self.capture()
        with self.assertRaisesRegex(ValueError, "Cortex-A53"):
            self.validate()

    def test_ram_and_cpu_affinity_must_match_the_dtb(self):
        self.lock["ram"][0][1] //= 2
        with self.assertRaisesRegex(ValueError, "RAM"):
            self.validate()
        self.lock["ram"][0][1] *= 2
        self.lock["dtb"] = self.write("board.dtb", dtb(cpu_affinity=1 << 32))
        self.capture()
        with self.assertRaisesRegex(ValueError, "affinit"):
            self.validate()

    def test_boot_cpu_header_must_match_observed_index_zero(self):
        self.lock["dtb"] = self.write("board.dtb", dtb(boot_cpu=1))
        self.capture()
        with self.assertRaisesRegex(ValueError, "DTB boot CPU"):
            self.validate()
        self.lock["cpus"][0]["mpidr_el1"] = 0x80000001
        self.lock["cpus"][1]["mpidr_el1"] = 0x80000000
        self.capture()
        self.assertEqual(self.validate()["status"], "STRUCTURE_VALID")

    def test_missing_cpu_and_wrong_image_capture_fail_even_when_rehashed(self):
        capture = (self.root / "capture.raw").read_bytes()
        self.lock["raw_capture"] = self.write("capture.raw", capture[:capture.rfind(b"CYX_A53_CPU ")])
        with self.assertRaisesRegex(ValueError, "CPU capture"):
            self.validate()
        updated = capture.replace(self.lock["boot_image"]["sha256"].encode(), b"f" * 64)
        self.lock["raw_capture"] = self.write("capture.raw", updated)
        with self.assertRaisesRegex(ValueError, "capture.*IMAGE"):
            self.validate()

    def test_raw_hash_mutation_and_symlink_rejected(self):
        capture = self.root / "capture.raw"
        capture.write_bytes(capture.read_bytes().replace(b"startup", b"altered"))
        with self.assertRaisesRegex(ValueError, "digest"):
            self.validate()
        capture.rename(self.root / "retarget.raw")
        capture.symlink_to("retarget.raw")
        with self.assertRaisesRegex(ValueError, "symlink|symbolic link|too many levels"):
            self.validate()

    def test_artifact_cannot_escape_archive(self):
        self.lock["raw_capture"]["path"] = "../capture.raw"
        with self.assertRaisesRegex(ValueError, "path"):
            self.validate()

    def test_boot_image_must_be_a_native_arm_elf(self):
        self.lock["boot_image"] = self.write("kernel.elf", elf(machine=62))
        self.lock["devices"][0]["driver"]["artifact"] = self.lock["boot_image"]
        self.capture()
        with self.assertRaisesRegex(ValueError, "AArch64.*ELF"):
            self.validate()

    def test_device_binding_checks_dtb_and_driver_bytes(self):
        device = self.lock["devices"][0]
        device["compatible"] = "test,absent"
        with self.assertRaisesRegex(ValueError, "device binding"):
            self.validate()
        device["compatible"] = "arm,pl011"
        device["driver"]["artifact"] = self.write("pl011.o", b"synthetic driver")
        (self.root / "pl011.o").write_bytes(b"replaced driver!")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
