import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import build_smithay_wayland_client as builder


class SmithayWaylandClientBuildTests(unittest.TestCase):
    def fixture(self, prefix):
        library = prefix / "sysroot/usr/lib"
        library.mkdir(parents=True)
        hashes = {}
        for name in ("libwayland-client.a", "libffi.a", "libxkbcommon.a", "libc.a"):
            path = library / name
            path.write_bytes(("unit-test archive identity: " + name).encode())
            hashes[name] = builder.digest(path)
        for name in ("wayland", "xkbcommon"):
            manifest = builder.ROOT / "ports/cosmic" / (name + "-source.json")
            report = dict(status="cross-built", manifest_sha256=builder.digest(manifest),
                          target_libc_sha256=hashes["libc.a"])
            if name == "wayland":
                report.update(target_libffi_sha256=hashes["libffi.a"],
                              target=dict(archives={
                                  "libwayland-client.a": dict(sha256=hashes["libwayland-client.a"])
                              }))
            else:
                report["target"] = dict(archive=dict(sha256=hashes["libxkbcommon.a"]))
            (prefix / (name + "-build-report.json")).write_text(json.dumps(report))
        return library

    def test_stale_sdk_archive_is_rejected_before_linking(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            library = self.fixture(prefix)
            inputs = builder.prerequisite_inputs(prefix)
            self.assertEqual(len(inputs), 8)
            path = library / "libwayland-client.a"
            path.write_bytes(path.read_bytes() + b" changed")
            with self.assertRaisesRegex(builder.BuildError, "archive changed"):
                builder.prerequisite_inputs(prefix)

    def test_target_header_dependency_cannot_escape_the_sysroot(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            source = prefix / "client.c"
            source.write_text("/* dependency fixture */")
            header = prefix / "sysroot/usr/include/wayland-client.h"
            header.parent.mkdir(parents=True)
            header.write_text("/* target dependency */")
            depfile = prefix / "deps.d"
            depfile.write_text(f"smithay-wayland-client: {source} \\\n {header}\n")
            self.assertEqual(len(builder.dependency_inputs(depfile, source, prefix)), 2)
            host = prefix / "host.h"
            host.write_text("/* unintended host dependency */")
            depfile.write_text(f"smithay-wayland-client: {source} {host}\n")
            with self.assertRaisesRegex(builder.BuildError, "unexpected header"):
                builder.dependency_inputs(depfile, source, prefix)

    def test_existing_evidence_is_not_rebuilt_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "existing"
            output.mkdir()
            evidence = output / "build-report.json"
            evidence.write_bytes(b"preserved evidence\n")
            with self.assertRaisesRegex(ValueError, "output already exists"):
                builder.build(output)
            self.assertEqual(evidence.read_bytes(), b"preserved evidence\n")


if __name__ == "__main__":
    unittest.main()
