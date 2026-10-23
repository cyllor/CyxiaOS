import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import build_smithay_xdg_client as builder


class SmithayXdgClientBuildTests(unittest.TestCase):
    def scanner_fixture(self, directory):
        prefix = directory / "sdk"
        scanner = prefix / "wayland-host-tools/bin/wayland-scanner"
        scanner.parent.mkdir(parents=True)
        scanner.write_bytes(b"scanner identity fixture, never executed\n")
        report = dict(status="cross-built", native_scanner=dict(
            path=str(scanner), version="wayland-scanner 1.24.0", sha256=builder.digest(scanner)))
        (prefix / "wayland-build-report.json").write_text(json.dumps(report))
        output = directory / "output"
        (output / "generated").mkdir(parents=True)
        (output / "provenance").mkdir()
        return prefix, scanner, output

    def test_xml_extracted_from_exact_archive_and_existing_evidence_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, scanner, output = self.scanner_fixture(Path(temporary))
            inputs, returned_scanner = builder.protocol_source(builder.DEFAULT_CRATE, prefix, output)
            self.assertEqual(returned_scanner, scanner)
            manifest = json.loads(builder.MANIFEST.read_text())
            xml = output / "generated/xdg-shell.xml"
            self.assertEqual(builder.digest(xml), manifest["xml_sha256"])
            self.assertEqual(inputs[builder.DEFAULT_CRATE], manifest["crate"]["sha256"])
            frozen = xml.read_bytes()
            with self.assertRaises(FileExistsError):
                builder.protocol_source(builder.DEFAULT_CRATE, prefix, output)
            self.assertEqual(xml.read_bytes(), frozen)

    def test_modified_crate_is_rejected_before_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            prefix, _, output = self.scanner_fixture(directory)
            crate = directory / "tampered.crate"
            shutil.copyfile(builder.DEFAULT_CRATE, crate)
            data = bytearray(crate.read_bytes())
            data[len(data) // 2] ^= 1
            crate.write_bytes(data)
            with self.assertRaisesRegex(builder.BuildError, "crate identity changed"):
                builder.protocol_source(crate, prefix, output)
            self.assertEqual(list((output / "generated").iterdir()), [])

    def test_archive_identity_does_not_replace_exact_xml_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            prefix, _, output = self.scanner_fixture(directory)
            manifest = json.loads(builder.MANIFEST.read_text())
            manifest["xml_sha256"] = "0" * 64
            path = directory / "different-xml-pin.json"
            path.write_text(json.dumps(manifest))
            with patch.object(builder, "MANIFEST", path):
                with self.assertRaisesRegex(builder.BuildError, "XML identity changed"):
                    builder.protocol_source(builder.DEFAULT_CRATE, prefix, output)

    def test_stale_scanner_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix, scanner, output = self.scanner_fixture(Path(temporary))
            scanner.write_bytes(scanner.read_bytes() + b"changed")
            with self.assertRaisesRegex(builder.BuildError, "Unverified native"):
                builder.protocol_source(builder.DEFAULT_CRATE, prefix, output)
            self.assertEqual(list((output / "generated").iterdir()), [])

    def test_generated_header_permission_is_exact_not_directory_wide(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            source = prefix / "client.c"
            source.write_text("/* source */")
            header = prefix / "generated/xdg-shell-client-protocol.h"
            header.parent.mkdir()
            header.write_text("/* exact generated header */")
            depfile = prefix / "dependencies.d"
            depfile.write_text(f"smithay-xdg-client: {source} {header}\n")
            self.assertEqual(len(builder.dependency_inputs(depfile, source, prefix, [header])), 2)
            unexpected = prefix / "generated/host-header.h"
            unexpected.write_text("/* unintended host dependency */")
            depfile.write_text(f"smithay-xdg-client: {source} {header} {unexpected}\n")
            with self.assertRaisesRegex(builder.BuildError, "unexpected header"):
                builder.dependency_inputs(depfile, source, prefix, [header])

    def test_existing_build_report_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "old-output"
            output.mkdir()
            report = output / "build-report.json"
            report.write_bytes(b"frozen evidence\n")
            with self.assertRaisesRegex(ValueError, "output already exists"):
                builder.build(output)
            self.assertEqual(report.read_bytes(), b"frozen evidence\n")


if __name__ == "__main__":
    unittest.main()
