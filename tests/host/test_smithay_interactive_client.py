import json
from pathlib import Path
import shutil
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import build_smithay_interactive_client as builder


class SmithayInteractiveClientBuildTests(unittest.TestCase):
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
            depfile.write_text(f"smithay-interactive-client: {source} {header}\n")
            self.assertEqual(len(builder.dependency_inputs(depfile, source, prefix, [header])), 2)
            unexpected = prefix / "generated/host-header.h"
            unexpected.write_text("/* unintended host dependency */")
            depfile.write_text(f"smithay-interactive-client: {source} {header} {unexpected}\n")
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


class InteractiveClientReceiptTests(unittest.TestCase):
    """Exercise the actual C emitter against the console's 64-byte boundary."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        directory = Path(cls.temporary.name)
        source = builder.SOURCE.read_text()
        emitter = source[source.index("static void emit("):source.index("static void fail(")]

        def receipt(prefix):
            matches = re.findall(r'emit\("(' + re.escape(prefix) + r'[^"\n]+)"', source)
            if len(matches) != 1:
                raise AssertionError((prefix, matches))
            return '"' + matches[0] + '"'

        harness = r'''
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static int mode, calls;
static ssize_t console_write(int fd, const void *bytes, size_t length) {
    (void)fd; (void)bytes;
    ++calls;
    if (length > 64) _exit(9);
    if (mode == 2) return (ssize_t)length - 1;
    if (mode == 3 && calls == 1) { errno = EINTR; return -1; }
    return (ssize_t)length;
}
#define write console_write
''' + emitter + r'''
int main(int argc, char **argv) {
    if (argc != 2) return 8;
    mode = atoi(argv[1]);
    if (mode == 0) {
        emit(CONFIG, 1u, 5u, UINT32_MAX, 68, 56, 1u, 0u);
        emit(COUNTS, 1u, 6u, 6u, 6u, 2u, 2u, 4u);
        emit(BUTTON, 1u, UINT32_MAX, 273u);
        emit(RESIZE, 1u, 3u, UINT32_MAX);
        return calls == 4 ? 0 : 7;
    }
    if (mode == 4) { emit("%065d", 0); return 6; }
    emit("%064d", 0);
    return calls == (mode == 3 ? 2 : 1) ? 0 : 5;
}
'''
        for name, prefix in (("CONFIG", "INT_CLIENT CFG "),
                             ("COUNTS", "INT_CLIENT COUNTS "),
                             ("BUTTON", "INT_CLIENT BUTTON "),
                             ("RESIZE", "INT_CLIENT REQ id=%u n=%u kind=resize ")):
            harness = harness.replace("emit(" + name + ",", "emit(" + receipt(prefix) + ",")
        code = directory / "receipt.c"
        code.write_text(harness)
        cls.program = directory / "receipt"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(code), "-o", str(cls.program)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_longest_receipts_each_fit_one_console_write(self):
        self.assertEqual(subprocess.run([self.program, "0"]).returncode, 0)

    def test_64_byte_record_accepted_and_65_byte_record_rejected(self):
        self.assertEqual(subprocess.run([self.program, "1"]).returncode, 0)
        self.assertEqual(subprocess.run([self.program, "4"]).returncode, 2)

    def test_short_write_fails_instead_of_emitting_a_spliceable_continuation(self):
        self.assertEqual(subprocess.run([self.program, "2"]).returncode, 2)

    def test_interrupted_zero_write_retries_the_same_complete_record(self):
        self.assertEqual(subprocess.run([self.program, "3"]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
