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
import build_smithay_dynamic_client as builder


class SmithayDynamicClientBuildTests(unittest.TestCase):
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
            depfile.write_text(f"smithay-dynamic-client: {source} {header}\n")
            self.assertEqual(len(builder.dependency_inputs(depfile, source, prefix, [header])), 2)
            unexpected = prefix / "generated/host-header.h"
            unexpected.write_text("/* unintended host dependency */")
            depfile.write_text(f"smithay-dynamic-client: {source} {header} {unexpected}\n")
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


class DynamicClientReceiptTests(unittest.TestCase):
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
        emit(CONFIG, 1u, 4u, UINT32_MAX, 1u);
        emit(COUNTS, 1u, 4u, 4u, 4u, 8u);
        emit(KEY, 3u, 1u, UINT32_MAX, 45u, 1u, 120u);
        emit(PEER, 3u, 2147483647, 0u, 0u);
        return calls == 4 ? 0 : 7;
    }
    if (mode == 4) { emit("%065d", 0); return 6; }
    emit("%064d", 0);
    return calls == (mode == 3 ? 2 : 1) ? 0 : 5;
}
'''
        for name, prefix in (("CONFIG", "DYN_CLIENT CFG "),
                             ("COUNTS", "DYN_CLIENT COUNTS "),
                             ("KEY", "DYN_CLIENT KEY "),
                             ("PEER", "DYN_CLIENT PEER ")):
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


class DynamicCapacityProbeTests(unittest.TestCase):
    """Run the production EOF gate: errors and protocol bytes cannot pass."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        directory = Path(cls.temporary.name)
        source = builder.SOURCE.read_text()
        probe = source[source.index("static void capacity_probe("):source.index("int main(")]
        harness = r'''
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
enum { EVENT_TIMEOUT_MS = 30000 };
struct wl_display { int unused; };
struct client { struct wl_display *display; };
static int mode, polls, reads, disconnects, receipts;
static void fail(const char *why) { (void)why; _exit(1); }
#define CHECK(condition, why) do { if (!(condition)) fail(why); } while (0)
static int64_t monotonic_ms(void) {
    static unsigned calls;
    return mode == 3 && calls++ ? 30000 : 0;
}
static int wl_display_get_fd(struct wl_display *display) { (void)display; return 3; }
static void wl_display_disconnect(struct wl_display *display) { (void)display; disconnects++; }
static void emit(const char *format, ...) { (void)format; receipts++; }
static int probe_poll(struct pollfd *fds, nfds_t count, int timeout) {
    CHECK(count == 1 && fds[0].fd == 3 && timeout > 0, "poll contract");
    polls++;
    if (mode == 4 && polls == 1) { errno = EINTR; return -1; }
    fds[0].revents = mode == 2 ? POLLERR : POLLHUP;
    return 1;
}
static ssize_t probe_read(int fd, void *bytes, size_t size) {
    CHECK(fd == 3 && size == 1, "read contract");
    reads++;
    if (mode == 5 && reads == 1) { errno = EAGAIN; return -1; }
    if (mode == 6) { errno = ECONNRESET; return -1; }
    if (mode == 1) { *(unsigned char *)bytes = 1; return 1; }
    return 0;
}
#define poll probe_poll
#define read probe_read
''' + probe + r'''
int main(int argc, char **argv) {
    if (argc != 2) return 8;
    mode = atoi(argv[1]);
    struct wl_display display = {0};
    struct client client = { .display = &display };
    capacity_probe(&client);
    return disconnects == 1 && receipts == 2 && reads > 0 ? 0 : 7;
}
'''
        code = directory / "probe.c"
        code.write_text(harness)
        cls.program = directory / "probe"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(code), "-o", str(cls.program)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_eof_disconnects_and_emits_success(self):
        self.assertEqual(subprocess.run([self.program, "0"]).returncode, 0)

    def test_protocol_byte_is_not_capacity_eof(self):
        self.assertEqual(subprocess.run([self.program, "1"]).returncode, 1)

    def test_poll_and_read_errors_are_not_capacity_eof(self):
        self.assertEqual(subprocess.run([self.program, "2"]).returncode, 1)
        self.assertEqual(subprocess.run([self.program, "6"]).returncode, 1)

    def test_timeout_is_not_capacity_eof(self):
        self.assertEqual(subprocess.run([self.program, "3"]).returncode, 1)

    def test_interruption_and_transient_read_retry_until_real_eof(self):
        self.assertEqual(subprocess.run([self.program, "4"]).returncode, 0)
        self.assertEqual(subprocess.run([self.program, "5"]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
