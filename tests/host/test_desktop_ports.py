import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import desktop_ports as ports


def archive_package(data=b"verified source fixture"):
    return {"name": "fixture", "version": "1.0", "source_url": "https://example.org/source.tar.xz",
            "expected_sha256": hashlib.sha256(data).hexdigest(), "source_commit": None,
            "depends_on": []}


def manifest(package=None):
    return {"schema_version": 1, "closure_complete": True,
            "packages": [package or archive_package()], "unresolved_dependencies": []}


class DesktopPortsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.manifest_path = self.root / "manifest.json"

    def tearDown(self):
        self.temporary.cleanup()

    def load(self, document):
        self.manifest_path.write_text(json.dumps(document))
        return ports.load_manifest(self.manifest_path)

    def offline(self, data=b"verified source fixture"):
        path = self.root / "offline-source.tar.xz"
        path.write_bytes(data)
        return path

    def assert_no_partial_entry(self):
        if self.cache.exists():
            self.assertEqual(list(self.cache.iterdir()), [])

    def test_real_manifest_reports_source_and_closure_gaps(self):
        loaded = ports.load_manifest()
        report = ports.inspect_manifest(loaded)
        self.assertFalse(report["source_closure_ready"])
        self.assertFalse(report["desktop_build_ready"])
        self.assertTrue(any(p["name"] == "libc" for p in report["blockers"]))
        self.assertTrue(ports.inspect_manifest(loaded, "lxmenu-data")["source_closure_ready"])

    def test_default_inventory_is_read_only_and_offline(self):
        self.load(manifest())
        with patch.object(ports, "build_opener", side_effect=AssertionError("network")), \
                patch.object(ports.subprocess, "Popen", side_effect=AssertionError("process")), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ports.main(["--manifest", str(self.manifest_path),
                                         "--cache", str(self.cache)]), 0)
        self.assertTrue(json.loads(output.getvalue())["source_closure_ready"])
        self.assertFalse(self.cache.exists())

    def test_check_does_not_confuse_pinned_source_with_full_desktop(self):
        document = manifest()
        document["closure_complete"] = False
        self.load(document)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ports.main(["--manifest", str(self.manifest_path), "check"]), 1)

    def test_duplicate_identity_and_unknown_dependency_fail(self):
        document = manifest()
        document["packages"].append(copy.deepcopy(document["packages"][0]))
        with self.assertRaisesRegex(ports.PortError, "duplicate"):
            self.load(document)
        document = manifest()
        document["packages"][0]["depends_on"] = ["absent"]
        with self.assertRaisesRegex(ports.PortError, "unknown"):
            self.load(document)

    def test_duplicate_json_keys_are_rejected(self):
        self.manifest_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ports.PortError, "duplicate JSON key"):
            ports.load_manifest(self.manifest_path)

    def test_package_and_version_cannot_escape_cache(self):
        for field, value in [("name", "../outside"), ("name", "/absolute"),
                             ("version", "1/../../outside"), ("version", ".."),
                             ("name", "a\\b"), ("name", "-option")]:
            package = archive_package()
            package[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ports.PortError):
                    self.load(manifest(package))
                with self.assertRaises(ports.PortError):
                    ports.fetch(package, self.cache, offline_file=self.offline())
        self.assertFalse(self.cache.exists())

    def test_invalid_or_non_https_source_urls_are_rejected(self):
        for url in ["http://example.org/source", "file:///etc/passwd", "https://x/y#fragment",
                    "https://user:password@example.org/y", "https://x/a\nb", "https://[broken"]:
            package = archive_package()
            package["source_url"] = url
            with self.subTest(url=url), self.assertRaises(ports.PortError):
                self.load(manifest(package))

    def test_https_redirect_cannot_downgrade_or_add_credentials(self):
        handler = ports.HTTPSRedirects()
        for url in ["http://example.org/archive", "https://user:secret@example.org/archive"]:
            with self.assertRaises(ports.PortError):
                handler.redirect_request(None, None, 302, "redirect", {}, url)

    def test_malformed_hash_and_mutable_git_ref_are_not_pins(self):
        for field, value in [("expected_sha256", "abc"), ("expected_sha256", 42),
                             ("source_commit", "main"), ("source_commit", "a" * 39)]:
            package = archive_package()
            package[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ports.PortError):
                self.load(manifest(package))

    def test_missing_pin_refuses_before_disk_or_network_mutation(self):
        package = archive_package()
        package["expected_sha256"] = None
        package["source_commit"] = "a" * 40
        # A commit-looking archive URL is insufficient without a pinned repository.
        with patch.object(ports, "build_opener", side_effect=AssertionError("network")):
            with self.assertRaisesRegex(ports.PortError, "no fixed"):
                ports.fetch(package, self.cache, online=True)
        self.assertFalse(self.cache.exists())

    def test_unresolved_transitive_dependency_is_reported(self):
        package = archive_package()
        package["depends_on"] = ["runtime"]
        document = manifest(package)
        document["unresolved_dependencies"] = [{"name": "runtime", "version": None}]
        report = ports.inspect_manifest(self.load(document), "fixture")
        self.assertFalse(report["source_closure_ready"])
        self.assertEqual(report["blockers"][0]["name"], "runtime")

    def test_source_mode_and_explicit_package_are_required(self):
        with self.assertRaises(ports.PortError):
            ports.fetch(archive_package(), self.cache)
        with self.assertRaises(ports.PortError):
            ports.fetch(archive_package(), self.cache, online=True, offline_file=self.offline())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            ports.main(["fetch", "--online"])

    def test_offline_archive_is_verified_published_and_rechecked(self):
        package = archive_package()
        with patch.object(ports, "build_opener", side_effect=AssertionError("network")):
            result = ports.fetch(package, self.cache, offline_file=self.offline())
            checked = ports.verify(package, self.cache)
        self.assertEqual(checked["sha256"], package["expected_sha256"])
        self.assertEqual(result["mode"], "offline")
        self.assertFalse(result["built"])
        self.assertFalse(result["extracted"])
        self.assertEqual(len(list(self.cache.iterdir())), 1)

    def test_wrong_hash_leaves_no_partial_source_or_lock(self):
        with self.assertRaisesRegex(ports.PortError, "SHA-256 mismatch"):
            ports.fetch(archive_package(), self.cache, offline_file=self.offline(b"tampered"))
        self.assert_no_partial_entry()

    def test_stream_failure_leaves_no_partial_entry(self):
        with patch.object(ports, "copy_verified", side_effect=OSError("interrupted write")):
            with self.assertRaises(OSError):
                ports.fetch(archive_package(), self.cache, offline_file=self.offline())
        self.assert_no_partial_entry()

    def test_oversize_source_and_invalid_budget_are_rejected(self):
        with self.assertRaisesRegex(ports.PortError, "exceeds"):
            ports.fetch(archive_package(), self.cache, offline_file=self.offline(), max_bytes=2)
        with self.assertRaisesRegex(ports.PortError, "positive"):
            ports.fetch(archive_package(), self.cache, online=True, max_bytes=0)
        self.assertFalse(self.cache.exists())

    def test_stream_limit_is_enforced_even_without_content_length(self):
        target = self.root / "part"
        with self.assertRaisesRegex(ports.PortError, "exceeds"):
            ports.copy_verified(io.BytesIO(b"abc"), target, "a" * 64, 2)

    def test_disk_shortage_fails_before_downloading(self):
        class FullDisk:
            free = 1
        with patch.object(ports.shutil, "disk_usage", return_value=FullDisk()), \
                patch.object(ports, "build_opener", side_effect=AssertionError("network")):
            with self.assertRaisesRegex(ports.PortError, "insufficient disk"):
                ports.fetch(archive_package(), self.cache, online=True)
        self.assert_no_partial_entry()

    def test_existing_tampered_cache_is_not_silently_replaced(self):
        package = archive_package()
        ports.fetch(package, self.cache, offline_file=self.offline())
        payload = ports.destination(self.cache, package) / "source.archive"
        payload.write_bytes(b"corruption")
        with self.assertRaisesRegex(ports.PortError, "content/size"):
            ports.fetch(package, self.cache, offline_file=self.offline())
        self.assertEqual(payload.read_bytes(), b"corruption")

    def test_modified_archive_and_provenance_still_fail_manifest_hash(self):
        package = archive_package()
        ports.fetch(package, self.cache, offline_file=self.offline())
        directory = ports.destination(self.cache, package)
        payload = b"forged archive"
        (directory / "source.archive").write_bytes(payload)
        metadata = directory / "provenance.json"
        record = json.loads(metadata.read_text())
        record.update(sha256=hashlib.sha256(payload).hexdigest(), bytes=len(payload))
        metadata.write_text(json.dumps(record))
        with self.assertRaisesRegex(ports.PortError, "manifest SHA-256"):
            ports.verify(package, self.cache)

    def test_offline_file_cache_payload_and_destination_symlinks_are_rejected(self):
        package = archive_package()
        source = self.offline()
        alias = self.root / "alias"
        alias.symlink_to(source)
        with self.assertRaisesRegex(ports.PortError, "regular file"):
            ports.fetch(package, self.cache, offline_file=alias)
        ports.fetch(package, self.cache, offline_file=source)
        directory = ports.destination(self.cache, package)
        payload = directory / "source.archive"
        payload.unlink()
        payload.symlink_to(source)
        with self.assertRaisesRegex(ports.PortError, "regular file"):
            ports.verify(package, self.cache)
        shutil.rmtree(directory)
        directory.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ports.PortError, "symlink"):
            ports.fetch(package, self.cache, offline_file=source)

    @unittest.skipUnless(shutil.which("git"), "Git needed for exact-commit integration")
    def test_offline_git_bundle_and_forged_archive_verification(self):
        repository = self.root / "upstream"
        repository.mkdir()
        git = shutil.which("git")

        def run(*args):
            result = subprocess.run([git, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                                     *args], cwd=repository, env=ports.git_env(),
                                    capture_output=True, text=True, check=True)
            return result.stdout.strip()

        run("init")
        (repository / "configure").write_text("exit 99\n")
        run("add", "configure")
        run("commit", "-m", "source fixture")
        commit = run("rev-parse", "HEAD")
        bundle = self.root / "source.bundle"
        run("bundle", "create", str(bundle), "HEAD")
        package = archive_package()
        package.update(expected_sha256=None, source_commit=commit,
                       source_git_url="https://example.org/repository.git")
        result = ports.fetch(package, self.cache, offline_file=bundle, max_bytes=1024 * 1024)
        self.assertEqual(result["identity"]["pin"], commit)
        self.assertEqual(ports.verify(package, self.cache, 1024 * 1024)["status"], "verified")
        directory = ports.destination(self.cache, package)
        (directory / "source.tar").write_bytes(b"fake")
        metadata = directory / "provenance.json"
        record = json.loads(metadata.read_text())
        record.update(sha256=hashlib.sha256(b"fake").hexdigest(), bytes=4)
        metadata.write_text(json.dumps(record))
        with self.assertRaisesRegex(ports.PortError, "exact Git commit"):
            ports.verify(package, self.cache, 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
