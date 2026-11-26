"""Actual catalog installer with byte fixtures; not executable or guest evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import assemble_cosmic_workspace_applets_v1 as subject


class CatalogInstallation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cyxia-applet-install-')
        self.addCleanup(self.temporary.cleanup)
        root = self.root = Path(self.temporary.name).resolve()
        self.build = root / 'build'; self.build.mkdir(); (self.build / 'source').mkdir()
        self.parent = root / 'parent'; self.parent.mkdir()
        self.prefix = root / 'prefix'; self.prefix.mkdir()
        (self.prefix / 'probe.elf').write_bytes(b'preserved byte fixture, not runnable')
        (self.prefix / 'rootfs').mkdir(); (self.prefix / 'rootfs/old').write_bytes(b'original user data')
        self.original = subject.os_x86.catalog_inputs(self.prefix)
        self.manifest = dict(status='BUILT_NOT_RUN', sysroot=str(self.prefix),
                             external_inputs=self.original, ram_mib=1024)
        (self.parent / 'build-manifest.json').write_text(json.dumps(self.manifest))
        (self.build / 'build-report.json').write_text('fixture receipt, validated separately')
        (self.build / 'source/LICENSE').write_text('complete upstream license byte fixture')
        for name in subject.applets.PROGRAMS:
            (self.build / (name + '.elf')).write_bytes(name.encode())
        for source in subject.ASSETS:
            path = self.build / 'source' / source; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('upstream asset byte fixture ' + source).encode())
        sdk = root / 'sdk'; sdk.mkdir(); (sdk / 'COPYING').write_bytes(b'upstream license fixture')
        self.record = dict(sysroot=str(sdk), recipe={'additional_native_licenses': [dict(
            path='COPYING', destination='usr/share/doc/library/COPYING', sha256=subject.base.digest(sdk / 'COPYING'))]})
        self.output = root / 'output'

    def install(self):
        with patch.object(subject, 'validate', return_value=self.record):
            return subject.assemble(self.build, self.parent, self.output)

    def test_preserves_parent_bytes_and_installs_both_complete_roots_and_assets(self):
        result = self.install()
        self.assertEqual(result['status'], 'WORKSPACE_APPLETS_INSTALLED_NOT_RUN')
        self.assertFalse(result['guest_execution'])
        self.assertFalse(result['cosmic_session_verified'])
        self.assertEqual(subject.os_x86.catalog_inputs(self.prefix), self.original)
        for name, digest in self.original.items():
            self.assertEqual(subject.base.digest(self.output / name), digest)
        for name in subject.applets.PROGRAMS:
            self.assertEqual((self.output / (name + '.elf')).read_bytes(), name.encode())
            self.assertEqual((self.output / (name + '.elf')).stat().st_mode & 0o777, 0o755)

    def test_missing_original_asset_or_budget_failure_never_publishes_partial_catalog(self):
        victim = self.build / 'source' / next(iter(subject.ASSETS))
        victim.unlink()
        with self.assertRaises(FileNotFoundError):
            self.install()
        self.assertFalse(self.output.exists())
        victim.write_bytes(b'restored fixture')
        with patch.object(subject, 'MAX_BYTES', 1), self.assertRaises(subject.base.CosmicBuildError):
            self.install()
        self.assertFalse(self.output.exists())
        self.assertEqual(subject.os_x86.catalog_inputs(self.prefix), self.original)

    def test_stale_parent_or_existing_output_is_rejected(self):
        (self.prefix / 'probe.elf').write_bytes(b'changed bytes')
        with self.assertRaises(subject.base.CosmicBuildError):
            self.install()
        self.assertFalse(self.output.exists())
        self.output.mkdir(); (self.output / 'user').write_text('preserve')
        with self.assertRaises(subject.base.CosmicBuildError):
            self.install()
        self.assertEqual((self.output / 'user').read_text(), 'preserve')

    def test_only_the_two_paired_hosts_can_replace_parent_images(self):
        builds = []; records = {}
        bus = self.prefix / subject.objects.BUS; bus.parent.mkdir(parents=True)
        original_bus = subject.objects.BUS_SOURCE.read_text()
        for key in ('max_completed_connections', 'max_connections_per_user'):
            original_bus = original_bus.replace(f'<limit name="{key}">32</limit>', f'<limit name="{key}">16</limit>')
        bus.write_text(original_bus)
        for kind in ('panel', 'session'):
            name = subject.hosts.hosts.NAMES[kind] + '.elf'
            (self.prefix / name).write_bytes(('old fixture ' + kind).encode())
            directory = self.root / kind; directory.mkdir()
            (directory / name).write_bytes(('new host fixture ' + kind).encode())
            (directory / 'build-report.json').write_text('mocked complete host receipt')
            records[directory] = dict(host=kind); builds.append(directory)
            if kind == 'panel': records[directory]['popup_input'] = dict(kind='cosmic-panel-popup-input-v1',
                source_policy_sha256=subject.base.digest(subject.objects.POPUP_POLICY))
        self.original = subject.os_x86.catalog_inputs(self.prefix)
        self.manifest['external_inputs'] = self.original
        (self.parent / 'build-manifest.json').write_text(json.dumps(self.manifest))
        repaired = self.root / 'repaired'; repaired.mkdir()
        (repaired / 'relink-report.json').write_text('mocked genuine applet relink receipt')
        for name in subject.applets.PROGRAMS:
            (repaired / (name + '.elf')).write_bytes(('repaired fixture ' + name).encode())
        with patch.object(subject, 'validate', return_value=self.record), \
             patch.object(subject.hosts, 'validate', side_effect=lambda p: records[Path(p)]), \
             patch.object(subject.repaired_applets, 'validate', return_value=dict(parent=str(self.build))):
            for incomplete in ([builds[0]], [builds[0], builds[0]]):
                with self.subTest(incomplete=incomplete), self.assertRaises(subject.base.CosmicBuildError):
                    subject.assemble(self.build, self.parent, self.output, host_builds=incomplete, applet_relink=repaired)
                self.assertFalse(self.output.exists())
            result = subject.assemble(self.build, self.parent, self.output, host_builds=builds, applet_relink=repaired)
        self.assertEqual(set(result['replaced']), {'cosmic-panel.elf', 'cosmic-session.elf', subject.objects.BUS})
        for name, digest in self.original.items():
            if name not in result['replaced']:
                self.assertEqual(subject.base.digest(self.output / name), digest)
        envelope = json.loads((self.output / 'rootfs/usr/share/cyxia/cosmic-applets-v1.json').read_text())
        self.assertEqual(envelope['fds_per_process'], 128)
        for name, digest in envelope['hosts'].items():
            self.assertEqual(digest, subject.base.digest(self.output / name))
        self.assertEqual(subject.os_x86.catalog_inputs(self.prefix), self.original)


if __name__ == '__main__':
    unittest.main()
