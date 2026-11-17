"""Pure metadata fixtures; no ELF, installer, compiler or guest is executed.

Known byte totals exercise the real capacity algorithm, but fixture paths and
digests do not authenticate actual catalog files. Genuine consumer replay is a
separate step and cannot be replaced by these cases.
"""
import contextlib
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


def forbidden_process(*args, **kwargs):
    raise AssertionError('External process forbidden in pure catalog fixtures')


def process_guards(stack):
    for module, names in (
            (subprocess, ('Popen', 'run', 'call', 'check_call', 'check_output')),
            (os, ('system', 'popen', 'fork', 'posix_spawn', 'posix_spawnp',
                  'execv', 'execve', 'execl', 'execle', 'execvp', 'execvpe'))):
        for name in names:
            if hasattr(module, name):
                stack.enter_context(patch.object(module, name, side_effect=forbidden_process))


with contextlib.ExitStack() as guards:
    process_guards(guards)
    selected = Path(__file__).with_name('cosmic_panel_catalog_capacity_v1.py')
    specification = importlib.util.spec_from_file_location('panel_capacity_v1_candidate', selected)
    subject = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(subject)


def identity(name, size):
    return {'bytes': size, 'sha256': hashlib.sha256(('HOST FIXTURE ' + name).encode()).hexdigest(),
            'mode': 0o755 if name.endswith('.elf') and not name.startswith('rootfs/') else 0o644}


def panel():
    names = {
        'cosmic-panel.elf': 33718544,
        'rootfs/usr/share/doc/cosmic-panel/LICENSE.md': 34902,
        'rootfs/usr/share/doc/cosmic-panel/launch-pad-LICENSE.md': 15551,
        'rootfs/usr/share/doc/cosmic-panel/smithay-LICENSE.txt': 1094,
        'rootfs/usr/share/doc/cosmic-panel/smithay-drm-extras-LICENSE': 1079,
        'rootfs/usr/share/doc/cosmic-panel/wayland-sys-LICENSE': 1057,
    }
    return {
        'kind': 'cosmic-panel-linux-v1-installation',
        'status': 'PANEL_INSTALLATION_REVALIDATED_NOT_RUN',
        'guest_execution': 'not performed',
        'panel_verified': False, 'panel_applet_lifecycle_verified': False,
        'cosmic_session_ready': False, 'cosmic_session_verified': False,
        'full_cosmic_complete': False,
        'image_load_pages': 6920, 'required_pages': 7432,
        'files': {name: identity(name, size) for name, size in names.items()},
    }


def small_base():
    return {name: identity(name, 1024)
            for name in subject.IMAGE_NAMES - {'cosmic-panel.elf'}}


class CapacityBoundaries(unittest.TestCase):
    def setUp(self):
        guards = contextlib.ExitStack()
        process_guards(guards)
        self.addCleanup(guards.close)

    def test_recorded_byte_shape_blocks_before_any_raw_catalog_assembly(self):
        sizes = {
            'cosmic-comp.elf': 41136280, 'cosmic-notifications.elf': 29912232,
            'cosmic-session.elf': 5332352, 'cosmic-settings-daemon.elf': 7424856,
            'dbus-daemon.elf': 469224, 'dbus-send.elf': 235024,
            'notification-probe.elf': 946192, 'probe.elf': 50448, 'settings-probe.elf': 954880,
        }
        base = {name: identity(name, size) for name, size in sizes.items()}
        # 137 explicit metadata-only asset fixtures reproduce the retained total.
        for i in range(137):
            name = f'rootfs/host-fixture/asset-{i}'
            base[name] = identity(name, 3356834 - 136 if i == 0 else 1)
        self.assertEqual(sum(row['bytes'] for row in base.values()), 89818322)
        result = subject.preflight(base, panel())
        self.assertEqual(result['catalog_count'], 152)
        self.assertEqual(result['catalog_bytes'], 123590549)
        self.assertEqual(result['excess_bytes'], 22927253)
        self.assertEqual(result['status'], 'BLOCKED_EXISTING_CATALOG_LIMIT')
        self.assertEqual(result['violations'], ['raw_catalog_bytes'])
        self.assertFalse(result['catalog_assembled'])
        with self.assertRaises(ValueError): subject.require_fit(base, panel())

    def test_exact_original_byte_limit_fits_and_one_more_byte_fails(self):
        base, addition = small_base(), panel()
        missing = subject.MAX_CATALOG_BYTES - subject.preflight(base, addition)['catalog_bytes']
        name = 'rootfs/host-fixture/padding'
        self.assertLessEqual(missing, subject.MAX_FILE_BYTES)
        base[name] = identity(name, missing)
        result = subject.require_fit(base, addition)
        self.assertEqual(result['catalog_bytes'], 96 * 1024**2)
        self.assertEqual(result['excess_bytes'], 0)
        base[name]['bytes'] += 1
        with self.assertRaises(ValueError): subject.require_fit(base, addition)
        self.assertEqual(subject.preflight(base, addition)['excess_bytes'], 1)

    def test_identical_content_at_two_paths_never_reduces_the_raw_gate(self):
        base, addition = small_base(), panel()
        duplicate = 'rootfs/host-fixture/complete-license'
        base[duplicate] = copy.deepcopy(addition['files']['rootfs/usr/share/doc/cosmic-panel/LICENSE.md'])
        padding = 'rootfs/host-fixture/padding'
        remaining = subject.MAX_CATALOG_BYTES + 1 - subject.preflight(base, addition)['catalog_bytes']
        base[padding] = identity(padding, remaining)
        result = subject.preflight(base, addition)
        self.assertEqual(result['excess_bytes'], 1)
        self.assertEqual(result['duplicate_savings_credited_to_existing_limit'], 0)
        self.assertTrue(any(row['potential_stored_saving'] == 34902 for row in result['content_duplicates']))
        with self.assertRaises(ValueError): subject.require_fit(base, addition)

    def test_exec_accounting_remains_per_process_and_is_not_combined_with_compositor(self):
        base, addition = small_base(), panel()
        base['cosmic-comp.elf']['required_pages'] = 8839
        self.assertGreater(8839 + 7432, 16256)
        result = subject.require_fit(base, addition)
        self.assertEqual(result['panel_required_pages'], 7432)
        self.assertIn('per-process private slot', result['exec_pool_scope'])
        for load_pages, required_pages in ((6920, 7433), (15873, 16385), (True, 513), (6920, True)):
            bad = {**addition, 'image_load_pages': load_pages, 'required_pages': required_pages}
            with self.subTest(load_pages=load_pages, required_pages=required_pages), self.assertRaises(ValueError):
                subject.preflight(base, bad)

    def test_entry_limit_is_independent_of_byte_limit(self):
        base, addition = small_base(), panel()
        for i in range(241):
            name = f'rootfs/host-fixture/asset-{i}'
            base[name] = identity(name, 1)
        self.assertEqual(subject.require_fit(base, addition)['catalog_count'], 256)
        name = 'rootfs/host-fixture/one-too-many'
        base[name] = identity(name, 0)
        result = subject.preflight(base, addition)
        self.assertEqual(result['violations'], ['entry_count'])
        with self.assertRaises(ValueError): subject.require_fit(base, addition)

    def test_original_component_set_claims_and_all_licenses_are_required(self):
        base, addition = small_base(), panel()
        for key, value in (
                ('kind', 'cosmic-panel-native-linux-v1'), ('status', 'INSTALLED_NOT_RUN'),
                ('guest_execution', False), ('panel_verified', True),
                ('panel_applet_lifecycle_verified', True), ('cosmic_session_ready', True),
                ('cosmic_session_verified', True), ('full_cosmic_complete', True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.preflight(base, {**addition, key: value})
        for name in addition['files']:
            bad = copy.deepcopy(addition)
            bad['files'].pop(name)
            with self.subTest(missing=name), self.assertRaises(ValueError): subject.preflight(base, bad)
        for name in base:
            bad = copy.deepcopy(base)
            bad.pop(name)
            with self.subTest(missing=name), self.assertRaises(ValueError): subject.preflight(bad, addition)

    def test_path_alias_utf8_byte_limit_and_malformed_identities_are_rejected(self):
        for name in ('rootfs/bin/cosmic-panel', 'rootfs/a/../b', 'rootfs/a//b',
                     'rootfs/host-fixture/' + 'é' * 50, 'other-component.elf'):
            base = small_base()
            base[name] = identity(name, 1)
            with self.subTest(name=name), self.assertRaises(ValueError): subject.preflight(base, panel())
        for key, value in (('bytes', True), ('bytes', -1), ('bytes', 64 * 1024**2 + 1),
                           ('sha256', 'x' * 64), ('mode', 0o4755)):
            bad = panel()
            bad['files']['cosmic-panel.elf'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): subject.preflight(small_base(), bad)

    def test_plan_cannot_mutate_inputs_or_authorize_a_later_changed_catalog(self):
        base, addition = small_base(), panel()
        before = copy.deepcopy((base, addition))
        result = subject.preflight(base, addition)
        result['catalog']['cosmic-panel.elf']['bytes'] = 0
        self.assertEqual((base, addition), before)
        self.assertEqual(subject.require_fit(base, addition)['catalog']['cosmic-panel.elf']['bytes'], 33718544)
        # The gate recomputes from the actual selected metadata; no old fit flag is consumed.
        base['rootfs/host-fixture/new-large-file'] = identity('rootfs/host-fixture/new-large-file', 64 * 1024**2)
        with self.assertRaises(ValueError): subject.require_fit(base, addition)


if __name__ == '__main__':
    unittest.main()
