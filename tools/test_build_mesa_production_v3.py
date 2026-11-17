"""Pure Python input/configuration checks; no scanner, compiler, Meson or guest.

The original v2 tests run against the new module unchanged. New metadata fixtures
exercise acceptance and rejection; they are explicitly not build/runtime proof.
Seventeen pure metadata cases always run. Ten genuine-data integration cases
run only with an explicit CYXIA_WAYLAND_TEST_FIXTURES JSON descriptor and otherwise
report a clear skip. Missing data never becomes build or runtime evidence.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

# Normal repository test execution resolves both implementation modules from
# the installed tools directory. Genuine integration fixtures are opt-in data.
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import install_wayland_protocols_v1 as data
import build_mesa_production_v3 as subject
REPO = subject.ROOT

spec = importlib.util.spec_from_file_location('_mesa_v3_retained_v2_tests', REPO / 'tools/test_build_mesa_production_v2.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.subject = subject

FIXTURE_ENV = 'CYXIA_WAYLAND_TEST_FIXTURES'
FIXTURES_AVAILABLE = False
FIXTURE_REASON = 'Real integration data is optional; set ' + FIXTURE_ENV + ' to its explicit JSON fixture descriptor.'
ARCHIVE = SDK2 = SCANNER_REPORT = SCANNER_REPORT_SHA256 = None
SCANNER = Path('/metadata-fixture/wayland-scanner')
configuration = os.environ.get(FIXTURE_ENV)
if configuration:
    descriptor = Path(configuration)
    if not descriptor.is_file():
        FIXTURE_REASON = 'Explicit real integration fixture descriptor is missing: ' + str(descriptor)
    else:
        if descriptor.stat().st_size > 64 * 1024:
            raise ValueError('Wayland test fixture descriptor is oversized')
        values = json.loads(descriptor.read_text())
        if values.get('schema_version') != 1:
            raise ValueError('Unsupported Wayland test fixture schema')
        selected = {name: Path(values[name]) for name in ('archive', 'sdk_prefix', 'scanner', 'scanner_report')}
        if not all(path.is_absolute() for path in selected.values()):
            raise ValueError('Integration fixture paths must be explicit absolute paths')
        checksum = values['scanner_report_sha256']
        if not isinstance(checksum, str) or len(checksum) != 64 or any(c not in '0123456789abcdef' for c in checksum):
            raise ValueError('Integration scanner report requires its explicit SHA-256')
        missing = [name for name, path in selected.items() if not (path.is_dir() if name == 'sdk_prefix' else path.is_file())]
        if missing:
            FIXTURE_REASON = 'Explicit genuine integration fixture inputs are missing: ' + ', '.join(missing)
        else:
            ARCHIVE, SDK2, SCANNER, SCANNER_REPORT = (selected[name] for name in ('archive', 'sdk_prefix', 'scanner', 'scanner_report'))
            SCANNER_REPORT_SHA256 = checksum
            FIXTURES_AVAILABLE = True



@unittest.skipUnless(FIXTURES_AVAILABLE, FIXTURE_REASON)
class ProtocolData(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bundle = self.root / 'bundle'
        self.addCleanup(self.temporary.cleanup)

    def prepare(self):
        return data.prepare(ARCHIVE, self.bundle)

    def test_complete_authentic_distribution_and_upstream_pc_template(self):
        result = self.prepare()
        origin = json.loads((self.bundle / 'origin.json').read_text())
        self.assertEqual(len(origin['source_files']), 125)
        self.assertEqual(result['protocol_xml_count'], 53)
        self.assertEqual(len(origin['protocol_xml']), 53)
        self.assertEqual(set(result['mesa_required_xml']), set(data.REQUIRED_XML))
        self.assertEqual(result['archive']['sha256'], data.ARCHIVE_SHA256)
        self.assertFalse(result['native_execution'])
        self.assertFalse(result['guest_execution'])
        pc = (self.bundle / 'sysroot' / data.PC_PATH).read_text()
        self.assertEqual(pc, 'prefix=/usr\ndatarootdir=${prefix}/share\npkgdatadir=${pc_sysrootdir}${datarootdir}/wayland-protocols\n\nName: Wayland Protocols\nDescription: Wayland protocol files\nVersion: 1.41\n')
        self.assertEqual(data.validate_installation(self.bundle, self.bundle / 'sysroot')['installation_verified'], True)

    def test_archive_mutation_and_symlink_rejected_before_output(self):
        invalid = self.root / 'changed.tar.xz'
        content = bytearray(ARCHIVE.read_bytes()); content[-1] ^= 1
        invalid.write_bytes(content)
        with self.assertRaises(ValueError): data.prepare(invalid, self.bundle)
        self.assertFalse(self.bundle.exists())
        linked = self.root / 'linked.tar.xz'; linked.symlink_to(ARCHIVE)
        with self.assertRaises(ValueError): data.prepare(linked, self.bundle)
        self.assertFalse(self.bundle.exists())

    def test_fresh_output_requirement_preserves_existing_content(self):
        self.prepare()
        before = (self.bundle / 'origin.json').read_bytes()
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual((self.bundle / 'origin.json').read_bytes(), before)

    def test_omission_outside_mesa_seven_and_added_xml_are_rejected(self):
        self.prepare()
        path = self.bundle / 'sysroot' / data.DATA_ROOT / 'stable/viewporter/viewporter.xml'
        original = path.read_bytes(); path.unlink()
        with self.assertRaises(ValueError): data.validate_bundle(self.bundle)
        path.write_bytes(original); path.chmod(0o644)
        extra = self.bundle / 'sysroot' / data.DATA_ROOT / 'staging/extra.xml'
        extra.write_text('<protocol name="invented"/>')
        with self.assertRaises(ValueError): data.validate_bundle(self.bundle)

    def test_every_mesa_xml_requires_exact_content(self):
        self.prepare()
        for name in data.REQUIRED_XML:
            with self.subTest(xml=name):
                path = self.bundle / 'sysroot' / data.DATA_ROOT / name
                original = path.read_bytes(); path.write_bytes(original + b'\n')
                with self.assertRaises(ValueError): data.validate_bundle(self.bundle)
                path.write_bytes(original)
        data.validate_bundle(self.bundle)

    def test_receipt_producer_source_license_and_pc_cannot_drift(self):
        self.prepare()
        receipt = self.bundle / 'origin.json'
        original = receipt.read_bytes()
        changed = json.loads(original); changed['producer_sha256'] = '0' * 64
        receipt.write_text(json.dumps(changed))
        with self.assertRaises(ValueError): data.validate_bundle(self.bundle)
        receipt.write_bytes(original)
        for relative in ('source/' + data.ARCHIVE_ROOT + '/COPYING', 'sysroot/' + data.PC_PATH,
                         'sysroot/' + data.LICENSE_PATH):
            with self.subTest(file=relative):
                path = self.bundle / relative; saved = path.read_bytes()
                path.write_bytes(saved + b'\n')
                with self.assertRaises(ValueError): data.validate_bundle(self.bundle)
                path.write_bytes(saved)

    def test_installed_overlay_requires_exact_complete_data(self):
        self.prepare()
        sdk = self.root / 'sdk'; shutil.copytree(self.bundle / 'sysroot', sdk)
        data.validate_installation(self.bundle, sdk)
        path = sdk / data.DATA_ROOT / data.REQUIRED_XML[0]
        path.unlink(); path.symlink_to(self.bundle / 'sysroot' / data.DATA_ROOT / data.REQUIRED_XML[0])
        with self.assertRaises(ValueError): data.validate_installation(self.bundle, sdk)
        path.unlink(); path.write_text('changed')
        with self.assertRaises(ValueError): data.validate_installation(self.bundle, sdk)


@unittest.skipUnless(FIXTURES_AVAILABLE, FIXTURE_REASON)
class GenuineWaylandInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.bundle = self.root / 'bundle'; data.prepare(ARCHIVE, self.bundle)
        self.sdk = self.root / 'sdk'; shutil.copytree(self.bundle / 'sysroot', self.sdk / 'sysroot')
        source = SDK2 / 'sysroot'
        inputs = [source / 'usr/lib' / name for name in ('libwayland-client.a', 'libwayland-server.a',
                                                       'libwayland-egl.a', 'libffi.a')]
        inputs += [source / 'usr/lib/pkgconfig' / (name + '.pc') for name in
                   ('wayland-client', 'wayland-server', 'wayland-egl-backend')]
        inputs += list((source / 'usr/include').glob('wayland-*.h'))
        for original in inputs:
            destination = self.sdk / 'sysroot' / original.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(original, destination)
        self.builder = SimpleNamespace(mesa_profile='native-wayland', sdk_prefix=self.sdk,
            target=SimpleNamespace(architecture='x86_64'), mesa_wayland_protocols=self.bundle,
            mesa_wayland_scanner=SCANNER, mesa_wayland_scanner_report=SCANNER_REPORT,
            mesa_wayland_scanner_report_sha256=SCANNER_REPORT_SHA256)

    def test_actual_retained_scanner_archive_receipts_and_protocol_overlay(self):
        result = subject.validate_wayland_inputs(self.builder)
        self.assertEqual(result['scanner']['sha256'], '665e6fc73743348f4af912521290b2b553b384047283f932decc8fc7c61d0f47')
        self.assertEqual(len(result['target_archives']), 4)
        self.assertEqual(result['protocols']['protocol_xml_count'], 53)
        self.assertFalse(result['guest_execution'])

    def test_missing_inputs_wrong_receipt_and_wrong_architecture_fail_cleanly(self):
        for attr, changed in (('mesa_wayland_protocols', None), ('mesa_wayland_scanner', None),
                              ('mesa_wayland_scanner_report_sha256', None),
                              ('mesa_wayland_scanner_report_sha256', '0' * 64)):
            with self.subTest(field=attr):
                original = getattr(self.builder, attr); setattr(self.builder, attr, changed)
                with self.assertRaises(subject.BuildError): subject.validate_wayland_inputs(self.builder)
                setattr(self.builder, attr, original)
        self.builder.target.architecture = 'aarch64'
        with self.assertRaises(subject.BuildError): subject.validate_wayland_inputs(self.builder)

    def test_library_and_package_version_drift_rejected(self):
        for relative in ('usr/lib/libwayland-client.a', 'usr/lib/libwayland-server.a', 'usr/lib/libwayland-egl.a',
                         'usr/lib/libffi.a', 'usr/lib/pkgconfig/wayland-client.pc'):
            with self.subTest(file=relative):
                path = self.sdk / 'sysroot' / relative; original = path.read_bytes()
                path.write_bytes(original.replace(b'1.24.0', b'1.23.0') if path.suffix == '.pc' else original + b'changed')
                with self.assertRaises(subject.BuildError): subject.validate_wayland_inputs(self.builder)
                path.write_bytes(original)


class WaylandConfiguration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = f = base.ProductionFixture(self.root)
        f.builder.mesa_profile = 'native-wayland'
        f.values['platforms'] = ['wayland']
        self.verified = {'scanner': {'path': str(SCANNER)}, 'fixture': 'metadata only, not a build'}
        f.builder.mesa_wayland_inputs = copy.deepcopy(self.verified)
        for relative in ('src/egl/drivers/dri2/platform_wayland.c', 'src/egl/drivers/dri2/platform_surfaceless.c',
                         'src/loader/loader_wayland_helper.c'):
            path = f.work / 'mesa-26.2.3' / relative
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text('/* metadata fixture only */\n')
            row = f.record('../mesa-26.2.3/' + relative, relative + '.o', f.cc)
            row['command'] += ' -DHAVE_WAYLAND_PLATFORM -DHAVE_SURFACELESS_PLATFORM -DMESA_SYSTEM_HAS_KMS_DRM=0'
            f.records.append(row)
        self.targets = []
        for xml in data.REQUIRED_XML:
            stem = Path(xml).stem
            for mode, name_suffix, file_suffix in (('private-code', '-protocol', '-protocol.c'),
                                                   ('client-header', '-client-protocol', '-client-protocol.h')):
                self.targets.append({'name': stem + name_suffix, 'type': 'custom',
                    'filename': [str(f.directory / 'src/loader' / (stem + file_suffix))],
                    'target_sources': [{'compiler': [str(SCANNER), mode, '@INPUT@', '@OUTPUT@'],
                        'sources': [str(f.prefix / 'sysroot' / data.DATA_ROOT / xml)],
                        'parameters': [], 'generated_sources': []}]})
        self.targets_path = f.directory / 'meson-info/intro-targets.json'
        self.save()

    def save(self):
        self.fixture.save(); self.targets_path.write_text(json.dumps(self.targets))

    def validate(self):
        f = self.fixture
        with patch.object(subject, 'validate_wayland_inputs', return_value=copy.deepcopy(self.verified)):
            return subject.validate_production_configuration(f.builder, f.directory,
                subject.options_for('native-wayland'), f.args)

    def test_minimal_option_delta_and_actual_metadata(self):
        native = subject.options_for('native-surfaceless')
        wayland = subject.options_for('native-wayland')
        self.assertEqual([(a, b) for a, b in zip(native, wayland) if a != b], [('-Dplatforms=', '-Dplatforms=wayland')])
        result = self.validate()
        self.assertEqual(result['command_counts'], {'c': 4, 'cpp': 64, 'assembly': 1})
        self.assertEqual(result['wayland']['scanner_target_count'], 14)
        self.assertEqual(len(result['wayland']['configured_sources']), 3)
        self.assertEqual(result['libcpp_hardening']['mode'], 'FAST')

    def test_wayland_and_surfaceless_sources_and_flags_cannot_disappear_or_relocate(self):
        f = self.fixture
        original = copy.deepcopy(f.records)
        for index in (-1, -2, -3):
            for mode in ('missing', 'duplicate', 'relocated', 'wayland_flag', 'surfaceless_flag', 'drm_flag'):
                with self.subTest(index=index, mode=mode):
                    f.records = copy.deepcopy(original)
                    if mode == 'missing': del f.records[index]
                    elif mode == 'duplicate':
                        row = copy.deepcopy(f.records[index]); row['output'] += '.second'
                        row['command'] = row['command'].replace(' -o ' + f.records[index]['output'], ' -o ' + row['output'])
                        f.records.append(row)
                    elif mode == 'relocated':
                        row = f.records[index]; old = row['file']; row['file'] = '/wrong/' + Path(old).name
                        row['command'] = row['command'].replace(old, row['file'])
                    else:
                        flag = {'wayland_flag': '-DHAVE_WAYLAND_PLATFORM', 'surfaceless_flag': '-DHAVE_SURFACELESS_PLATFORM',
                                'drm_flag': '-DMESA_SYSTEM_HAS_KMS_DRM=0'}[mode]
                        f.records[index]['command'] = f.records[index]['command'].replace(' ' + flag, '')
                    self.save()
                    with self.assertRaises(subject.BuildError): self.validate()

    def test_all_fourteen_scanner_targets_bind_tool_mode_xml_and_output(self):
        original = copy.deepcopy(self.targets)
        for index in range(14):
            for mode in ('missing', 'duplicate', 'scanner', 'mode', 'xml', 'output', 'extra_args'):
                with self.subTest(index=index, mode=mode):
                    self.targets = copy.deepcopy(original)
                    if mode == 'missing': del self.targets[index]
                    elif mode == 'duplicate': self.targets.append(copy.deepcopy(self.targets[index]))
                    else:
                        row = self.targets[index]; source = row['target_sources'][0]
                        if mode == 'scanner': source['compiler'][0] = '/wrong/target-scanner'
                        elif mode == 'mode': source['compiler'][1] = 'public-code'
                        elif mode == 'xml': source['sources'] = ['/wrong/protocol.xml']
                        elif mode == 'output': row['filename'] = ['/wrong/protocol.c']
                        else: source['compiler'].append('--include-core-only')
                    self.save()
                    with self.assertRaises(subject.BuildError): self.validate()

    def test_wayland_preserves_sixty_four_fast_cpp_commands(self):
        f = self.fixture; original = copy.deepcopy(f.records)
        for mode in ('drop', 'add', 'missing_fast', 'none'):
            with self.subTest(mode=mode):
                f.records = copy.deepcopy(original)
                if mode == 'drop': del f.records[1]
                elif mode == 'add': f.records.append(f.record('extra.cpp', 'extra.o', f.cxx))
                else:
                    f.records[64]['command'] = f.records[64]['command'].replace(subject.LIBCPP_FAST_ARGUMENT,
                        '' if mode == 'missing_fast' else '-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE')
                self.save()
                with self.assertRaises(subject.BuildError): self.validate()

    def test_post_setup_input_drift_and_malformed_target_metadata_rejected(self):
        self.fixture.builder.mesa_wayland_inputs['changed'] = True
        with self.assertRaises(subject.BuildError): self.validate()
        self.fixture.builder.mesa_wayland_inputs = copy.deepcopy(self.verified)
        self.targets[0]['target_sources'] = [None]; self.save()
        with self.assertRaises(subject.BuildError): self.validate()

    def test_cross_file_binds_host_scanner_without_target_pkgconfig_leak(self):
        f = self.fixture
        (f.prefix / 'build-report.json').parent.mkdir(parents=True, exist_ok=True)
        (f.prefix / 'build-report.json').write_text('{}')
        f.builder.target.require_report = lambda value: None
        f.builder.target.inspect_archive = lambda path: None
        f.builder.target.meson_machine = lambda: '[host_machine]\nsystem = "linux"\n'
        f.builder.tools = {'clang': '/fixture/clang', 'llvm-ar': '/fixture/llvm-ar', 'llvm-strip': '/fixture/llvm-strip'}
        resource = self.root / 'clang-resource'; (resource / 'include').mkdir(parents=True)
        (resource / 'include/emmintrin.h').write_text('/* fixture only */\n')
        wrappers = {}
        def wrapper(name, argv):
            wrappers[name] = argv
            return f.work / 'bin' / name
        f.builder.shell_wrapper = wrapper
        with patch.object(subject, 'validate_wayland_inputs', return_value=copy.deepcopy(self.verified)), \
             patch.object(subject.shutil, 'which', return_value='/fixture/pkg-config'), \
             patch.object(subject.subprocess, 'check_output', return_value=str(resource) + '\n') as command:
            cross, native, args = subject.environment(f.builder)
        command.assert_called_once_with(['/fixture/clang', '-print-resource-dir'], text=True)
        text = cross.read_text()
        scanner = 'wayland-scanner = ' + repr(str(SCANNER))
        self.assertEqual(text.count(scanner), 1)
        self.assertLess(text.index(scanner), text.index('[host_machine]'))
        self.assertNotIn('wayland-scanner', native.read_text())
        self.assertEqual(wrappers['mesa-target-pkg-config'], ['/fixture/pkg-config', '--static'])
        self.assertIn('PKG_CONFIG_LIBDIR=' + str(f.work / 'host-empty-pkgconfig'), wrappers['mesa-host-pkg-config'])
        self.assertIn('-u', wrappers['mesa-host-pkg-config'])
        self.assertIn('PKG_CONFIG_SYSROOT_DIR', wrappers['mesa-host-pkg-config'])
        self.assertIn(str(f.prefix / 'sysroot/usr/share/pkgconfig'), f.builder.env['PKG_CONFIG_LIBDIR'])


def suite():
    tests = unittest.TestSuite()
    tests.addTests(unittest.defaultTestLoader.loadTestsFromModule(base))
    for cls in (ProtocolData, GenuineWaylandInputs, WaylandConfiguration):
        tests.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    return tests


def load_tests(loader, discovered, pattern):
    return unittest.TestSuite([loader.loadTestsFromModule(base), discovered])


if __name__ == '__main__':
    # Any accidental process execution is a hard failure. The original v2 build
    # tests use an explicit in-memory builder.run fixture and never spawn tools.
    with patch.object(subject.subprocess, 'Popen', side_effect=AssertionError('Native execution is forbidden in this suite')):
        result = unittest.TextTestRunner(verbosity=2).run(suite())
    raise SystemExit(0 if result.wasSuccessful() else 1)
