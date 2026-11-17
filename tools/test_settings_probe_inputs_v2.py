"""Pure host producer/consumer and real embedding-parser adversarial fixtures.

Only the actual external compiler and original retained D-Bus source validator
are replaced at their I/O boundaries. SDK/archive/ELF/JSON/command/mode/source
checks below execute the real code. Synthetic files are never native evidence.
"""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools import build_settings_probe_v1 as producer
from tools import settings_probe_inputs_v1 as subject
from tools import cosmic_services_catalog_v1 as catalog
from tools.test_build_notification_probe import Fixture as OriginalFixture
from tools.test_cosmic_notifications_elf import fixture as static_elf

CANDIDATE = Path(__file__).resolve().parents[1]
SOURCE = CANDIDATE / 'user/ported/settings_probe_v1.c'
base = producer.base


class Fixture(OriginalFixture):
    def __init__(self, root):
        super().__init__(root)
        self.source = root / 'settings_probe_v1.c'
        self.source.write_bytes(SOURCE.read_bytes())
        self.program = static_elf(high=0x01010000)
        self.lock = root / 'native.lock'
        self.source_closure = {'tools/build_settings_probe_v1.py':
            hashlib.sha256(Path(producer.__file__).read_bytes()).hexdigest()}

    @contextlib.contextmanager
    def gates(self):
        # Source bytes and fixed upstream policy still use the real reader.
        # The local closure fixture avoids installing candidates in the repo.
        with patch.object(producer, 'SOURCE', self.source), \
                patch.object(producer, '__file__', str(producer.ROOT / 'tools/build_settings_probe_v1.py')), \
                patch.object(producer, 'NATIVE_LOCK', self.lock), \
                patch.object(base, 'producer_sources', return_value=self.source_closure), \
                patch.object(base.build_dbus, 'validate_build', side_effect=self.validate_dbus):
            yield

    def build(self):
        fixture = self
        def run(builder, command, log, cwd=None):
            fixture.run(builder, [str(item) for item in command], log, cwd)
        with self.gates(), patch.object(base, 'toolchain', return_value=self.tools), \
                patch.object(base, 'native_lease', side_effect=lambda _: contextlib.nullcontext()), \
                patch.object(base, 'idle_native_host'), patch.object(base.Builder, 'run', run):
            return producer.build(self.output, self.sdk, self.dbus, native_lock=self.lock)

    def validate(self):
        with self.gates():
            return subject.validate_build(self.output)

    def receipt_document(self):
        return json.loads((self.output / producer.RECEIPT).read_bytes())

    def write_report(self, report):
        (self.output / producer.RECEIPT).write_text(json.dumps(report, allow_nan=False) + '\n')

    def failed_receipt(self):
        report = self.receipt_document()
        assert report['status'] == 'FAILED'
        assert report['guest_execution'] is False
        assert report['settings_verified'] is False
        assert not (self.output / producer.EXECUTABLE).exists()
        return report


class SettingsProbeInputs(unittest.TestCase):
    def make(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name).resolve())

    def test_real_source_pin_and_original_filesystem_timeout_functions_are_preserved(self):
        data = SOURCE.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), producer.SOURCE_SHA256)
        original = producer.ORIGINAL_SOURCE.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), producer.ORIGINAL_SOURCE_SHA256)
        self.assertEqual(hashlib.sha256(producer.POLICY.read_bytes()).hexdigest(), producer.POLICY_SHA256)
        # Original functions have no nested file-scope closing brace; compare
        # whole lexical slices, not a mirrored implementation of their effects.
        for name in ('fail', 'milliseconds', 'value', 'prepare_value', 'prepare', 'theme_export'):
            pattern = rb'(?m)^static [^\n]*\b' + name.encode() + rb'\([^\n]*\) \{.*?^\}'
            with self.subTest(name=name):
                self.assertEqual(re.search(pattern, data, re.S).group(),
                                 re.search(pattern, original, re.S).group())
        self.assertIn(b'GetNameOwner', data)
        self.assertIn(b'GetConnectionUnixProcessID', data)
        self.assertNotIn(b'dbus_bus_request_name', data)

    def test_actual_producer_receipt_roundtrip_full_static_elf_and_pure_consumer(self):
        f = self.make()
        before = f.snapshot()
        produced = f.build()
        preserved = (f.output / producer.RECEIPT).read_bytes()
        proof = f.validate()
        self.assertEqual(proof['status'], 'SETTINGS_PROBE_BUILD_REVALIDATED_NOT_RUN')
        self.assertEqual(proof['required_pages'], 515)
        self.assertEqual(proof['image_load_pages'], 3)
        self.assertEqual(proof['executable']['mode'], 0o755)
        self.assertEqual(proof['executable']['sha256'], produced['probe']['sha256'])
        self.assertEqual(proof['image_admission']['executable']['sha256'], produced['probe']['sha256'])
        self.assertIs(proof['guest_execution'], False)
        self.assertIs(proof['settings_verified'], False)
        self.assertIs(proof['cosmic_session_ready'], False)
        self.assertIs(proof['full_cosmic_complete'], False)
        self.assertEqual(len(f.calls), 4)
        self.assertEqual(f.snapshot(), before)
        self.assertEqual((f.output / producer.RECEIPT).read_bytes(), preserved)
        self.assertEqual(proof, f.validate())
        unsigned = dict(proof)
        del unsigned['identity_sha256']
        self.assertEqual(proof['identity_sha256'], base.json_digest(unsigned))

    def test_status_claim_schema_missing_extra_and_numeric_types_are_rejected(self):
        f = self.make(); f.build(); original = f.receipt_document()
        mutations = [('status', 'PASS'), ('schema_version', True), ('guest_execution', True),
                     ('settings_verified', 0), ('render_verified', True), ('cosmic_session_verified', True),
                     ('cosmic_session_ready', True), ('full_cosmic_complete', True),
                     ('output', str(f.root)), ('source', str(producer.ORIGINAL_SOURCE)),
                     ('native_lock', str(f.root / 'different.lock')), ('unexpected', False)]
        for key, value in mutations:
            changed = copy.deepcopy(original); changed[key] = value; f.write_report(changed)
            with self.subTest(key=key), self.assertRaises((base.BuildError, ValueError)):
                f.validate()
        for key in ('kind', 'probe', 'image_admission', 'producer_inputs'):
            changed = copy.deepcopy(original); del changed[key]; f.write_report(changed)
            with self.subTest(missing=key), self.assertRaises((base.BuildError, ValueError)):
                f.validate()
        for section, key in [('target_profile', 'machine'), ('limits', 'timeout_seconds'),
                             ('client_contract', 'owner_timeout_ms'), ('probe', 'bytes'),
                             ('image_admission', 'required_pages')]:
            changed = copy.deepcopy(original); changed[section][key] = float(changed[section][key])
            f.write_report(changed)
            with self.subTest(section=section, key=key), self.assertRaises((base.BuildError, ValueError)):
                f.validate()

    def test_duplicate_json_keys_and_nonobject_reports_are_rejected(self):
        f = self.make(); f.build(); path = f.output / producer.RECEIPT
        original = path.read_text()
        for data in ('[]', original.replace('{', '{"schema_version": 1,', 1)):
            path.write_text(data)
            with self.subTest(data=data[:30]), self.assertRaises((base.BuildError, ValueError)):
                f.validate()

    def test_independent_compile_and_link_argv_reject_every_changed_command(self):
        f = self.make(); f.build(); original = f.receipt_document()
        changes = []
        for index in range(4):
            changed = copy.deepcopy(original); changed['commands'][index].append('--unreviewed')
            changes.append(changed)
        for token in ('-nostdinc', '-O2', '-fno-pie', '-Werror'):
            changed = copy.deepcopy(original); changed['commands'][2].remove(token); changes.append(changed)
        for token in ('-static', '--no-pie', 'max-page-size=4096', 'separate-code', '--gc-sections'):
            changed = copy.deepcopy(original); changed['commands'][3].remove(token); changes.append(changed)
        for changed in changes:
            f.write_report(changed)
            with self.subTest(commands=changed['commands']), self.assertRaisesRegex(base.BuildError, 'commands changed'):
                f.validate()

    def test_source_object_compiler_and_version_log_mutations_are_rejected(self):
        for which in ('source', 'object', 'compiler', 'version', 'compile-log'):
            with self.subTest(which=which):
                f = self.make(); f.build()
                path = {'source': f.source, 'object': f.output / producer.OBJECT,
                        'compiler': Path(f.tools['clang']), 'version': f.output / 'logs/clang-version.log',
                        'compile-log': f.output / 'logs/compile.log'}[which]
                path.write_bytes(path.read_bytes() + b'changed')
                with self.assertRaises((base.BuildError, ValueError)):
                    f.validate()

    def test_elf_mode_bytes_wrong_arch_wx_and_admission_mutations_are_rejected(self):
        for which in ('mode', 'byte', 'arch', 'wx', 'pages', 'loader', 'digest'):
            with self.subTest(which=which):
                f = self.make(); f.build(); path = f.output / producer.EXECUTABLE
                if which == 'mode':
                    path.chmod(0o644)
                elif which in ('byte', 'arch', 'wx'):
                    data = bytearray(path.read_bytes())
                    if which == 'byte': data[-1] ^= 1
                    elif which == 'arch': struct.pack_into('<H', data, 18, 183)
                    else: struct.pack_into('<I', data, 64 + 2 * 56 + 4, 7)
                    path.write_bytes(data)
                else:
                    report = f.receipt_document()
                    if which == 'pages': report['image_admission']['required_pages'] += 1
                    elif which == 'loader': report['image_admission']['loader_contract'] = {}
                    else: report['probe']['sha256'] = '0' * 64
                    f.write_report(report)
                with self.assertRaises((base.BuildError, ValueError)):
                    f.validate()

    def test_original_sdk_and_dbus_archive_header_receipt_drift_still_rejected(self):
        for which in ('sdk', 'dbus-archive', 'header', 'dbus-receipt', 'dbus-validation'):
            with self.subTest(which=which):
                f = self.make(); f.build()
                if which == 'dbus-validation':
                    f.validation_error = 'original retained build invalid'
                else:
                    path = {'sdk': f.headers / 'stdio.h',
                            'dbus-archive': f.stage / 'usr/lib/libdbus-1.a',
                            'header': f.stage / 'usr/include/dbus-1.0/dbus/dbus.h',
                            'dbus-receipt': f.dbus / 'dbus-build-report.json'}[which]
                    path.write_bytes(path.read_bytes() + b'changed')
                with self.assertRaises((base.BuildError, ValueError)):
                    f.validate()

    def test_file_and_ancestor_symlinks_and_relative_paths_are_rejected(self):
        f = self.make(); f.build()
        with self.assertRaises(base.BuildError):
            subject.validate_build(Path('relative-output'))
        link = f.root / 'alias'; link.symlink_to(f.output, target_is_directory=True)
        with self.assertRaises((base.BuildError, ValueError)):
            subject.validate_build(link)
        for name in (producer.RECEIPT, producer.EXECUTABLE, producer.OBJECT):
            path = f.output / name; moved = f.root / ('held-' + name)
            path.rename(moved); path.symlink_to(moved)
            with self.subTest(name=name), self.assertRaises((base.BuildError, ValueError)):
                f.validate()
            path.unlink(); moved.rename(path)

    def test_producer_failed_compile_or_changed_input_never_publishes_success(self):
        for which in ('compile', 'foreign', 'wx', 'source', 'sdk', 'dbus', 'compiler'):
            with self.subTest(which=which):
                f = self.make()
                if which == 'compile': f.failure = 'compile.log'
                elif which == 'foreign': struct.pack_into('<H', f.program, 18, 183)
                elif which == 'wx': struct.pack_into('<I', f.program, 64 + 2 * 56 + 4, 7)
                else:
                    path = {'source': f.source, 'sdk': f.headers / 'stdio.h',
                            'dbus': f.stage / 'usr/lib/libdbus-1.a', 'compiler': Path(f.tools['clang'])}[which]
                    f.mutate = lambda path=path: path.write_bytes(path.read_bytes() + b'changed')
                with self.assertRaises((base.BuildError, ValueError)):
                    f.build()
                f.failed_receipt()

    def test_build_preserves_existing_outputs_and_both_readonly_inputs(self):
        f = self.make(); f.build(); preserved = f.receipt_document()
        with self.assertRaises(base.BuildError):
            f.build()
        self.assertEqual(f.receipt_document(), preserved)
        for path in (f.sdk / 'output', f.dbus / 'output', f.root):
            with self.subTest(path=path), self.assertRaises(base.BuildError):
                base.validate_output(path, f.sdk, f.dbus)


class CatalogFixture:
    def __init__(self, root):
        self.root, self.prefix, self.build = root, root / 'prefix', root / 'os'
        self.prefix.mkdir(); self.build.mkdir()
        self.cache = root / 'cache'
        self.directory = self.cache / 'x86_64-unknown-none/release/build/cyxia-kernel-aaaaaaaaaaaaaaaa/out'
        self.directory.mkdir(parents=True)
        self.catalog = self.directory / 'ported_catalog.rs'
        self.programs, self.rows, self.roots, inputs, kernel = {}, [], [], {}, bytearray(b'HEADER')
        for index, name in enumerate(catalog.IMAGE_NAMES):
            # Each unique embedded blob is synthetic; this tests the genuine
            # byte-placement consumer, not a compiler or the kernel ELF parser.
            raw = b'HOST-IMAGE\x00' + name.encode() + bytes([index + 1]) * 32
            program = root / ('original-' + name); program.write_bytes(raw)
            self.programs[name] = program
            (self.prefix / name).write_bytes(raw); (self.directory / name).write_bytes(raw)
            inputs[name] = hashlib.sha256(raw).hexdigest(); kernel.extend(raw)
            stem = name.removesuffix('.elf')
            self.rows.append(f'("{stem}", "/bin/{stem}", include_bytes!(concat!(env!("OUT_DIR"), "/{name}"))),')
            self.roots.append(f'("/bin/{stem}", PORTED[{index}].2),')
        asset = self.prefix / 'rootfs/etc/example'; asset.parent.mkdir(parents=True)
        asset.write_bytes(b'REAL HOST ASSET FIXTURE\n'); (self.directory / 'asset-0').write_bytes(asset.read_bytes())
        inputs['rootfs/etc/example'] = hashlib.sha256(asset.read_bytes()).hexdigest()
        self.asset = '("/etc/example", include_bytes!(concat!(env!("OUT_DIR"), "/asset-0"))),'
        self.save_catalog()
        self.kernel = self.build / 'kernel.elf'; self.kernel.write_bytes(kernel)
        self.manifest = {'target': 'x86_64-unknown-none', 'profile': 'release',
                         'cache': {'effective': str(self.cache)}, 'sysroot': str(self.prefix),
                         'external_inputs': inputs, 'elf': {'loads': [{'offset': 6, 'size': len(kernel) - 6, 'flags': 4}]}}

    def save_catalog(self):
        self.catalog.write_text('\n'.join(self.rows + self.roots + [self.asset]) + '\n')

    def validate(self):
        return catalog.catalog_identity(self.build, self.manifest, self.programs)


class ServiceCatalog(unittest.TestCase):
    def make(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        return CatalogFixture(Path(temporary.name).resolve())

    def test_nine_exact_real_byte_placements_plus_root_asset(self):
        f = self.make(); proof = f.validate()
        self.assertEqual(set(proof['embedded']), set(catalog.IMAGE_NAMES))
        self.assertEqual(set(proof['generated_assets']), {'/etc/example'})
        self.assertEqual(proof['catalog_bytes'], sum(p.stat().st_size for p in f.programs.values())
                         + (f.directory / 'asset-0').stat().st_size)
        self.assertEqual(catalog.base.IMAGE_NAMES, ('probe.elf', 'dbus-daemon.elf', 'dbus-send.elf',
            'cosmic-comp.elf', 'cosmic-notifications.elf', 'notification-probe.elf'))

    def test_six_image_fallback_undeclared_or_duplicate_programs_rejected(self):
        for which in ('six', 'extra', 'duplicate', 'missing-row'):
            f = self.make()
            if which == 'six': f.programs = {name: path for name, path in f.programs.items() if name in catalog.base.IMAGE_NAMES}
            elif which == 'extra': f.programs['unreviewed.elf'] = next(iter(f.programs.values()))
            elif which == 'duplicate': f.rows.append(f.rows[-1]); f.save_catalog()
            else: f.rows.pop(); f.save_catalog()
            with self.subTest(which=which), self.assertRaises(ValueError): f.validate()

    def test_all_nine_require_exactly_once_readonly_load_embedding(self):
        for name in catalog.IMAGE_NAMES:
            for which in ('missing', 'duplicate', 'writable', 'outside-load'):
                f = self.make(); data = f.kernel.read_bytes(); blob = f.programs[name].read_bytes()
                if which == 'missing': f.kernel.write_bytes(data.replace(blob, b'\x00' * len(blob)))
                elif which == 'duplicate': f.kernel.write_bytes(data + blob)
                elif which == 'writable': f.manifest['elf']['loads'][0]['flags'] = 6
                else: f.manifest['elf']['loads'][0]['size'] = 1
                with self.subTest(name=name, which=which), self.assertRaisesRegex(ValueError, 'embedded once'):
                    f.validate()

    def test_generated_installed_original_root_index_and_manifest_each_bound(self):
        for name in catalog.IMAGE_NAMES:
            for which in ('original', 'generated', 'installed', 'root-index', 'manifest'):
                f = self.make()
                if which == 'root-index':
                    index = catalog.IMAGE_NAMES.index(name)
                    f.roots[index] = f.roots[index].replace(f'PORTED[{index}]', 'PORTED[99]'); f.save_catalog()
                elif which == 'manifest': f.manifest['external_inputs'][name] = '0' * 64
                else:
                    path = {'original': f.programs[name], 'generated': f.directory / name,
                            'installed': f.prefix / name}[which]
                    path.write_bytes(path.read_bytes() + b'drift')
                with self.subTest(name=name, which=which), self.assertRaises(ValueError): f.validate()

    def test_asset_mutations_extra_input_path_collisions_and_catalog_symlink_rejected(self):
        for which in ('asset', 'asset-hash', 'extra-input', 'root-collision', 'catalog-link'):
            f = self.make()
            if which == 'asset': (f.directory / 'asset-0').write_bytes(b'changed')
            elif which == 'asset-hash': f.manifest['external_inputs']['rootfs/etc/example'] = '0' * 64
            elif which == 'extra-input': f.manifest['external_inputs']['ignored.json'] = '0' * 64
            elif which == 'root-collision':
                f.asset = f.asset.replace('/etc/example', '/bin/cosmic-session'); f.save_catalog()
            else:
                held = f.root / 'held-catalog'; f.catalog.rename(held); f.catalog.symlink_to(held)
            with self.subTest(which=which), self.assertRaises(ValueError): f.validate()


if __name__ == '__main__':
    unittest.main()
