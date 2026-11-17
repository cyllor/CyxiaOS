"""Real Git/archive/file contract fixtures; no Cargo, native build or guest proof.

Only source-policy pin constants select the tiny fixture instead of upstream.
The export, metadata, compiler-file, ELF and installation validators all run.
"""
import copy
import contextlib
import difflib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import unittest
from unittest import mock

from tools import install_cosmic_notifications_static_v1 as subject
from tools import build_cosmic_notifications_static_v1 as builder
from tools import test_install_cosmic_notifications as fixture

static = subject.static
write, save = fixture.write, fixture.save


def patch_bytes(before, after, prefix=''):
    result = ''
    for name in sorted(set(before) | set(after)):
        if before.get(name) == after.get(name):
            continue
        result += ''.join(difflib.unified_diff(
            before.get(name, b'').decode().splitlines(True),
            after.get(name, b'').decode().splitlines(True),
            fromfile='a/' + prefix + name if name in before else '/dev/null',
            tofile='b/' + prefix + name if name in after else '/dev/null'))
    return result.encode()


@unittest.skipUnless(Path('/usr/bin/git').is_file(), 'real Git is required')
class StaticNotificationInstallation(unittest.TestCase):
    def setUp(self):
        # Reuse file-only compiler/SDK/ELF fixtures, not the old validation path.
        fixture.NotificationInstallation.setUp(self)
        packages, vendor_after, patches = [], {}, []
        for name, version, license_file, feature in (
                ('wayland-sys', '0.31.11', 'LICENSE.txt', 'cyxia-static-client'),
                ('xkbcommon-dl', '0.4.2', 'LICENSE', 'static-link')):
            stem = name + '-' + version
            files = {'Cargo.toml': ('[package]\nname="' + name + '"\nversion="' + version + '"\n').encode(),
                     'src/lib.rs': b'// Source identity fixture only; never compiled.\n',
                     license_file: (name + ' license fixture\n').encode()}
            after = dict(files)
            after['Cargo.toml'] += ('\n[features]\n' + feature + '=[]\n').encode()
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                for filename, data in files.items():
                    item = tarfile.TarInfo(stem + '/' + filename)
                    item.size, item.mode = len(data), 0o644
                    archive.addfile(item, io.BytesIO(data))
                    write(self.cache / 'registry/src/fixture' / stem / filename, data)
            archive = write(self.cache / 'registry/cache/fixture' / (stem + '.crate'), stream.getvalue())
            destination = 'native-deps/' + name
            package = {'name': name, 'version': version, 'destination': destination,
                       'source': 'registry+https://github.com/rust-lang/crates.io-index',
                       'archive_sha256': static.sha(archive.read_bytes()), 'license_files': [license_file],
                       'files': {filename: {**subject.legacy.common.identity(data), 'mode': 0o644}
                                 for filename, data in files.items()},
                       'before_tree_sha256': static.file_tree(files)['sha256'],
                       'after_tree_sha256': static.file_tree(after)['sha256']}
            packages.append(package)
            vendor_after.update({destination + '/' + filename: data for filename, data in after.items()})
            patch = write(self.policy_path.parent / (name + '.patch'), patch_bytes(files, after, destination + '/'))
            patches.append({'path': patch.name, 'sha256': static.sha(patch.read_bytes())})
        root_lock = ('version=4\n[[package]]\nname="cosmic-notifications"\nversion="1.10.0"\n'
                     'dependencies=["dependency"]\n[[package]]\nname="dependency"\nversion="1.0.0"\n'
                     'source="registry+https://example.invalid/index"\n')
        for package in packages:
            root_lock += ('[[package]]\nname="' + package['name'] + '"\nversion="' + package['version'] + '"\n'
                          'source="' + package['source'] + '"\nchecksum="' + package['archive_sha256'] + '"\n')
        write(self.source / 'Cargo.lock', root_lock)
        subprocess.run(['/usr/bin/git', '-C', str(self.source), 'add', '.'], check=True, capture_output=True,
                       env=static.build.clean_environment('/usr/bin:/bin'))
        subprocess.run(['/usr/bin/git', '-C', str(self.source), '-c', 'user.name=Install Test',
                        '-c', 'user.email=install@example.invalid', 'commit', '-qm', 'Static identity fixture'],
                       check=True, capture_output=True, env=static.build.clean_environment('/usr/bin:/bin'))
        self.component['commit'] = static.dependencies.pinned_git(self.source, 'rev-parse', 'HEAD')
        declared = static.dependencies.parse_git_tree(static.dependencies.pinned_git(self.source, 'ls-tree', '-rz', 'HEAD'))
        original = {name: (self.source / name).read_bytes() for name in declared}
        effective = dict(original)
        effective.pop('.cargo/config.toml')
        effective['Cargo.toml'] += b'\n[features]\ncyxia-static=[]\n'
        effective_lock = root_lock.replace('dependencies=["dependency"]',
                                           'dependencies=["dependency","wayland-sys","xkbcommon-dl"]')
        for package in packages:
            effective_lock = effective_lock.replace('source="' + package['source'] + '"\nchecksum="'
                                                     + package['archive_sha256'] + '"\n', '')
        effective['Cargo.lock'] = effective_lock.encode()
        root_patch = write(self.policy_path.parent / 'root.patch', patch_bytes(original, effective))
        patches.insert(0, {'path': root_patch.name, 'sha256': static.sha(root_patch.read_bytes())})
        effective.update(vendor_after)

        root_id = 'path+' + self.stage.as_uri() + '#cosmic-notifications@1.10.0'
        records = [{'name': 'cosmic-notifications', 'version': '1.10.0', 'id': root_id, 'source': None,
                    'manifest_path': str(self.stage / 'Cargo.toml'),
                    'targets': [{'name': 'cosmic-notifications', 'kind': ['bin']}]},
                   {'name': 'dependency', 'version': '1.0.0', 'id': 'dependency-id',
                    'source': 'registry+https://example.invalid/index',
                    'manifest_path': str(self.dependency / 'Cargo.toml'), 'targets': []}]
        for package in packages:
            records.append({'name': package['name'], 'version': package['version'], 'id': package['name'],
                            'source': None, 'manifest_path': str(self.stage / package['destination'] / 'Cargo.toml'),
                            'targets': []})
        root_edges = [{'name': record['name'].replace('-', '_'), 'pkg': record['id'],
                       'dep_kinds': [{'kind': None, 'target': None}]} for record in records[1:]]
        self.metadata = {'version': 1, 'workspace_root': str(self.stage), 'workspace_members': [root_id],
                         'packages': records, 'resolve': {'nodes': [
                             {'id': record['id'], 'features': features,
                              'dependencies': [edge['pkg'] for edge in root_edges] if index == 0 else [],
                              'deps': root_edges if index == 0 else []}
                             for index, (record, features) in enumerate(zip(records,
                                 (['cyxia-static'], [], ['client', 'dlopen', 'cyxia-static-client'], ['x11', 'static-link']))) ]}}
        graph = static.canonical_hash(static.normalized_resolution(self.metadata))
        self.policy = {'schema_version': 1, 'kind': subject.KIND, 'runtime_verified': False,
                       'repository': self.component['repository'], 'commit': self.component['commit'],
                       'git_tree': static.dependencies.pinned_git(self.source, 'rev-parse', 'HEAD^{tree}'),
                       'original_tree_sha256': static.file_tree(original)['sha256'],
                       'source_lock_sha256': static.sha(original['Cargo.lock']),
                       'effective_lock_sha256': static.sha(effective['Cargo.lock']),
                       'root_before': {name: static.sha(original[name]) for name in
                                       ('Cargo.toml', 'Cargo.lock', '.cargo/config.toml')},
                       'source_tree_sha256': static.file_tree(effective)['sha256'],
                       'patches': patches, 'registry_inputs': packages,
                       'resolution': {'package_count': 4, 'workspace_package_count': 1,
                                      'local_package_count': 3, 'expected_sha256': graph}}
        save(self.policy_path, self.policy)
        # Fixture pin only: production validators are deliberately not mocked.
        mock.patch.object(static, 'POLICY_SHA256', static.sha(self.policy_path.read_bytes())).start()
        shutil.copyfile(static.PORT / 'resource-profile.json', self.resource)
        self.profile = static.select_profile(self.resource, 1)
        self.recipe = json.loads((static.PORT / 'native-recipe.json').read_bytes())
        native = []
        for name in static.NATIVE_NAMES:
            path = self.sysroot / 'sysroot/usr/lib' / name
            if not path.exists(): write(path, fixture.archive())
            native.append({'path': str(path.relative_to(self.sysroot)), 'sha256': static.build.digest(path)})
        sdk_origin = save(self.sysroot / 'runtime-sdk-origin.json', {'fixture_only': True})
        self.recipe.update(commit=self.component['commit'], patches=patches, native_inputs=native,
                           source_lock_sha256=self.policy['source_lock_sha256'],
                           effective_lock_sha256=self.policy['effective_lock_sha256'],
                           static_source_policy={'path': 'source-policy.json', 'sha256': static.POLICY_SHA256},
                           native_sdk_origin={'path': sdk_origin.name, 'sha256': static.build.digest(sdk_origin)})
        save(self.recipe_path, self.recipe)
        static.validate_recipe(self.recipe, self.component, self.policy)
        static_source = static.export_source(self.source, self.cache, self.stage, self.policy_path)
        shutil.rmtree(self.exported)
        shutil.copytree(self.stage, self.exported)
        dependencies = static.verify_metadata(self.metadata, self.stage, self.cache, self.recipe, self.policy)
        save(self.build_output / 'metadata.json', self.metadata)
        for command in ('command', 'metadata_command'):
            self.report[command] += ['--features', 'cyxia-static']
        tools = self.report['toolchain']['tools']
        self.report['toolchain'].update(native_inputs=native, static_link_inputs=self.recipe['static_link_inputs'],
            selection={'schema_version': 1, 'rust_root': str(Path(tools['rustc']['path']).parent.parent),
                       'host_cc': tools['host_cc']['path']},
            host_cc_version='clang 19 fixture; never executed\n',
            rustc_version='rustc 1.95.0 fixture; never executed\nhost: fixture-host\n')
        native_search = static.stage_native_archives(self.build_output, self.sysroot, self.recipe,
            self.report['toolchain'], {'CARGO_ENCODED_RUSTFLAGS': '-L\x1fnative=' + str(self.build_output / 'native')})
        inspection = subject.image.inspect_full_os_elf(self.build_output / subject.PROGRAM, self.profile)
        producers = static.producer_sources(subject.ROOT / 'tools/build_cosmic_notifications_static_v1.py')
        self.report.update(schema_version=1, kind=subject.KIND, recipe=self.recipe,
            recipe_sha256=static.build.digest(self.recipe_path), resource_profile=self.profile,
            resource_source_sha256=static.RESOURCE_SHA256,
            profile_sha256=static.sha(json.dumps(self.profile, sort_keys=True).encode()),
            policy_sha256=static.POLICY_SHA256, cargo_resolution_verified=True,
            source_cache=str(self.source_cache), cache=str(self.cache), sysroot=str(self.sysroot),
            recipe_path=str(self.recipe_path), resource_path=str(self.resource),
            producer_sources=producers, producer_sources_after=producers,
            static_source=static_source, source_tree=static_source['source_tree'],
            metadata_sha256=static.build.digest(self.build_output / 'metadata.json'),
            cargo_dependencies=dependencies, resolved_graph_sha256=graph,
            native_sdk_origin=static.sdk_origin(self.sysroot, self.recipe),
            sysroot_before=static.build.tree_identity(self.sysroot / 'sysroot'),
            image_admission=inspection, executable=inspection['executable'],
            image_load_pages=inspection['image_load_pages'], notifications_verified=False,
            cosmic_session_verified=False,
            native_archive_search=native_search, native_archive_search_after=copy.deepcopy(native_search),
            native_archive_search_preserved=True,
            evidence_files={name: subject.legacy.common.identity((self.build_output / name).read_bytes())
                            for name in subject.LOGS})
        save(self.build_output / 'build-report.json', self.report)
        # The production temporary directory has gone by the time installation starts.
        shutil.rmtree(self.stage.parent)

    def install(self):
        return subject.install(self.build_output, self.output)

    def save_report(self):
        save(self.build_output / 'build-report.json', self.report)

    def test_atomic_install_after_deleted_stage_checks_real_files_without_native_calls(self):
        self.assertFalse(self.stage.exists())
        original_run, original_rename = subprocess.run, Path.rename
        published = []
        def only_git(command, *args, **kwargs):
            self.assertEqual(command[0], '/usr/bin/git')
            return original_run(command, *args, **kwargs)
        def publish(pending, output):
            self.assertFalse(output.exists())
            self.assertEqual(output, self.output)
            self.assertTrue((pending / subject.RECEIPT).is_file())
            self.assertEqual(len(subject.validate_inputs(pending)['receipt']['artifacts']), 4)
            published.append(pending)
            return original_rename(pending, output)
        with mock.patch.object(subprocess, 'run', side_effect=only_git), \
             mock.patch.object(subprocess, 'check_output', side_effect=AssertionError('native invocation')), \
             mock.patch.object(Path, 'rename', publish):
            receipt = self.install()
            checked = subject.validate_inputs(self.output)
        self.assertEqual(len(published), 1)
        self.assertEqual(receipt['status'], 'INSTALLED_NOT_RUN')
        self.assertEqual(checked['status'], 'VALIDATED_NOT_RUN')
        self.assertIs(checked['notifications_verified'], False)
        self.assertIs(checked['cosmic_session_verified'], False)
        self.assertEqual(len(receipt['inputs']['licenses']), 3)
        self.assertFalse(self.stage.exists())

    def test_metadata_only_failed_old_or_runtime_claimed_report_is_rejected(self):
        original = copy.deepcopy(self.report)
        changes = [('status', 'METADATA_VERIFIED_NOT_BUILT'), ('status', 'failed'), ('kind', 'cosmic-notifications'),
                   ('schema_version', True), ('target', 'aarch64-unknown-linux-musl'), ('target_linked', False),
                   ('link_completed', 1), ('cargo_resolution_verified', False), ('source_preserved', False),
                   ('producer_sources_preserved', False), ('notifications_verified', True),
                   ('cosmic_session_verified', True), ('native_archive_search_preserved', False),
                   ('native_archive_check_error', 'staged archive changed'), ('error', 'failed postcheck')]
        for key, value in changes:
            self.report = copy.deepcopy(original); self.report[key] = value; self.save_report()
            with self.subTest(key=key, value=value), self.assertRaises(subject.BuildError):
                self.install()
            self.assertFalse(self.output.exists())

    def test_source_vendor_cache_archive_and_patch_tampering_is_rejected(self):
        package = self.policy['registry_inputs'][0]
        paths = [self.source / 'src/main.rs', self.exported / 'src/main.rs',
                 self.exported / package['destination'] / 'src/lib.rs',
                 self.cache / 'registry/src/fixture/wayland-sys-0.31.11/src/lib.rs',
                 self.cache / 'registry/cache/fixture/wayland-sys-0.31.11.crate',
                 self.policy_path.parent / self.policy['patches'][1]['path']]
        for path in paths:
            original = path.read_bytes(); path.write_bytes(original + b'changed\n')
            with self.subTest(path=path), self.assertRaises((ValueError, subject.BuildError)):
                self.install()
            path.write_bytes(original)
            self.assertFalse(self.output.exists())

    def test_local_manifest_escape_or_wrong_vendor_location_is_rejected(self):
        original = copy.deepcopy(self.metadata)
        for path in (self.dependency / 'Cargo.toml', self.stage / 'other/Cargo.toml'):
            self.metadata = copy.deepcopy(original)
            self.metadata['packages'][2]['manifest_path'] = str(path)
            save(self.build_output / 'metadata.json', self.metadata)
            with self.subTest(path=path), self.assertRaises((ValueError, subject.BuildError)):
                self.install()
        self.assertFalse(self.output.exists())

    def test_feature_resolution_change_cannot_be_hidden_by_rehashing_metadata_log(self):
        self.metadata['resolve']['nodes'][3]['features'].remove('x11')
        save(self.build_output / 'metadata.json', self.metadata)
        data = (self.build_output / 'metadata.json').read_bytes()
        self.report['metadata_sha256'] = static.sha(data)
        self.report['evidence_files']['metadata.json'] = subject.legacy.common.identity(data)
        self.save_report()
        with self.assertRaisesRegex(ValueError, 'resolution changed'):
            self.install()

    def test_producer_compiler_sdk_assembly_and_evidence_drift_is_rejected(self):
        original = copy.deepcopy(self.report)
        self.report['producer_sources'] = dict(self.report['producer_sources'])
        self.report['producer_sources']['tools/build_cosmic_notifications_static_v1.py'] = '0' * 64
        self.save_report()
        with self.assertRaisesRegex(subject.BuildError, 'producers changed'): self.install()
        self.report = original; self.save_report()
        paths = [Path(self.report['toolchain']['tools']['host_cc']['path']),
                 self.sysroot / 'runtime-sdk-origin.json', self.sysroot / self.recipe['native_inputs'][-1]['path'],
                 self.build_output / 'cargo.log', self.build_output / 'metadata.stderr.log']
        for path in paths:
            data = path.read_bytes(); path.write_bytes(data + b'changed\n')
            with self.subTest(path=path), self.assertRaises((ValueError, subject.BuildError)):
                self.install()
            path.write_bytes(data)
            self.assertFalse(self.output.exists())

    def test_published_elf_and_linked_elf_must_match_the_same_admission(self):
        linked = Path(self.report['linked_binary']['path'])
        for path in (linked, self.build_output / subject.PROGRAM):
            data = path.read_bytes(); changed = bytearray(data); changed[-1] ^= 1; path.write_bytes(changed)
            with self.subTest(path=path), self.assertRaises((ValueError, subject.BuildError)):
                self.install()
            path.write_bytes(data)
        changed = copy.deepcopy(self.report['image_admission'])
        self.report['image_admission']['required_pages'] += 1; self.save_report()
        with self.assertRaises(subject.BuildError): self.install()
        self.report['image_admission'] = changed

    def test_native_rlib_search_receipts_and_exact_copied_archives_are_required(self):
        original = copy.deepcopy(self.report)
        for field in ('native_archive_search', 'native_archive_search_after'):
            self.report = copy.deepcopy(original); del self.report[field]; self.save_report()
            with self.subTest(field=field), self.assertRaises(subject.BuildError): self.install()
        self.report = copy.deepcopy(original)
        self.report['native_archive_search_after']['schema_version'] = True; self.save_report()
        with self.assertRaisesRegex(ValueError, 'receipt changed'): self.install()
        self.report = original; self.save_report()
        path = self.build_output / 'native/libxkbcommon.a'; data = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'missing or extra'): self.install()
        path.write_bytes(data + b'changed')
        with self.assertRaisesRegex(ValueError, 'Staged rustc native archive changed'): self.install()
        path.unlink(); path.symlink_to(self.sysroot / 'sysroot/usr/lib/libxkbcommon.a')
        with self.assertRaisesRegex(ValueError, 'symlink'): self.install()
        path.unlink(); path.write_bytes(data)
        write(self.build_output / 'native/unreviewed.a', fixture.archive())
        with self.assertRaisesRegex(ValueError, 'missing or extra'): self.install()
        self.assertFalse(self.output.exists())

    def test_staged_native_archive_change_during_copy_prevents_publication(self):
        read = subject.legacy.common.read_regular
        changed = []
        def drift(path, *args, **kwargs):
            data = read(path, *args, **kwargs)
            if Path(path) == self.build_output / subject.PROGRAM and not changed:
                changed.append(True)
                with (self.build_output / 'native/libxkbcommon.a').open('ab') as stream:
                    stream.write(b'changed during publication')
            return data
        with mock.patch.object(subject.legacy.common, 'read_regular', side_effect=drift):
            with self.assertRaisesRegex(ValueError, 'Staged rustc native archive changed'):
                self.install()
        self.assertTrue(changed)
        self.assertFalse(self.output.exists())

    def failed_build(self, *, corrupt_archive):
        """Exercise the real producer flow; only native execution/selection is a fixture."""
        output = self.root / 'failed-producer'
        tools = {name: Path(row['path']) for name, row in self.report['toolchain']['tools'].items()}
        calls = []
        def cargo_fixture(command, control, environment, log, *args, **kwargs):
            calls.append(command[1])
            if command[1] == 'metadata':
                stage = Path(command[command.index('--manifest-path') + 1]).parent
                encoded = json.dumps(self.metadata).replace(str(self.stage), str(stage))
                save(Path(log), json.loads(encoded))
                write(Path(kwargs['stderr_log']), '')
                return
            self.assertEqual(command[1], 'build')
            self.assertTrue((output / 'native/libxkbcommon.a').is_file())
            write(Path(log), 'HOST FIXTURE ONLY: Cargo was not executed\n')
            if corrupt_archive:
                with (output / 'native/libxkbcommon.a').open('ab') as stream:
                    stream.write(b'fixture build changed a native input')
            raise static.build.CosmicBuildError('fixture command exit 101')
        with mock.patch.object(builder.toolchain_selection, 'tools_and_sysroot',
                               return_value=(tools, self.report['toolchain'])), \
             mock.patch.object(builder.base, 'run_bounded', side_effect=cargo_fixture):
            with self.assertRaisesRegex(ValueError, 'fixture command exit 101'):
                builder.perform_build(self.recipe_path, self.resource, output, self.sysroot,
                    self.cache, self.source_cache, 1,
                    rust_root=Path(tools['rustc']).parent.parent, host_cc=tools['host_cc'])
        self.assertEqual(calls, ['metadata', 'build'])
        report = json.loads((output / 'build-report.json').read_bytes())
        self.assertEqual(report['status'], 'failed')
        self.assertIs(report['link_completed'], False)
        self.assertIs(report['target_linked'], False)
        self.assertIs(report['notifications_verified'], False)
        self.assertIs(report['producer_sources_preserved'], True)
        self.assertEqual(set(report['evidence_files']), set(subject.LOGS))
        self.assertEqual(set(report['native_archive_search']['files']), {'libunwind.a', *static.STATIC_NAMES})
        return report

    def test_failed_cargo_retains_archive_postcheck_without_claiming_a_link(self):
        report = self.failed_build(corrupt_archive=False)
        self.assertIs(report['native_archive_search_preserved'], True)
        self.assertEqual(report['native_archive_search'], report['native_archive_search_after'])
        self.assertNotIn('native_archive_check_error', report)

    def test_failed_cargo_native_archive_tamper_cannot_claim_preservation(self):
        report = self.failed_build(corrupt_archive=True)
        self.assertIs(report['native_archive_search_preserved'], False)
        self.assertIn('Staged rustc native archive changed', report['native_archive_check_error'])
        self.assertNotIn('native_archive_search_after', report)

    def successful_compiler_fixture(self, output, *, metadata_only=False):
        """Real producer lifecycle with explicit file-only Cargo/SDK selection fixtures."""
        tools = {name: Path(row['path']) for name, row in self.report['toolchain']['tools'].items()}
        def cargo_fixture(command, control, environment, log, *args, **kwargs):
            if command[1] == 'metadata':
                stage = Path(command[command.index('--manifest-path') + 1]).parent
                save(Path(log), json.loads(json.dumps(self.metadata).replace(str(self.stage), str(stage))))
                write(Path(kwargs['stderr_log']), '')
                return
            self.assertEqual(command[1], 'build')
            write(Path(log), 'HOST FILE FIXTURE ONLY: no Cargo/native program was executed\n')
            write(output / 'target' / static.TARGET / 'release/cosmic-notifications', fixture.elf())
        with mock.patch.object(builder.toolchain_selection, 'tools_and_sysroot',
                               return_value=(tools, self.report['toolchain'])), \
             mock.patch.object(builder.base, 'run_bounded', side_effect=cargo_fixture):
            return builder.perform_build(self.recipe_path, self.resource, output, self.sysroot,
                self.cache, self.source_cache, 1,
                rust_root=Path(tools['rustc']).parent.parent, host_cc=tools['host_cc'],
                metadata_only=metadata_only)

    def check_revoked_publication(self, output, *, missing_evidence=()):
        report = json.loads((output / 'build-report.json').read_bytes())
        self.assertEqual(report['status'], 'failed')
        self.assertIs(report['target_linked'], False)
        self.assertIs(report['link_completed'], True)
        self.assertIs(report['notifications_verified'], False)
        self.assertFalse((output / subject.PROGRAM).exists())
        self.assertFalse((output / ('.' + subject.PROGRAM + '.pending')).exists())
        self.assertEqual((output / 'target' / static.TARGET / 'release/cosmic-notifications').read_bytes(), fixture.elf())
        for name in subject.LOGS:
            self.assertEqual((output / name).is_file(), name not in missing_evidence)
        self.assertTrue((output / 'source/Cargo.toml').is_file())
        with self.assertRaisesRegex(subject.BuildError, 'Not a preserved static-v1'):
            subject.validate_build_directory(output)
        return report

    def test_verified_candidate_is_atomically_published_and_consumer_accepts_complete_fixture(self):
        output = self.root / 'complete-producer'
        original = Path.replace
        published = []
        def replace(candidate, final):
            self.assertEqual(candidate, output / ('.' + subject.PROGRAM + '.pending'))
            self.assertEqual(final, output / subject.PROGRAM)
            self.assertFalse(final.exists())
            observed = subject.image.inspect_full_os_elf(candidate, self.profile)
            self.assertEqual(observed['executable']['sha256'], static.sha(fixture.elf()))
            published.append(candidate)
            return original(candidate, final)
        with mock.patch.object(Path, 'replace', replace):
            report = self.successful_compiler_fixture(output)
        self.assertEqual(len(published), 1)
        self.assertEqual(report['status'], 'cross-built')
        self.assertIs(report['target_linked'], True)
        self.assertIs(report['native_archive_search_preserved'], True)
        self.assertFalse(published[0].exists())
        self.assertEqual(subject.validate_build_directory(output)['inputs']['executable'], report['executable'])

    def test_late_archive_evidence_producer_inspection_and_report_io_failures_revoke_final(self):
        for failure in ('archive', 'evidence', 'producer', 'inspection', 'report_io'):
            with self.subTest(failure=failure), contextlib.ExitStack() as mocks:
                output = self.root / ('late-' + failure)
                final = output / subject.PROGRAM
                triggered = []
                if failure == 'archive':
                    original = static.verify_native_archive_search
                    def changed_archive(*args, **kwargs):
                        if final.exists() and not triggered:
                            triggered.append(True)
                            with (output / 'native/libxkbcommon.a').open('ab') as stream:
                                stream.write(b'late fixture archive change')
                        return original(*args, **kwargs)
                    mocks.enter_context(mock.patch.object(static, 'verify_native_archive_search', side_effect=changed_archive))
                elif failure == 'evidence':
                    original = static.read_regular
                    def unreadable_log(path, *args, **kwargs):
                        if Path(path) == output / 'cargo.log' and final.exists():
                            triggered.append(True)
                            raise OSError('late fixture log read failure')
                        return original(path, *args, **kwargs)
                    mocks.enter_context(mock.patch.object(static, 'read_regular', side_effect=unreadable_log))
                elif failure == 'producer':
                    original = static.producer_sources
                    def changed_producer(*args, **kwargs):
                        result = original(*args, **kwargs)
                        if final.exists():
                            triggered.append(True)
                            result['tools/build_cosmic_notifications_static_v1.py'] = '0' * 64
                        return result
                    mocks.enter_context(mock.patch.object(static, 'producer_sources', side_effect=changed_producer))
                elif failure == 'inspection':
                    original = subject.image.inspect_full_os_elf
                    def failed_inspection(path, *args, **kwargs):
                        if Path(path) == final:
                            triggered.append(True)
                            raise ValueError('late fixture published ELF inspection failure')
                        return original(path, *args, **kwargs)
                    mocks.enter_context(mock.patch.object(subject.image, 'inspect_full_os_elf', side_effect=failed_inspection))
                else:
                    original = Path.write_text
                    def failed_report(path, data, *args, **kwargs):
                        if path == output / 'build-report.json' and not triggered:
                            triggered.append(True)
                            original(path, data[:20], *args, **kwargs)
                            raise OSError('late fixture partial report write')
                        return original(path, data, *args, **kwargs)
                    mocks.enter_context(mock.patch.object(Path, 'write_text', failed_report))
                with self.assertRaises((ValueError, OSError)):
                    self.successful_compiler_fixture(output)
                self.assertTrue(triggered)
                self.check_revoked_publication(output)

    def test_missing_successful_build_evidence_revokes_publication(self):
        for name in subject.LOGS:
            with self.subTest(name=name):
                output = self.root / ('missing-' + name)
                original = static.verify_native_archive_search
                removed = []
                def remove_evidence(*args, **kwargs):
                    if (output / subject.PROGRAM).exists() and not removed:
                        (output / name).unlink()
                        removed.append(name)
                    return original(*args, **kwargs)
                with mock.patch.object(static, 'verify_native_archive_search', side_effect=remove_evidence):
                    with self.assertRaisesRegex(ValueError, 'Incomplete successful static build evidence'):
                        self.successful_compiler_fixture(output)
                self.assertEqual(removed, [name])
                self.check_revoked_publication(output, missing_evidence=(name,))

    def test_metadata_only_requires_complete_evidence_without_claiming_a_link(self):
        output = self.root / 'complete-metadata-only'
        report = self.successful_compiler_fixture(output, metadata_only=True)
        self.assertEqual(report['status'], 'METADATA_VERIFIED_NOT_BUILT')
        self.assertEqual(set(report['evidence_files']), {'metadata.json', 'metadata.stderr.log'})
        self.assertIs(report['link_completed'], False)
        self.assertIs(report['target_linked'], False)
        self.assertFalse((output / subject.PROGRAM).exists())
        for name in ('metadata.json', 'metadata.stderr.log'):
            with self.subTest(name=name):
                output = self.root / ('metadata-only-missing-' + name)
                original = static.verify_native_archive_search
                calls = []
                def remove_evidence(*args, **kwargs):
                    calls.append(True)
                    if len(calls) == 3:
                        (output / name).unlink()
                    return original(*args, **kwargs)
                with mock.patch.object(static, 'verify_native_archive_search', side_effect=remove_evidence):
                    with self.assertRaisesRegex(ValueError, 'Incomplete successful static build evidence'):
                        self.successful_compiler_fixture(output, metadata_only=True)
                self.assertEqual(len(calls), 3)
                report = json.loads((output / 'build-report.json').read_bytes())
                self.assertEqual(report['status'], 'failed')
                self.assertIs(report['link_completed'], False)
                self.assertIs(report['target_linked'], False)
                self.assertIs(report['notifications_verified'], False)
                self.assertFalse((output / subject.PROGRAM).exists())
                self.assertFalse((output / ('.' + subject.PROGRAM + '.pending')).exists())
                with self.assertRaisesRegex(subject.BuildError, 'Not a preserved static-v1'):
                    subject.validate_build_directory(output)

    def test_partial_candidate_copy_is_removed_without_modifying_raw_link_output(self):
        output = self.root / 'partial-copy-producer'
        original = builder.shutil.copyfileobj
        observed = []
        def partial(source, destination, *args, **kwargs):
            if Path(destination.name).name == '.' + subject.PROGRAM + '.pending':
                destination.write(source.read(31))
                observed.append(True)
                raise OSError('fixture partial copy failure')
            return original(source, destination, *args, **kwargs)
        with mock.patch.object(builder.shutil, 'copyfileobj', side_effect=partial):
            with self.assertRaisesRegex(OSError, 'partial copy failure'):
                self.successful_compiler_fixture(output)
        self.assertTrue(observed)
        self.check_revoked_publication(output)

    def test_post_publication_interrupt_also_revokes_final(self):
        output = self.root / 'interrupted-producer'
        original = static.verify_native_archive_search
        def interrupted(*args, **kwargs):
            if (output / subject.PROGRAM).exists():
                raise KeyboardInterrupt('fixture interrupt during final checks')
            return original(*args, **kwargs)
        with mock.patch.object(static, 'verify_native_archive_search', side_effect=interrupted):
            with self.assertRaisesRegex(KeyboardInterrupt, 'fixture interrupt'):
                self.successful_compiler_fixture(output)
        self.check_revoked_publication(output)

    def test_input_alias_output_overlap_and_existing_destination_are_preserved(self):
        source = self.build_output / subject.PROGRAM
        data = source.read_bytes(); outside = write(self.root / 'other-elf', data)
        source.unlink(); source.symlink_to(outside)
        with self.assertRaises(subject.BuildError): self.install()
        source.unlink(); source.write_bytes(data)
        with self.assertRaisesRegex(subject.BuildError, 'overlaps an input'):
            subject.install(self.build_output, self.build_output / 'overlap')
        self.output.mkdir(); marker = write(self.output / 'keep', 'existing')
        with self.assertRaisesRegex(subject.BuildError, 'Preserving existing'):
            self.install()
        self.assertEqual(marker.read_text(), 'existing')

    def test_changed_input_during_copy_cannot_publish_partial_installation(self):
        real_read = subject.legacy.common.read_regular
        changed = []
        def drift(path, *args, **kwargs):
            data = real_read(path, *args, **kwargs)
            if Path(path) == self.build_output / subject.PROGRAM and not changed:
                changed.append(True)
                write(self.exported / 'src/main.rs', '// changed after initial validation\n')
            return data
        with mock.patch.object(subject.legacy.common, 'read_regular', side_effect=drift):
            with self.assertRaisesRegex(ValueError, 'exported source changed'):
                self.install()
        self.assertTrue(changed)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.output.parent.glob('.' + self.output.name + '-*')))

    def test_installed_receipt_file_mode_license_and_elf_tampering_is_rejected(self):
        receipt = self.install()
        path = self.output / subject.RECEIPT
        wrong = copy.deepcopy(receipt); wrong['notifications_verified'] = True; save(path, wrong)
        with self.assertRaises(subject.BuildError): subject.validate_inputs(self.output)
        save(path, receipt)
        for artifact in receipt['artifacts']:
            path = self.output / artifact['path']; data = path.read_bytes()
            path.write_bytes(data + b'changed')
            with self.subTest(path=path), self.assertRaises(subject.BuildError):
                subject.validate_inputs(self.output)
            path.write_bytes(data)
        executable = self.output / subject.PROGRAM; executable.chmod(0o644)
        with self.assertRaisesRegex(subject.BuildError, 'file mode changed'):
            subject.validate_inputs(self.output)


if __name__ == '__main__':
    unittest.main()
