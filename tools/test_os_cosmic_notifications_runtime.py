"""Pure host acceptance-boundary fixtures; never QEMU, native, or GUI evidence."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch

try:
    from tools import os_cosmic_notifications_runtime as subject
    from tools import test_build_notification_probe as probe_fixture
except ImportError:
    import os_cosmic_notifications_runtime as subject
    import test_build_notification_probe as probe_fixture


def protocol(service=31, client=32, number=7):
    return (f'NOTIFICATION_PROBE START service=org.freedesktop.Notifications render_verified=false\n'
            f'NOTIFICATION_PROBE OWNER PASS unique=:1.12 service_pid={service} client_pid={client}\n'
            f'NOTIFICATION_PROBE INFO PASS name=cosmic-notifications vendor=System76 version=1.10.0 spec=1.2\n'
            f'NOTIFICATION_PROBE CREATED id={number} service_pid={service} capture_ms=5000 render_verified=false\n'
            f'NOTIFICATION_PROBE CLOSED id={number} service_pid={service} reason=3\n'
            f'NOTIFICATION_PROBE PASS service_pid={service} id={number} render_verified=false\n').encode()


def snapshot(completed=0, owner=0):
    display = (f'AI_DOMAIN name=display available=true phase=Idle scope=submit_pacing model=1 version=1 '
               f'submitted={completed} completed={completed} failed=0 policy_invalid=0 clock_rejected=0\n')
    receipt = (f'AI_DISPLAY_RECEIPT id={completed} owner={owner} model=1 pixels=16384 observed_completed=8 '
               'phase=Idle outcome=Completed\n') if completed else ''
    return (display + receipt +
            'OFD_OBJECTS live=0 references=0 retired=0 capacity=256 epolls=0 watches=0 fd_refs=0 staged_refs=0 inflight_refs=0\n'
            'ANCILLARY_OBJECTS messages=0 references=0 staged_messages=0 inflight_messages=0 staged_refs=0 inflight_refs=0 capacity_messages=8 capacity_references=64\n'
            'SHARED_OBJECTS available=true objects=0 pages=0 mappings=0 description_refs=0 mapping_refs=0 free_pages=4096 grant_reserved=0 grant_used=0 metadata_capacity=64 page_capacity=4096 MECHANISM\n'
            'ANON_POOL capacity=65536 free=65536 used=0 peak=0 virtual_pages=16384 backing=BOOTSTRAP ownership=PRIVATE commit=MMAP\n'
            'PIPE_POOL capacity=32 unavailable=0 free=32 bytes_per_pair=4096 backing=BOOTSTRAP policy=AI_DIRECT model=8193\n'
            'AI_SYSTEM_END\n').encode()


def process(state='Exited', code=0):
    return {'pid': 32, 'state': state, 'code': code, 'free_pages': 64, 'heap_pages': 0,
            'image_pages': 0, 'thread_count': 0, 'heap_free': 16384, 'heap_allocations': 0,
            'heap_largest_free': 16384, 'image_free': 16384}


class FontFixture:
    """Small explicit byte fixtures; canonical Git boundary is mocked."""
    def __init__(self, root):
        self.root = root
        self.checkout = root / 'checkout'
        self.prefix = root / 'catalog'
        self.files, self.pins, self.records = {}, {}, {}
        for index, relative in enumerate(subject.FONT_FILES):
            raw = ('HOST TEST FONT/LICENCE FIXTURE ' + str(index)).encode()
            path = self.checkout / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            if relative.endswith('.ttf'):
                guest = '/usr/share/fonts/cosmic/' + Path(relative).name
            else:
                name = 'OpenSans' if relative.startswith('res/open-sans/') else 'NotoSansMono'
                guest = '/usr/share/licenses/cosmic-fonts/' + name + '-LICENSE'
            target = self.prefix / 'rootfs' / guest.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o644)
            sha = hashlib.sha256(raw).hexdigest()
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            self.pins[relative] = sha
            self.records[relative] = '100644 blob ' + blob + '\t' + relative
            self.files[guest] = {'source_relative': relative, 'source': str(path), 'sha256': sha,
                                 'bytes': len(raw), 'git_blob': blob, 'mode': '100644'}
        self.report = {'schema_version': 1, 'status': 'ASSETS_INSTALLED_NOT_RUN',
                       'source': {'repository': 'https://github.com/pop-os/libcosmic',
                                  'checkout': str(self.checkout), 'commit': subject.FONT_COMMIT,
                                  'git_tree': 'fixture-tree'}, 'files': self.files}
        self.receipt = self.prefix / 'cosmic-font-assets.json'
        self.save()

    def save(self):
        self.receipt.write_text(json.dumps(self.report))

    def git(self, checkout, *arguments):
        assert checkout == self.checkout
        if arguments == ('rev-parse', 'HEAD'):
            return subject.FONT_COMMIT
        if arguments == ('rev-parse', 'HEAD^{tree}'):
            return 'fixture-tree'
        assert arguments[:3] == ('ls-tree', 'HEAD', '--')
        return self.records[arguments[3]]

    def validate(self):
        with patch.object(subject, 'FONT_FILES', self.pins), \
                patch.object(subject.dependencies, 'pinned_git', side_effect=self.git):
            return subject.font_inputs(self.prefix)


class GeneratedCatalogSelection(unittest.TestCase):
    """Real host paths only; catalog selection is not kernel or guest evidence."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.manifest = {'target': 'x86_64-unknown-none', 'profile': 'release',
                         'cache': {'effective': str(self.cache)}}

    def catalog(self, profile, suffix='a' * 16, *, target='x86_64-unknown-none'):
        path = self.cache / target / profile / 'build' / ('cyxia-kernel-' + suffix) / 'out/ported_catalog.rs'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'HOST CATALOG PATH FIXTURE\n')
        return path

    def test_debug_and_release_coexist_and_only_manifest_profile_is_selected(self):
        debug = self.catalog('debug')
        release = self.catalog('release')
        # Cargo may retain an otherwise empty build-script directory too.
        (release.parents[2] / ('cyxia-kernel-' + 'c' * 16)).mkdir()
        for profile, expected in [('dev', debug), ('release', release)]:
            with self.subTest(profile=profile):
                self.manifest['profile'] = profile
                manifest = json.loads(json.dumps(self.manifest))
                self.assertEqual(subject.generated_catalog_path(manifest), expected)
                self.assertEqual(expected.read_bytes(), b'HOST CATALOG PATH FIXTURE\n')

    def test_missing_selected_profile_cannot_fall_back_to_another_profile_or_target(self):
        self.catalog('debug')
        self.catalog('release', target='aarch64-unknown-none')
        selected_build = self.cache / self.manifest['target'] / 'release/build'
        with self.assertRaises(ValueError):
            subject.generated_catalog_path(self.manifest)
        selected_build.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'Missing/ambiguous actual generated catalog'):
            subject.generated_catalog_path(self.manifest)

    def test_duplicate_catalogs_inside_selected_profile_are_rejected_even_with_equal_bytes(self):
        self.catalog('debug')
        first = self.catalog('release', 'a' * 16)
        second = self.catalog('release', 'b' * 16)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with self.assertRaisesRegex(ValueError, 'Missing/ambiguous actual generated catalog'):
            subject.generated_catalog_path(self.manifest)

    def test_unknown_or_nonmatching_target_and_profile_are_rejected(self):
        self.catalog('release')
        invalid = [('profile', value) for value in (None, '', 'debug', '../release', 'bench', True, [])]
        invalid += [('target', value) for value in (None, '', 'x86_64-unknown-linux-musl',
                    'aarch64-unknown-none', '../x86_64-unknown-none', True, [])]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                manifest = copy.deepcopy(self.manifest)
                manifest[key] = value
                with self.assertRaisesRegex(ValueError, 'Unsupported OS catalog target/profile'):
                    subject.generated_catalog_path(manifest)

    def test_symlink_at_every_selected_path_boundary_and_dangling_catalog_are_rejected(self):
        for boundary in ('cache', 'target', 'profile', 'build', 'crate', 'out', 'catalog', 'dangling'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                cache = root / 'cache'
                catalog = cache / 'x86_64-unknown-none/release/build/cyxia-kernel-aaaaaaaaaaaaaaaa/out/ported_catalog.rs'
                catalog.parent.mkdir(parents=True)
                catalog.write_bytes(b'HOST CATALOG PATH FIXTURE\n')
                selected = {'cache': cache, 'target': catalog.parents[4], 'profile': catalog.parents[3],
                            'build': catalog.parents[2], 'crate': catalog.parents[1],
                            'out': catalog.parent, 'catalog': catalog, 'dangling': catalog}[boundary]
                moved = root / 'retained-original'
                selected.rename(moved)
                selected.symlink_to(root / 'absent' if boundary == 'dangling' else moved,
                                    target_is_directory=moved.is_dir())
                manifest = {'target': 'x86_64-unknown-none', 'profile': 'release',
                            'cache': {'effective': str(cache)}}
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    subject.generated_catalog_path(manifest)


class ProbeReceiptJson(unittest.TestCase):
    @contextlib.contextmanager
    def consumer(self, fixture):
        # Reuse the producer's host-only fixture. Its compiler boundary and
        # original D-Bus validator are mocked; JSON I/O and client checks are real.
        builder = probe_fixture.subject
        with patch.object(subject, 'probe_builder', builder), \
                patch.object(subject, 'profile_for', builder.profile_for), \
                patch.object(builder, 'SOURCE', fixture.source), \
                patch.object(builder.build_dbus, 'validate_build', side_effect=fixture.validate_dbus):
            yield

    def test_producer_receipt_json_roundtrip_is_accepted_without_changing_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = probe_fixture.Fixture(Path(directory))
            original = fixture.build()
            receipt = fixture.output / probe_fixture.subject.RECEIPT
            preserved = receipt.read_bytes()
            loaded = json.loads(preserved)
            self.assertIsInstance(original['target_profile']['clang_args'], tuple)
            self.assertIsInstance(loaded['target_profile']['clang_args'], list)
            with self.consumer(fixture):
                result = subject.probe_inputs(fixture.output)
            self.assertEqual(result['report'], loaded)
            self.assertEqual(result['receipt'], subject.identity(receipt))
            self.assertEqual(result['image_admission']['executable']['sha256'],
                             loaded['probe']['sha256'])
            self.assertIs(result['report']['guest_execution'], False)
            self.assertEqual(receipt.read_bytes(), preserved)
            self.assertIsInstance(fixture.target.identity()['clang_args'], tuple)

    def test_json_receipt_rejects_wrong_or_incomplete_target_profile_before_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = probe_fixture.Fixture(Path(directory))
            fixture.build()
            receipt = fixture.output / probe_fixture.subject.RECEIPT
            original = json.loads(receipt.read_bytes())
            wrong_arch = json.loads(json.dumps(probe_fixture.subject.profile_for('aarch64').identity()))
            cases = [wrong_arch]
            for key, value in [('clang_args', ['--target=x86_64-linux-musl']),
                               ('machine', 183), ('cpu', 'unreviewed-cpu')]:
                profile = copy.deepcopy(original['target_profile'])
                profile[key] = value
                cases.append(profile)
            missing = copy.deepcopy(original['target_profile'])
            del missing['linker_emulation']
            cases.append(missing)
            extra = copy.deepcopy(original['target_profile'])
            extra['unreviewed_option'] = True
            cases.append(extra)
            for profile in cases:
                changed = copy.deepcopy(original)
                changed['target_profile'] = profile
                receipt.write_text(json.dumps(changed) + '\n')
                with self.subTest(profile=profile), self.consumer(fixture), \
                        patch.object(probe_fixture.subject, 'producer_identity') as producer:
                    with self.assertRaisesRegex(ValueError, 'preserved notification client build'):
                        subject.probe_inputs(fixture.output)
                    producer.assert_not_called()


class ProcessSnapshotBoundaries(unittest.TestCase):
    # Actual notification-runtime-capture-v1 serial.raw at commands.json's
    # posix-list offset 8794. The complete 21-byte response has SHA256
    # afd3a1956c9ad5e82d7afafa0e85cb367d790c97e94ec7a67a696fcfab80f834.
    EMPTY = b'posix list\r\ncyxia:/> '

    def console(self, output):
        # Old rows must not be mistaken for this command's snapshot.
        previous = b'UserStatus { pid: 90, state: Running }\r\ncyxia:/> '
        console = SimpleNamespace(raw=bytearray(previous + output))

        def command(text):
            self.assertEqual(text, 'posix list')
            return len(previous)

        console.command = command
        return console

    def test_actual_complete_empty_initial_snapshot_is_accepted(self):
        # The shared nonempty parser is deliberately unchanged.
        with self.assertRaisesRegex(AssertionError, 'Missing process snapshot'):
            subject.parse_processes(self.EMPTY)
        for output in (self.EMPTY, self.EMPTY.replace(b'\r\n', b'\n')):
            with self.subTest(output=output):
                self.assertEqual(subject.processes(self.console(output)), {})
                self.assertEqual(subject.active_processes(self.console(output), set(), set(), allow_empty=True), {})

    def test_missing_malformed_or_diagnostic_output_is_not_an_empty_snapshot(self):
        for output in (
            b'', b'cyxia:/> ', b'posix list\r\n', b'posix list\r\ncyxia:/>',
            b'posix list\r\nunknown output\r\ncyxia:/> ',
            b'posix list\r\nerror: NotFound\r\ncyxia:/> ',
            b'posix list\r\nUserStatus { pid: 31, state: Running\r\ncyxia:/> ',
            b'posix list\r\n\r\ncyxia:/> ',
            self.EMPTY + b'unknown output', self.EMPTY + b'cyxia:/> ',
            b'posix list\r\n' + self.EMPTY,
        ):
            with self.subTest(output=output), self.assertRaises(AssertionError):
                subject.processes(self.console(output))

    def test_empty_or_exited_rows_cannot_hide_a_missing_active_service(self):
        with self.assertRaisesRegex(ValueError, 'Missing process snapshot'):
            subject.active_processes(self.console(self.EMPTY), {32}, {32})
        for state in ('Running', 'Waiting', 'Exited'):
            row = process(state=state)
            row['free_pages'] = 56 if state in ('Running', 'Waiting') else 64
            body = ', '.join(f'{key}: {value}' for key, value in row.items()).encode()
            output = b'posix list\r\nUserStatus { ' + body + b' }\r\ncyxia:/> '
            if state == 'Exited':
                with self.assertRaisesRegex(ValueError, 'Unexpected exited or unrelated active process'):
                    subject.active_processes(self.console(output), {32}, {32})
            else:
                self.assertEqual(subject.active_processes(self.console(output), {32}, {32}), {32: row})
                with self.assertRaisesRegex(ValueError, 'Unexpected exited or unrelated active process'):
                    subject.active_processes(self.console(output), {31, 32}, {31, 32})
                with self.assertRaisesRegex(ValueError, 'Unexpected exited or unrelated active process'):
                    subject.active_processes(self.console(output), set(), set())


class ProcessArenaBoundaries(unittest.TestCase):
    # Actual capture-v2 final posix-list command, offset 9832: dbus-daemon
    # remains live while the dbus-send client has fully exited.
    ACTUAL_V2 = (
        b"posix list\r\n"
        b"EL0 UserStatus { pid: 1, parent_pid: 0, exit_signal: 0, state: Running, code: 0, syscalls: 205, preemptions: 39, ai_slices: 244, cpu_model: 12290, last_slice_ms: 1, esr: 0, far: 0, free_pages: 56, rank_model: 12289, ai_selections: 244, guard_selections: 0, thread_count: 1, thread_peak: 1, thread_memory_model: 0, thread_admissions: 0, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 244, thread_guard_selections: 0, ipc_sent: 0, ipc_received: 0, waits: 6, wakeups: 6, heap_pages: 13, heap_free: 16371, heap_model: 8199, heap_peak: 13, heap_allocations: 11, heap_peak_allocations: 11, heap_largest_free: 16371, image_pages: 629, image_free: 15755 }\r\n"
        b"EL0 UserStatus { pid: 2, parent_pid: 0, exit_signal: 0, state: Exited, code: 0, syscalls: 47, preemptions: 54, ai_slices: 101, cpu_model: 12290, last_slice_ms: 4, esr: 0, far: 0, free_pages: 56, rank_model: 12289, ai_selections: 101, guard_selections: 0, thread_count: 0, thread_peak: 1, thread_memory_model: 0, thread_admissions: 0, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 101, thread_guard_selections: 0, ipc_sent: 0, ipc_received: 0, waits: 4, wakeups: 4, heap_pages: 0, heap_free: 16384, heap_model: 8199, heap_peak: 8, heap_allocations: 0, heap_peak_allocations: 6, heap_largest_free: 16384, image_pages: 0, image_free: 16384 }\r\n"
        b"cyxia:/> "
    )

    def test_actual_completed_client_with_live_broker_owns_no_process_resources(self):
        console = ProcessSnapshotBoundaries().console(self.ACTUAL_V2)
        rows = subject.active_processes(console, {1}, {1})
        self.assertEqual(rows[1]['state'], 'Running')
        self.assertEqual(rows[2]['state'], 'Exited')
        self.assertEqual(subject.global_arena(rows),
                         {'capacity_pages': 64, 'pages_per_active_process': 8,
                          'free_pages': 56, 'active_pids': [1]})
        subject.process_reclaimed(rows[2], 'Exited', 0)
        self.assertEqual(rows[2]['heap_pages'], 0)
        self.assertEqual(rows[2]['image_pages'], 0)
        self.assertEqual(rows[2]['thread_count'], 0)

    def test_missing_inconsistent_or_unaccounted_global_pages_are_rejected(self):
        rows = subject.parse_processes(self.ACTUAL_V2)
        invalid = []
        changed = copy.deepcopy(rows)
        del changed[2]['free_pages']
        invalid.append(changed)
        for value in (-1, 65, True, '56', 64):
            changed = copy.deepcopy(rows)
            changed[2]['free_pages'] = value
            invalid.append(changed)
        for value in (48, 55, 64):
            changed = copy.deepcopy(rows)
            for row in changed.values():
                row['free_pages'] = value
            invalid.append(changed)
        changed = copy.deepcopy(rows)
        changed[1]['state'] = 'Unknown'
        invalid.append(changed)
        invalid.append({2: copy.deepcopy(rows[2])})  # Omitted live owner, still 56.
        for changed in invalid:
            with self.subTest(rows=changed), self.assertRaises(ValueError):
                subject.global_arena(changed)
        with self.assertRaises(ValueError):
            subject.processes(ProcessSnapshotBoundaries().console(
                self.ACTUAL_V2.replace(b'free_pages: 56', b'free_pages: 64')))

    def test_sequential_kills_require_a_fresh_complete_global_recovery_snapshot(self):
        # Synthetic lifecycle fixture, not guest evidence. The real client row
        # above establishes why these historical global values may differ.
        rows = {pid: dict(process('Running' if pid < 4 else 'Exited'), pid=pid, free_pages=40)
                for pid in range(1, 5)}
        history = {4: copy.deepcopy(rows[4])}
        subject.process_reclaimed(history[4], 'Exited', 0)
        for pid in (3, 2, 1):
            rows[pid].update(state='Killed', code=137)
            for row in rows.values():
                row['free_pages'] = 64 - 8 * (pid - 1)
            subject.process_reclaimed(rows[pid], 'Killed', 137)
            self.assertEqual(subject.global_arena(rows)['free_pages'], 64 - 8 * (pid - 1))
            history[pid] = copy.deepcopy(rows[pid])
        self.assertEqual([history[pid]['free_pages'] for pid in (4, 3, 2, 1)], [40, 48, 56, 64])
        with self.assertRaisesRegex(ValueError, 'Contradictory global arena'):
            subject.global_arena(history, required_pids={1, 2, 3, 4})
        final = subject.global_arena(rows, required_pids={1, 2, 3, 4})
        self.assertEqual(final['active_pids'], [])
        self.assertEqual(final['free_pages'], 64)
        for absent in rows:
            changed = {pid: row for pid, row in rows.items() if pid != absent}
            with self.subTest(absent=absent), self.assertRaisesRegex(ValueError, 'Missing process'):
                subject.global_arena(changed, required_pids={1, 2, 3, 4})
        for row in rows.values():
            row['free_pages'] = 56  # All PIDs terminal but one grant leaked.
        with self.assertRaisesRegex(ValueError, 'Global arena grants'):
            subject.global_arena(rows)

    def test_empty_list_cannot_substitute_for_final_arena_recovery(self):
        with self.assertRaisesRegex(ValueError, 'Missing or oversized process arena snapshot'):
            subject.global_arena({})
        with self.assertRaisesRegex(ValueError, 'Missing process snapshot'):
            subject.active_processes(ProcessSnapshotBoundaries().console(
                ProcessSnapshotBoundaries.EMPTY), set(), set())


class CommandBoundaries(unittest.TestCase):
    # Actual capture-v3 command span: offset 110669, 1586 bytes, SHA256
    # 766463ea209702af5ba82c790b3b1e5f6cf2bdd3a18cc3ac3188a2d945089205.
    ACTUAL_V3 = (
        b"\x1b[2m2026-11-16T18:08:03.000000Z\x1b[0m \x1b[31mERROR\x1b[0m \x1b[2mcosmic_settings_config::shortcuts\x1b[0m\x1b[2m:\x1b[0m shortcuts custom config error: GetKey(\"custom\", Os { code: 2, kind: NotFound, message: \"No such file or directory\" })\n"
        b"posix list\r\n"
        b"EL0 UserStatus { pid: 1, parent_pid: 0, exit_signal: 0, state: Waiting, code: 0, syscalls: 211, preemptions: 51, ai_slices: 262, cpu_model: 12290, last_slice_ms: 1, esr: 0, far: 0, free_pages: 48, rank_model: 12289, ai_selections: 261, guard_selections: 1, thread_count: 1, thread_peak: 1, thread_memory_model: 0, thread_admissions: 0, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 261, thread_guard_selections: 1, ipc_sent: 0, ipc_received: 0, waits: 7, wakeups: 6, heap_pages: 11, heap_free: 16373, heap_model: 8199, heap_peak: 13, heap_allocations: 10, heap_peak_allocations: 11, heap_largest_free: 16371, image_pages: 629, image_free: 15755 }\r\n"
        b"EL0 UserStatus { pid: 3, parent_pid: 0, exit_signal: 0, state: Running, code: 0, syscalls: 279, preemptions: 48, ai_slices: 327, cpu_model: 12290, last_slice_ms: 1, esr: 0, far: 0, free_pages: 48, rank_model: 12289, ai_selections: 327, guard_selections: 0, thread_count: 4, thread_peak: 4, thread_memory_model: 8193, thread_admissions: 3, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 327, thread_guard_selections: 0, ipc_sent: 0, ipc_received: 0, waits: 5, wakeups: 2, heap_pages: 1606, heap_free: 14778, heap_model: 8199, heap_peak: 1606, heap_allocations: 34, heap_peak_allocations: 34, heap_largest_free: 14768, image_pages: 9069, image_free: 7315 }\r\n"
        b"cyxia:/> "
    )

    # Actual capture-v11 span at serial offset 151827: an asynchronous
    # logging line surrounds the complete echo/response/prompt. Preserve
    # all 2543 bytes, including the later real EGL diagnostics.
    ACTUAL_V11 = (
        b'\x1b[2m2026-11-16T19:31:16.000000Z\x1b[0m \x1b[31mERROR\x1b[0m \x1b[2mcosmic_settings_config::shortcuts\x1b[0m\x1b[2m:\x1b[0m shortcuts custom config error: GetKey("custom", Os { code: 2, kind: NotFound, message: "Noposix list\r\n'
        b'EL0 UserStatus { pid: 1, parent_pid: 0, exit_signal: 0, state: Waiting, code: 0, syscalls: 211, observed_tid: 1, observed_pc: 17224220, observed_sp: 169866904, observed_syscall: 281, space_rebuilds: 305, space_prepare_ns: 216576020, space_retire_ns: 25640170, preemptions: 66, ai_slices: 277, cpu_model: 12290, last_slice_ms: 1, esr: 0, far: 0, free_pages: 48, rank_model: 12289, ai_selections: 276, guard_selections: 1, thread_count: 1, thread_peak: 1, thread_memory_model: 0, thread_admissions: 0, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 276, thread_guard_selections: 1, ipc_sent: 0, ipc_received: 0, waits: 6, wakeups: 5, heap_pages: 11, heap_free: 16373, heap_model: 8199, heap_peak: 13, heap_allocations: 10, heap_peak_allocations: 11, heap_largest_free: 16371, image_pages: 629, image_free: 15755 }\r\n'
        b'EL0 UserStatus { pid: 3, parent_pid: 0, exit_signal: 0, state: Running, code: 0, syscalls: 262, observed_tid: 3, observed_pc: 47236572, observed_sp: 169841336, observed_syscall: 1, space_rebuilds: 452, space_prepare_ns: 4685568610, space_retire_ns: 481881180, preemptions: 174, ai_slices: 436, cpu_model: 12290, last_slice_ms: 1, esr: 0, far: 0, free_pages: 48, rank_model: 12289, ai_selections: 435, guard_selections: 1, thread_count: 3, thread_peak: 3, thread_memory_model: 8193, thread_admissions: 2, thread_denials: 0, thread_rank_model: 12289, thread_ai_selections: 435, thread_guard_selections: 1, ipc_sent: 0, ipc_received: 0, waits: 4, wakeups: 2, heap_pages: 1090, heap_free: 15294, heap_model: 8199, heap_peak: 1100, heap_allocations: 32, heap_peak_allocations: 34, heap_largest_free: 15283, image_pages: 9069, image_free: 7315 }\r\n'
        b'cyxia:/>  such file or directory" })\n'
        b'UNIX_ADMISSION AI_DIRECT model=8193 committed=true\n'
        b'UNIX_ADMISSION AI_DIRECT model=8193 committed=true\n'
        b'UNIX_ADMISSION AI_DIRECT model=8193 committed=true\n'
        b'\x1b[2m2026-11-16T19:31:38.000000Z\x1b[0m \x1b[31mERROR\x1b[0m \x1b[2msmithay::backend::egl::ffi\x1b[0m\x1b[2m:\x1b[0m [EGL] 0x3001 (NOT_INITIALIZED) eglInitialize: DRI2: failed to load driver\n'
        b'\x1b[2m2026-11-16T19:31:38.000000Z\x1b[0m \x1b[31mERROR\x1b[0m \x1b[2msmithay::backend::egl::ffi\x1b[0m\x1b[2m:\x1b[0m [EGL] 0x3001 (NOT_INITIALIZED) eglInitialize: DRI2: failed to load driver\n'
        b'\x1b[2m2026-11-16T19:31:40.000000Z\x1b[0m \x1b[33m WARN\x1b[0m \x1b[2msmithay::backend::egl::display\x1b[0m\x1b[2m:\x1b[0m Dmabuf import extension not available\n'
    )

    @contextlib.contextmanager
    def replay(self, response):
        # Replay recorded bytes through the real Console methods. No guest,
        # service, compiler or VM runs; only the waiting timeout is shortened.
        class Channel:
            def __init__(self):
                self.pending = None
                self.sent = []

            def setblocking(self, value):
                pass

            def sendall(self, value):
                self.sent.append(value)
                self.pending = response

            def recv(self, size):
                if self.pending is None:
                    raise BlockingIOError()
                data, self.pending = self.pending, None
                return data

        class QuickConsole(subject.Console):
            def until(self, pattern, start=0, timeout=30):
                return super().until(pattern, start, min(timeout, .01))

        with tempfile.TemporaryDirectory() as directory:
            channel = Channel()
            console = QuickConsole(channel, SimpleNamespace(poll=lambda: None),
                                   Path(directory), time.monotonic() + 5)
            console.raw.extend(b'cyxia:/> ')
            console.capture_path.write_bytes(console.raw)
            yield console, channel

    def test_actual_interleaved_echo_is_fresh_complete_and_preserves_all_raw_bytes(self):
        self.assertEqual(len(self.ACTUAL_V11), 2543)
        self.assertEqual(hashlib.sha256(self.ACTUAL_V11).hexdigest(),
                         'f86d28c2c333dbcc5a249324cf340cee599920b56efe2568deffa69743f68249')
        self.assertIn(b'message: "Noposix list\r\n', self.ACTUAL_V11)
        with self.replay(self.ACTUAL_V11) as (console, channel):
            rows = subject.active_processes(console, {1, 3}, {1, 3})
            self.assertEqual(rows[1]['state'], 'Waiting')
            self.assertEqual(rows[3]['state'], 'Running')
            self.assertEqual(rows[3]['observed_pc'], 47236572)
            self.assertEqual(subject.global_arena(rows)['free_pages'], 48)
            self.assertEqual(channel.sent, [b'posix list\r'])
            self.assertEqual(console.commands, [{'command': 'posix list', 'serial_offset': 9}])
            self.assertEqual(bytes(console.raw), b'cyxia:/> ' + self.ACTUAL_V11)
            self.assertEqual(console.capture_path.read_bytes(), bytes(console.raw))
        # Complete status rows and a prompt cannot substitute for our exact echo.
        changed = self.ACTUAL_V11.replace(b'posix list\r\n', b'posix list extra\r\n', 1)
        with self.replay(changed) as (console, _):
            with self.assertRaises(TimeoutError):
                console.command('posix list')

    def test_actual_ansi_background_error_does_not_fail_a_successful_command(self):
        with self.replay(self.ACTUAL_V3) as (console, _):
            with self.assertRaisesRegex(ValueError, 'command failed'):
                subject.os_smoke.Console.command(console, 'posix list')
        with self.replay(self.ACTUAL_V3) as (console, channel):
            rows = subject.active_processes(console, {1, 3}, {1, 3})
            self.assertEqual(rows[1]['state'], 'Waiting')
            self.assertEqual(rows[3]['thread_count'], 4)
            self.assertEqual(subject.global_arena(rows)['free_pages'], 48)
            self.assertEqual(channel.sent, [b'posix list\r'])
            self.assertEqual(console.commands, [{'command': 'posix list', 'serial_offset': 9}])
            self.assertEqual(bytes(console.raw), b'cyxia:/> ' + self.ACTUAL_V3)
            self.assertEqual(console.capture_path.read_bytes(), bytes(console.raw))
        tracing = self.ACTUAL_V3.split(b'\n', 1)[0] + b'\n'
        for ending in (b'\r\n', b'\n'):
            for prefix in (b'', b'cyxia:/> '):
                response = prefix + b'posix list' + ending + tracing + b'cyxia:/> '
                with self.subTest(ending=ending, prefix=prefix), self.replay(response) as (console, _):
                    self.assertEqual(console.command('posix list'), 9)

    def test_every_shell_error_and_kernel_failure_format_is_rejected(self):
        shell = (
            b'error: damaged input; command discarded',
            b'error: line too long; command discarded',
            b'error: invalid UTF-8', b'error: Capacity', b'error: NotFound',
            b'error: invalid arguments; type help', b'error: user request busy',
            b'error: storage request busy', b'error: user process busy',
            b'error: unknown command; type help',
        )
        kernel = (
            b'ELF start failed: Nomem',
            b'ELF cosmic-comp start failed: ported feature unavailable',
            b'USER start failed: Again', b'EL0 start failed: Again',
            b'USER pair failed: Again', b'EL0 pair failed: Again',
            b'USER kill failed: Noent', b'EL0 kill failed: Noent',
        )
        for failure in shell + kernel:
            for prefix in (b'', b'cyxia:/> '):
                response = b'posix list\r\n' + prefix + failure + b'\r\ncyxia:/> '
                with self.subTest(failure=failure, prefix=prefix), self.replay(response) as (console, _):
                    with self.assertRaises(ValueError):
                        console.command('posix list')

    def test_missing_echo_or_complete_prompt_cannot_finish_command(self):
        for response in (
            b'cyxia:/> ', b'posix status\r\ncyxia:/> ',
            b'posix list\r\n', b'posix list\r\ncyxia:/>',
            b'posix list\r\ntracing quotes cyxia:/> ',
            b'cyxia:/> \nbackground\nposix list\r\n',
            b'error: damaged input; command discarded\r\ncyxia:/> ',
        ):
            with self.subTest(response=response), self.replay(response) as (console, _):
                with self.assertRaises(TimeoutError):
                    console.command('posix list')

    def test_expected_markers_must_follow_this_command_echo(self):
        echo = b'posix list\r\n'
        prompt = b'cyxia:/> '
        for response in (echo + b'EXPECTED_OK\n' + prompt,
                         echo + prompt + b'\r\nEXPECTED_OK\r\n'):
            with self.replay(response) as (console, _):
                self.assertEqual(console.command('posix list', [rb'EXPECTED_OK']), 9)
        for response in (b'EXPECTED_OK\n' + echo + prompt, echo + prompt):
            with self.subTest(response=response), self.replay(response) as (console, _):
                with self.assertRaises(TimeoutError):
                    console.command('posix list', [rb'EXPECTED_OK'])

    def test_failed_or_missing_async_launch_and_kill_cannot_pass(self):
        launch = b'posix exec cosmic-comp\r\nEL0 request queued\r\ncyxia:/> '
        with self.replay(launch + b'\r\nELF start failed: Nomem\r\n') as (console, _):
            with self.assertRaises(ValueError):
                subject.launch(console, 'cosmic-comp', {'required_pages': 9069})
        with self.replay(launch) as (console, _):
            with self.assertRaises(TimeoutError):
                subject.launch(console, 'cosmic-comp', {'required_pages': 9069})
        with self.replay(b'posix kill 3\r\ncyxia:/> \r\nUSER kill failed: Noent\r\n') as (console, _):
            with self.assertRaisesRegex(ValueError, 'command failed'):
                console.command('posix kill 3', [rb'pid=3 killed; pages reclaimed'])


class RuntimeBoundaries(unittest.TestCase):
    def test_actual_owner_info_notify_close_order_is_separate_from_rendering(self):
        value = subject.protocol_markers(protocol(), 31, 32, complete=True)
        self.assertEqual((value['service_pid'], value['client_pid'], value['id']), (31, 32, 7))
        self.assertIs(value['render_verified'], False)
        self.assertNotIn('cosmic_session_verified', value)
        self.assertEqual(len(value['markers']), 6)

    def test_protocol_rejects_wrong_pid_identity_id_close_reason_and_duplicate_success(self):
        original = protocol()
        cases = [original.replace(b'service_pid=31', b'service_pid=33'),
                 original.replace(b'client_pid=32', b'client_pid=31'),
                 original.replace(b'name=cosmic-notifications', b'name=fake-server'),
                 original.replace(b'version=1.10.0', b'version=1.11.0'),
                 original.replace(b'CLOSED id=7', b'CLOSED id=8'),
                 original.replace(b'reason=3', b'reason=2'),
                 original.replace(b'capture_ms=5000', b'capture_ms=100'),
                 original.replace(b'render_verified=false', b'render_verified=true'),
                 original + original.splitlines()[-1] + b'\n',
                 original.replace(b'INFO PASS', b'INFO FAIL'),
                 protocol(number=0)]
        lines = original.splitlines(keepends=True)
        cases.append(b''.join([lines[0], lines[2], lines[1], *lines[3:]]))
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                subject.protocol_markers(raw, 31, 32, complete=True)

    def test_created_window_requires_owner_and_info_and_refuses_already_closed(self):
        raw = b''.join(protocol().splitlines(keepends=True)[:4])
        self.assertEqual(subject.protocol_markers(raw, 31, 32, complete=False)['id'], 7)
        for changed in (protocol(), b'\n'.join(raw.splitlines()[1:]), raw.replace(b'INFO PASS', b'INFO WAIT')):
            with self.assertRaises(ValueError):
                subject.protocol_markers(changed, 31, 32, complete=False)

    def test_display_uses_real_completion_and_exact_owner(self):
        before = subject.system_snapshot(snapshot())
        after = subject.system_snapshot(snapshot(12, 30))
        result = subject.completed_scanout(before, after, 30)
        self.assertEqual(result['completed_delta'], 12)
        self.assertIs(result['semantic_ui_verified'], False)

    def test_admission_history_cannot_substitute_for_completed_transfer(self):
        before = subject.system_snapshot(snapshot(12, 30))
        after = copy.deepcopy(before)
        after['display_receipt']['observed_completed'] = 255
        after['display_receipt']['id'] = 100
        with self.assertRaisesRegex(ValueError, 'No completed'):
            subject.completed_scanout(before, after, 30)

    def test_display_foreign_owner_pending_submission_or_mechanism_failure_cannot_pass(self):
        before = subject.system_snapshot(snapshot())
        for area, key, value in [('display_receipt', 'owner', 29), ('display_receipt', 'outcome', 'Admitted'),
                                  ('display_receipt', 'phase', 'Submitted'), ('display', 'phase', 'Queued'),
                                  ('display', 'failed', 1), ('display', 'policy_invalid', 1),
                                  ('display', 'clock_rejected', 1), ('display', 'submitted', 0)]:
            after = subject.system_snapshot(snapshot(12, 30))
            after[area][key] = value
            with self.subTest(area=area, key=key), self.assertRaises(ValueError):
                subject.completed_scanout(before, after, 30)

    def test_observed_snapshots_must_be_single_complete_unambiguous_records(self):
        original = snapshot()
        for raw in (original + original, original.replace(b'AI_SYSTEM_END\n', b''),
                    original.replace(b'free=32', b'free=32 free=0'),
                    original.replace(b'ANON_POOL ', b'UNKNOWN_POOL ')):
            with self.assertRaises(ValueError):
                subject.system_snapshot(raw)

    def test_all_owned_resources_return_to_baseline_while_peak_is_historical(self):
        before = subject.system_snapshot(snapshot())
        after = subject.system_snapshot(snapshot(50, 30))
        after['anon']['peak'] = 1000
        subject.reclaimed(before, after)
        for name, key, value in [('ofd', 'references', 1), ('ancillary', 'inflight_refs', 1),
                                  ('shared', 'grant_reserved', 1), ('shared', 'pages', 1),
                                  ('pipe', 'unavailable', 1), ('anon', 'used', 1), ('anon', 'free', 65535),
                                  ('display', 'phase', 'Submitted'), ('display', 'failed', 1)]:
            changed = copy.deepcopy(after)
            changed[name][key] = value
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                subject.reclaimed(before, changed)

    def test_process_exit_or_kernel_kill_requires_threads_images_and_heap_released(self):
        subject.process_reclaimed(process(), 'Exited', 0)
        subject.process_reclaimed(process('Killed', 137), 'Killed', 137)
        for key in ('heap_pages', 'image_pages', 'thread_count', 'heap_free',
                    'heap_allocations', 'heap_largest_free', 'image_free', 'code'):
            changed = process()
            changed[key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.process_reclaimed(changed, 'Exited', 0)

    def test_raw_pixel_difference_remains_candidate_and_never_text_or_ui_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            colors = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0),
                      (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0)]
            data = bytearray(b''.join(bytes(color) * 128 for color in colors) * 768)
            header = b'P6\n1024 768\n255\n'
            first, second = root / 'boot.ppm', root / 'changed.ppm'
            first.write_bytes(header + data)
            self.assertTrue(subject.frame_metadata(first)['boot_colorbars'])
            for x, y in ((25, 20), (30, 22)):
                offset = (y * 1024 + x) * 3
                data[offset:offset + 3] = b'\x12\x34\x56'
            second.write_bytes(header + data)
            result = subject.frame_metadata(second, first)
            self.assertEqual(result['changed_pixels'], 2)
            self.assertEqual(result['changed_bounds_xyxy'], [25, 20, 30, 22])
            self.assertFalse(result['boot_colorbars'])
            self.assertIs(result['text_verified'], False)
            self.assertIs(result['notification_render_verified'], False)

    def test_incomplete_or_foreign_framebuffer_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'invalid.ppm'
            for data in (b'P6\n1024 768\n255\n', b'P6\n1 1\n255\nabc', b'P3\n1024 768\n255\n'):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    subject.frame_metadata(path)

    def test_wayland_trace_is_recorded_without_claiming_that_buffers_contain_text(self):
        raw = (b'[12.0] -> zwlr_layer_shell_v1#3.get_layer_surface(new id zwlr_layer_surface_v1#4)\n'
               b'[12.1] -> wl_surface@5.attach(wl_buffer@6, 0, 0)\n'
               b'[12.2] -> wl_surface#5.commit()\n'
               b'[12.4] wl_callback@8.done(123)\n')
        value = subject.wayland_observations(raw)
        self.assertEqual([value[key] for key in ('layer_surface', 'surface_attach', 'surface_commit', 'callback_done')],
                         [1, 1, 1, 1])
        self.assertIs(value['notification_render_verified'], False)

    def test_nine_exact_fonts_and_full_licenses_are_bound_to_pinned_git_and_curated_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = FontFixture(Path(directory))
            result = fixture.validate()
            self.assertEqual(len(result['files']), 9)
            self.assertIs(result['guest_font_loading_observed'], False)
            self.assertEqual(result['receipt'], subject.identity(fixture.receipt))

    def test_font_bad_pin_missing_license_wrong_blob_permissions_or_replacement_is_rejected(self):
        for mutation in ('pin', 'license', 'git_blob', 'mode', 'installed_mode', 'installed_bytes', 'source_bytes', 'extra'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                fixture = FontFixture(Path(directory))
                guest = next(iter(fixture.files))
                row = fixture.files[guest]
                if mutation == 'pin': fixture.report['source']['commit'] = '0' * 40
                elif mutation == 'license': del fixture.files['/usr/share/licenses/cosmic-fonts/OpenSans-LICENSE']
                elif mutation == 'git_blob': row['git_blob'] = '0' * 40
                elif mutation == 'mode': row['mode'] = '120000'
                elif mutation == 'installed_mode': (fixture.prefix / 'rootfs' / guest.lstrip('/')).chmod(0o755)
                elif mutation == 'installed_bytes': (fixture.prefix / 'rootfs' / guest.lstrip('/')).write_bytes(b'changed')
                elif mutation == 'source_bytes': Path(row['source']).write_bytes(b'changed')
                else: fixture.files['/usr/share/fonts/fake.ttf'] = dict(row)
                fixture.save()
                with self.assertRaises(ValueError):
                    fixture.validate()

    def test_output_must_not_replace_evidence_or_modify_read_only_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / 'sdk'; sdk.mkdir()
            for output in (sdk, sdk / 'capture', root, subject.ROOT / 'tools/unwanted-capture'):
                with self.assertRaises(ValueError):
                    subject.fresh_output(output, [sdk])
            self.assertEqual(subject.fresh_output(root / 'capture', [sdk]), root / 'capture')
            alias = root / 'alias'; alias.symlink_to(sdk, target_is_directory=True)
            with self.assertRaises(subject.probe_builder.CosmicBuildError):
                subject.fresh_output(alias / 'capture', [sdk])

    def test_pre_vm_validator_failure_retains_failed_summary_and_cannot_spawn_qemu(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('build', 'dbus', 'comp', 'notify', 'probe', 'sdk', 'catalog', 'fonts', 'qemu-data', 'modules'):
                (root / name).mkdir()
            (root / 'build/build-manifest.json').write_text(json.dumps({'sysroot': str(root / 'catalog')}))
            for name, receipt in (('dbus', 'dbus-build-report.json'), ('comp', 'build-report.json'),
                                   ('notify', 'build-report.json'), ('probe', 'build-report.json')):
                (root / name / receipt).write_text(json.dumps({'sysroot': str(root / 'sdk')}))
            (root / 'catalog/cosmic-font-assets.json').write_text(json.dumps({'source': {'checkout': str(root / 'fonts')}}))
            args = SimpleNamespace(build=root / 'build', dbus_build=root / 'dbus', compositor_build=root / 'comp',
                                   notifications_build=root / 'notify', probe_build=root / 'probe', output=root / 'capture',
                                   qemu_data=root / 'qemu-data', qemu_module_dir=root / 'modules', native_lock=root / 'lease')
            with patch.object(subject, 'native_lease', side_effect=lambda path: contextlib.nullcontext()), \
                    patch.object(subject, 'idle_native_host'), \
                    patch.object(subject, 'validate_inputs', side_effect=ValueError('actual source identity rejected')), \
                    patch.object(subject.subprocess, 'Popen') as spawn:
                result = subject.capture(args)
            spawn.assert_not_called()
            self.assertEqual(result['status'], 'FAIL')
            self.assertIn('source identity rejected', result['error'])
            saved = json.loads((args.output / 'summary.json').read_text())
            self.assertEqual(saved['status'], 'FAIL')
            self.assertIs(saved['notification_protocol_verified'], False)
            self.assertIs(saved['notification_render_verified'], False)
            self.assertEqual((args.output / 'serial.raw').read_bytes(), b'')

    def test_independent_compositor_cargo_cache_cannot_receive_capture_or_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('build', 'dbus', 'comp', 'notify', 'probe', 'sdk', 'catalog', 'fonts', 'qemu-data',
                         'modules', 'private-comp-cache'):
                (root / name).mkdir()
            (root / 'build/build-manifest.json').write_text(json.dumps({'sysroot': str(root / 'catalog')}))
            for name, receipt in (('dbus', 'dbus-build-report.json'), ('comp', 'build-report.json'),
                                   ('notify', 'build-report.json'), ('probe', 'build-report.json')):
                record = {'sysroot': str(root / 'sdk')}
                if name == 'comp':
                    record['cargo_cache'] = str(root / 'private-comp-cache')
                (root / name / receipt).write_text(json.dumps(record))
            (root / 'catalog/cosmic-font-assets.json').write_text(json.dumps({'source': {'checkout': str(root / 'fonts')}}))
            args = SimpleNamespace(build=root / 'build', dbus_build=root / 'dbus', compositor_build=root / 'comp',
                                   notifications_build=root / 'notify', probe_build=root / 'probe',
                                   qemu_data=root / 'qemu-data', qemu_module_dir=root / 'modules')
            for choice in ('output', 'native_lock'):
                args.output, args.native_lock = root / 'capture', root / 'lease'
                setattr(args, choice, root / 'private-comp-cache/new-file')
                with self.subTest(choice=choice), \
                        patch.object(subject, 'native_lease') as lease, \
                        patch.object(subject, 'validate_inputs') as validator, \
                        patch.object(subject.subprocess, 'Popen') as native:
                    with self.assertRaisesRegex(ValueError, 'read-only input'):
                        subject.capture(args)
                    lease.assert_not_called()
                    validator.assert_not_called()
                    native.assert_not_called()
                self.assertFalse((root / 'capture').exists())
                self.assertEqual(list((root / 'private-comp-cache').iterdir()), [])

    def test_real_host_fifo_distinguishes_startup_idle_peer_loss_and_final_eof(self):
        # Real named-pipe I/O, but no process, emulator, compiler or guest.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            channel = subject.PipeChannel(root / 'serial', time.monotonic() + 10)
            process = SimpleNamespace(returncode=None)
            process.poll = lambda: process.returncode
            channel.process = process
            channel.setblocking(False)
            writer = None
            try:
                with self.assertRaises(BlockingIOError):
                    channel.recv(100)  # QEMU has not connected its writer yet.
                writer = os.open(str(channel.path) + '.out', os.O_WRONLY | os.O_NONBLOCK)
                os.write(writer, b'HOST FIFO FIXTURE\n')
                self.assertEqual(channel.recv(100), b'HOST FIFO FIXTURE\n')
                with self.assertRaises(BlockingIOError):
                    channel.recv(100)  # Real connected but idle writer.
                os.close(writer)
                writer = None
                with self.assertRaisesRegex(ConnectionError, 'disconnected'):
                    channel.recv(100)  # Cannot turn a real peer loss into idle.
                process.returncode = 0
                self.assertEqual(channel.recv(100), b'')  # Normal final drain.
            finally:
                if writer is not None:
                    os.close(writer)
                channel.close()


class LateFrameObservationBoundaries(unittest.TestCase):
    """Controlled host clocks/I/O only; these are not guest or timing evidence."""

    def frame_window(self, root, *, observe=True, available=60, global_deadline=240,
                     command_delay=0, frame_delay=0, bad_frame=False, error=None, block_command=False,
                     fail_milestone=False):
        clock = SimpleNamespace(now=0.0)
        console = subject.Console.__new__(subject.Console)
        console.deadline, console.sock = global_deadline, SimpleNamespace(deadline=global_deadline)
        console.raw, console.commands = bytearray(b'preserved partial background UART'), []
        console.pump = lambda: subject.require(clock.now < console.deadline, 'fixture wait deadline')
        qmp = SimpleNamespace(sock=SimpleNamespace(deadline=global_deadline + 8),
                              observation_deadline=None, calls=[])
        colors = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0),
                  (255, 0, 255), (255, 0, 0), (0, 0, 255), (0, 0, 0)]
        boot = b'P6\n1024 768\n255\n' + b''.join(bytes(color) * 128 for color in colors) * 768
        (root / 'boot.ppm').write_bytes(boot)

        def execute(command, args):
            self.assertEqual(command, 'screendump')
            qmp.calls.append((console.deadline, console.sock.deadline, qmp.sock.deadline,
                              qmp.observation_deadline))
            Path(args['filename']).write_bytes(boot if bad_frame else boot[:-3] + b'\x12\x34\x56')
            clock.now += frame_delay

        qmp.execute = execute

        def observation(_):
            clock.now += command_delay
            if error is not None:
                raise error
            return subject.system_snapshot(snapshot(1, 3) if clock.now >= available else snapshot())

        def active(*_):
            if block_command:
                clock.now = 119  # A first-loop command is still waiting near the absolute cap.
                console.until(b'never emitted by this host fixture', timeout=30)

        result = {'frames': [], 'observe_after_frame_deadline': observe, 'first_frame_deadline_failed': False}
        caught = None
        with patch.object(subject.time, 'monotonic', side_effect=lambda: clock.now), \
                patch.object(subject.time, 'sleep', side_effect=lambda seconds: setattr(clock, 'now', clock.now + seconds)), \
                patch.object(subject, 'active_processes', side_effect=active), \
                patch.object(subject, 'system', side_effect=observation), \
                patch.object(subject, 'write_json', wraps=subject.write_json,
                             side_effect=OSError('host milestone write failure') if fail_milestone else None):
            try:
                subject.await_compositor_frame(console, qmp, root, subject.system_snapshot(snapshot()), 1, 3, result)
            except (ValueError, TimeoutError) as failure:
                caught = failure
        self.assertEqual((console.deadline, console.sock.deadline, qmp.sock.deadline, qmp.observation_deadline),
                         (global_deadline, global_deadline, global_deadline + 8, None))
        self.assertEqual(console.raw, b'preserved partial background UART')
        return result, clock, qmp, caught

    def test_default_stops_at_original_gate_but_explicit_late_frame_keeps_failure(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result, clock, qmp, error = self.frame_window(root, observe=enabled)
                if not enabled:
                    self.assertIsInstance(error, ValueError)
                    self.assertEqual(clock.now, 45)
                    self.assertFalse(result['first_frame_deadline_failed'])
                    self.assertFalse((root / 'first-frame-deadline-failure.json').exists())
                    self.assertEqual(qmp.calls, [])
                else:
                    self.assertIsNone(error)
                    self.assertEqual(clock.now, 60)
                    self.assertTrue(result['first_frame_deadline_failed'])
                    self.assertEqual(subject.document(root / 'first-frame-deadline-failure.json'),
                                     result['first_frame_deadline_failure'])
                    self.assertEqual(result['first_frame_deadline_failure']['status'], 'FAIL')
                    self.assertEqual(qmp.calls, [(120, 120, 120, 120)])
                    self.assertEqual(result['compositor_scanout']['completion']['receipt']['owner'], 3)
                    self.assertEqual(result['compositor_scanout']['frame']['changed_pixels'], 1)
                    self.assertFalse(result['compositor_scanout']['semantic_ui_verified'])

    def test_commands_or_screenshots_crossing_45_are_late_without_duplicate_frames(self):
        for command_delay, frame_delay in ((46, 0), (0, 46)):
            with self.subTest(command_delay=command_delay, frame_delay=frame_delay), tempfile.TemporaryDirectory() as directory:
                result, _, qmp, error = self.frame_window(Path(directory), available=0,
                                                        command_delay=command_delay, frame_delay=frame_delay)
                self.assertIsNone(error)
                self.assertTrue(result['first_frame_deadline_failed'])
                self.assertEqual(len(qmp.calls), 1)
                self.assertEqual(len(result['frames']), 1)
                self.assertEqual(result['compositor_scanout']['frame']['file'], 'compositor.ppm')

    def test_late_window_never_extends_global_limit_and_rejects_missing_or_invalid_frame(self):
        for global_deadline, expected_stop in ((240, 120), (60, 60)):
            with self.subTest(global_deadline=global_deadline), tempfile.TemporaryDirectory() as directory:
                result, clock, qmp, error = self.frame_window(Path(directory), available=999,
                                                            global_deadline=global_deadline)
                self.assertIsInstance(error, ValueError)
                self.assertEqual(clock.now, expected_stop)
                self.assertTrue(result['first_frame_deadline_failed'])
                self.assertNotIn('compositor_scanout', result)
                self.assertEqual(qmp.calls, [])
        for change in ({'bad_frame': True}, {'available': 119, 'frame_delay': 2},
                       {'error': ValueError('real command/fatal/process failure')},
                       {'error': ValueError('original command failure after 45s'), 'command_delay': 46},
                       {'error': ValueError('original survives milestone write failure'),
                        'command_delay': 46, 'fail_milestone': True},
                       {'block_command': True}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                result, clock, _, error = self.frame_window(Path(directory), **change)
                self.assertIsInstance(error, ValueError)
                self.assertNotIn('compositor_scanout', result)
                self.assertEqual(result['first_frame_deadline_failed'],
                                 'error' not in change or change.get('command_delay', 0) >= 45)
                if 'error' in change:
                    self.assertIs(error, change['error'])
                if change.get('fail_milestone'):
                    self.assertIn('host milestone write failure', result['first_frame_deadline_milestone_error'])
                if change.get('block_command'):
                    self.assertLess(clock.now, 120.01)

    def test_qmp_real_receive_uses_earlier_cutoff_and_checks_already_pending_responses(self):
        clock = SimpleNamespace(now=119.0)
        channel = SimpleNamespace(timeout=0, sendall=lambda data: None)
        channel.settimeout = lambda value: setattr(channel, 'timeout', value)

        def timeout(_):
            clock.now += channel.timeout
            raise subject.socket.timeout('host fixture only')

        channel.recv = timeout
        qmp = subject.SessionQmp(channel)
        with patch.object(subject.time, 'monotonic', side_effect=lambda: clock.now):
            qmp.observation_deadline = 120
            with self.assertRaisesRegex(TimeoutError, 'QMP response timeout'):
                qmp.execute('screendump', {'filename': 'unused-host-fixture'})
            self.assertEqual(clock.now, 120)
            qmp.pending.append({'id': 1, 'return': {}})
            with self.assertRaisesRegex(ValueError, 'Late frame observation deadline'):
                qmp.receive(130)
            qmp.observation_deadline = None
            self.assertEqual(qmp.receive(130), {'id': 1, 'return': {}})

    def test_actual_capture_finalizer_keeps_late_failure_and_rechecks_final_inputs_and_frames(self):
        # Mock only the native/guest boundary. Execute the real capture finalizer,
        # protocol parser, file hashes, summary writer and exit-status decision.
        for mode in ('timely', 'late', 'changed-input', 'changed-frame', 'later-error'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ('build', 'dbus', 'comp', 'notify', 'probe', 'sdk', 'catalog', 'fonts', 'data', 'modules'):
                    (root / name).mkdir()
                (root / 'build/build-manifest.json').write_text(json.dumps({'sysroot': str(root / 'catalog')}))
                for name, receipt in (('dbus', 'dbus-build-report.json'), ('comp', 'build-report.json'),
                                      ('notify', 'build-report.json'), ('probe', 'build-report.json')):
                    (root / name / receipt).write_text(json.dumps({'sysroot': str(root / 'sdk')}))
                (root / 'catalog/cosmic-font-assets.json').write_text(json.dumps({'source': {'checkout': str(root / 'fonts')}}))
                (root / 'catalog/ported_catalog.rs').write_bytes(b'host catalog fixture, not compiled')
                (root / 'bios').write_bytes(b'host firmware fixture, not executable')
                args = SimpleNamespace(build=root / 'build', dbus_build=root / 'dbus', compositor_build=root / 'comp',
                                       notifications_build=root / 'notify', probe_build=root / 'probe', output=root / 'capture',
                                       qemu_data=root / 'data', qemu_module_dir=root / 'modules', native_lock=root / 'lease',
                                       bios=root / 'bios', observe_after_frame_deadline=mode != 'timely')
                inputs = {'catalog': {'path': str(root / 'catalog/ported_catalog.rs')}}
                machine = {'program': {'path': 'host-fixture-only'}, 'data_directory': str(root / 'data'),
                           'module_directory': str(root / 'modules')}
                raw = protocol()
                pumps = []

                class Channel:
                    def __init__(self, path, deadline): self.deadline = deadline
                    def connect(self, process): pass
                    def close(self): pass

                class GuestConsole:
                    def __init__(self, *args): self.raw, self.commands = bytearray(raw), []
                    def pump(self, *, require_running=True):
                        pumps.append(require_running)
                        if not require_running and mode == 'changed-frame':
                            (args.output / 'host-frame.ppm').write_bytes(b'changed')

                class Management:
                    def __init__(self, channel): self.transcript = []
                    def receive(self, deadline): return {'QMP': {}}
                    def execute(self, command):
                        self.transcript.append({'host_fixture_command': command})
                        return {}

                def session(console, qmp, output, values, result):
                    result.update(launched={'cosmic-notifications': 31, 'notification-probe': 32},
                                  probe_serial_start=0, protocol=subject.protocol_markers(raw, 31, 32, complete=True),
                                  notification_protocol_observed=True)
                    frame = output / 'host-frame.ppm'
                    frame.write_bytes(b'explicit finalizer byte fixture, not a guest framebuffer')
                    result['frames'].append({'file': frame.name, **subject.identity(frame)})
                    if mode != 'timely':
                        failure = {'status': 'FAIL', 'error': 'original 45s gate failed'}
                        result.update(first_frame_deadline_failed=True, first_frame_deadline_failure=failure)
                        subject.write_json(output / 'first-frame-deadline-failure.json', failure)
                    if mode == 'later-error':
                        raise ValueError('later real protocol error must survive')

                def disk(path):
                    path.write_bytes(b'explicit host disk fixture')
                    return path

                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(subject, 'native_lease', return_value=contextlib.nullcontext()))
                    stack.enter_context(patch.object(subject, 'idle_native_host'))
                    validator = stack.enter_context(patch.object(subject, 'validate_inputs', side_effect=[inputs,
                        {'changed': True} if mode == 'changed-input' else inputs]))
                    stack.enter_context(patch.object(subject, 'qemu_inputs', return_value=machine))
                    stack.enter_context(patch.object(subject.pc, 'version', return_value='host fixture only'))
                    stack.enter_context(patch.object(subject.pc, 'env', return_value={}))
                    stack.enter_context(patch.object(subject.os_x86, 'launch_argv', return_value=['fixture', '-serial', 'stdio']))
                    stack.enter_context(patch.object(subject, 'create_disk', side_effect=disk))
                    stack.enter_context(patch.object(subject, 'PipeChannel', Channel))
                    stack.enter_context(patch.object(subject, 'Console', GuestConsole))
                    stack.enter_context(patch.object(subject, 'SessionQmp', Management))
                    stack.enter_context(patch.object(subject, 'run_session', side_effect=session))
                    stack.enter_context(patch.object(subject.threading, 'Timer'))
                    spawn = stack.enter_context(patch.object(subject.subprocess, 'Popen'))
                    spawn.return_value.wait.return_value = 0
                    result = subject.capture(args)
                self.assertEqual(pumps, [True, False])
                self.assertEqual(validator.call_count, 1 if mode == 'later-error' else 2)
                self.assertEqual(result['status'], subject.SUCCESS if mode == 'timely' else 'FAIL')
                self.assertEqual(result['notification_protocol_verified'], mode == 'timely')
                self.assertEqual(result['late_observation_evidence_verified'], mode == 'late')
                self.assertTrue(result['notification_protocol_observed'])
                self.assertEqual(subject.document(args.output / 'summary.json'), result)
                if mode != 'timely':
                    self.assertEqual(result['first_frame_deadline_failure']['error'], 'original 45s gate failed')
                    if mode != 'late': self.assertNotEqual(result['error'], 'original 45s gate failed')
                with patch.object(subject, 'capture', return_value=result), patch('builtins.print'):
                    cli = sum(([f'--{name}', 'unused'] for name in ('build', 'dbus-build', 'compositor-build',
                              'notifications-build', 'probe-build', 'output', 'qemu', 'qemu-data', 'qemu-module-dir', 'bios')), [])
                    self.assertEqual(subject.main(cli), 0 if mode == 'timely' else 1)


if __name__ == '__main__':
    unittest.main()
