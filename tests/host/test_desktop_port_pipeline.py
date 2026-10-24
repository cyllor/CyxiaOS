"""Host-only orchestration tests. Synthetic receipts are NOT guest evidence."""
import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import port_smithay_dynamic as port

PYTHON = Path(sys.executable).resolve()
CARGO = Path('/not-installed/bin/cargo')


def checkout(root):
    root.mkdir()
    for name in ('Cargo.toml', 'Cargo.lock', 'kernel/build.rs', 'kernel/Cargo.toml',
                 'kernel/src/user/shared_memory.rs', 'crates/posix/src/epoll.rs'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('unit-test fixture; not buildable kernel\n')
    (root / '.gitignore').write_text('/artifacts/\n__pycache__/\n')
    for args in (['init', '-q'], ['add', '.'],
                 ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                  'commit', '-qm', 'synthetic source fixture']):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)


def synthetic_runtime(output, identities, iterations=3):
    """Exercise receipt validation only; never launch or imitate a guest process."""
    output.mkdir(parents=True)
    report = dict(status='PASS', smithay_dynamic_verified=True, full_cosmic_port=False,
                  cosmic_runtime_verified=False, iterations=iterations,
                  provenance={name + '_sha256': value for name, value in identities.items()}, runs=[])
    for number in range(1, iterations + 1):
        directory = output / f'run-{number}'
        directory.mkdir()
        evidence = {}
        for name in ('qmp.jsonl', 'host-commands.json', 'uart-input.jsonl'):
            path = directory / name
            path.write_text('SYNTHETIC HOST TEST FIXTURE\n')
            evidence[str(path)] = port.digest(path)
        witnesses = []
        for scene in [*range(12), 4]:
            name = f'scene-{scene}.ppm' if len(witnesses) < 12 else 'capacity.ppm'
            path = directory / name
            path.write_text(f'SYNTHETIC; NOT A SCREENSHOT; scene={scene}\n')
            evidence[str(path)] = port.digest(path)
            witnesses.append(dict(scene=scene, path=str(path), pixels=12288,
                                  sha256=port.digest(path), canvas_sha256=f'{scene:064x}'))
        report['runs'].append(dict(iteration=number,
            observations=dict(scenes=12, commits=8, pixels=147456, configures=7, acknowledgements=7,
                admitted_clients=3, capacity_rejections=1, reused_slots=1, stale_keys_rejected=1,
                graceful_closes=2, abrupt_disconnects=1, independently_launched_processes=5),
            qmp_observations=dict(scanouts=12, capacity_scanouts=1, input_commands=16),
            scanouts=witnesses[:12], capacity_scanout=witnesses[12], evidence_sha256=evidence))
    port.write_json(output / 'summary.json', report)
    return report


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / 'repo'
        checkout(self.root)
        self.config = port.Config(self.root, self.root / 'artifacts/new-run', self.base / 'cache',
                                  self.base / 'mesa-report.json', self.base / 'protocol.crate')
        self.identities = dict(kernel='a' * 64, server='b' * 64, client='c' * 64)

    def test_config_accepts_fresh_artifacts_or_external_directory(self):
        self.config.validate()
        replace(self.config, output=self.base / 'external').validate()

    def test_config_rejects_inadequate_boot_count_and_timeout(self):
        for field, values in (('iterations', [0, 1, 2, 6, True]), ('timeout', [0, -1, 7201, True])):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(port.PortError):
                    replace(self.config, **{field: value}).validate()

    def test_config_preserves_source_cache_and_input_locations(self):
        bad = [replace(self.config, output=self.root), replace(self.config, output=self.base),
               replace(self.config, output=self.root / 'tools/output'),
               replace(self.config, cache=self.config.output / 'cache'),
               replace(self.config, mesa_report=self.config.output / 'mesa.json'),
               replace(self.config, protocol_crate=self.config.output / 'protocol.crate'),
               replace(self.config, output=self.config.cache / 'output'),
               replace(self.config, output=Path('relative'))]
        for config in bad:
            with self.subTest(config=config), self.assertRaises(port.PortError):
                config.validate()

    def test_plan_binds_correct_images_and_preserves_pinned_builders(self):
        steps = port.commands(self.config, PYTHON, CARGO)
        self.assertEqual([s['name'] for s in steps], ['doctor', 'host-tests', 'rust-tests',
                         'rust-large-memory', 'server', 'client', 'kernel', 'runtime'])
        for step in steps:
            self.assertNotIn('--fetch', step['argv'])
            self.assertNotIn('-O', step['argv'])
        kernel = next(s for s in steps if s['name'] == 'kernel')
        self.assertEqual(kernel['environment'], dict(
            CYXIA_SMITHAY_DYNAMIC_PROBE_ELF=str(self.config.output / 'server/smithay-dynamic.elf'),
            CYXIA_SMITHAY_DYNAMIC_CLIENT_ELF=str(self.config.output / 'client/smithay-dynamic-client.elf')))
        self.assertIn('smithay-dynamic-probe', kernel['argv'])
        self.assertIn('--offline', kernel['argv'])
        self.assertEqual(steps[-1]['argv'][-2:], ['--iterations', '3'])
        fetched = port.commands(replace(self.config, fetch=True), PYTHON, CARGO)
        self.assertEqual([s['name'] for s in fetched if '--fetch' in s['argv']], ['server'])

    def test_plan_cli_has_no_execution_or_write_side_effects(self):
        args = ['--output', str(self.config.output), '--cache', str(self.config.cache),
                '--mesa-report', str(self.config.mesa_report), '--protocol-crate', str(self.config.protocol_crate), '--plan']
        text = io.StringIO()
        with patch.object(port, 'ROOT', self.root), patch.object(port.subprocess, 'Popen') as popen:
            with contextlib.redirect_stdout(text):
                self.assertEqual(port.main(args), 0)
            popen.assert_not_called()
        self.assertEqual(json.loads(text.getvalue())['status'], 'PLAN_ONLY')
        self.assertFalse(self.config.output.exists())

    def test_environment_cannot_override_images_or_disable_assertions(self):
        incoming = dict(PATH='/usr/bin', HOME='/home/test', CARGO_HOME='/custom',
            PYTHONOPTIMIZE='2', PYTHONPATH='/other', PYTHONHOME='/other', RUSTFLAGS='-Cdebug-assertions=no',
            CARGO_ENCODED_RUSTFLAGS='bad', CARGO_TARGET_DIR='/other', RUSTC_WRAPPER='/wrapper',
            CARGO_BUILD_RUSTC_WRAPPER='/wrapper', CARGO_PROFILE_RELEASE_LTO='off',
            CARGO_TARGET_AARCH64_UNKNOWN_NONE_SOFTFLOAT_LINKER='/other', CYXIA_CC='/other',
            CYXIA_PORTED_ELF='/old', CYXIA_SMITHAY_DYNAMIC_PROBE_ELF='/old')
        cleaned = port.clean_env(incoming, CARGO.parent)
        self.assertEqual(set(cleaned), {'PATH', 'HOME', 'CARGO_HOME', 'PYTHONDONTWRITEBYTECODE'})
        self.assertTrue(cleaned['PATH'].startswith(str(CARGO.parent) + os.pathsep))

    def test_manifest_includes_untracked_source_and_excludes_artifacts(self):
        path = self.root / 'tools/new.py'; path.parent.mkdir(); path.write_text('print(1)\n')
        artifact = self.root / 'artifacts/old.log'; artifact.parent.mkdir(); artifact.write_text('old')
        manifest = port.source_manifest(self.root)
        self.assertEqual(manifest['tools/new.py'], port.digest(path))
        self.assertNotIn('artifacts/old.log', manifest)

    def test_manifest_rejects_deleted_tracked_source(self):
        (self.root / 'Cargo.lock').unlink()
        with self.assertRaises(port.PortError):
            port.source_manifest(self.root)

    def test_manifest_rejects_symlinks(self):
        path = self.root / 'kernel/alias.rs'; path.symlink_to(self.root / 'Cargo.toml')
        with self.assertRaises(port.PortError):
            port.source_manifest(self.root)

    def test_unchanged_detects_modification_and_new_source(self):
        manifest = port.source_manifest(self.root)
        (self.root / 'kernel/new.rs').write_text('new')
        with self.assertRaisesRegex(port.PortError, 'kernel/new.rs'):
            port.unchanged(self.root, manifest)
        (self.root / 'kernel/new.rs').unlink()
        (self.root / 'Cargo.lock').write_text('changed')
        with self.assertRaisesRegex(port.PortError, 'Cargo.lock'):
            port.unchanged(self.root, manifest)

    def test_atomic_json_preserves_previous_on_serialization_failure(self):
        path = self.base / 'receipt.json'; port.write_json(path, {'old': True})
        with self.assertRaises(TypeError):
            port.write_json(path, {'bad': object()})
        self.assertEqual(port.read_json(path), {'old': True})
        self.assertEqual(list(self.base.glob('*.tmp')), [])

    def test_build_receipt_requires_status_path_and_hash(self):
        directory = self.base / 'build'; directory.mkdir()
        path = directory / 'server.elf'; path.write_bytes(b'test fixture')
        report = dict(status='cross-built', probe=dict(file=str(path), sha256=port.digest(path)))
        port.write_json(directory / 'build-report.json', report)
        self.assertEqual(port.built_program(directory, path.name, 'probe'), path)
        path.write_bytes(b'changed')
        with self.assertRaises(port.PortError):
            port.built_program(directory, path.name, 'probe')
        report['status'] = 'FAIL'; port.write_json(directory / 'build-report.json', report)
        with self.assertRaises(port.PortError):
            port.built_program(directory, path.name, 'probe')

    def test_runner_executes_foreground_process_and_hashes_log(self):
        log = self.base / 'run.log'
        result = port.Runner(self.root, dict(os.environ)).run(dict(name='test',
            argv=[str(PYTHON), '-c', 'print("actual subprocess")'], environment={}, timeout_seconds=5), log)
        self.assertEqual(log.read_text(), 'actual subprocess\n')
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(result['log_sha256'], port.digest(log))
        with self.assertRaises(FileExistsError):
            port.Runner(self.root, {}).run({}, log)

    def test_runner_preserves_failed_process_log(self):
        log = self.base / 'failure.log'
        with self.assertRaisesRegex(port.PortError, 'exit 7'):
            port.Runner(self.root, dict(os.environ)).run(dict(name='failed', environment={}, timeout_seconds=5,
                argv=[str(PYTHON), '-c', 'print("failed evidence"); raise SystemExit(7)']), log)
        self.assertIn('failed evidence', log.read_text())

    def test_runner_terminates_on_timeout(self):
        with self.assertRaisesRegex(port.PortError, 'timeout'):
            port.Runner(self.root, dict(os.environ)).run(dict(name='timeout', environment={}, timeout_seconds=.15,
                argv=[str(PYTHON), '-c', 'import time; time.sleep(10)']), self.base / 'timeout.log')

    def test_runner_rejects_log_over_budget_even_after_exit(self):
        with self.assertRaisesRegex(port.PortError, 'log budget'):
            port.Runner(self.root, dict(os.environ), log_limit=32).run(dict(name='large-log', environment={},
                timeout_seconds=5, argv=[str(PYTHON), '-c', 'print("x" * 4096)']), self.base / 'large.log')

    def receipt(self):
        output = self.base / 'runtime'
        report = synthetic_runtime(output, self.identities)
        return output, report

    def test_synthetic_receipts_validate_but_never_certify_cosmic(self):
        output, report = self.receipt()
        accepted = port.accept_runtime(output, self.identities, 3)
        self.assertEqual(accepted['independent_boots'], 3)
        self.assertEqual(accepted['verified_pixels'], 479232)
        self.assertEqual(accepted['input_commands'], 48)
        self.assertFalse(report['full_cosmic_port'])

    def test_receipt_rejects_status_scope_identity_and_iteration_changes(self):
        output, report = self.receipt()
        mutations = [('status', 'FAIL'), ('full_cosmic_port', True), ('cosmic_runtime_verified', True),
                     ('smithay_dynamic_verified', False), ('iterations', 1), ('iterations', True)]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                port.write_json(output / 'summary.json', dict(report, **{key: value}))
                with self.assertRaises(port.PortError):
                    port.accept_runtime(output, self.identities, 3)
        port.write_json(output / 'summary.json', report)
        with self.assertRaisesRegex(port.PortError, 'different kernel'):
            port.accept_runtime(output, dict(self.identities, kernel='0' * 64), 3)

    def test_receipt_rejects_missing_boot(self):
        output, report = self.receipt(); report['runs'].pop()
        port.write_json(output / 'summary.json', report)
        with self.assertRaises(port.PortError):
            port.accept_runtime(output, self.identities, 3)

    def test_receipt_rejects_incomplete_lifecycle_and_boolean_count(self):
        output, report = self.receipt()
        for value in [0, True]:
            report['runs'][0]['observations']['abrupt_disconnects'] = value
            port.write_json(output / 'summary.json', report)
            with self.assertRaises(port.PortError):
                port.accept_runtime(output, self.identities, 3)

    def test_receipt_rejects_incomplete_qmp(self):
        output, report = self.receipt()
        report['runs'][0]['qmp_observations']['input_commands'] = 15
        port.write_json(output / 'summary.json', report)
        with self.assertRaises(port.PortError):
            port.accept_runtime(output, self.identities, 3)

    def test_receipt_rejects_capacity_changed_screen(self):
        output, report = self.receipt()
        report['runs'][0]['capacity_scanout']['canvas_sha256'] = 'f' * 64
        port.write_json(output / 'summary.json', report)
        with self.assertRaises(port.PortError):
            port.accept_runtime(output, self.identities, 3)

    def test_receipt_rejects_tampered_raw_evidence(self):
        output, report = self.receipt()
        path = Path(next(iter(report['runs'][0]['evidence_sha256'])))
        path.write_text('tampered')
        with self.assertRaisesRegex(port.PortError, 'Raw evidence changed'):
            port.accept_runtime(output, self.identities, 3)

    def test_receipt_rejects_cross_run_evidence_reuse(self):
        output, report = self.receipt()
        old = report['runs'][0]['scanouts'][0]['path']
        report['runs'][1]['evidence_sha256'][old] = port.digest(Path(old))
        port.write_json(output / 'summary.json', report)
        with self.assertRaisesRegex(port.PortError, 'Invalid raw evidence path'):
            port.accept_runtime(output, self.identities, 3)

    def test_receipt_rejects_removed_scanout_binding(self):
        output, report = self.receipt()
        del report['runs'][0]['evidence_sha256'][report['runs'][0]['scanouts'][0]['path']]
        port.write_json(output / 'summary.json', report)
        with self.assertRaisesRegex(port.PortError, 'Unbound scanout'):
            port.accept_runtime(output, self.identities, 3)

    def test_execute_persists_failure_and_does_not_start_later_steps(self):
        with patch.object(port.Runner, 'run', side_effect=port.PortError('missing tool')) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                result = port.execute(self.config, PYTHON, CARGO)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result['failed_stage'], 'doctor')
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['smithay_dynamic_verified'])
        self.assertEqual(port.read_json(self.config.output / 'summary.json'), result)
        with self.assertRaises(FileExistsError):
            port.execute(self.config, PYTHON, CARGO)

    def test_execute_preserves_interrupt_status(self):
        with patch.object(port.Runner, 'run', side_effect=KeyboardInterrupt):
            with contextlib.redirect_stdout(io.StringIO()):
                result = port.execute(self.config, PYTHON, CARGO)
        self.assertEqual(result['status'], 'INTERRUPTED')
        self.assertFalse(result['full_cosmic_port'])

    def test_execute_rejects_source_drift_between_stages(self):
        def drift(step, log):
            (self.root / 'Cargo.lock').write_text('changed during execution')
            log.write_text('success before drift')
            return dict(returncode=0)
        with patch.object(port.Runner, 'run', side_effect=drift) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                result = port.execute(self.config, PYTHON, CARGO)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('Source changed', result['error'])

    def test_mocked_pipeline_packages_exact_artifacts_and_limits_success_scope(self):
        # This tests sequencing with fake ELF bytes, not any guest or target build.
        def fake_run(step, log):
            out = self.config.output
            if step['name'] in ('server', 'client'):
                kind = step['name']; directory = out / kind; directory.mkdir()
                name = 'smithay-dynamic.elf' if kind == 'server' else 'smithay-dynamic-client.elf'
                binary = directory / name; binary.write_bytes(b'SYNTHETIC ' + kind.encode())
                port.write_json(directory / 'build-report.json', dict(status='cross-built', **{
                    'probe' if kind == 'server' else 'client': dict(file=str(binary), sha256=port.digest(binary))}))
            elif step['name'] == 'kernel':
                binary = out / 'kernel-target' / port.TARGET / 'release/cyxia-kernel'
                binary.parent.mkdir(parents=True); binary.write_bytes(b'SYNTHETIC KERNEL')
                self.assertTrue(Path(step['environment']['CYXIA_SMITHAY_DYNAMIC_PROBE_ELF']).is_file())
            elif step['name'] == 'runtime':
                identities = {key: port.digest(out / name) for key, name in dict(kernel='kernel/cyxia-kernel.elf',
                    server='server/smithay-dynamic.elf', client='client/smithay-dynamic-client.elf').items()}
                synthetic_runtime(out / 'runtime', identities)
                self.assertEqual(port.read_json(out / 'kernel/kernel-source-manifest.json'), port.source_manifest(self.root))
            log.write_text('MOCKED STAGE; NO GUEST EXECUTION\n')
            return dict(returncode=0, log_sha256=port.digest(log))
        with patch.object(port.Runner, 'run', side_effect=fake_run) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                result = port.execute(self.config, PYTHON, CARGO)
        self.assertEqual(run.call_count, 8)
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['smithay_dynamic_verified'])
        for key in ('full_cosmic_port', 'cosmic_runtime_verified', 'desktop_session_ready', 'desktop_regression_verified'):
            self.assertIs(result[key], False)


if __name__ == '__main__':
    unittest.main()
