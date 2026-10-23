#!/usr/bin/env python3
"""Build, package and verify the native dynamic Wayland work package.

Reuses the pinned upstream builders and actual ARM/QEMU verifier. This is NOT
cosmic-comp or a COSMIC desktop launcher. --plan runs nothing and writes nothing.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'aarch64-unknown-none-softfloat'
SOURCE_PATHS = ('.cargo', 'crates', 'kernel', 'ports', 'tests', 'tools', 'user',
                'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml')


class PortError(RuntimeError):
    """A prerequisite, build or evidence check failed."""


def require(condition: bool, message: str) -> None:
    # Must remain active under python -O; the guest verifier uses assertions.
    if not condition:
        raise PortError(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(value, dict), f'Expected a JSON object: {path}')
    return value


def write_json(path: Path, value: Any) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                dir=path.parent, prefix=path.name + '.', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Config:
    root: Path
    output: Path
    cache: Path
    mesa_report: Path
    protocol_crate: Path
    iterations: int = 3
    fetch: bool = False
    timeout: int = 3600

    def validate(self) -> None:
        require(type(self.iterations) is int and 3 <= self.iterations <= 5,
                'Freeze requires 3 to 5 independent boots')
        require(type(self.timeout) is int and 1 <= self.timeout <= 7200,
                'Step timeout must be 1 to 7200 seconds')
        paths = (self.root, self.output, self.cache, self.mesa_report, self.protocol_crate)
        require(all(path.is_absolute() and path == path.resolve() for path in paths),
                'Configuration paths must be absolute and resolved')
        require(self.root.is_dir(), 'Repository root does not exist')
        require(not self.root.is_relative_to(self.output), 'Output must not contain the repository')
        if self.output.is_relative_to(self.root):
            require(self.output.relative_to(self.root).parts[0] == 'artifacts',
                    'In-repository output must be under artifacts/')
        for path in (self.cache, self.mesa_report, self.protocol_crate):
            require(not path.is_relative_to(self.output), 'Inputs must be outside the fresh output')
        require(not self.output.is_relative_to(self.cache), 'Output must not be inside the source cache')


def clean_env(source: dict[str, str], rust_bin: Path) -> dict[str, str]:
    exact = {'PYTHONOPTIMIZE', 'PYTHONPATH', 'PYTHONHOME', 'RUSTFLAGS', 'RUSTDOCFLAGS',
             'CARGO_ENCODED_RUSTFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC', 'RUSTDOC',
             'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_TARGET_DIR', 'CYXIA_CC'}
    result = {key: value for key, value in source.items()
              if key not in exact
              and not key.startswith(('CARGO_PROFILE_', 'CARGO_BUILD_', 'CARGO_TARGET_'))
              and not (key.startswith('CYXIA_') and key.endswith('_ELF'))}
    result['PATH'] = str(rust_bin) + os.pathsep + result.get('PATH', '')
    result['PYTHONDONTWRITEBYTECODE'] = '1'
    return result


def source_manifest(root: Path) -> dict[str, str]:
    result = subprocess.run(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', *SOURCE_PATHS],
        cwd=root, capture_output=True, check=True, timeout=30)
    names = sorted(set(os.fsdecode(name) for name in result.stdout.split(b'\0') if name))
    mandatory = {'Cargo.toml', 'Cargo.lock', 'kernel/build.rs', 'kernel/Cargo.toml',
                 'kernel/src/user/shared_memory.rs', 'crates/posix/src/epoll.rs'}
    require(mandatory <= set(names), 'Incomplete CyxiaOS checkout')
    manifest = {}
    for name in names:
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe source path')
        path = root / relative
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root),
                f'Missing, non-regular or escaping source: {name}')
        manifest[name] = digest(path)
    return manifest


def unchanged(root: Path, expected: dict[str, str]) -> None:
    current = source_manifest(root)
    changed = sorted(name for name in current.keys() | expected.keys()
                     if current.get(name) != expected.get(name))
    require(not changed, 'Source changed during run: ' + ', '.join(changed[:8]))


def commands(config: Config, python: Path, cargo: Path) -> list[dict[str, Any]]:
    root, out = config.root, config.output
    server = out / 'server/smithay-dynamic.elf'
    client = out / 'client/smithay-dynamic-client.elf'
    def script(name):
        return [str(python), '-B', str(root / 'tools' / name)]
    definitions = [
        ('doctor', script('doctor.py'), {}),
        ('host-tests', [str(python), '-B', '-m', 'unittest', 'discover', '-s', 'tests/host', '-v'], {}),
        ('rust-tests', [str(cargo), 'test', '--locked', '--offline', '--target-dir', str(out / 'host-target')], {}),
        ('rust-large-memory', [str(cargo), 'test', '--locked', '--offline', '-p', 'cyxia-posix',
             '--features', 'large-memory', '--target-dir', str(out / 'host-target')], {}),
        ('server', script('build_smithay_dynamic.py') + ['--output', str(out / 'server'),
             '--cache', str(config.cache), '--mesa-report', str(config.mesa_report)]
             + (['--fetch'] if config.fetch else []), {}),
        ('client', script('build_smithay_dynamic_client.py') + ['--output', str(out / 'client'),
             '--protocol-crate', str(config.protocol_crate)], {}),
        ('kernel', [str(cargo), 'build', '--locked', '--offline', '--release', '-p', 'cyxia-kernel',
             '--target', TARGET, '--no-default-features', '--features', 'smithay-dynamic-probe',
             '--target-dir', str(out / 'kernel-target')],
             {'CYXIA_SMITHAY_DYNAMIC_PROBE_ELF': str(server),
              'CYXIA_SMITHAY_DYNAMIC_CLIENT_ELF': str(client)}),
        ('runtime', script('verify_smithay_dynamic.py') + ['--elf', str(out / 'kernel/cyxia-kernel.elf'),
             '--server', str(server), '--client', str(client), '--output', str(out / 'runtime'),
             '--iterations', str(config.iterations)], {}),
    ]
    return [dict(name=name, argv=argv, environment=extra, timeout_seconds=config.timeout)
            for name, argv, extra in definitions]


class Runner:
    """Run in the foreground, preserve logs, and reap process groups on failure."""
    def __init__(self, root: Path, environment: dict[str, str], log_limit: int = 16 * 1024 * 1024):
        self.root, self.environment, self.log_limit = root, environment, log_limit

    @staticmethod
    def stop(process: subprocess.Popen) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)

    def run(self, step: dict[str, Any], log: Path) -> dict[str, Any]:
        started = time.monotonic()
        with log.open('xb') as stream:
            process = subprocess.Popen(step['argv'], cwd=self.root,
                env=dict(self.environment, **step['environment']), stdout=stream,
                stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while True:
                    code = process.poll()
                    require(stream.tell() <= self.log_limit, f"{step['name']}: log budget exceeded")
                    require(time.monotonic() - started <= step['timeout_seconds'], f"{step['name']}: timeout")
                    if code is not None:
                        require(code == 0, f"{step['name']}: exit {code}; see {log}")
                        break
                    time.sleep(.05)
            except BaseException:
                self.stop(process)
                raise
        return dict(returncode=0, elapsed_seconds=round(time.monotonic() - started, 3),
                    log=str(log), log_sha256=digest(log))


def built_program(output: Path, filename: str, field: str) -> Path:
    path = output / filename
    require(path.is_file() and not path.is_symlink(), f'Missing target ELF: {path}')
    report = read_json(output / 'build-report.json')
    require(report.get('status') == 'cross-built', f'Build did not complete: {output}')
    identity = report.get(field, {})
    require(identity.get('file') == str(path) and identity.get('sha256') == digest(path),
            f'Build report/ELF identity mismatch: {path}')
    return path


def accept_runtime(output: Path, identities: dict[str, str], iterations: int) -> dict[str, Any]:
    report = read_json(output / 'summary.json')
    require(report.get('status') == 'PASS' and report.get('smithay_dynamic_verified') is True,
            'Native dynamic-client acceptance did not pass')
    require(report.get('full_cosmic_port') is False and report.get('cosmic_runtime_verified') is False,
            'A Smithay work package cannot certify COSMIC')
    require(type(report.get('iterations')) is int and report['iterations'] == iterations,
            'Wrong number of independent boots')
    provenance = report.get('provenance', {})
    for name, value in identities.items():
        require(provenance.get(name + '_sha256') == value, f'Runtime used a different {name}')
    runs = report.get('runs', [])
    require(isinstance(runs, list) and len(runs) == iterations, 'Incomplete boot evidence')
    pixels = 0
    for index, run in enumerate(runs, 1):
        require(type(run.get('iteration')) is int and run['iteration'] == index, 'Missing or duplicated boot')
        observed = run.get('observations', {})
        expected = dict(scenes=12, commits=8, pixels=147456, configures=7, acknowledgements=7,
            admitted_clients=3, capacity_rejections=1, reused_slots=1, stale_keys_rejected=1,
            graceful_closes=2, abrupt_disconnects=1, independently_launched_processes=5)
        require(all(type(observed.get(key)) is int and observed[key] == value
                    for key, value in expected.items()), 'Incomplete client lifecycle observations')
        qmp = run.get('qmp_observations', {})
        require(all(type(qmp.get(key)) is int and qmp[key] == value for key, value in
                    dict(scanouts=12, capacity_scanouts=1, input_commands=16).items()),
                'Missing physical display/input evidence')
        witnesses = run.get('scanouts', [])
        require(isinstance(witnesses, list) and len(witnesses) == 12
                and all(type(w.get('scene')) is int for w in witnesses)
                and [w['scene'] for w in witnesses] == list(range(12)), 'Incomplete scanouts')
        capacity = run.get('capacity_scanout', {})
        require(type(capacity.get('scene')) is int and capacity['scene'] == 4
                and capacity.get('canvas_sha256') == witnesses[4].get('canvas_sha256'),
                'Capacity rejection altered the displayed scene')
        evidence = run.get('evidence_sha256', {})
        require(isinstance(evidence, dict) and bool(evidence), 'Missing raw guest evidence')
        require({'qmp.jsonl', 'host-commands.json', 'uart-input.jsonl'} <=
                {Path(name).name for name in evidence}, 'Missing raw command transcripts')
        run_dir = output / f'run-{index}'
        for name, expected_hash in evidence.items():
            path = Path(name)
            require(path.is_absolute() and path.resolve().is_relative_to(run_dir)
                    and path.is_file() and not path.is_symlink(), 'Invalid raw evidence path')
            require(digest(path) == expected_hash, f'Raw evidence changed: {path}')
        for witness in [*witnesses, capacity]:
            canvas_hash = witness.get('canvas_sha256', '')
            require(isinstance(canvas_hash, str) and len(canvas_hash) == 64
                    and all(c in '0123456789abcdef' for c in canvas_hash), 'Invalid canvas hash')
            require(type(witness.get('pixels')) is int and witness['pixels'] == 12288,
                    'Incomplete scanout pixel accounting')
            require(witness.get('path') in evidence
                    and evidence[witness['path']] == witness.get('sha256'), 'Unbound scanout')
            pixels += witness['pixels']
    return dict(summary_sha256=digest(output / 'summary.json'), independent_boots=iterations,
                verified_pixels=pixels, input_commands=16 * iterations)


def execute(config: Config, python: Path, cargo: Path) -> dict[str, Any]:
    config.validate()
    require(sys.flags.optimize == 0, 'Do not run acceptance with python -O/-OO')
    config.output.mkdir(parents=True, exist_ok=False)  # Never reuse PASS or FAIL evidence.
    (config.output / 'logs').mkdir()
    report: dict[str, Any] = dict(schema_version=1, status='FAIL',
        scope='smithay-dynamic work package; not a COSMIC desktop session',
        smithay_dynamic_verified=False, full_cosmic_port=False, cosmic_runtime_verified=False,
        desktop_session_ready=False, desktop_regression_verified=False, steps=[])
    runner = Runner(config.root, clean_env(dict(os.environ), cargo.parent))
    stage = 'source-snapshot'
    try:
        manifest = source_manifest(config.root)
        write_json(config.output / 'source-manifest.json', manifest)
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=config.root, text=True, timeout=30).strip()
        report['source'] = dict(commit=head, files=len(manifest),
            manifest_sha256=digest(config.output / 'source-manifest.json'))
        for step in commands(config, python, cargo):
            stage = step['name']
            record = dict(step, status='RUNNING')
            report['steps'].append(record)
            write_json(config.output / 'summary.json', report)
            unchanged(config.root, manifest)
            if stage == 'kernel':
                server = built_program(config.output / 'server', 'smithay-dynamic.elf', 'probe')
                client = built_program(config.output / 'client', 'smithay-dynamic-client.elf', 'client')
                report['identities'] = dict(server=digest(server), client=digest(client))
            if stage == 'runtime':
                kernel = config.output / 'kernel/cyxia-kernel.elf'
                kernel.parent.mkdir()
                shutil.copyfile(config.output / 'kernel-target' / TARGET / 'release/cyxia-kernel', kernel)
                write_json(kernel.parent / 'kernel-source-manifest.json', manifest)
                report['identities']['kernel'] = digest(kernel)
            print('desktop-port: ' + stage, flush=True)
            record.update(runner.run(step, config.output / 'logs' / (stage + '.log')), status='PASS')
        stage = 'evidence-validation'
        unchanged(config.root, manifest)
        for name, relative in dict(kernel='kernel/cyxia-kernel.elf', server='server/smithay-dynamic.elf',
                                   client='client/smithay-dynamic-client.elf').items():
            require(digest(config.output / relative) == report['identities'][name], f'Final {name} artifact changed')
        report['acceptance'] = accept_runtime(config.output / 'runtime', report['identities'], config.iterations)
        report.update(status='PASS', smithay_dynamic_verified=True)
    except (Exception, KeyboardInterrupt) as error:
        if report['steps'] and report['steps'][-1]['status'] == 'RUNNING':
            report['steps'][-1]['status'] = 'FAIL'
        report.update(failed_stage=stage, error=f'{type(error).__name__}: {error}')
        if isinstance(error, KeyboardInterrupt):
            report['status'] = 'INTERRUPTED'
    finally:
        report['logs_sha256'] = {path.name: digest(path) for path in sorted((config.output / 'logs').glob('*.log'))}
        write_json(config.output / 'summary.json', report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'cache', 'mesa-report', 'protocol-crate'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--iterations', type=int, choices=range(3, 6), default=3)
    parser.add_argument('--fetch', action='store_true', help="Allow the server builder's pinned downloads")
    parser.add_argument('--plan', action='store_true', help='Print commands; create no files and run no tools')
    parser.add_argument('--step-timeout', type=int, default=3600)
    args = parser.parse_args(argv)
    config = Config(ROOT.resolve(), args.output.resolve(), args.cache.resolve(), args.mesa_report.resolve(),
                    args.protocol_crate.resolve(), args.iterations, args.fetch, args.step_timeout)
    rust_bin = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))).expanduser().resolve() / 'bin'
    python, cargo = Path(sys.executable).resolve(), rust_bin / 'cargo'
    try:
        config.validate()
        if args.plan:
            print(json.dumps(dict(status='PLAN_ONLY', full_cosmic_port=False,
                                  steps=commands(config, python, cargo)), indent=2))
            return 0
        result = execute(config, python, cargo)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result['status'] == 'PASS' else 130 if result['status'] == 'INTERRUPTED' else 1
    except (OSError, ValueError, PortError, subprocess.SubprocessError) as error:
        print('desktop-port: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
