#!/usr/bin/env python3
"""Configuration-1.3 delivery commands backed by the native tools.

Usage: python3 tools/prototype.py {build,run-single,run-pair,test,report} ...
Native commands accept the options of their underlying builder/verifier.
Host checks and functional probes do not establish complete acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from check_prototype_evidence import read_json
from check_v13_evidence import DEFAULT, validate
from doctor import ROOT, RUST_BIN, TARGET, env

# Each engineering gate has one lane; native execution remains separate.
TEST_LANES = {
    'static': ('format', 'governance-format', 'clippy', 'governance-clippy'),
    'rust': ('rust', 'tls'),
    'host': ('fixtures', 'host'),
    'tools': ('tools',),
}

NATIVE_COMMANDS = {
    'build': ('build_unified.py', []),
    'run-single': ('verify_domains.py', ['--single']),
    'run-pair': ('verify_unified.py', []),
}


def stop_step(process: subprocess.Popen) -> None:
    """Terminate only this runner's new process group, then reap its leader."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # The group may outlive its leader (for example a nested compiler).
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def run_steps(steps: list[tuple[str, list[str]]], output: Path) -> int:
    """Retain all independent check results, including launch/interruption errors."""
    if not steps:
        raise ValueError('at least one validation step is required')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'scope': 'host-validation', 'status': 'RUNNING',
              'release_acceptance_verified': False, 'steps': []}

    def save():
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    interrupted = False
    for index, (name, argv) in enumerate(steps, 1):
        logfile = output / f'{index:02}-{name}.log'
        row = {'name': name, 'argv': argv, 'log': logfile.name,
               'returncode': None, 'status': 'RUNNING'}
        report['steps'].append(row)
        save()
        started = time.monotonic()
        print(f'{name}: running ({logfile})', flush=True)
        with logfile.open('x') as log:
            try:
                with subprocess.Popen(argv, cwd=ROOT, env=env(), stdout=log,
                        stderr=subprocess.STDOUT, start_new_session=True) as process:
                    try:
                        row['returncode'] = process.wait()
                    except BaseException:
                        stop_step(process)
                        raise
            except OSError as error:
                row['returncode'] = 127
                log.write(f'{type(error).__name__}: {error}\n')
            except KeyboardInterrupt:
                row['returncode'] = 130
                log.write('Interrupted by user\n')
                interrupted = True
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)
        row['status'] = 'PASS' if row['returncode'] == 0 else 'FAIL'
        print(f'{name}: {row["status"]} (exit {row["returncode"]})', flush=True)
        save()
        if interrupted:
            break
    report['status'] = 'PASS' if all(r['returncode'] == 0 for r in report['steps']) else 'FAIL'
    save()
    return 130 if interrupted else int(report['status'] != 'PASS')


def test_steps(fetch: bool, lane: str = "all") -> list[tuple[str, list[str]]]:
    cargo = str(RUST_BIN / 'cargo')
    python = [sys.executable, '-B']
    steps = [
        ('fixtures', python + [str(ROOT / 'tools/prepare_host_tests.py')]
         + (['--fetch'] if fetch else [])),
        ('format', [cargo, 'fmt', '--all', '--', '--check']),
        ('governance-format', [cargo, 'fmt', '--manifest-path',
                              str(ROOT / 'user/prototype-governance/Cargo.toml'), '--', '--check']),
        ('rust', [cargo, 'test', '--locked', '--offline', '--workspace', '--exclude', 'cyxia-kernel']),
        ('tls', [cargo, 'test', '--locked', '--offline', '-p',
                 'cyxia-cluster-transport', '--features', 'tls']),
        ('host', python + ['-m', 'unittest', 'discover', '-s', 'tests/host', '-p', 'test_*.py']),
        ('tools', python + ['-m', 'unittest', 'discover', '-s', 'tools', '-p', 'test_*.py']),
        ('clippy', [cargo, 'clippy', '--locked', '--offline', '-p', 'cyxia-kernel',
                    '--target', TARGET, '--features', 'smp-selftest', '--', '-D', 'warnings']),
        ('governance-clippy', [cargo, 'clippy', '--locked', '--offline', '--manifest-path',
                               str(ROOT / 'user/prototype-governance/Cargo.toml'),
                               '--target-dir', str(ROOT / 'target/prototype-governance'),
                               '--target', TARGET, '--', '-D', 'warnings']),
    ]
    if lane == 'all':
        return steps
    if lane not in TEST_LANES:
        raise ValueError('unknown validation lane: ' + lane)
    selected = set(TEST_LANES[lane])
    return [(name, argv) for name, argv in steps if name in selected]


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Delegate parsing directly so backend help, validation and exit codes stay
    # authoritative. The wrapper never interprets a native producer's PASS.
    if argv and argv[0] in NATIVE_COMMANDS:
        script, fixed = NATIVE_COMMANDS[argv[0]]
        result = subprocess.run([sys.executable, str(ROOT / 'tools' / script),
                                 *fixed, *argv[1:]], cwd=ROOT, env=env(), check=False)
        return result.returncode if result.returncode >= 0 else 128 - result.returncode
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in NATIVE_COMMANDS:
        sub.add_parser(name, help='forward to the native builder/verifier')
    test = sub.add_parser('test', help='run host validation; keep per-step logs')
    test.add_argument('--output', type=Path, required=True, help='new evidence directory')
    test.add_argument('--fetch', action='store_true', help='fetch exact pinned host fixtures')
    test.add_argument('--lane', choices=['all', *TEST_LANES], default='all',
                      help='independent CI lane; default runs all host validation gates')
    report = sub.add_parser('report', help='independently validate the 1.3 catalogue')
    report.add_argument('--manifest', type=Path, default=DEFAULT)
    report.add_argument('--output', type=Path, help='optional new JSON file; otherwise stdout')
    args = parser.parse_args(argv)
    try:
        if args.command == 'test':
            return run_steps(test_steps(args.fetch, args.lane), args.output)
        result = validate(read_json(args.manifest), ROOT)
        text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
        if args.output is not None:
            with args.output.open('x') as destination:
                destination.write(text)
        else:
            sys.stdout.write(text)
        return 0 if result['functional_acceptance_complete'] else 2
    except (OSError, ValueError, TypeError) as error:
        print(f'prototype: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
