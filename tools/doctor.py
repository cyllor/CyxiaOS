"""Read-only, pinned M1 environment checks; no installation or profile changes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RUST_BIN = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))).expanduser().resolve() / 'bin'
TARGET = 'aarch64-unknown-none-softfloat'


def env():
    return dict(os.environ, PATH=str(RUST_BIN) + os.pathsep + os.environ.get('PATH', ''))


def run(args):
    try:
        result = subprocess.run(args, env=env(), capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ''
    return result.stdout.strip() if result.returncode == 0 else ''


def pinned(value, prefix):
    return value == prefix or value.startswith(prefix + ' ')


def assess(facts):
    checks = {
        'rust': {'ready': pinned(facts.get('rust', ''), 'rustc 1.95.0')},
        'cargo': {'ready': pinned(facts.get('cargo', ''), 'cargo 1.95.0')},
        'qemu': {'ready': facts.get('qemu', '').splitlines()[0:1] in (
            ['QEMU emulator version 10.2.2'],
            ['QEMU emulator version 10.2.2 (v10.2.2)'])},
        'baremetal_target': {'ready': TARGET in facts.get('targets', [])},
        'llvm': {'ready': bool(facts.get('llvm'))},
    }
    checks['ready'] = all(check['ready'] for check in checks.values())
    checks['facts'] = facts
    return checks


def llvm_dir():
    sysroot = run([str(RUST_BIN / 'rustc'), '--print', 'sysroot'])
    host = next((line.split(': ', 1)[1] for line in run(
        [str(RUST_BIN / 'rustc'), '-vV']).splitlines() if line.startswith('host: ')), '')
    if (not sysroot or not Path(sysroot).is_absolute() or not host
            or any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-. ' for char in host)
            or host in ('.', '..') or ' ' in host):
        raise RuntimeError('Rust sysroot/host metadata is unavailable or invalid')
    return Path(sysroot) / 'lib/rustlib' / host / 'bin'


def inspect():
    qemu = shutil.which('qemu-system-aarch64', path=env()['PATH'])
    try:
        directory = llvm_dir()
    except RuntimeError:
        directory = None
    return assess(dict(
        rust=run([str(RUST_BIN / 'rustc'), '--version']),
        cargo=run([str(RUST_BIN / 'cargo'), '--version']),
        qemu=run([qemu, '--version']) if qemu else '',
        targets=run([str(RUST_BIN / 'rustup'), 'target', 'list', '--installed']).splitlines(),
        llvm=directory is not None and all((directory / name).is_file()
             for name in ('llvm-readobj', 'llvm-objdump', 'rust-lld')),
        rust_path=str(RUST_BIN / 'rustc'),
        llvm_dir=str(directory) if directory is not None else None,
        project=str(ROOT)))


if __name__ == '__main__':
    result = inspect()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['ready'] else 1)
