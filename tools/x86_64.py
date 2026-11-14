#!/usr/bin/env python3
"""Build and verify the x86-64 PC platform selftest; never A01–A16 acceptance."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import selectors
import shutil
import struct
import subprocess
import sys
import time

import elf64
from doctor import ROOT, env
from build_sources import build_cache_context, code_source_map
from native_session import DEFAULT_NATIVE_LOCK, native_lease, idle_native_host
from transport import FrameDecoder

TARGET = 'x86_64-unknown-none'
LOAD_BASE = 0x100000
LOAD_LIMIT = 0x4000000
MAX_SERIAL = 8 * 1024 * 1024
MAX_ELF = 64 * 1024 * 1024
MARKERS = ('X86_BOOT_OK', 'PAGING_WX_OK', 'EXCEPTION_OK', 'FRAME_POOL_OK',
           'SHARED_CORE_OK', 'TIMER_IRQ_OK', 'USER_MODE_OK', 'X86_SELFTEST_OK')
VERSION = 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded_bytes(path, limit):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
            'missing, linked or oversized file: ' + str(path))
    raw = path.read_bytes()
    require(len(raw) <= limit, 'file grew beyond limit')
    return raw


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest_map(value):
    return sha_bytes(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def read_json(path):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON field: ' + key)
            out[key] = value
        return out
    def number(value):
        parsed = float(value)
        require(math.isfinite(parsed), 'nonfinite JSON number')
        return parsed
    def constant(value):
        raise ValueError('nonfinite JSON constant: ' + value)
    return json.loads(bounded_bytes(path, 4 * 1024 * 1024), object_pairs_hook=pairs,
                      parse_float=number, parse_constant=constant)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def tool_sources():
    """Hash the local Python import closure used by this producer/checker."""
    root = Path(__file__).resolve().parent
    pending = [Path(__file__).resolve()]
    result = {}
    while pending:
        path = pending.pop()
        name = str(path.relative_to(root.parent))
        if name in result:
            continue
        raw = bounded_bytes(path, 4 * 1024 * 1024)
        result[name] = sha_bytes(raw)
        for node in ast.walk(ast.parse(raw)):
            imports = ([n.name for n in node.names] if isinstance(node, ast.Import)
                       else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for module in imports:
                local = root / (module.split('.')[0] + '.py')
                if local.is_file():
                    pending.append(local)
    return dict(sorted(result.items()))


def inspect_elf(raw):
    require(len(raw) <= MAX_ELF, 'ELF exceeds file budget')
    header = elf64.decode(raw)
    require(header['kind'] == 2 and header['machine'] == 62 and header['flags'] == 0,
            'not x86-64 executable')
    require(not any(s['type'] in (2, 3) for s in header['segments']), 'dynamic ELF is unsupported')
    loads = []
    for s in header['segments']:
        if s['type'] != 1 or s['mem'] == 0:
            continue
        pa, va, ms, fs, fl, al, off = (s[k] for k in ('pa', 'va', 'mem', 'size', 'flags', 'align', 'offset'))
        require(LOAD_BASE <= pa < pa + ms <= LOAD_LIMIT and va == pa, 'load outside low identity pool')
        require(fl in (4, 5, 6), 'writable executable or invalid segment permissions')
        require(al in (0, 1) or (al & (al - 1) == 0 and va % al == off % al), 'invalid segment alignment')
        for old in loads:
            require(not (pa < old['pa'] + old['mem'] and old['pa'] < pa + ms), 'physical overlap')
            require(not (va < old['va'] + old['mem'] and old['va'] < va + ms), 'virtual overlap')
        loads.append({k: s[k] for k in ('pa', 'va', 'mem', 'size', 'offset', 'flags')})
    loads.sort(key=lambda s: s['pa'])
    require(loads and loads[0]['pa'] == LOAD_BASE, 'incorrect load base')
    entry = header['entry']
    require(any(s['flags'] & 1 and s['va'] <= entry < s['va'] + s['size'] for s in loads), 'entry not executable')
    require(entry < 2 ** 32, 'Multiboot entry exceeds 32-bit address')
    return dict(entry=entry, loads=loads)


def symbol(raw, name):
    return elf64.symbol(raw, name, inspect_elf(raw)['loads'])


def boot_image(raw):
    info = inspect_elf(raw)
    loads = info['loads']
    file_end = max(s['pa'] + s['size'] for s in loads if s['size'])
    mem_end = max(s['pa'] + s['mem'] for s in loads)
    image = bytearray(file_end - LOAD_BASE)
    for s in loads:
        offset = s['pa'] - LOAD_BASE
        image[offset:offset + s['size']] = raw[s['offset']:s['offset'] + s['size']]
    candidates = [off for off in range(0, min(len(image), 8192) - 31, 4)
                  if struct.unpack_from('<I', image, off)[0] == 0x1badb002]
    require(len(candidates) == 1, 'missing or ambiguous Multiboot address header')
    off = candidates[0]
    magic, flags, checksum, header, base, end, bss, entry = struct.unpack_from('<8I', image, off)
    require(flags == 0x10003 and (magic + flags + checksum) & 0xffffffff == 0, 'invalid Multiboot flags/checksum')
    require((header, base, end, bss, entry) == (LOAD_BASE + off, LOAD_BASE, file_end, mem_end, info['entry']),
            'Multiboot load/entry fields disagree with ELF')
    require(loads[0]['flags'] == 5 and off + 32 <= loads[0]['size']
            and LOAD_BASE + off + 32 <= entry < LOAD_BASE + loads[0]['size'],
            'bootstrap entry/header outside first executable segment')
    return bytes(image)


def validate_timeout(value):
    require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 900,
            'timeout must be finite and in (0, 900] seconds')


def accelerator(value):
    require(value in ('tcg', 'kvm'), 'unsupported accelerator')
    if value == 'kvm':
        require(platform.system() == 'Linux' and platform.machine().lower() in ('x86_64', 'amd64'),
                'KVM requires an explicitly selected Linux x86-64 host')
        return 'kvm'
    return 'tcg,thread=multi'


def prepare_native_lock(path):
    """Bootstrap only the established workspace lock on a fresh checkout.

    Both architectures still take exactly the same native_lease. Custom paths
    must already have a parent; linked default ancestors never receive writes.
    """
    path = Path(path).absolute()
    if path == Path(DEFAULT_NATIVE_LOCK).absolute():
        root = ROOT.resolve(strict=True)
        require(path.is_relative_to(root), 'default native lock is outside workspace')
        relative = path.relative_to(root)
        require('..' not in relative.parts, 'escaping native lock path')
        current = root
        for part in relative.parts[:-1]:
            current = current / part
            require(not current.is_symlink(), 'linked native lock ancestor')
            current.mkdir(mode=0o700, exist_ok=True)
            require(current.is_dir() and current.resolve() == current, 'invalid native lock ancestor')
    require(path.parent.is_dir() and not path.is_symlink(), 'native lock parent/target unavailable')
    return path


def executable(name):
    found = shutil.which(str(name), path=env()['PATH'])
    require(found is not None, 'executable not found: ' + str(name))
    # rustup dispatches by argv[0]; resolving cargo/rustc symlinks would invoke
    # rustup itself. Binary hashes still follow the link to bind its contents.
    path = Path(found).absolute()
    require(path.is_file() and os.access(path, os.X_OK), 'executable is unavailable')
    return str(path)


def version(path, args=('--version',)):
    result = subprocess.run([str(path), *args], env=env(), capture_output=True, text=True, timeout=10, check=True)
    require(len(result.stdout) < 65536, 'oversized version output')
    return result.stdout.strip()


def fresh_output(path):
    path = Path(path).absolute()
    require(not path.exists() and not path.is_symlink(), 'output already exists: ' + str(path))
    path.mkdir(parents=True, mode=0o700)
    require(path.resolve() == path, 'linked output ancestor')
    return path


def build_argv(cargo, profile):
    argv = [cargo, 'build', '--locked', '--offline', '-p', 'cyxia-kernel', '--bin', 'cyxia-kernel',
            '--target', TARGET, '--no-default-features', '--features', 'selftest']
    return argv + (['--release'] if profile == 'release' else [])


def build_environment(cache):
    environment = env()
    # Reject implicit compiler substitution and flags that override the tracked
    # target configuration. Record only these build controls, never credentials.
    controls = ('RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTFLAGS',
                'CARGO_ENCODED_RUSTFLAGS', 'CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS',
                'CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER')
    require(not any(environment.get(name) for name in controls), 'ambient compiler/flag override is unsupported')
    environment['CARGO_TARGET_DIR'] = cache['effective']
    return environment


def compiler_tools(cargo, rustc):
    versions = {'cargo': version(cargo), 'rustc': version(rustc, ('-vV',))}
    sysroot = Path(version(rustc, ('--print', 'sysroot'))).resolve(strict=True)
    require(sysroot.is_absolute(), 'invalid rustc sysroot')
    binaries = {name: dict(path=str(sysroot / 'bin' / name), sha256=sha(sysroot / 'bin' / name))
                for name in ('cargo', 'rustc')}
    return versions, binaries


def build(output, *, profile='dev', cargo='cargo', target_dir=None, native_lock=DEFAULT_NATIVE_LOCK):
    require(profile in ('dev', 'release'), 'invalid profile')
    with native_lease(prepare_native_lock(native_lock)):
        idle_native_host()
        output = fresh_output(output)
        sources = code_source_map(ROOT)
        producer = tool_sources()
        cache = build_cache_context(target_dir or ROOT / 'target' / 'x86_64', ROOT, sources)
        cargo = executable(cargo)
        rustc = executable('rustc')
        argv = build_argv(cargo, profile)
        environment = build_environment(cache)
        versions, binaries = compiler_tools(cargo, rustc)
        with (output / 'build.log').open('wb') as log:
            result = subprocess.run(argv, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=600)
        require(result.returncode == 0, 'Cargo build failed; see ' + str(output / 'build.log'))
        require((output / 'build.log').stat().st_size <= 4 * 1024 * 1024, 'build log exceeds budget')
        require(code_source_map(ROOT) == sources and tool_sources() == producer, 'sources changed during build')
        artifact = Path(cache['effective']) / TARGET / ('debug' if profile == 'dev' else 'release') / 'cyxia-kernel'
        require(artifact.resolve(strict=True).is_relative_to(Path(cache['effective']).resolve()), 'external Cargo artifact')
        raw = bounded_bytes(artifact, MAX_ELF)
        flat = boot_image(raw)
        (output / 'kernel.elf').write_bytes(raw)
        (output / 'boot.bin').write_bytes(flat)
        manifest = dict(version=VERSION, status='BUILT_NOT_RUN', target=TARGET, profile=profile,
            features=['selftest'], source_root=str(ROOT.resolve()), sources=sources, source_sha256=digest_map(sources),
            producer_sources=producer, build_argv=argv, cache=cache, tool_versions=versions,
            compiler_binaries=binaries,
            cargo=dict(path=cargo, sha256=sha(cargo)), rustc=dict(path=rustc, sha256=sha(rustc)),
            artifacts={'kernel.elf': sha_bytes(raw), 'boot.bin': sha_bytes(flat)}, elf=inspect_elf(raw),
            native_acceptance_status='NOT_RUN')
        write_json(output / 'build-manifest.json', manifest)
        return manifest


def validate_build(directory, *, cargo='cargo'):
    directory = Path(directory).resolve(strict=True)
    manifest = read_json(directory / 'build-manifest.json')
    require(manifest.get('version') == VERSION and manifest.get('target') == TARGET
            and manifest.get('status') == 'BUILT_NOT_RUN' and manifest.get('features') == ['selftest']
            and manifest.get('profile') in ('dev', 'release'), 'unsupported build manifest')
    sources = code_source_map(ROOT)
    require(manifest.get('sources') == sources and manifest.get('source_sha256') == digest_map(sources), 'compiled source mismatch')
    require(manifest.get('producer_sources') == tool_sources(), 'producer/checker source mismatch')
    require(manifest.get('source_root') == str(ROOT.resolve()) and manifest.get('native_acceptance_status') == 'NOT_RUN',
            'unsupported source/acceptance declaration')
    cache = manifest.get('cache', {})
    require(isinstance(cache.get('base'), str) and cache == build_cache_context(cache['base'], ROOT, sources),
            'build cache namespace mismatch')
    build_environment(cache)
    trusted_tools = {'cargo': executable(cargo), 'rustc': executable('rustc')}
    for name in ('cargo', 'rustc'):
        identity = manifest.get(name, {})
        path = trusted_tools[name]
        require(identity == dict(path=path, sha256=sha(path)), 'build executable identity mismatch')
    versions, binaries = compiler_tools(trusted_tools['cargo'], trusted_tools['rustc'])
    require(manifest.get('tool_versions') == versions and manifest.get('compiler_binaries') == binaries,
            'compiler toolchain identity mismatch')
    require(manifest.get('build_argv') == build_argv(manifest['cargo']['path'], manifest['profile']),
            'build argv mismatch')
    raw = bounded_bytes(directory / 'kernel.elf', MAX_ELF)
    flat = bounded_bytes(directory / 'boot.bin', LOAD_LIMIT - LOAD_BASE)
    require(flat == boot_image(raw), 'flat boot image disagrees with validated ELF')
    require(manifest.get('elf') == inspect_elf(raw), 'ELF metadata mismatch')
    require(manifest.get('artifacts') == {'kernel.elf': sha_bytes(raw), 'boot.bin': sha_bytes(flat)}, 'artifact hash mismatch')
    return manifest


def decoded_serial(raw):
    require(0 < len(raw) <= MAX_SERIAL, 'empty or oversized serial capture')
    decoder = FrameDecoder()
    chunks = []
    for offset in range(0, len(raw), 65536):
        chunks.extend(decoder.feed(raw[offset:offset + 65536]))
    require(not decoder.buffer and decoder.corrupt == 0 and decoder.loss == 0 and decoder.frames > 0,
            'truncated, corrupt, replayed or lossy serial frames')
    text = b''.join(chunks).decode('ascii', errors='strict')
    return text, chunks, decoder


def validate_serial(raw, returncode, *, forced, eof):
    require(type(returncode) is int and returncode == 33 and forced is False and eof is True,
            'guest did not finish with owned, clean debug-exit success (33)')
    text, chunks, decoder = decoded_serial(raw)
    # A marker may span transport frames; records themselves must be exact lines.
    # Legacy fixture streams use one marker per frame without line terminators.
    if '\n' in text:
        lines = text.splitlines()
    else:
        lines = [chunk.decode('ascii') for chunk in chunks]
    require(not any('PANIC' in line.upper() or 'FAIL' in line.upper() for line in lines), 'guest failure marker')
    observed = [line.strip() for line in lines if line.strip() in MARKERS]
    require(observed == list(MARKERS), 'missing, duplicated or out-of-order x86 selftest markers')
    require([line.strip() for line in lines if line.strip()][-1] == MARKERS[-1], 'selftest success is not terminal')
    return dict(markers=observed, frames=decoder.frames, session=decoder.session,
                serial_sha256=sha_bytes(raw), text=text)


def capture_stdout(proc, raw, deadline, stderr_raw=None):
    require(proc.stdout is not None, 'missing owned stdout pipe')
    os.set_blocking(proc.stdout.fileno(), False)
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ, raw)
        if stderr_raw is not None:
            require(proc.stderr is not None, 'missing owned stderr pipe')
            os.set_blocking(proc.stderr.fileno(), False)
            selector.register(proc.stderr, selectors.EVENT_READ, stderr_raw)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('x86 observation timeout')
            for key, event in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                key.data.extend(chunk)
                require(len(key.data) <= (MAX_SERIAL if key.data is raw else 1024 * 1024), 'process output exceeded budget')
    return True


def close_process(proc):
    if proc.poll() is not None:
        proc.wait(timeout=2)
        return False
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)
    return True


def launch_argv(qemu, image, accel):
    return [str(qemu), '-machine', 'pc-i440fx-10.2', '-cpu', 'qemu64', '-smp', '1', '-m', '256M',
            '-accel', accelerator(accel), '-display', 'none', '-monitor', 'none', '-serial', 'stdio',
            '-nic', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=4', '-kernel', str(image)]


def inventory(directory):
    directory = Path(directory)
    result = {}
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(), 'linked capture artifact')
        if path.is_file() and path.name != 'summary.json':
            require(path.stat().st_size <= MAX_ELF, 'oversized capture artifact')
            result[str(path.relative_to(directory))] = sha(path)
    require(len(result) <= 16, 'capture inventory exceeds budget')
    return result


def check(directory, *, qemu='qemu-system-x86_64', cargo='cargo'):
    directory = Path(directory).resolve(strict=True)
    before = inventory(directory)
    manifest = validate_build(directory / 'build', cargo=cargo)
    request = read_json(directory / 'request.json')
    process = read_json(directory / 'process.json')
    require(request.get('version') == VERSION and request.get('markers') == list(MARKERS), 'unsupported capture request')
    validate_timeout(request.get('timeout'))
    qemu = executable(qemu)
    require(request.get('qemu') == dict(path=qemu, sha256=sha(qemu), version=version(qemu)), 'QEMU binary identity mismatch')
    require(request.get('argv') == launch_argv(qemu, directory / 'build' / 'boot.bin', request['accel']), 'launch argv mismatch')
    require(request.get('build_manifest_sha256') == sha(directory / 'build' / 'build-manifest.json'), 'build receipt mismatch')
    require(process.get('error') is None and type(process.get('pid')) is int and process['pid'] > 0,
            'capture error or missing owned process')
    require(type(process.get('elapsed_seconds')) in (int, float) and 0 <= process['elapsed_seconds'] <= request['timeout'] + 5,
            'invalid observation duration')
    require(type(process.get('started_ns')) is int and type(process.get('ended_ns')) is int
            and 0 < process['started_ns'] <= process['ended_ns'], 'invalid process wall timestamps')
    serial = validate_serial(bounded_bytes(directory / 'serial.raw', MAX_SERIAL), process.get('returncode'),
                             forced=process.get('forced'), eof=process.get('eof'))
    require(bounded_bytes(directory / 'serial.txt', MAX_SERIAL) == serial['text'].encode(), 'decoded serial mismatch')
    require(process.get('serial_sha256') == serial['serial_sha256'], 'process serial digest mismatch')
    require(inventory(directory) == before, 'capture mutated during verification')
    return dict(version=VERSION, status='X86_PLATFORM_SELFTEST_PASS', native_acceptance_status='NOT_RUN',
                a01_a16_complete=False, unified_runtime_supported=False, markers=serial['markers'],
                serial_frames=serial['frames'], serial_sha256=serial['serial_sha256'],
                compiled_source_sha256=manifest['source_sha256'], evidence_inventory=before)


def run(build_dir, output, *, qemu='qemu-system-x86_64', cargo='cargo', accel='tcg', timeout=30, native_lock=DEFAULT_NATIVE_LOCK):
    validate_timeout(timeout)
    accelerator(accel)
    with native_lease(prepare_native_lock(native_lock)):
        idle_native_host()
        build_dir = Path(build_dir).resolve(strict=True)
        validate_build(build_dir, cargo=cargo)
        output = fresh_output(output)
        (output / 'build').mkdir()
        for name in ('kernel.elf', 'boot.bin', 'build-manifest.json'):
            shutil.copyfile(build_dir / name, output / 'build' / name)
        validate_build(output / 'build', cargo=cargo)
        qemu = executable(qemu)
        argv = launch_argv(qemu, output / 'build' / 'boot.bin', accel)
        request = dict(version=VERSION, argv=argv, accel=accel, timeout=timeout, markers=list(MARKERS),
                       qemu=dict(path=qemu, sha256=sha(qemu), version=version(qemu)),
                       build_manifest_sha256=sha(output / 'build' / 'build-manifest.json'))
        write_json(output / 'request.json', request)
        raw = bytearray()
        stderr_raw = bytearray()
        proc = None
        state = dict(pid=None, returncode=None, forced=False, eof=False, error=None)
        started = time.monotonic()
        state['started_ns'] = time.time_ns()
        try:
            proc = subprocess.Popen(argv, cwd=ROOT, env=env(), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            state['pid'] = proc.pid
            state['eof'] = capture_stdout(proc, raw, started + timeout, stderr_raw)
            state['returncode'] = proc.wait(timeout=max(0.001, started + timeout - time.monotonic()))
        except Exception as error:
            state['error'] = str(error)
        finally:
            if proc is not None:
                state['forced'] = close_process(proc)
                state['returncode'] = proc.returncode
                proc.stdout.close()
                proc.stderr.close()
            state['elapsed_seconds'] = time.monotonic() - started
            state['ended_ns'] = time.time_ns()
            state['serial_sha256'] = sha_bytes(raw)
            (output / 'serial.raw').write_bytes(raw)
            (output / 'stderr.log').write_bytes(stderr_raw)
            try:
                text = decoded_serial(raw)[0]
            except (ValueError, UnicodeError):
                text = ''
            (output / 'serial.txt').write_text(text)
            write_json(output / 'process.json', state)
        try:
            result = check(output, qemu=qemu, cargo=cargo)
        except Exception as error:
            result = dict(version=VERSION, status='FAIL', error=str(error), native_acceptance_status='NOT_RUN',
                          a01_a16_complete=False, unified_runtime_supported=False)
        write_json(output / 'summary.json', result)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build_parser = commands.add_parser('build')
    build_parser.add_argument('--output', type=Path, required=True)
    build_parser.add_argument('--profile', choices=('dev', 'release'), default='dev')
    build_parser.add_argument('--cargo', default='cargo')
    build_parser.add_argument('--target-dir', type=Path)
    build_parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    run_parser = commands.add_parser('run')
    run_parser.add_argument('--build', dest='build_dir', type=Path, required=True)
    run_parser.add_argument('--output', type=Path, required=True)
    run_parser.add_argument('--qemu', default='qemu-system-x86_64')
    run_parser.add_argument('--cargo', default='cargo')
    run_parser.add_argument('--accel', choices=('tcg', 'kvm'), default='tcg')
    run_parser.add_argument('--timeout', type=float, default=30)
    run_parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    check_parser = commands.add_parser('check')
    check_parser.add_argument('--directory', type=Path, required=True)
    check_parser.add_argument('--qemu', default='qemu-system-x86_64')
    check_parser.add_argument('--cargo', default='cargo')
    args = vars(parser.parse_args(argv))
    command = args.pop('command')
    try:
        result = globals()[command](**args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return int(result.get('status') == 'FAIL')
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('x86-64: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
