#!/usr/bin/env python3
"""Link and run the unchanged pinned theme exporter on a Linux host.

Current retained rlibs are explicit NEW inputs. The older settings receipt
proves its preserved source/build contract, not historical hashes of each
rlib. The committed 79 assets are comparison data, never generation evidence.
Only build() starts the compiler/exporter. The CLI holds the shared lease.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

if __package__:
    from . import build_cosmic_config as files
    from . import build_cosmic as processes
    from . import build_notification_probe as provenance
    from . import cosmic_settings_inputs_v1 as settings
    from . import install_cosmic_theme_defaults as reference
    from . import native_session
    from . import build_sysroot
else:
    import build_cosmic_config as files
    import build_cosmic as processes
    import build_notification_probe as provenance
    import cosmic_settings_inputs_v1 as settings
    import install_cosmic_theme_defaults as reference
    import native_session
    import build_sysroot

ROOT = settings.contract.ROOT
SOURCE = ROOT / 'ports/cosmic/theme-defaults/client.rs'
SOURCE_ID = {'bytes': 6266, 'sha256': '1003586674225500970f26fb895863d27c2baf89cd5e4d592338c19a59de94b2'}
MANIFEST = ROOT / 'ports/cosmic/theme-defaults/assets.json'
MANIFEST_SHA256 = '0b4c9e50fe1f6747ff26356e15c9a171be0f99cd058cd8973b7842a26569f442'
COMMIT = '5a8bd9482a35ae94c1e54edf77b331c6b970f170'
TARGET = 'x86_64-unknown-linux-musl'
EXECUTABLE = 'theme-defaults.elf'
RECEIPT = 'build-report.json'
KIND = 'cosmic-theme-linux-host-generation-v1'
NATIVE_LOCK = ROOT / 'artifacts/v017-cosmic-completion-20261116/native-session.lock'
LIMITS = {'jobs': 1, 'timeout_seconds': 120, 'min_free_bytes': 1024 ** 3,
          'max_output_bytes': 256 * 1024 ** 2, 'max_key_bytes': 8192,
          'max_asset_bytes': 256 * 1024, 'keys_per_mode': 39}
TIMEOUT_SCOPE = 'shared-link-and-two-host-runs-excludes-read-only-input-validation'
SEARCH_ROOTS = files.SEARCH_ROOTS
EXTERNS = ('cosmic_config', 'cosmic_theme')
require, BuildError = files.require, files.BuildError
plain, identity = files.plain_path, files.file_identity
canonical = settings.contract.canonical


def read(path, limit=64 * 1024 ** 2):
    return settings.contract.read_regular(plain(path), limit)


def decode(data):
    return json.loads(data, object_pairs_hook=files.unique_object)


def producer_sources():
    entry = plain(__file__)
    require(entry == ROOT / 'tools/build_cosmic_theme_linux_v1.py',
            'Use the reviewed installed Linux theme producer')
    return provenance.producer_sources(entry)


def reference_assets():
    raw = read(MANIFEST, 1024 ** 2)
    require(hashlib.sha256(raw).hexdigest() == MANIFEST_SHA256,
            'Pinned comparison manifest changed')
    manifest = reference.load_manifest(MANIFEST)
    require(identity(SOURCE) == SOURCE_ID, 'The original 6266-byte generator changed')
    rows = [{**row, 'mode': 0o644} for row in manifest['files']]
    require(len(rows) == 79 and sum(row['bytes'] for row in rows) == 34654,
            'Original complete comparison inventory changed')
    for row in rows:
        path = MANIFEST.parent / 'rootfs' / row['path'][1:]
        require(identity(path) == {k: row[k] for k in ('bytes', 'sha256')}
                and path.stat().st_mode & 0o7777 == row['mode'],
                'Committed comparison asset changed: ' + row['path'])
    return {'manifest': {'path': str(MANIFEST), **identity(MANIFEST)},
            'assets': rows, 'reference_is_generation_proof': False}


def tool_identity(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Invalid executable/library path')
    resolved = plain(path.resolve(strict=True))
    return {'resolved': str(resolved), **identity(resolved)}


def elf_dependencies(path):
    """Read ELF dynamic dependencies without executing ldd or a loader."""
    path = plain(path)
    size = path.stat().st_size
    with path.open('rb') as stream:
        def part(offset, count):
            require(0 <= offset <= size and 0 <= count <= 4 * 1024 ** 2
                    and offset + count <= size, 'Invalid host ELF extent')
            stream.seek(offset)
            value = stream.read(count)
            require(len(value) == count, 'Truncated host ELF extent')
            return value
        header = part(0, min(size, 64))
        if not header.startswith(b'\x7fELF'):
            return None
        require(len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01',
                'Host tool is not little-endian ELF64')
        h = struct.unpack('<16sHHIQQQIHHHHHH', header)
        require(h[2] == 62 and h[9] == 56 and 0 < h[10] <= 256,
                'Unsupported host ELF machine/program headers')
        segments = [struct.unpack('<IIQQQQQQ', part(h[5] + i * 56, 56)) for i in range(h[10])]
        interpreter = None
        dynamic = []
        for segment in segments:
            if segment[0] == 3:
                interpreter = part(segment[2], segment[5]).rstrip(b'\0').decode()
            if segment[0] == 2:
                require(segment[5] % 16 == 0, 'Invalid host dynamic section')
                raw = part(segment[2], segment[5])
                for offset in range(0, len(raw), 16):
                    tag, value = struct.unpack_from('<qQ', raw, offset)
                    if tag == 0:
                        break
                    dynamic.append((tag, value))
        if not dynamic:
            return {'interpreter': interpreter, 'needed': [], 'rpath': [], 'runpath': []}
        values = dict(dynamic)
        require(5 in values and 10 in values, 'Host dynamic string table is missing')
        address, length = values[5], values[10]
        loads = [p for p in segments if p[0] == 1 and p[3] <= address
                 and address + length <= p[3] + p[5]]
        require(len(loads) == 1, 'Host dynamic string table is not uniquely mapped')
        p = loads[0]
        strings = part(p[2] + address - p[3], length)
        def string(offset):
            require(offset < len(strings), 'Host dynamic string offset escapes')
            end = strings.find(b'\0', offset)
            require(end != -1, 'Unterminated host dynamic string')
            return strings[offset:end].decode()
        return {'interpreter': interpreter, 'needed': [string(v) for k, v in dynamic if k == 1],
                'rpath': string(values[15]).split(':') if 15 in values else [],
                'runpath': string(values[29]).split(':') if 29 in values else []}


def host_runtime(tools, library_paths):
    """Bind explicit search roots and statically resolved host ELF dependencies."""
    roots = {}
    for root in library_paths:
        directory = plain(root)
        roots[str(directory)] = {p.name: tool_identity(p) for p in sorted(directory.iterdir())
                                 if '.so' in p.name and (p.is_file() or p.is_symlink())}
    pending = [Path(p) for p in tools]
    for records in roots.values():
        pending += [Path(row['resolved']) for row in records.values()]
    graph = {}
    defaults = ['/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu', '/usr/local/lib', '/lib64', '/usr/lib64']
    while pending:
        path = pending.pop().resolve(strict=True)
        if str(path) in graph:
            continue
        require(len(graph) < 256, 'Host runtime dependency closure exceeds its bound')
        row = tool_identity(path)
        dynamic = elf_dependencies(path)
        row['dynamic'] = dynamic
        selected = {}
        if dynamic is not None:
            def expanded(entries):
                result = []
                for entry in entries:
                    entry = entry.replace('${ORIGIN}', str(path.parent)).replace('$ORIGIN', str(path.parent))
                    require(entry.startswith('/') and '$' not in entry, 'Unbounded host ELF library search')
                    result.append(str(Path(entry).resolve(strict=False)))
                return result
            # DT_RPATH precedes LD_LIBRARY_PATH only when DT_RUNPATH is absent.
            search = (expanded(dynamic['rpath']) if not dynamic['runpath'] else [])
            search += list(library_paths) + expanded(dynamic['runpath']) + defaults
            for needed in dynamic['needed']:
                require(needed and '/' not in needed and '\0' not in needed, 'Unsafe host DSO name')
                matches = [Path(root) / needed for root in search if (Path(root) / needed).is_file()]
                require(matches, 'Unresolved host runtime library: ' + needed)
                target = matches[0].resolve(strict=True)
                selected[needed] = str(target)
                pending.append(target)
            if dynamic['interpreter']:
                interpreter = Path(dynamic['interpreter']).resolve(strict=True)
                selected['PT_INTERP'] = str(interpreter)
                pending.append(interpreter)
        row['selected'] = selected
        graph[str(path)] = row
    loader_configuration = {}
    for selected in (Path('/etc/ld.so.cache'), Path('/etc/ld.so.conf')):
        if selected.exists():
            loader_configuration[str(selected)] = tool_identity(selected)
    configuration_directory = Path('/etc/ld.so.conf.d')
    if configuration_directory.is_dir():
        loader_configuration[str(configuration_directory)] = files.file_map(configuration_directory)
    preload = Path('/etc/ld.so.preload')
    if preload.exists():
        data = read(preload, 1024 ** 2)
        require(not any(line.split(b'#', 1)[0].strip() for line in data.splitlines()),
                'Global loader preloads are outside the explicit host tool contract')
        loader_configuration[str(preload)] = tool_identity(preload)
    else:
        loader_configuration[str(preload)] = {'absent': True}
    return {'library_paths': list(library_paths), 'search_directory_libraries': roots,
            'elf_closure': dict(sorted(graph.items())), 'loader_configuration': loader_configuration,
            'resolution_method': 'static-DT_NEEDED-and-explicit-paths', 'loader_observed': False}


def capture_inputs(settings_build):
    build = plain(settings_build)
    validated = settings.validate_build(build)
    require(validated['status'] == 'VALIDATED_NOT_RUN' and validated['kind'] == settings.contract.KIND
            and validated['build_output'] == str(build) and validated['guest_execution'] == 'not performed'
            and validated['settings_verified'] is False, 'Invalid genuine settings supplier')
    report_path = build / 'build-report.json'
    raw = read(report_path)
    require(hashlib.sha256(raw).hexdigest() == validated['hashes'][str(report_path)],
            'Settings report changed after independent validation')
    report = decode(raw)
    direct = {}
    for name in ('cosmic-config', 'cosmic-theme'):
        rows = [row for row in report['cargo_dependencies']['packages'] if row['name'] == name]
        require(len(rows) == 1 and rows[0]['source'] == 'git+https://github.com/pop-os/libcosmic#' + COMMIT,
                'Theme supplier is not the exact pinned libcosmic dependency')
        row = rows[0]
        direct[name] = {key: row[key] for key in ('name', 'version', 'source', 'manifest', 'source_tree_sha256')}
        direct[name]['checkout'] = row['git_checkout']['path']
    require(direct['cosmic-config']['checkout'] == direct['cosmic-theme']['checkout']
            and direct['cosmic-config']['source_tree_sha256'] == direct['cosmic-theme']['source_tree_sha256'],
            'Theme/config are from different upstream trees')
    checkout = plain(direct['cosmic-theme']['checkout'])
    comparator = reference_assets()
    theme_source = checkout / 'cosmic-theme/src/model/theme.rs'
    require(identity(theme_source) == {'bytes': 55054,
            'sha256': '9a2d7fc34b28c90c7c18227c2ac45a18b76980dc479799fe773a93768bad36f0'},
            'Pinned upstream Theme v2 source changed')
    license_row = next(row for row in comparator['assets'] if row['path'] == reference.LICENSE_PATH)
    require(identity(checkout / 'LICENSE') == {k: license_row[k] for k in ('bytes', 'sha256')},
            'Current pinned upstream license differs from the complete comparison license')
    searches = {name: files.file_map(build / name) for name in SEARCH_ROOTS}
    native = validated['generated_inputs']['native_search']['files']
    require(searches['native'] == {key: {k: row[k] for k in ('bytes', 'sha256')} for key, row in native.items()},
            'Theme native search differs from the independently validated settings libraries')
    externs = {}
    for name in EXTERNS:
        choices = sorted((build / SEARCH_ROOTS[0]).glob('lib' + name + '-*.rlib'))
        require(len(choices) == 1, 'Missing or ambiguous retained direct rlib: ' + name)
        externs[name] = {'path': str(plain(choices[0])), **identity(choices[0])}
    toolchain = report['toolchain']
    rust_root = plain(toolchain['selection']['rust_root'])
    rustc = plain(toolchain['tools']['rustc']['path'])
    require(rustc == rust_root / 'bin/rustc', 'Unexpected supplier Rust compiler selection')
    sdk = plain(report['sysroot'])
    host_cc = Path(toolchain['selection']['host_cc']).resolve(strict=True)
    library_paths = [str(plain(host_cc.parent.parent / 'lib')),
                     str(plain(host_cc.parent.parent.parent / 'x86_64-linux-gnu'))]
    tool_paths = {row['path'] for row in toolchain['tools'].values() if row['available'] is True}
    tool_paths.update((str(Path(sys.executable).resolve(strict=True)), '/usr/bin/env',
                      str(sdk / 'bin/ld.lld'), str(rust_root / 'lib/rustlib' / toolchain['host'] / 'bin/rust-lld')))
    tools = {path: tool_identity(path) for path in sorted(tool_paths)}
    rust_trees = {str(rust_root / 'lib/rustlib' / name / 'lib'):
                  files.file_map(rust_root / 'lib/rustlib' / name / 'lib') for name in (TARGET, toolchain['host'])}
    rust_shared = {str(p): tool_identity(p) for p in sorted((rust_root / 'lib').iterdir()) if '.so' in p.name}
    fingerprints = {name: files.file_map(build / name) for name in (
        'target/' + TARGET + '/release/.fingerprint', 'target/release/.fingerprint')}
    return {'settings_build': str(build), 'settings_proof': validated,
        'settings_report': {'path': str(report_path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
        'rlib_snapshot_is_new_input': True, 'old_settings_receipt_bound_each_rlib': False,
        'direct_dependencies': direct, 'search_roots': searches, 'fingerprints': fingerprints, 'externs': externs,
        'sdk': str(sdk), 'sdk_sysroot': files.file_map(sdk / 'sysroot', allow_internal_links=True),
        'sdk_bin': files.file_map(sdk / 'bin'), 'rustc': str(rustc), 'rust_root': str(rust_root),
        'rust_trees': rust_trees, 'rust_shared': rust_shared, 'tools': tools,
        'declared_tools': toolchain['tools'],
        'host_runtime': host_runtime(tool_paths | set(rust_shared), library_paths),
        'python': str(Path(sys.executable).resolve(strict=True)),
        'upstream_license': {'path': str(checkout / 'LICENSE'), **identity(checkout / 'LICENSE')},
        'theme_source': {'path': str(theme_source), **identity(theme_source)},
        'generator': {'path': str(SOURCE), **identity(SOURCE)}, 'comparison': comparator,
        'producer_sources': producer_sources()}


def protected_paths(inputs):
    paths = [ROOT / name for name in ('tools', 'ports', 'kernel', 'crates')]
    paths += [plain(p) for p in inputs['settings_proof']['input_directories']]
    paths += [plain(inputs[name]) for name in ('settings_build', 'sdk', 'rust_root')]
    for name, row in inputs['tools'].items():
        paths.extend((plain(Path(name).parent), plain(Path(row['resolved']).parent)))
    for row in inputs['declared_tools'].values():
        paths.append(plain(Path(row['path']).parent))
        if row['available'] is True:
            paths.append(plain(Path(row['path']).resolve(strict=True).parent))
    for name in inputs['host_runtime']['elf_closure']:
        paths.append(plain(Path(name).parent))
    return paths


def fresh_output(output, inputs):
    output = plain(output)
    require(output.is_relative_to(ROOT / 'artifacts') and output != ROOT / 'artifacts'
            and not output.exists(), 'Theme output must be a fresh repository artifact directory')
    require(all(not output.is_relative_to(path) and not path.is_relative_to(output)
                for path in protected_paths(inputs)), 'Theme output overlaps a protected input')
    return output


def link_command(inputs, output):
    build, sdk = Path(inputs['settings_build']), Path(inputs['sdk'])
    command = [inputs['rustc'], str(output / 'client.rs'), '--edition=2024', '--target', TARGET,
        '--sysroot', inputs['rust_root'], '-C', 'panic=abort', '-C', 'opt-level=2',
        '-C', 'link-self-contained=no', '-C', 'relocation-model=static', '-C', 'target-feature=+crt-static',
        '-C', 'linker=' + str(sdk / 'bin/x86_64-linux-musl-cc')]
    for name in SEARCH_ROOTS:
        command += ['-L', ('native=' if name == 'native' else 'dependency=') + str(build / name)]
    command += ['-L', 'native=' + str(sdk / 'sysroot/usr/lib'), '-l', 'static=xkbcommon',
                '-o', str(output / (EXECUTABLE + '.pending'))]
    for name in EXTERNS:
        command += ['--extern', name + '=' + inputs['externs'][name]['path']]
    return command


def environment(inputs, output, mode=None):
    if mode is None:
        # Complete allowlist; no ambient RUSTFLAGS, Cargo config, preload or XDG variables.
        return {'PATH': str(Path(inputs['python']).parent) + ':/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
                'HOME': str(output / 'link-home'), 'TMPDIR': str(output / 'tmp'),
                'LD_LIBRARY_PATH': ':'.join(inputs['host_runtime']['library_paths'])}
    require(mode in reference.IDS, 'Unsupported theme generation mode')
    return {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
            'HOME': str(output / 'homes' / mode), 'TMPDIR': str(output / 'tmp')}


def generated_keys(output, mode, comparison):
    root = plain(output / 'homes' / mode)
    config = root / '.config/cosmic' / reference.IDS[mode] / 'v2'
    actual = files.file_map(root)
    expected_names = {str((config / key).relative_to(root)) for key in reference.KEYS}
    require(set(actual) == expected_names, 'Generated HOME has missing, extra or unsafe files')
    raw = read(output / ('run-' + mode + '.stdout.log'), reference.MAX_EVIDENCE_BYTES)
    require(raw.endswith(b'\n') and len(raw.splitlines()) == 41
            and all(line.startswith(b'THEME_DEFAULTS ') for line in raw.splitlines()),
            'Host exporter stdout contains unexpected lines')
    payloads = reference.parse_serial(raw, mode)
    require(read(output / ('run-' + mode + '.stderr.log')) == b'', 'Host exporter wrote unexpected stderr')
    expected = {row['path']: row for row in comparison['assets']}
    result = {}
    for key, payload in payloads.items():
        path = config / key
        row = expected[reference.destination(mode, key)]
        require(read(path, LIMITS['max_key_bytes']) == payload
                and identity(path) == {k: row[k] for k in ('bytes', 'sha256')}
                and path.stat().st_mode & 0o7777 == row['mode'],
                'Generated key, emitted payload or original comparison differs: ' + key)
        result[reference.destination(mode, key)] = path
    return result


def assets_from_build(output, comparison):
    result = []
    expected = {row['path']: row for row in comparison['assets']}
    actual = files.file_map(output / 'rootfs')
    require(set(actual) == {path[1:] for path in expected}, 'Generated rootfs inventory differs')
    for name, row in sorted(expected.items()):
        path = output / 'rootfs' / name[1:]
        require(identity(path) == {k: row[k] for k in ('bytes', 'sha256')}
                and path.stat().st_mode & 0o7777 == row['mode'], 'Generated installed asset differs: ' + name)
        result.append(row)
    return result


def inventory(output):
    rows = files.file_map(output)
    rows.pop(RECEIPT, None)
    return {name: {**row, 'mode': (output / name).stat().st_mode & 0o7777} for name, row in rows.items()}


def write_report(output, report):
    temporary = output / (RECEIPT + '.pending')
    with temporary.open('w') as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o644)
    temporary.replace(output / RECEIPT)


def run_step(command, env, output, label, deadline, start, report):
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Shared theme compiler/exporter deadline exceeded')
    row = {'label': label, 'argv': command, 'cwd': str(ROOT), 'environment': env,
           'started_seconds': time.monotonic() - start, 'timeout_seconds': remaining,
           'stdout': label + '.stdout.log', 'stderr': label + '.stderr.log', 'status': 'running'}
    report['steps'].append(row)
    write_report(output, report)
    try:
        processes.run_bounded(command, ROOT, env, output / row['stdout'], remaining,
            LIMITS['min_free_bytes'], LIMITS['max_output_bytes'], budget_root=output,
            stderr_log=output / row['stderr'])
    except BaseException as error:
        row.update(status='failed', error=str(error), ended_seconds=time.monotonic() - start)
        # The original bounded runner records a real nonzero exit in its exception
        # and performs process-group termination/reaping on all failure paths.
        write_report(output, report)
        raise
    row.update(status='exited', returncode=0, ended_seconds=time.monotonic() - start)
    require(row['ended_seconds'] <= LIMITS['timeout_seconds'], 'Shared theme native deadline exceeded')
    for name in ('stdout', 'stderr'):
        (output / row[name]).chmod(0o644)
    write_report(output, report)


def build(settings_build, output):
    require(sys.platform.startswith('linux'), 'Linux host generation requires Linux')
    native_session.idle_native_host()
    before = capture_inputs(settings_build)
    output = fresh_output(output, before)
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'kind': KIND, 'status': 'building', 'output': str(output),
        'architecture': 'x86_64', 'target': TARGET, 'limits': LIMITS, 'timeout_scope': TIMEOUT_SCOPE,
        'inputs_before': before, 'inputs_preserved': False, 'steps': [], 'host_generation': False,
        'guest_execution': False, 'full_cosmic_complete': False, 'reference_is_generation_proof': False,
        'network_requested': False, 'build_script_network_sandbox': False}
    write_report(output, report)
    old_umask = os.umask(0o022)
    try:
        for relative in ('tmp', 'link-home', 'homes/dark', 'homes/light'):
            (output / relative).mkdir(parents=True, exist_ok=False)
        raw = read(SOURCE, SOURCE_ID['bytes'])
        require({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} == SOURCE_ID,
                'Exporter source changed before copy')
        (output / 'client.rs').write_bytes(raw)
        (output / 'client.rs').chmod(0o644)
        start = time.monotonic()
        deadline = start + LIMITS['timeout_seconds']
        run_step(link_command(before, output), environment(before, output), output, 'link', deadline, start, report)
        pending = output / (EXECUTABLE + '.pending')
        require(identity(pending)['bytes'] <= LIMITS['max_output_bytes'], 'Theme executable exceeds original output budget')
        build_sysroot.inspect_elf(pending, 'x86_64')
        pending.chmod(0o755)
        pending.rename(output / EXECUTABLE)
        report['executable'] = {'path': str(output / EXECUTABLE), **identity(output / EXECUTABLE), 'mode': 0o755}
        report['elf'] = build_sysroot.inspect_elf(output / EXECUTABLE, 'x86_64')
        generated = {}
        for mode in ('dark', 'light'):
            require(not any((output / 'homes' / mode).iterdir()), 'Host generation HOME is not pristine')
            run_step([str(output / EXECUTABLE), mode], environment(before, output, mode),
                     output, 'run-' + mode, deadline, start, report)
            generated.update(generated_keys(output, mode, before['comparison']))
        report['native_elapsed_seconds'] = time.monotonic() - start
        require(report['native_elapsed_seconds'] <= LIMITS['timeout_seconds'], 'Shared theme native deadline exceeded')
        generated[reference.LICENSE_PATH] = Path(before['upstream_license']['path'])
        for name, source in sorted(generated.items()):
            target = output / 'rootfs' / name[1:]
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(read(source, reference.common.MAX_INPUT_BYTES))
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o644)
        report['assets'] = assets_from_build(output, before['comparison'])
        report['inputs_after'] = capture_inputs(settings_build)
        require(report['inputs_after'] == before, 'Theme generation supplier/source/tool closure changed')
        for mode in ('dark', 'light'):
            generated_keys(output, mode, before['comparison'])
        report['files'] = inventory(output)
        processes.resource_check(output, LIMITS['min_free_bytes'], LIMITS['max_output_bytes'])
        report.update(status='HOST_GENERATED_NOT_GUEST_RUN', host_generation=True, inputs_preserved=True)
        write_report(output, report)
        return report
    except BaseException as error:
        report.update(status='failed', error=str(error), host_generation=False, inputs_preserved=False)
        write_report(output, report)
        raise
    finally:
        os.umask(old_umask)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-lock', type=Path, default=NATIVE_LOCK)
    args = parser.parse_args(argv)
    try:
        require(plain(args.native_lock) == plain(NATIVE_LOCK), 'Use the original shared native lease')
        with native_session.native_lease(args.native_lock):
            report = build(args.settings_build, args.output)
        print(json.dumps({'status': report['status'], 'output': report['output'],
                          'host_generation': True, 'guest_execution': False}, indent=2))
        return 0
    except (BuildError, processes.CosmicBuildError, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
