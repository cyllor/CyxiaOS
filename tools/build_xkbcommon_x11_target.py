#!/usr/bin/env python3
"""Build pinned xkbcommon core + X11 in a fresh output, with a read-only SDK.

Offline only. Native Bison is reused with its original source/build provenance.
The old build_xkbcommon_x11.py remains unchanged. No target code is executed.
"""
import argparse
import ast
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import sys
import time
from types import SimpleNamespace

if __package__:
    from . import desktop_ports, build_cosmic as base, build_sysroot as sdk_tools
    from .build_dbus import clean_environment, file_map
    from .native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
    from .target_profile import profile_for
else:
    import desktop_ports
    import build_cosmic as base
    import build_sysroot as sdk_tools
    from build_dbus import clean_environment, file_map
    from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
    from target_profile import profile_for

ROOT = sdk_tools.ROOT
MANIFEST = ROOT / 'ports/cosmic/xkbcommon-source.json'
SOURCE_SHA256 = 'acc4d5f7c3cbba5f9f8d08d8bdbeede84ecede46792f47929aa9321873385528'
BISON_SHA256 = '9bba0214ccf7f1079c5d59210045227bcf619519840ebfa80cd3849cff5a5bf2'
MIN_FREE_BYTES = 512 * 1024**2
MAX_OUTPUT_BYTES = 256 * 1024**2
BUILD_TIMEOUT_SECONDS = 900
LIBRARIES = ('libxkbcommon.a', 'libxkbcommon-x11.a')
BuildError = sdk_tools.BuildError
digest = base.digest


def regular(path):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise BuildError('Expected retained regular file: ' + str(path))
    return path


def document(path):
    value = json.loads(regular(path).read_text(), object_pairs_hook=desktop_ports.unique_object)
    if not isinstance(value, dict):
        raise BuildError('Expected JSON object: ' + str(path))
    return value


def producer_sources(entry):
    """Bind transitive local imports without importing an OS/guest entry point."""
    pending, result = [Path(entry).resolve()], {}
    while pending:
        path = pending.pop()
        key = path.relative_to(ROOT).as_posix()
        if key in result:
            continue
        result[key] = digest(regular(path))
        for node in ast.walk(ast.parse(path.read_bytes())):
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module] if node.module else [item.name for item in node.names]
            else:
                continue
            for name in names:
                local = ROOT / 'tools' / (name.split('.')[0] + '.py')
                if local.is_file():
                    pending.append(local)
    return dict(sorted(result.items()))


def executable(path):
    path = Path(path).resolve(strict=True)
    regular(path)
    if not os.access(path, os.X_OK):
        raise BuildError('Tool is not executable: ' + str(path))
    return {'path': str(path), 'sha256': digest(path)}


def load_manifest(path=MANIFEST):
    package = document(path)
    bison = package['host_tools'][0]
    sdk_tools.validate_packages([package, bison])
    if (package['name'] != 'libxkbcommon' or package['version'] != '1.13.2'
            or package['expected_sha256'] != SOURCE_SHA256
            or bison['name'] != 'bison' or bison['version'] != '3.8.2'
            or bison['expected_sha256'] != BISON_SHA256):
        raise BuildError('Expected the reviewed libxkbcommon 1.13.2 / Bison 3.8.2 pins')
    return package


def validate_output(output, *inputs):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise BuildError('Output must be fresh; existing evidence is preserved')
    output = base.no_symlink_path(output)
    for value in inputs:
        value = Path(value).resolve()
        if output.is_relative_to(value) or value.is_relative_to(output):
            raise BuildError('Output overlaps read-only input: ' + str(value))
    return output


def validate_driver(sdk, target, compiler):
    """Compare the actual driver with the frozen producer, rendered in memory."""
    path = target.cc(sdk)
    text = regular(path).read_text()
    values = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = node.targets[0]
            if isinstance(name, ast.Name) and name.id in ('CC', 'LIB', 'LD', 'BUILTINS'):
                if name.id in values:
                    raise BuildError('Duplicate compiler driver identity')
                values[name.id] = ast.literal_eval(node.value)
    cc = values.get('CC', [])
    prefix = [compiler, *target.clang_args, '-nostdinc', '-isystem',
              str(sdk / 'sysroot/usr/include'), '-isystem']
    if (not isinstance(cc, list) or cc[:-1] != prefix or not isinstance(cc[-1], str)
            or values.get('LIB') != str(sdk / 'sysroot/usr/lib')
            or values.get('LD') != str(sdk / 'bin/ld.lld')
            or values.get('BUILTINS') != target.builtins_archive):
        raise BuildError('Compiler driver target, SDK paths or inputs differ')
    resource = base.no_symlink_path(Path(cc[-1]))
    if not resource.is_dir() or resource.name != 'include':
        raise BuildError('Missing actual Clang resource headers')

    class Capture:
        def write_text(self, content):
            self.content = content

        def chmod(self, mode):
            pass

    capture = Capture()
    render_target = SimpleNamespace(cc=lambda unused: capture,
                                    builtins_archive=target.builtins_archive)
    sdk_tools.Builder.write_cc_wrapper(SimpleNamespace(target=render_target, output=sdk),
                                       cc, sdk / 'sysroot/usr/lib', sdk / 'bin/ld.lld')
    if text != capture.content:
        raise BuildError('Compiler driver differs from frozen Builder.write_cc_wrapper')
    return {'sha256': digest(path), 'resource_headers': str(resource),
            'resource_files': file_map(resource, allow_internal_links=True)}


def sdk_identity(sdk, target):
    sdk = base.no_symlink_path(sdk)
    report_path = sdk / 'build-report.json'
    report = document(report_path)
    target.require_report(report)
    if report.get('status') != 'cross-built':
        raise BuildError('A successful original core SDK report is required')
    libraries = {name: target.inspect_archive(sdk / 'sysroot/usr/lib' / name)
                 for name in ('libc.a', target.builtins_archive, 'libXau.a', 'libxcb.a', 'libxcb-xkb.a')}
    if (libraries['libc.a']['sha256'] != report['libc_sha256']
            or libraries[target.builtins_archive]['sha256'] != report['builtins_sha256']):
        raise BuildError('SDK core library identity differs from original producer')
    reports = {'build-report.json': digest(report_path)}
    tool_paths = report['toolchain']
    driver_hash = digest(regular(target.cc(sdk)))
    foundation_status = None
    if driver_hash != report['driver_sha256']:
        origin = document(sdk / 'sdk-base-origin.json')
        foundation = document(sdk / 'sdk-foundation-report.json')
        foundation_status = foundation.get('status')
        completed = foundation_status == 'NATIVE_LIBRARIES_BUILT_NOT_RUN'
        steps = foundation.get('steps', [])
        # An unrelated later zlib/pixman failure does not erase the completed
        # X.Org step or rewrite the original failed receipt into a success.
        xorg_completed_before_failure = (
            foundation_status == 'FAILED'
            and any(step.get('name') == 'xorg' and step.get('status') == 'COMPLETED' for step in steps)
            and any(step.get('name') in ('zlib', 'pixman') and step.get('status') == 'FAILED' for step in steps)
        )
        if (origin.get('status') != 'COPIED_NATIVE_INPUTS_NOT_RUN'
                or origin['original_files']['build-report.json']['sha256'] != reports['build-report.json']
                or not (completed or xorg_completed_before_failure)
                or (completed and foundation.get('parent_preserved') is not True)
                or foundation['drivers'][target.cc(sdk).name] != driver_hash
                or (completed and foundation['sdk_tree'] != base.tree_identity(sdk / 'sysroot'))
                or foundation['producers'].get('tools/build_sysroot.py') != digest(sdk_tools.__file__)):
            raise BuildError('Relocated SDK driver lacks matching completed foundation/X.Org provenance')
        xorg = document(sdk / 'xorg-bootstrap-report.json')
        target.require_report(xorg)
        for name in ('libXau.a', 'libxcb.a'):
            if libraries[name] != xorg['target_archives'][name]:
                raise BuildError('Completed X.Org archive differs from its build receipt: ' + name)
        for name, expected in foundation['producers'].items():
            if digest(regular(ROOT / name)) != expected:
                raise BuildError('SDK foundation producer changed: ' + name)
        tool_paths = {name: item['path'] for name, item in foundation['tools'].items()}
        for name, item in foundation['tools'].items():
            if executable(item['path'])['sha256'] != item['sha256']:
                raise BuildError('SDK foundation tool changed: ' + name)
        reports.update({name: digest(sdk / name) for name in
                        ('sdk-base-origin.json', 'sdk-foundation-report.json', 'xorg-bootstrap-report.json')})
    tools = {name: executable(tool_paths[name]) for name in ('clang', 'rust-lld', 'llvm-ar', 'llvm-strip')}
    # Preserve the producer's spelled path in the exact compiler driver check.
    driver = validate_driver(sdk, target, tool_paths['clang'])
    for name, command in {
        'ld.lld': [tool_paths['rust-lld'], '-flavor', 'gnu'],
        target.c_target + '-ar': [tool_paths['llvm-ar']],
        target.c_target + '-ranlib': [tool_paths['llvm-ar'], 's'],
    }.items():
        expected = '#!/bin/sh\nexec ' + shlex.join(command) + ' "$@"\n'
        if regular(sdk / 'bin' / name).read_text() != expected:
            raise BuildError('SDK tool wrapper differs from recorded tools: ' + name)
    return {'path': str(sdk), 'reports': reports, 'libraries': libraries,
            'original_foundation_status': foundation_status,
            'driver': driver, 'tools': tools,
            'sysroot_files': file_map(sdk / 'sysroot', allow_internal_links=True),
            'wrapper_files': file_map(sdk / 'bin', allow_internal_links=True)}


def bison_identity(prefix, report_path):
    prefix, report_path = base.no_symlink_path(prefix), base.no_symlink_path(report_path)
    report = document(report_path)
    native = report['native_bison']
    source = next(item['source'] for item in report['sources']
                  if item['source']['identity']['name'] == 'bison')
    if (report.get('status') != 'cross-built' or report['manifest_sha256'] != digest(MANIFEST)
            or source['sha256'] != BISON_SHA256
            or native['version'] != 'bison (GNU Bison) 3.8.2'
            or native['sha256'] != digest(regular(prefix / 'bin/bison'))):
        raise BuildError('Native Bison source/build provenance or binary differs')
    for relative in ('share/bison/skeletons/yacc.c', 'share/bison/m4sugar/m4sugar.m4'):
        regular(prefix / relative)
    return {'prefix': str(prefix), 'report': str(report_path),
            'report_sha256': digest(report_path), 'source_sha256': source['sha256'],
            'version': native['version'], 'binary': executable(prefix / 'bin/bison'),
            'files': file_map(prefix, allow_internal_links=True)}


def build_options(cross):
    return ['--prefix=/usr', '--libdir=lib', '--wrap-mode=nofallback',
            '--cross-file=' + str(cross), '-Dbuildtype=release',
            '-Ddefault_library=static', '-Db_staticpic=false',
            '-Denable-x11=true', '-Denable-wayland=false', '-Denable-docs=false',
            '-Denable-xkbregistry=false', '-Denable-tools=false',
            '-Denable-bash-completion=false', '-Dxkb-config-root=/usr/share/X11/xkb',
            '-Dc_args=-ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables']


class Builder:
    def __init__(self, args, output, target, inputs, bison):
        self.args, self.output, self.target = args, output, target
        self.deadline = time.monotonic() + BUILD_TIMEOUT_SECONDS
        self.commands = []
        self.tools = {name: item for name, item in inputs['tools'].items()}
        for name in ('pkg-config', 'ninja', 'm4'):
            path = shutil.which(name, path=str(sdk_tools.BUILD_TOOLS / 'bin') + os.pathsep + os.environ.get('PATH', ''))
            if not path:
                raise BuildError('Missing native build tool: ' + name)
            self.tools[name] = executable(path)
        self.tools['meson'] = executable(sdk_tools.BUILD_TOOLS / 'bin/meson')
        self.tools['python'] = executable(sys.executable)
        self.tools['bison'] = bison['binary']
        self.env = clean_environment()
        self.env.update(PATH=os.pathsep.join(dict.fromkeys([
            str(Path(bison['binary']['path']).parent),
            str(Path(self.tools['m4']['path']).parent),
            str(sdk_tools.BUILD_TOOLS / 'bin'),
        ] + [
            str(Path(item['path']).parent) for item in self.tools.values()
        ] + [str(sdk_tools.BUILD_TOOLS / 'bin'), '/usr/bin', '/bin'])),
            BISON_PKGDATADIR=str(Path(bison['prefix']) / 'share/bison'),
            M4=self.tools['m4']['path'], TMPDIR=str(output / 'tmp'),
            PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
        target_root = Path(inputs['path']) / 'sysroot'
        pcdirs = [str(target_root / path) for path in ('usr/lib/pkgconfig', 'usr/share/pkgconfig')]
        pc_env = {'PKG_CONFIG_PATH': '', 'PKG_CONFIG_LIBDIR': os.pathsep.join(pcdirs),
                  'PKG_CONFIG_SYSROOT_DIR': str(target_root)}
        self.env.update(pc_env)
        pc = base.target_pkg_wrapper(output / 'bin/target-pkg-config',
                                     Path(self.tools['pkg-config']['path']), pc_env, target_root)
        cross = output / 'cross.ini'
        cross.write_text('[binaries]\nc = ' + repr(str(target.cc(Path(inputs['path'])))) + '\n'
                         + 'ar = ' + repr(self.tools['llvm-ar']['path']) + '\n'
                         + 'strip = ' + repr(self.tools['llvm-strip']['path']) + '\n'
                         + 'pkg-config = ' + repr(str(pc)) + '\n' + target.meson_machine()
                         + '[properties]\nneeds_exe_wrapper = true\nsys_root = ' + repr(str(target_root)) + '\n'
                         + 'pkg_config_libdir = ' + repr(pcdirs) + '\n')
        self.cross = cross

    def run(self, command, log, extra=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BuildError('xkbcommon X11 total build deadline exceeded')
        command = [str(value) for value in command]
        self.commands.append(command)
        base.run_bounded(command, self.output, {**self.env, **(extra or {})},
                         self.output / 'logs' / log, remaining, MIN_FREE_BYTES,
                         MAX_OUTPUT_BYTES, budget_root=self.output)


def validate_build(output):
    output = base.no_symlink_path(output)
    report = document(output / 'build-report.json')
    target = profile_for(report['architecture'])
    target.require_report(report)
    if report['status'] != 'cross-built' or report['guest_execution'] != 'not performed':
        raise BuildError('No completed target-library build receipt')
    libraries = {name: target.inspect_archive(output / 'sdk/usr/lib' / name) for name in LIBRARIES}
    if (libraries != report['libraries'] or file_map(output / 'sdk') != report['installed_files']
            or file_map(output / 'licenses') != report['licenses']
            or file_map(output / 'logs') != report['logs']):
        raise BuildError('Installed target libraries or retained evidence changed')
    return report


def build(args):
    target = profile_for(args.arch)
    sdk, cache = base.no_symlink_path(args.sysroot), base.no_symlink_path(args.cache)
    bison_prefix = args.bison_prefix or sdk / 'xkbcommon-host-tools'
    bison_report = args.bison_report or sdk / 'xkbcommon-build-report.json'
    output = validate_output(args.output, sdk, cache, bison_prefix, bison_report)
    if type(args.jobs) is not int or not 1 <= args.jobs <= 4:
        raise BuildError('jobs must be in 1..4')
    package = load_manifest()
    with native_lease(args.native_lock):
        idle_native_host()
        inputs = sdk_identity(sdk, target)
        bison = bison_identity(bison_prefix, bison_report)
        cached = desktop_ports.verify(package, cache, max_bytes=8 * 1024**2)
        base.resource_check(output.parent, MIN_FREE_BYTES + MAX_OUTPUT_BYTES, 2**63)
        output.mkdir()
        for name in ('source', 'logs', 'licenses', 'stage', 'bin', 'tmp'):
            (output / name).mkdir()
        report = {'schema_version': 1, 'status': 'building', 'architecture': target.architecture,
                  'target_triple': target.rust_target, 'guest_execution': 'not performed',
                  'cosmic_session_ready': False, 'network': False, 'input_sdk_read_only': True,
                  'manifest_sha256': digest(MANIFEST), 'source_archive': cached,
                  'inputs': inputs, 'native_bison': bison,
                  'producer_inputs': producer_sources(Path(__file__)),
                  'bounds': {'timeout_seconds': BUILD_TIMEOUT_SECONDS, 'min_free_bytes': MIN_FREE_BYTES,
                             'max_output_bytes': MAX_OUTPUT_BYTES, 'jobs': args.jobs}}
        try:
            builder = Builder(args, output, target, inputs, bison)
            report.update(commands=builder.commands, tools=builder.tools,
                          cross_file_sha256=digest(builder.cross),
                          pkg_config_wrapper_sha256=digest(output / 'bin/target-pkg-config'))
            for name in ('clang', 'llvm-ar', 'llvm-strip', 'pkg-config', 'ninja', 'm4', 'meson', 'python', 'bison'):
                builder.run([builder.tools[name]['path'], '--version'], name + '-version.log')
            bison_version = (output / 'logs/bison-version.log').read_text().splitlines()[0]
            if bison_version != bison['version']:
                raise BuildError('Running native Bison version differs from provenance')
            builder.run([builder.tools['clang']['path'], '-print-resource-dir'], 'clang-resource.log')
            resource = str(Path((output / 'logs/clang-resource.log').read_text().strip()) / 'include')
            if resource != inputs['driver']['resource_headers']:
                raise BuildError('Compiler resource headers differ from recorded driver')
            source = sdk_tools.unpack(package, cached, output / 'source')
            before = file_map(source, allow_internal_links=True)
            report['source_tree'] = before
            shutil.copyfile(source / package['license_file'], output / 'licenses/LICENSE')
            options = build_options(builder.cross)
            report['options'] = options
            meson = builder.tools['meson']['path']
            directory = output / 'build'
            builder.run([meson, 'setup', directory, source, *options], 'setup.log')
            builder.run([meson, 'compile', '-C', directory, '-j', str(args.jobs),
                         'xkbcommon', 'xkbcommon-x11'], 'compile.log')
            builder.run([meson, 'install', '-C', directory, '--no-rebuild'], 'install.log',
                        {'DESTDIR': str(output / 'stage')})
            report['libraries'] = {name: target.inspect_archive(output / 'stage/usr/lib' / name)
                                   for name in LIBRARIES}
            for relative in ('usr/include/xkbcommon/xkbcommon.h', 'usr/include/xkbcommon/xkbcommon-x11.h',
                             'usr/lib/pkgconfig/xkbcommon.pc', 'usr/lib/pkgconfig/xkbcommon-x11.pc'):
                regular(output / 'stage' / relative)
            if (file_map(source, allow_internal_links=True) != before
                    or sdk_identity(sdk, target) != inputs
                    or bison_identity(bison_prefix, bison_report) != bison
                    or desktop_ports.verify(package, cache, max_bytes=8 * 1024**2) != cached):
                raise BuildError('Source, read-only SDK, Bison or archive changed during build')
            for item in builder.tools.values():
                if executable(item['path']) != item:
                    raise BuildError('Native build tool changed during build')
            if producer_sources(Path(__file__)) != report['producer_inputs']:
                raise BuildError('Build producer changed during execution')
            base.resource_check(output, MIN_FREE_BYTES, MAX_OUTPUT_BYTES)
            report.update(installed_files=file_map(output / 'stage'),
                          licenses=file_map(output / 'licenses'), logs=file_map(output / 'logs'),
                          inputs_preserved=True, source_preserved=True)
            (output / 'stage').rename(output / 'sdk')
            report['status'] = 'cross-built'
        except Exception as error:
            report.update(status='failed', error=str(error))
            raise
        finally:
            (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
        return validate_build(output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=('x86_64', 'aarch64'), required=True)
    parser.add_argument('--sysroot', type=Path, required=True, help='Read-only input SDK prefix')
    parser.add_argument('--output', type=Path, required=True, help='Fresh output; installs into output/sdk/usr')
    parser.add_argument('--cache', type=Path, default=desktop_ports.DEFAULT_CACHE)
    parser.add_argument('--bison-prefix', type=Path, help='Existing genuine native Bison prefix')
    parser.add_argument('--bison-report', type=Path, help='Original successful Bison/core build report')
    parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    parser.add_argument('--jobs', type=int, default=1)
    args = parser.parse_args(argv)
    try:
        report = build(args)
        print(json.dumps({'status': report['status'], 'report': str(args.output / 'build-report.json'),
                          'architecture': report['architecture'], 'guest_execution': 'not performed'}))
        return 0
    except (BuildError, base.CosmicBuildError, desktop_ports.PortError, OSError, ValueError, KeyError, StopIteration) as error:
        print('xkbcommon-x11-target: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
