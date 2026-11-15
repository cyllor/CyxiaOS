#!/usr/bin/env python3
"""Build real upstream static D-Bus in a fresh directory, using a read-only SDK.

Inventory is read-only. Build requires --output, is offline by default, holds
the shared native lease, and bounds every compiler/build subprocess. --fetch
permits missing pinned archives; --dbus-archive imports a pinned local archive.
Only named target programs are built. No target executable is run or installed
into the input SDK. The resulting rootfs/config and binaries need guest tests.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

if __package__:
    from . import desktop_ports
    from .build_sysroot import (ROOT, BUILD_TOOLS, Builder as SysrootBuilder,
                               BuildError, clean_env, digest, inspect_elf,
                               unpack, validate_packages)
    from .build_cosmic import run_bounded, CosmicBuildError
    from .native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
    from .target_profile import profile_for
else:
    import desktop_ports
    from build_sysroot import (ROOT, BUILD_TOOLS, Builder as SysrootBuilder,
                              BuildError, clean_env, digest, inspect_elf,
                              unpack, validate_packages)
    from build_cosmic import run_bounded, CosmicBuildError
    from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
    from target_profile import profile_for

MANIFEST = ROOT / 'ports/dbus/manifest.json'
EXPAT_MANIFEST = ROOT / 'ports/libc/openbox-fonts.json'
SESSION_CONFIG = ROOT / 'ports/dbus/session.conf'
SESSION_ADDRESS = 'unix:path=/run/user/0/bus'
GUEST_CONFIG = '/etc/dbus-1/session.conf'
PROBE_SOURCE = ROOT / 'user/ported/dbus_probe.c'
ROOTFS_ASSETS = {GUEST_CONFIG: SESSION_CONFIG,
                 '/etc/passwd': ROOT / 'ports/dbus/passwd',
                 '/etc/group': ROOT / 'ports/dbus/group'}
MIN_FREE_BYTES = 1024 ** 3
MAX_OUTPUT_BYTES = 512 * 1024 ** 2
BUILD_TIMEOUT_SECONDS = 900
ARCHIVE_LIMIT = 8 * 1024 ** 2
BINARIES = {'dbus-daemon': 'bus/dbus-daemon', 'dbus-send': 'tools/dbus-send',
            'dbus-uuidgen': 'tools/dbus-uuidgen'}
PUBLIC_HEADERS = (
    'dbus-address.h', 'dbus-bus.h', 'dbus-connection.h', 'dbus-errors.h',
    'dbus-macros.h', 'dbus-memory.h', 'dbus-message.h', 'dbus-misc.h',
    'dbus-pending-call.h', 'dbus-protocol.h', 'dbus-server.h', 'dbus-shared.h',
    'dbus-signature.h', 'dbus-syntax.h', 'dbus-threads.h', 'dbus-types.h', 'dbus.h',
)


def load_manifest(path=MANIFEST, expat_manifest=EXPAT_MANIFEST):
    data = json.loads(Path(path).read_text(), object_pairs_hook=desktop_ports.unique_object)
    if (data.get('schema_version') != 1 or
            data.get('expat_source_manifest') != 'ports/libc/openbox-fonts.json' or
            data.get('session_config') != 'ports/dbus/session.conf'):
        raise BuildError('Unsupported D-Bus manifest references')
    expat = next(package for package in json.loads(Path(expat_manifest).read_text())['packages']
                 if package['name'] == 'expat')
    dbus = data['dbus']
    validate_packages([expat, dbus])
    if (expat['version'] != '2.7.5' or
            expat['expected_sha256'] != '1032dfef4ff17f70464827daa28369b20f6584d108bc36f17ab1676e1edd2f91' or
            dbus['name'] != 'dbus' or dbus['version'] != '1.16.4' or
            dbus.get('depends_on') != ['expat']):
        raise BuildError('D-Bus recipe requires the reviewed D-Bus/Expat source closure')
    return {**data, 'packages': [expat, dbus]}


def config_identity(path):
    """Fail closed if a build silently changes the reviewed session policy."""
    root = ET.fromstring(Path(path).read_bytes())
    simple = {tag: [element.text for element in root.findall(tag)]
              for tag in ('type', 'auth', 'listen')}
    policies = root.findall('policy')
    expected = [
        ({'context': 'default'}, [('deny', {'user': '*'}), ('allow', {'user': '0'}),
          ('deny', {'own': '*'}), ('deny', {'send_destination': '*'}),
          ('deny', {'receive_sender': '*'})]),
        ({'user': '0'}, [('allow', {'own': '*'}), ('allow', {'send_destination': '*'}),
                       ('allow', {'receive_sender': '*'})]),
    ]
    actual = [(element.attrib, [(rule.tag, rule.attrib) for rule in element])
              for element in policies]
    if (root.tag != 'busconfig' or root.attrib or
            simple != {'type': ['session'], 'auth': ['EXTERNAL'], 'listen': [SESSION_ADDRESS]} or
            actual != expected or
            any(child.tag not in {'type', 'auth', 'listen', 'keep_umask', 'policy', 'limit'}
                for child in root)):
        raise BuildError('Session policy must retain EXTERNAL, UID 0, and no activation/includes')
    return {'source': str(path), 'sha256': digest(Path(path)), 'guest_path': GUEST_CONFIG,
            'address': SESSION_ADDRESS, 'authentication': 'EXTERNAL', 'uid': 0,
            'service_activation': False, 'system_bus': False}


def validate_output(output, sdk):
    output, sdk = Path(output), Path(sdk).resolve()
    if output.exists() or output.is_symlink():
        raise BuildError('Build output must be fresh; existing evidence is never overwritten')
    output = output.resolve()
    if output.is_relative_to(sdk) or sdk.is_relative_to(output):
        raise BuildError('Build output must be separate from the read-only input SDK')
    return output


def sdk_identity(sdk, target):
    sdk = Path(sdk)
    report_path = sdk / 'build-report.json'
    report = json.loads(report_path.read_text())
    target.require_report(report)
    lib = sdk / 'sysroot/usr/lib'
    libc = target.inspect_archive(lib / 'libc.a')
    if libc['sha256'] != report.get('libc_sha256'):
        raise BuildError('SDK libc identity differs from its producer report')
    return {'path': str(sdk), 'report_sha256': digest(report_path), 'libc': libc,
            'builtins': target.inspect_archive(lib / target.builtins_archive),
            'compiler_driver_sha256': digest(target.cc(sdk)),
            'wrapper_sha256': file_map(sdk / 'bin', allow_internal_links=True)}


def file_map(directory, *, allow_internal_links=False):
    """Bind every file/link; SDK compatibility links must stay within this tree.

    Links are not traversed during enumeration. Their resolved target is also
    present under its real path, so both link identity and target bytes are
    bound. Generated evidence rejects links altogether.
    """
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise BuildError('Receipt tree must be a real directory: ' + str(directory))
    directory = directory.resolve(strict=True)
    result = {}
    for path in sorted(directory.rglob('*')):
        relative = str(path.relative_to(directory))
        if path.is_symlink():
            if not allow_internal_links:
                raise BuildError('Unexpected symlink in receipt tree: ' + str(path))
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise BuildError('Unresolvable SDK compatibility symlink: ' + str(path)) from error
            if not resolved.is_relative_to(directory):
                raise BuildError('SDK compatibility symlink escapes receipt tree: ' + str(path))
            if not (resolved.is_file() or resolved.is_dir()):
                raise BuildError('Unsupported SDK compatibility symlink target: ' + str(path))
            result[relative] = {'symlink': os.readlink(path),
                                'resolved': str(resolved.relative_to(directory)),
                                'kind': 'file' if resolved.is_file() else 'directory'}
        elif path.is_file():
            result[relative] = checked_digest(path)
        elif not path.is_dir():
            raise BuildError('Unexpected entry in receipt tree: ' + str(path))
    return result


def tree_identity(directory):
    """Bind source data and archive-internal symlinks without following links."""
    if directory.is_symlink() or not directory.is_dir():
        raise BuildError('Source tree must be a real directory: ' + str(directory))
    result = {}
    for path in sorted(directory.rglob('*')):
        key = str(path.relative_to(directory))
        if path.is_symlink():
            result[key] = {'symlink': os.readlink(path)}
        elif path.is_file():
            result[key] = {'sha256': digest(path)}
        elif not path.is_dir():
            raise BuildError('Unexpected source entry: ' + str(path))
    return result


def clean_environment():
    env = clean_env()
    for key in list(env):
        if (key.startswith(('PKG_CONFIG', 'RUST', 'CARGO', 'LD_', 'DYLD_', 'ac_cv_', 'lt_cv_')) or
                key.endswith(('_CFLAGS', '_LIBS')) or
                key in ('DESTDIR', 'LIBS', 'CONFIG_SITE', 'CMAKE_TOOLCHAIN_FILE',
                        'CC_FOR_BUILD', 'CXX_FOR_BUILD', 'PYTHONPATH', 'PYTHONHOME',
                        'MESON_ARGS', 'MESON_CROSS_FILE', 'NINJAFLAGS')):
            env.pop(key)
    return env


def source_record(package, cache, output, *, fetch=False, archive=None):
    """An existing bad entry is an error, never a reason to try the network."""
    if archive is not None:
        return desktop_ports.fetch(package, output / 'source-cache', offline_file=Path(archive),
                                   max_bytes=ARCHIVE_LIMIT)
    cached = desktop_ports.destination(cache, package)
    if cached.exists() or cached.is_symlink() or not fetch:
        return desktop_ports.verify(package, cache, max_bytes=ARCHIVE_LIMIT)
    return desktop_ports.fetch(package, output / 'source-cache', online=True,
                               max_bytes=ARCHIVE_LIMIT)


class Builder(SysrootBuilder):
    def __init__(self, output, sdk, jobs, target):
        super().__init__(output, {}, jobs, target)
        self.sdk = sdk
        self.env = clean_environment()
        self.deadline = time.monotonic() + BUILD_TIMEOUT_SECONDS
        for directory in ('logs', 'bin', 'source', 'licenses', 'tmp', 'stage'):
            (output / directory).mkdir()

    def run(self, command, log, cwd=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BuildError('D-Bus build deadline exceeded')
        self.env['TMPDIR'] = str(self.output / 'tmp')
        command = [str(arg) for arg in command]
        self.commands.append(command)
        try:
            run_bounded(command, cwd or self.output, self.env, self.output / 'logs' / log,
                        remaining, MIN_FREE_BYTES, MAX_OUTPUT_BYTES, budget_root=self.output)
        except CosmicBuildError as error:
            raise BuildError(str(error)) from error

    def capture(self, command, log, cwd=None):
        self.run(command, log, cwd)
        return (self.output / 'logs' / log).read_text()

    def discover(self):
        script = ('import json,sys; sys.path.insert(0,' + repr(str(ROOT / 'tools')) + '); '
                  'from build_sysroot import toolchain; print(json.dumps(toolchain()))')
        self.tools = json.loads(self.capture([sys.executable, '-c', script], 'toolchain.log'))
        for name in ('pkg-config', 'ninja'):
            path = shutil.which(name, path=str(BUILD_TOOLS / 'bin') + os.pathsep + os.environ.get('PATH', ''))
            if not path:
                raise BuildError('Missing build tool: ' + name)
            self.tools[name] = path
        meson = BUILD_TOOLS / 'bin/meson'
        if not meson.is_file():
            raise BuildError('Missing project-local Meson: ' + str(meson))
        self.tools['meson'] = str(meson)
        self.tools['python'] = sys.executable

    def target_environment(self):
        self.env = clean_environment()
        stage = self.output / 'stage'
        self.env.update(
            CC=str(self.target.cc(self.sdk)), CXX=str(self.target.cc(self.sdk)),
            AR=self.tools['llvm-ar'],
            RANLIB=str(self.sdk / 'bin' / (self.target.c_target + '-ranlib')),
            CFLAGS='-Os -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables',
            LDFLAGS='-Wl,--gc-sections', CONFIG_SITE='/dev/null',
            PKG_CONFIG=str(self.shell_wrapper('dbus-target-pkg-config', [self.tools['pkg-config'], '--static'])),
            PKG_CONFIG_PATH='', PKG_CONFIG_LIBDIR=str(stage / 'usr/lib/pkgconfig'),
            PKG_CONFIG_SYSROOT_DIR=str(stage),
            PATH=str(BUILD_TOOLS / 'bin') + os.pathsep + self.env.get('PATH', ''),
        )


def prepare_source(builder, package, record):
    source = unpack(package, record, builder.output / 'source')
    license_dir = builder.output / 'licenses' / package['name']
    license_dir.mkdir()
    shutil.copyfile(source / package['license_file'], license_dir / package['license_file'])
    if (source / 'LICENSES').is_dir():
        shutil.copytree(source / 'LICENSES', license_dir / 'LICENSES')
    return source, {'source': record, 'directory': str(source),
                    'tree': tree_identity(source), 'licenses': file_map(license_dir)}


def build_expat(builder, source):
    builder.target_environment()
    directory = builder.output / 'expat-build'
    directory.mkdir()
    triplet = builder.capture(['sh', source / 'conftools/config.guess'], 'expat-build-triplet.log').strip()
    options = ['--prefix=/usr', '--host=' + builder.target.c_target, '--build=' + triplet,
               '--disable-shared', '--enable-static', '--disable-maintainer-mode',
               '--without-xmlwf', '--without-examples', '--without-tests', '--without-docbook']
    builder.run([source / 'configure', *options], 'expat-configure.log', directory)
    builder.run([builder.tools['make'], '-j' + str(builder.jobs)], 'expat-build.log', directory)
    builder.run([builder.tools['make'], 'install', 'DESTDIR=' + str(builder.output / 'stage')],
                'expat-install.log', directory)
    archive = builder.target.inspect_archive(builder.output / 'stage/usr/lib/libexpat.a')
    return {'options': options, 'archive': archive,
            'archive_file': str(builder.output / 'stage/usr/lib/libexpat.a'),
            'pkgconfig_sha256': digest(builder.output / 'stage/usr/lib/pkgconfig/expat.pc')}


def dbus_options(cross):
    return ['--prefix=/usr', '--libdir=lib', '--sysconfdir=/etc', '--localstatedir=/var',
            '--wrap-mode=nofallback', '--cross-file=' + str(cross),
            '-Dbuildtype=minsize', '-Ddefault_library=static', '-Db_staticpic=false', '-Db_pie=false',
            '-Dmessage_bus=true', '-Dtools=true', '-Dtraditional_activation=false',
            '-Dsystemd=disabled', '-Duser_session=false', '-Dx11_autolaunch=disabled',
            '-Dlaunchd=disabled', '-Dapparmor=disabled', '-Dselinux=disabled', '-Dlibaudit=disabled',
            '-Dmodular_tests=disabled', '-Dintrusive_tests=false', '-Dinstalled_tests=false',
            '-Ddoxygen_docs=disabled', '-Dducktype_docs=disabled', '-Dxml_docs=disabled',
            '-Dqt_help=disabled', '-Dvalgrind=disabled', '-Dkqueue=disabled',
            '-Depoll=enabled', '-Dinotify=disabled', '-Drelocation=disabled',
            '-Druntime_dir=/run', '-Dsession_socket_dir=/run/user/0',
            '-Ddbus_session_bus_listen_address=' + SESSION_ADDRESS,
            '-Ddbus_session_bus_connect_address=' + SESSION_ADDRESS]


def build_dbus(builder, source):
    builder.target_environment()
    cross = builder.output / 'dbus-cross.ini'
    cross.write_text('[binaries]\n' +
        'c = ' + repr(builder.env['CC']) + '\n' +
        'ar = ' + repr(builder.tools['llvm-ar']) + '\n' +
        'strip = ' + repr(builder.tools['llvm-strip']) + '\n' +
        'pkg-config = ' + repr(builder.env['PKG_CONFIG']) + '\n' +
        builder.target.meson_machine() +
        '[properties]\nneeds_exe_wrapper = true\n' +
        'sys_root = ' + repr(str(builder.output / 'stage')) + '\n' +
        'pkg_config_libdir = ' + repr([builder.env['PKG_CONFIG_LIBDIR']]) + '\n')
    directory = builder.output / 'dbus-build'
    options = dbus_options(cross)
    builder.run([builder.tools['meson'], 'setup', directory, source, *options], 'dbus-setup.log')
    builder.run([builder.tools['meson'], 'compile', '-C', directory, '-j', str(builder.jobs),
                 *BINARIES], 'dbus-build.log')
    # Use upstream-generated public metadata and exactly the installed header
    # set listed in dbus/meson.build, without invoking the broad install target
    # (which also installs system policies, activation tools and helper scripts).
    stage = builder.output / 'stage'
    copies = {directory / 'dbus/libdbus-1.a': stage / 'usr/lib/libdbus-1.a',
              directory / 'meson-private/dbus-1.pc': stage / 'usr/lib/pkgconfig/dbus-1.pc',
              directory / 'dbus/dbus-arch-deps.h': stage / 'usr/lib/dbus-1.0/include/dbus/dbus-arch-deps.h'}
    copies.update({source / 'dbus' / header: stage / 'usr/include/dbus-1.0/dbus' / header
                   for header in PUBLIC_HEADERS})
    archive = builder.target.inspect_archive(directory / 'dbus/libdbus-1.a')
    for original, destination in copies.items():
        if original.is_symlink() or not original.is_file():
            raise BuildError('Missing/non-regular D-Bus development file: ' + str(original))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
    return {'options': options, 'archive': archive,
            'archive_file': str(stage / 'usr/lib/libdbus-1.a'),
            'cross_file_sha256': digest(cross), 'config_h_sha256': digest(directory / 'config.h'),
            'development_files': {str(path.relative_to(stage)): digest(path) for path in copies.values()}}, directory


def publish_executable(builder, source, name):
    if source.is_symlink() or not source.is_file():
        raise BuildError('Executable output must be a regular file: ' + str(source))
    layout = inspect_elf(source, builder.target)
    symbols = builder.output / (name + '.symbols.elf')
    target = builder.output / (name + '.elf')
    shutil.copyfile(source, symbols)
    shutil.copyfile(source, target)
    builder.run([builder.tools['llvm-strip'], '--strip-all', target], name + '-strip.log')
    return {'elf': inspect_elf(target, builder.target),
            'symbols': {'file': str(symbols), 'sha256': layout['sha256']}}


def build_probe(builder, source):
    flags = shlex.split(builder.capture(
        [builder.env['PKG_CONFIG'], '--cflags', '--libs', 'dbus-1'], 'dbus-client-pkgconfig.log'))
    path = builder.output / 'dbus-probe.unstripped.elf'
    builder.run([builder.env['CC'], '-Os', '-Wall', '-Wextra', '-Werror',
                 '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
                 source, *flags, '-o', path], 'dbus-probe-build.log')
    return {'source': str(source), 'source_sha256': digest(source), 'pkgconfig_flags': flags,
            **publish_executable(builder, path, 'dbus-probe')}


def write_report(path, report):
    temporary = path.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(path)


def checked_digest(path):
    """Receipts and payloads must be regular files, never redirected links."""
    path = Path(path)
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise BuildError('Receipt input contains a symlink: ' + str(path))
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise BuildError('Receipt input is not a regular file: ' + str(path))
        import hashlib
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def producer_paths(probe):
    return (Path(__file__).resolve(), ROOT / 'tools/build_sysroot.py',
            ROOT / 'tools/target_profile.py', ROOT / 'tools/desktop_ports.py',
            ROOT / 'tools/build_cosmic.py', ROOT / 'tools/native_session.py',
            MANIFEST, EXPAT_MANIFEST, *ROOTFS_ASSETS.values(), Path(probe))


def validate_evidence(origin, report):
    """Check retained notices, command logs and generated build configuration."""
    if file_map(origin / 'logs') != report['logs']:
        raise BuildError('D-Bus command logs changed')
    for source in report['sources']:
        name = desktop_ports.component(source['source']['identity']['name'], 'package name')
        if file_map(origin / 'licenses' / name) != source['licenses']:
            raise BuildError('D-Bus source licenses changed: ' + name)
    for relative, expected in (
            ('dbus-cross.ini', report['dbus']['cross_file_sha256']),
            ('dbus-build/config.h', report['dbus']['config_h_sha256'])):
        if checked_digest(origin / relative) != expected:
            raise BuildError('D-Bus build configuration changed: ' + relative)


def validate_build(output):
    """Revalidate a completed build, or its receipt copied to a curated SDK.

Original build sources/development files remain required. When output differs
from the receipt's original output, also verify each copied executable and
rootfs asset in that curated directory. This is provenance, not runtime proof.
"""
    requested = Path(output)
    if requested.is_symlink():
        raise BuildError('Build/curated output cannot be a symlink')
    requested = requested.resolve(strict=True)
    receipt = requested / 'dbus-build-report.json'
    receipt_hash = checked_digest(receipt)
    report = json.loads(receipt.read_text(), object_pairs_hook=desktop_ports.unique_object)
    if report.get('schema_version') != 1 or report.get('status') != 'cross-built':
        raise BuildError('D-Bus receipt is not a completed cross-build')
    origin = Path(report['output'])
    if origin.is_symlink() or origin.resolve(strict=True) != origin:
        raise BuildError('Original D-Bus output identity changed')
    if checked_digest(origin / 'dbus-build-report.json') != receipt_hash:
        raise BuildError('Curated D-Bus receipt differs from the original')
    target = profile_for(report['architecture'])
    target.require_report(report)
    producers = producer_paths(report['probe']['source'])
    if report['producer_sha256'] != {str(path): checked_digest(path) for path in producers}:
        raise BuildError('D-Bus producer/configuration/probe identity changed')
    if report['session'] != config_identity(SESSION_CONFIG):
        raise BuildError('D-Bus session configuration changed')
    for tool in report['toolchain'].values():
        resolved = Path(tool['path']).resolve(strict=True)
        if str(resolved) != tool['resolved_path'] or checked_digest(resolved) != tool['sha256']:
            raise BuildError('D-Bus toolchain changed: ' + tool['path'])
    sdk = Path(report['sdk']['path'])
    if (sdk_identity(sdk, target) != report['sdk'] or
            file_map(sdk / 'sysroot', allow_internal_links=True) != report['preserved_sdk_files']):
        raise BuildError('D-Bus input SDK changed')
    manifest = load_manifest()
    if len(report['sources']) != len(manifest['packages']):
        raise BuildError('D-Bus source closure changed')
    for package, source in zip(manifest['packages'], report['sources']):
        record = source['source']
        cache = Path(record['directory']).parent
        if desktop_ports.verify(package, cache, ARCHIVE_LIMIT) != record:
            raise BuildError('D-Bus source provenance changed')
        extracted = origin / 'source' / package['archive_root']
        if source['directory'] != str(extracted) or tree_identity(extracted) != source['tree']:
            raise BuildError('D-Bus extracted source changed')
    validate_evidence(origin, report)
    if file_map(origin / 'stage') != report['stage_files']:
        raise BuildError('D-Bus staged development files changed')
    for relative, expected in report['stage_files'].items():
        if checked_digest(origin / 'stage' / relative) != expected:
            raise BuildError('D-Bus development file changed: ' + relative)
    for name, filename in (('expat', 'libexpat.a'), ('dbus', 'libdbus-1.a')):
        archive = origin / 'stage/usr/lib' / filename
        if (report[name]['archive_file'] != str(archive) or
                target.inspect_archive(archive) != report[name]['archive']):
            raise BuildError('D-Bus target archive changed: ' + filename)
    if set(report['executables']) != set(BINARIES):
        raise BuildError('D-Bus executable set changed')
    artifacts = {}
    executables = {**report['executables'], 'dbus-probe': report['probe']}
    for name, entry in executables.items():
        path = origin / (name + '.elf')
        symbols = origin / (name + '.symbols.elf')
        if (entry['elf']['file'] != str(path) or entry['symbols']['file'] != str(symbols) or
                checked_digest(path) != entry['elf']['sha256'] or
                checked_digest(symbols) != entry['symbols']['sha256'] or
                inspect_elf(path, target) != entry['elf']):
            raise BuildError('D-Bus executable identity changed: ' + name)
        inspect_elf(symbols, target)
        copied = requested / path.name
        if checked_digest(copied) != entry['elf']['sha256']:
            raise BuildError('Curated D-Bus executable changed: ' + name)
        artifacts[str(copied)] = entry['elf']['sha256']
    if set(report['rootfs']) != set(ROOTFS_ASSETS):
        raise BuildError('D-Bus runtime asset set changed')
    for guest, expected in report['rootfs'].items():
        original, copied = (base / 'rootfs' / guest.lstrip('/') for base in (origin, requested))
        if checked_digest(original) != expected or checked_digest(copied) != expected:
            raise BuildError('D-Bus runtime asset changed: ' + guest)
        artifacts[str(copied)] = expected
    return {'receipt_sha256': receipt_hash, 'output': str(origin),
            'validated_output': str(requested), 'artifacts': artifacts, 'report': report}


def build(args, manifest, target, sdk, output):
    with native_lease(args.native_lock):
        idle_native_host()
        # Recheck freshness after taking the shared lease.
        validate_output(output, sdk)
        identity = sdk_identity(sdk, target)
        before = file_map(sdk / 'sysroot', allow_internal_links=True)
        config = config_identity(SESSION_CONFIG)
        if args.probe_source.is_symlink() or not args.probe_source.is_file():
            raise BuildError('Real D-Bus probe source is required: ' + str(args.probe_source))
        output.mkdir(parents=True)
        report_path = output / 'dbus-build-report.json'
        producers = producer_paths(args.probe_source)
        report = {'schema_version': 1, 'status': 'building', 'architecture': target.architecture,
                  'output': str(output),
                  'target_triple': target.rust_target, 'sdk': identity,
                  'producer_sha256': {str(path): digest(path) for path in producers},
                  'network_requested': args.fetch, 'native_lock': str(args.native_lock),
                  'limits': {'timeout_seconds': BUILD_TIMEOUT_SECONDS, 'max_output_bytes': MAX_OUTPUT_BYTES,
                             'min_free_bytes': MIN_FREE_BYTES},
                  'session': config, 'guest_execution': 'not performed', 'scope': manifest['scope']}
        write_report(report_path, report)
        builder = None
        try:
            builder = Builder(output, sdk, args.jobs, target)
            report['commands'] = builder.commands
            # Verify every source before invoking compilers or build systems.
            records = [source_record(package, args.cache, output, fetch=args.fetch,
                       archive=args.dbus_archive if package['name'] == 'dbus' else None)
                       for package in manifest['packages']]
            sources = [prepare_source(builder, package, record)
                       for package, record in zip(manifest['packages'], records)]
            report['sources'] = [record for _, record in sources]
            builder.discover()
            report['toolchain'] = {name: {'path': path, 'resolved_path': str(Path(path).resolve(strict=True)),
                                         'sha256': digest(Path(path))}
                                   for name, path in builder.tools.items()}
            report['expat'] = build_expat(builder, sources[0][0])
            report['dbus'], directory = build_dbus(builder, sources[1][0])
            report['executables'] = {name: publish_executable(builder, directory / relative, name)
                                     for name, relative in BINARIES.items()}
            report['probe'] = build_probe(builder, args.probe_source)
            report['rootfs'] = {}
            for guest, original in ROOTFS_ASSETS.items():
                destination = output / 'rootfs' / guest.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, destination)
                report['rootfs'][guest] = digest(destination)
            report['stage_files'] = file_map(output / 'stage')
            for source in report['sources']:
                if tree_identity(Path(source['directory'])) != source['tree']:
                    raise BuildError('Pinned extracted source changed during the D-Bus build')
            if (before != file_map(sdk / 'sysroot', allow_internal_links=True) or
                    identity != sdk_identity(sdk, target)):
                raise BuildError('Read-only SDK changed during the D-Bus build')
            if report['producer_sha256'] != {str(path): digest(path) for path in producers}:
                raise BuildError('D-Bus recipe/configuration/probe changed during build')
            report['preserved_sdk_files'] = before
            report['status'] = 'cross-built'
        except BaseException as error:
            report['status'], report['error'] = 'failed', str(error)
            raise
        finally:
            report['logs'] = file_map(output / 'logs') if (output / 'logs').is_dir() else {}
            write_report(report_path, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inventory', 'build'), nargs='?', default='inventory')
    parser.add_argument('--arch', choices=('x86_64', 'aarch64'), default='x86_64')
    parser.add_argument('--sdk', type=Path, help='Prepared input SDK; read-only')
    parser.add_argument('--output', type=Path, help='Fresh build/output directory, separate from SDK')
    parser.add_argument('--cache', type=Path, default=desktop_ports.DEFAULT_CACHE)
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--fetch', action='store_true')
    source.add_argument('--dbus-archive', type=Path, help='Pinned local upstream tarball; no network')
    parser.add_argument('--probe-source', type=Path, default=PROBE_SOURCE)
    parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest()
        target = profile_for(args.arch)
        sdk = (args.sdk or target.default_output(ROOT)).resolve()
        if args.command != 'build' and (args.fetch or args.dbus_archive is not None):
            raise BuildError('--fetch and --dbus-archive require build')
        if not 1 <= args.jobs <= 4:
            raise BuildError('--jobs must be in 1..4')
        if args.command == 'inventory':
            print(json.dumps({'packages': manifest['packages'], 'sdk': str(sdk),
                              'output': str(args.output) if args.output else None,
                              'architecture': target.architecture, 'network': False,
                              'session': config_identity(SESSION_CONFIG),
                              'guest_execution': 'not performed'}, indent=2))
            return 0
        if args.output is None:
            raise BuildError('--output is required for build')
        output = validate_output(args.output, sdk)
        args.probe_source = args.probe_source.absolute()
        args.cache = args.cache.resolve()
        report = build(args, manifest, target, sdk, output)
        print(json.dumps({'status': report['status'], 'report': str(output / 'dbus-build-report.json'),
                          'executables': report['executables'], 'probe': report['probe'],
                          'guest_execution': 'not performed'}, indent=2))
        return 0
    except (BuildError, desktop_ports.PortError, OSError, ValueError, KeyError,
            StopIteration, ET.ParseError, subprocess.SubprocessError) as error:
        print('dbus: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
