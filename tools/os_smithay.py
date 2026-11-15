"""Read-only canonical Smithay publication/input checks; never build or run a target.

Only fixed trusted rustc/cargo metadata commands run. Report command arrays and
reported executable paths are data, never subprocess arguments.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from build_cosmic import tree_identity
from build_sysroot import inspect_elf
from doctor import ROOT, RUST_BIN, env
from target_profile import profile_for

TARGET = profile_for('x86_64')


def require(condition, message):
    if not condition: raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    path = Path(path)
    require(path.stat().st_size <= 8 * 1024 * 1024, 'oversized Smithay receipt')
    value = json.loads(path.read_text())
    require(isinstance(value, dict), 'invalid Smithay receipt object')
    return value


class Binder:
    def __init__(self, root=ROOT, external=()):
        self.root = Path(root).resolve(strict=True)
        self.external = tuple(Path(p).resolve(strict=True) for p in external)
        self.inputs = {}

    def path(self, name, *, base=None):
        require(isinstance(name, (str, Path)), 'invalid receipt path')
        path = Path(name)
        require('..' not in path.parts, 'escaping receipt input')
        if not path.is_absolute(): path = Path(base or self.root) / path
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(self.root) or
                any(resolved == p or (p.is_dir() and resolved.is_relative_to(p)) for p in self.external),
                'external receipt input: ' + str(path))
        require(path.is_file(), 'missing receipt input: ' + str(path))
        return path

    def bind(self, name, expected=None, *, base=None):
        path = self.path(name, base=base)
        actual = digest(path)
        if expected is not None:
            require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected), 'invalid SHA256 pin')
            require(actual == expected, 'Smithay input changed: ' + str(path))
        self.inputs[str(path)] = actual
        return path

    def bind_map(self, values, *, base=None):
        require(isinstance(values, dict) and 0 < len(values) <= 16384, 'missing or oversized input closure')
        for name, expected in values.items(): self.bind(name, expected, base=base)


def publication(prefix, stem, kind, binder):
    canonical = prefix / (stem + '.elf')
    receipt_path = binder.bind(prefix / (stem + '-build-report.json'))
    receipt = read_json(receipt_path)
    require(receipt.get('status') == 'cross-built', 'unbuilt canonical Smithay input')
    TARGET.require_report(receipt)
    published = receipt.get('publication', {})
    required = {'source_build_report', 'source_build_report_sha256', 'original_' + kind + '_file'}
    require(required <= set(published) <= required | {'previous_canonical_archive'},
            'missing original Smithay publication')
    source = binder.bind(published['source_build_report'], published['source_build_report_sha256'])
    require(source.name == 'build-report.json' and source.is_relative_to(binder.root / 'artifacts'),
            'invalid original publication location')
    original = read_json(source)
    image = binder.path(published['original_' + kind + '_file'])
    require(image.parent == source.parent and original[kind]['file'] == str(image), 'original image location mismatch')
    require(inspect_elf(image, TARGET) == original[kind], 'original target ELF layout changed')
    binder.bind(image, original[kind]['sha256'])
    binder.bind(canonical, original[kind]['sha256'])
    require(inspect_elf(canonical, TARGET) == receipt[kind], 'canonical target ELF layout changed')
    expected = {**original, kind: {**original[kind], 'file': str(canonical)}}
    require({k: v for k, v in receipt.items() if k != 'publication'} == expected,
            'canonical receipt differs from original publication')
    return original, source.parent


def trusted_rust():
    # Fixed local tools, never a path selected by a report.
    def output(tool, *args):
        return subprocess.check_output([str(RUST_BIN / tool), *args], cwd=ROOT,
                                       env=env(), text=True, timeout=15)
    version = output('rustc', '-vV')
    host = next((line[6:] for line in version.splitlines() if line.startswith('host: ')), '')
    require(re.fullmatch('[A-Za-z0-9_.-]+', host or ''), 'invalid trusted Rust host')
    sysroot = Path(output('rustc', '--print', 'sysroot').strip()).resolve(strict=True)
    targetlib = Path(output('rustc', '--print', 'target-libdir', '--target', TARGET.rust_target).strip()).resolve(strict=True)
    require(targetlib.is_relative_to(sysroot), 'Rust target library outside toolchain')
    clang = shutil.which('clang')
    require(clang is not None, 'trusted clang unavailable')
    tools = {'clang': str(Path(clang)), **{name: str(sysroot / 'lib/rustlib' / host / 'bin' / name)
             for name in ('rust-lld', 'llvm-strip')}}
    return version, output('cargo', '-V'), targetlib, sysroot, tools


def validate_inputs(prefix):
    prefix = Path(prefix).absolute()
    require(not prefix.is_symlink() and prefix.resolve(strict=True) == prefix, 'linked Smithay sysroot')
    rustc, cargo, targetlib, sysroot, tools = trusted_rust()
    binder = Binder(external=(sysroot, Path(tools['clang']).resolve(strict=True),
                              RUST_BIN / 'rustc', RUST_BIN / 'cargo'))
    server, output = publication(prefix, 'smithay-dynamic-probe', 'probe', binder)
    client, client_output = publication(prefix, 'smithay-dynamic-client', 'client', binder)
    require(server.get('rustc') == rustc and server.get('cargo') == cargo, 'Smithay Rust compiler version changed')
    require(client.get('toolchain') == tools, 'Smithay client compiler selection changed')
    for name in ('rustc', 'cargo'): binder.bind(RUST_BIN / name)
    for path in tools.values(): binder.bind(path)
    require(server['build_profile']['manifest'] == str(ROOT / 'ports/cosmic/smithay-dynamic-source.json')
            and server['build_profile']['source'] == str(ROOT / 'ports/cosmic/smithay-dynamic/main.rs')
            and server['build_profile']['binary_stem'] == 'smithay-dynamic', 'wrong Smithay server source profile')
    fixed = {
        ROOT / 'ports/cosmic/smithay-dynamic-source.json': server['manifest_sha256'],
        ROOT / 'ports/cosmic/smithay-dynamic/main.rs': server['source_sha256'],
        ROOT / 'tools/build_smithay_wayland.py': server['builder_sha256'],
        ROOT / 'ports/cosmic/smithay-wayland.Cargo.lock': server['cargo_lock_sha256'],
        ROOT / 'artifacts/cosmic-sources/cosmic-comp-epoch/Cargo.lock': server['cosmic_lock_sha256'],
        TARGET.cc(prefix): server['target_driver_sha256'],
        output / 'mesa-build-report.json': server['mesa_report_sha256'],
        prefix / 'xkbcommon-build-report.json': server['xkbcommon_report_sha256'],
        output / 'xkbcommon-build-report.json': server['xkbcommon_report_sha256'],
    }
    binder.bind_map(fixed)
    for field in ('helper_sha256', 'modules_sha256', 'patches_sha256', 'model_inputs_sha256', 'static_inputs_sha256'):
        binder.bind_map(server[field])
    model = [ROOT / p for p in ('Cargo.toml', 'Cargo.lock', '.cargo/config.toml', 'rust-toolchain.toml')]
    for name in ('ai-runtime', 'kernel-core', 'contracts'):
        directory = ROOT / 'crates' / name
        model.extend([directory / 'Cargo.toml', *sorted(directory.rglob('*.rs'))])
    require(set(map(str, model)) == set(server['model_inputs_sha256']), 'model source closure changed')
    binder.bind_map(client['inputs_sha256'])
    require(str(ROOT / 'user/ported/smithay_dynamic_client.c') in client['inputs_sha256'], 'missing client source binding')
    for field in ('cargo_inputs_sha256', 'compiled_artifacts_sha256', 'generated_bindings', 'model_preflight_executable_sha256'):
        binder.bind_map(server[field], base=output)
    binder.bind(output / 'source/src/main.rs', server['source_sha256'])
    binder.bind(output / 'source/Cargo.lock', server['cargo_lock_sha256'])
    for name, expected in server['modules_sha256'].items():
        binder.bind(output / 'source/src' / Path(name).name, expected)
    current_rlibs = {p.name: digest(p) for p in sorted(targetlib.glob('*.rlib'))}
    require(current_rlibs == server['rust_target_rlibs_sha256'], 'Rust target library closure changed')
    binder.bind_map(current_rlibs, base=targetlib)
    binder.bind(targetlib / 'self-contained/libunwind.a', server['rust_unwind_sha256'])
    binder.bind(output / 'native/libunwind.a', server['rust_unwind_sha256'])
    for record in client['generated'].values(): binder.bind(record['path'], record['sha256'])
    # These are recorded produced artifacts; they are never executed by verification.
    for report in (server, client): binder.bind(report['symbols']['file'], report['symbols']['sha256'])
    pages = sum((p['vaddr'] + p['memsz'] + 4095)//4096 - p['vaddr']//4096
                for p in server['probe']['program_headers'] if p['type'] == 1 and p['memsz'])
    require(server['image_pages'] == pages and server['stack_pages'] == 64
            and server['admission_pages'] == pages + 64 <= 4096, 'executable allocation receipt mismatch')
    require(server['model_preflight'] == dict(free=4096, requested=pages+64, allowed=True, model=8195),
            'current pinned model did not approve the real executable size')
    trees = {}
    for directory, expected in ((output / 'source/smithay', server['patched_source_tree_sha256']),
                                (output / 'vendor', server['vendor_tree_sha256'])):
        require(directory.resolve(strict=True).is_relative_to(output), 'escaping compiled source tree')
        identity = tree_identity(directory)
        require(identity['sha256'] == expected, 'compiled source tree changed: ' + str(directory))
        trees[str(directory)] = dict(sha256=expected, entries=len(identity['files']))
    # Bind the actual Mesa dependency receipt and its current producer/patch pins.
    mesa = read_json(output / 'mesa-build-report.json')
    TARGET.require_report(mesa)
    require(mesa.get('status') == 'libraries-compiled', 'uncompiled Mesa dependency')
    binder.bind_map(mesa['producer_inputs_sha256'])
    binder.bind_map(mesa['source']['identity']['patches'])
    expected_static = {**mesa['target']['link_dependencies_sha256'],
        str(prefix / 'sysroot/usr/lib/libxkbcommon.a'): read_json(prefix / 'xkbcommon-build-report.json')['target']['archive']['sha256']}
    require(server['static_inputs_sha256'] == expected_static, 'static link closure differs from dependency receipts')
    return dict(version=1, status='VALIDATED_NOT_RUN', architecture='x86_64', target=TARGET.rust_target,
        programs={'smithay-dynamic-probe.elf': server['probe']['sha256'],
                  'smithay-dynamic-client.elf': client['client']['sha256']},
        inputhashes=dict(sorted(binder.inputs.items())), trees=trees,
        compiled_artifacts=len(server['compiled_artifacts_sha256']), admission_pages=server['admission_pages'],
        compiler_identity_scope='recorded Rust versions and target libraries; recorded client compiler bytes; current Rust launcher bytes',
        guest_execution='not performed by receipt validation')
