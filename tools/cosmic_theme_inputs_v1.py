"""Read-only revalidation of genuine Linux host theme generation.

No compiler, Cargo, exporter, loader or guest is executed. The settings source
consumer may use its established read-only Git checks. This proof binds the
new rlib snapshot and both real retained exporter runs; it makes no guest claim.
"""
from __future__ import annotations

import math
from pathlib import Path

if __package__:
    from . import build_cosmic_theme_linux_v1 as producer
else:
    import build_cosmic_theme_linux_v1 as producer

ROOT, KIND = producer.ROOT, producer.KIND
require, BuildError = producer.require, producer.BuildError
REPORT_KEYS = {'schema_version', 'kind', 'status', 'output', 'architecture', 'target', 'limits',
    'timeout_scope', 'inputs_before', 'inputs_preserved', 'steps', 'host_generation', 'guest_execution',
    'full_cosmic_complete', 'reference_is_generation_proof', 'network_requested',
    'build_script_network_sandbox', 'executable', 'elf', 'native_elapsed_seconds', 'assets',
    'inputs_after', 'files'}


def consumer_sources():
    require(producer.plain(__file__) == ROOT / 'tools/cosmic_theme_inputs_v1.py',
            'Use the reviewed installed Linux theme consumer')
    return producer.provenance.producer_sources(ROOT / 'tools/cosmic_theme_inputs_v1.py')


def bounds(assets):
    return {**producer.reference.bounds(assets), 'max_asset_bytes': max(row['bytes'] for row in assets),
            'max_guest_path_bytes': max(len(row['path'].encode()) for row in assets)}


def expected_files():
    names = {'client.rs', producer.EXECUTABLE}
    names.update(label + '.' + stream + '.log' for label in ('link', 'run-dark', 'run-light')
                 for stream in ('stdout', 'stderr'))
    names.update('rootfs' + path for path in producer.reference.expected_paths())
    names.update('homes/' + mode + '/.config/cosmic/' + ident + '/v2/' + key
                 for mode, ident in producer.reference.IDS.items() for key in producer.reference.KEYS)
    return names


def check_steps(report, inputs, output):
    steps = report['steps']
    require(type(steps) is list and len(steps) == 3, 'Link plus both genuine host runs are required')
    labels = ['link', 'run-dark', 'run-light']
    keys = {'label', 'argv', 'cwd', 'environment', 'started_seconds', 'timeout_seconds',
            'stdout', 'stderr', 'status', 'returncode', 'ended_seconds'}
    end = 0
    for label, row in zip(labels, steps):
        require(type(row) is dict and set(row) == keys and row['label'] == label
                and row['status'] == 'exited' and type(row['returncode']) is int and row['returncode'] == 0
                and row['stdout'] == label + '.stdout.log' and row['stderr'] == label + '.stderr.log'
                and row['cwd'] == str(ROOT), 'Incomplete, failed or substituted host process receipt')
        mode = None if label == 'link' else label[4:]
        command = producer.link_command(inputs, output) if mode is None else [str(output / producer.EXECUTABLE), mode]
        require(row['argv'] == command
                and row['environment'] == producer.environment(inputs, output, mode),
                'Theme compiler/exporter command or isolated environment changed')
        for name in ('started_seconds', 'ended_seconds', 'timeout_seconds'):
            require(type(row[name]) in (int, float) and math.isfinite(row[name]) and row[name] >= 0,
                    'Invalid native timing evidence')
        require(end <= row['started_seconds'] <= row['ended_seconds'] <= producer.LIMITS['timeout_seconds']
                and 0 < row['timeout_seconds'] <= producer.LIMITS['timeout_seconds']
                and abs(row['started_seconds'] + row['timeout_seconds'] - producer.LIMITS['timeout_seconds']) < .1,
                'Theme processes were parallel or did not share the original deadline')
        end = row['ended_seconds']
    elapsed = report['native_elapsed_seconds']
    require(type(elapsed) in (int, float) and math.isfinite(elapsed)
            and end <= elapsed <= producer.LIMITS['timeout_seconds'], 'Theme native operation exceeded its original budget')


def validate_build(output):
    try:
        output = producer.plain(output)
        require(output.is_dir(), 'Missing retained Linux theme generation')
        report_path = output / producer.RECEIPT
        raw = producer.read(report_path, 32 * 1024 ** 2)
        report = producer.decode(raw)
        required = {'schema_version': 1, 'kind': KIND, 'status': 'HOST_GENERATED_NOT_GUEST_RUN',
            'output': str(output), 'architecture': 'x86_64', 'target': producer.TARGET,
            'timeout_scope': producer.TIMEOUT_SCOPE, 'inputs_preserved': True,
            'host_generation': True, 'guest_execution': False, 'full_cosmic_complete': False,
            'reference_is_generation_proof': False, 'network_requested': False,
            'build_script_network_sandbox': False}
        require(type(report) is dict and set(report) == REPORT_KEYS
                and all(type(report[key]) is type(value) and report[key] == value for key, value in required.items())
                and producer.canonical(report['limits']) == producer.canonical(producer.LIMITS),
                'Invalid Linux host generation receipt or readiness claim')
        before = report['inputs_before']
        require(producer.canonical(before) == producer.canonical(report['inputs_after']),
                'Theme generation inputs changed during producer execution')
        current = producer.capture_inputs(before['settings_build'])
        require(producer.canonical(before) == producer.canonical(current),
                'Current supplier, tool, source or reference closure differs from actual generation inputs')
        check_steps(report, current, output)
        require(producer.identity(output / 'client.rs') == producer.SOURCE_ID
                and (output / 'client.rs').stat().st_mode & 0o7777 == 0o644,
                'Retained exporter source is not the unchanged original')
        executable = output / producer.EXECUTABLE
        require(report['executable'] == {'path': str(executable), **producer.identity(executable), 'mode': 0o755}
                and executable.stat().st_mode & 0o7777 == 0o755,
                'Retained actually executed exporter identity changed')
        require(report['elf'] == producer.build_sysroot.inspect_elf(executable, 'x86_64'),
                'Retained host exporter static ELF contract changed')
        for mode in ('dark', 'light'):
            generated = producer.generated_keys(output, mode, current['comparison'])
            for path, source in generated.items():
                require(producer.read(source) == producer.read(output / 'rootfs' / path[1:]),
                        'Installed theme bytes do not come from actual generated HOME files')
        license_path = producer.reference.LICENSE_PATH
        require(producer.read(Path(current['upstream_license']['path']))
                == producer.read(output / 'rootfs' / license_path[1:]),
                'Generated rootfs does not retain the complete current upstream license')
        assets = producer.assets_from_build(output, current['comparison'])
        require(producer.canonical(report['assets']) == producer.canonical(assets),
                'Actual generated complete asset inventory differs')
        actual = producer.inventory(output)
        require(set(actual) == expected_files() and producer.canonical(report['files']) == producer.canonical(actual),
                'Retained generation evidence has changed or has missing/extra files')
        require(sum(row['bytes'] for row in actual.values()) + len(raw) <= producer.LIMITS['max_output_bytes'],
                'Retained generation exceeds the original output budget')
        require(producer.read(report_path, 32 * 1024 ** 2) == raw
                and current['producer_sources'] == producer.producer_sources(),
                'Generation receipt or producer source changed during validation')
        proof = {'schema_version': 1, 'kind': KIND, 'status': 'THEME_HOST_GENERATION_REVALIDATED_NOT_GUEST_RUN',
            'build_output': str(output), 'receipt_sha256': producer.identity(report_path)['sha256'],
            'executable': report['executable'], 'elf': report['elf'], 'assets': assets, 'bounds': bounds(assets),
            'limits': producer.LIMITS, 'input_identity_sha256': producer.canonical(current),
            'settings_consumer_identity_sha256': producer.canonical(current['settings_proof']),
            'settings_build_report': current['settings_report'], 'producer_sources': current['producer_sources'],
            'consumer_sources': consumer_sources(),
            'protected_paths': [str(path) for path in producer.protected_paths(current)] + [str(output)],
            'commit': producer.COMMIT, 'theme_version': 2, 'host_generation': True, 'guest_execution': False,
            'reference_is_generation_proof': False, 'full_cosmic_complete': False}
        return {**proof, 'identity_sha256': producer.canonical(proof)}
    except BuildError:
        raise
    except (OSError, ValueError, KeyError, TypeError, IndexError, StopIteration, producer.settings.BuildError) as error:
        raise BuildError('Invalid retained Linux theme generation: ' + str(error)) from error
