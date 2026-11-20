#!/usr/bin/env python3
"""Independently validate the peer build and replace only its admitted ELF."""
import argparse
import json
from pathlib import Path
import tempfile

import build_cosmic_notifications_static_v1 as parent_builder
import cosmic_notifications_peer_v2 as peer
import cosmic_notifications_elf as image
import os_x86

static, base = peer.static, peer.static.build
PROGRAM = 'cosmic-notifications.elf'


def validate_build(output):
    output = base.no_symlink_path(output)
    report = base.load_json(output / 'build-report.json')
    peer.require(report['kind'] == peer.KIND and report['status'] == 'cross-built'
        and report['policy_sha256'] == peer.POLICY_SHA256
        and report['guest_execution'] is False and report['full_os_verified'] is False
        and report['cosmic_session_verified'] is False and 'error' not in report,
        'Peer build was not admitted')
    parent_output = base.no_symlink_path(report['parent_build'])
    parent, validation = peer.validate_parent(parent_output)
    peer.require(base.digest(parent_output / 'build-report.json') == report['parent_report_sha256']
        and static.canonical_hash(validation) == report['parent_validation_sha256']
        and report['recipe'] == parent['recipe'] and report['toolchain'] == parent['toolchain']
        and static.producer_sources(base.ROOT / 'tools/build_cosmic_notifications_peer_v2.py') == report['producers'],
        'Peer parent, complete recipe, compiler or producers changed')
    reused = report['cache_reuse']
    peer.require(reused['parent_target'] == str(parent_output / 'target')
        and reused['parent_preserved'] is True
        and base.tree_identity(parent_output / 'target')['sha256'] == reused['input_tree_sha256']
        and base.digest(output / 'cache-clone.log') == reused['clone_log_sha256'],
        'Peer cache input/clone evidence changed')
    source = output / 'source'
    peer.require(peer.validate_source(source, parent['source_tree']) == report['source_tree'], 'Peer source changed')
    recipe = report['recipe']
    jobs = peer.parent_consumer.legacy.validate_metadata(report, recipe, output, source, Path(parent['cache']))
    profile = static.select_profile(Path(parent['resource_path']), jobs)
    policy = static.load_policy(Path(parent['recipe_path']).parent / 'source-policy.json')
    metadata = base.load_json(output / 'metadata.json')
    peer.require(static.verify_resolution(metadata, policy)
        == report['resolved_graph_sha256'] == parent['resolved_graph_sha256']
        and profile == report['resource_profile'], 'Peer graph or bounds changed')
    parent_builder.tool_inputs_preserved(report['toolchain'])
    peer.require(base.tree_identity(Path(parent['sysroot']) / 'sysroot') == parent['sysroot_before'], 'Peer SDK changed')
    peer.require(report['native_archive_directory'] == str(parent_output), 'Peer native reuse directory changed')
    static.verify_native_archive_search(parent_output, Path(parent['sysroot']), recipe,
                                       report['toolchain'], report['native_archive_search'])
    binary = output / PROGRAM
    linked = output / 'target' / static.TARGET / 'release' / recipe['binary']
    admission = image.inspect_full_os_elf(binary, profile)
    peer.require(admission == report['image_admission']
        and report['linked_binary'] == dict(path=str(linked), bytes=linked.stat().st_size, sha256=base.digest(linked))
        and base.digest(binary) == report['linked_binary']['sha256'], 'Peer ELF differs from the real link')
    peer.require(set(report['evidence_files']) == {'cargo.log', 'metadata.json', 'metadata.stderr.log'}
        and all(base.digest(output / name) == digest for name, digest in report['evidence_files'].items()),
        'Peer logs or metadata changed')
    licenses = peer.parent_consumer.license_inputs(source, policy)
    return report, admission, licenses


def assemble(build, base_build, output):
    build, base_build, output = map(base.no_symlink_path, (build, base_build, output))
    report, admission, licenses = validate_build(build)
    manifest = base.load_json(base_build / 'build-manifest.json')
    parent = base.no_symlink_path(manifest['sysroot'])
    for protected in (build, base_build, parent, peer.PORT):
        peer.require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                     'Peer catalog overlaps an input')
    peer.require(not output.exists(), 'Preserving existing peer catalog')
    inputs = os_x86.catalog_inputs(parent)
    peer.require(manifest['status'] == 'BUILT_NOT_RUN' and manifest['external_inputs'] == inputs,
                 'Peer base catalog changed')
    old_parent = base.load_json(Path(report['parent_build']) / 'build-report.json')
    peer.require(inputs[PROGRAM] == old_parent['executable']['sha256'], 'Catalog is not the bound original notifications')
    for item in licenses:
        peer.require(inputs[item['path']] == item['sha256'], 'Complete notification license changed')
    sources = {name: parent / name for name in inputs}
    sources[PROGRAM] = build / PROGRAM
    hashes = dict(inputs, **{PROGRAM: admission['executable']['sha256']})
    sizes = {name: path.stat().st_size for name, path in sources.items()}
    modes = {name: path.stat().st_mode & 0o777 for name, path in sources.items()}
    peer.require(sum(sizes.values()) <= 128 * 1024**2 and len(sources) <= 256,
                 'Peer catalog exceeds the unchanged core-v1 ROM bounds')
    producers = os_x86.producer_sources(__file__)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as temporary:
        pending = Path(temporary).resolve()
        for name, source in sources.items():
            data = peer.parent_consumer.legacy.common.read_regular(source, 64 * 1024**2)
            peer.require(len(data) == sizes[name] and static.sha(data) == hashes[name], 'Peer copy source changed')
            destination = pending / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(modes[name])
        peer.require(os_x86.catalog_inputs(pending) == hashes and os_x86.catalog_inputs(parent) == inputs
            and base.load_json(base_build / 'build-manifest.json') == manifest,
            'Peer catalog copy changed bytes outside its one ELF')
        peer.require(all((pending / name).stat().st_mode & 0o777 == modes[name]
            and source.stat().st_mode & 0o777 == modes[name] for name, source in sources.items()),
            'Peer catalog file mode changed during copy')
        origin = dict(schema_version=1, kind=peer.KIND, status='PEER_CATALOG_ASSEMBLED_NOT_RUN',
            build=str(build), build_report_sha256=base.digest(build / 'build-report.json'),
            base_build=str(base_build), base_manifest_sha256=base.digest(base_build / 'build-manifest.json'),
            original_inputs=inputs, files=hashes, modes=modes, raw_catalog_bytes=sum(sizes.values()),
            image_admission=admission, licenses=licenses, producers=producers,
            full_os_verified=False, cosmic_session_verified=False, guest_execution=False)
        (pending / 'cosmic-notifications-peer-v2-origin.json').write_text(json.dumps(origin, indent=2) + '\n')
        peer.require(not output.exists(), 'Concurrent peer catalog publication')
        pending.rename(output)
    return origin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = assemble(args.build, args.base_build, args.output)
    print(json.dumps({key: result[key] for key in ('status', 'raw_catalog_bytes', 'full_os_verified')}, indent=2))


if __name__ == '__main__':
    main()
