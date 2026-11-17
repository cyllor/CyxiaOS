#!/usr/bin/env python3
"""Export reviewed notification static bindings from existing inputs, without Cargo.

This does not acquire sources or resolve a lockfile. The output and receipt are
source evidence only; the root lease owner must perform actual locked/offline
Cargo validation and target compilation through the versioned build entry point.
"""
import argparse
import json
from pathlib import Path
import sys

if __package__:
    from . import cosmic_notifications_static_v1 as static
else:
    import cosmic_notifications_static_v1 as static


def prepare(output, *, source_cache=static.build.ports.CACHE, cache=static.build.CARGO_CACHE,
            policy_path=static.PORT / 'source-policy.json'):
    policy = static.load_policy(policy_path)
    source_cache, cache = map(static.build.no_symlink_path, (source_cache, cache))
    original = source_cache / 'cosmic-notifications'
    for protected in (source_cache, cache, static.build.no_symlink_path(policy_path).parent):
        selected = static.build.no_symlink_path(output)
        static.require(not selected.is_relative_to(protected) and not protected.is_relative_to(selected),
                       'Static preparation overlaps an input')
    output = static.build.new_output(output)
    producers = static.producer_sources(__file__)
    report = {'schema_version': 1, 'kind': policy['kind'], 'status': 'PREPARING',
              'source_cache': str(source_cache), 'cache': str(cache),
              'policy_path': str(static.build.no_symlink_path(policy_path)),
              'policy_sha256': static.POLICY_SHA256, 'producer_sources': producers,
              'cargo_executed': False, 'cargo_resolution_verified': False,
              'target_linked': False, 'guest_execution': 'not performed',
              'notifications_verified': False, 'cosmic_session_verified': False}
    try:
        report['static_source'] = static.export_source(original, cache, output / 'source', policy_path)
        report['status'] = 'STATIC_SOURCE_EXPORTED_NOT_BUILT'
    except Exception as error:
        report.update(status='FAILED', error=str(error))
        raise
    finally:
        report['producer_sources_after'] = static.producer_sources(__file__)
        report['producer_sources_preserved'] = report['producer_sources_after'] == producers
        if not report['producer_sources_preserved']:
            report.update(status='FAILED', error='Static preparation producers changed')
        (output / 'source-report.json').write_text(json.dumps(report, indent=2) + '\n')
        if not report['producer_sources_preserved']:
            raise static.build.CosmicBuildError(report['error'])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-cache', type=Path, default=static.build.ports.CACHE)
    parser.add_argument('--cache', type=Path, default=static.build.CARGO_CACHE)
    parser.add_argument('--policy', type=Path, default=static.PORT / 'source-policy.json')
    args = parser.parse_args(argv)
    try:
        report = prepare(args.output, source_cache=args.source_cache, cache=args.cache, policy_path=args.policy)
        print(json.dumps({key: report[key] for key in ('status', 'cargo_executed',
                          'cargo_resolution_verified', 'target_linked', 'notifications_verified')}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print('Static notification export failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
