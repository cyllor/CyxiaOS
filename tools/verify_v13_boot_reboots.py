#!/usr/bin/env python3
"""Replay all eight native boots and their closed-process disk handoff chain.

This establishes persistent-epoch continuity under ordinary QEMU process exit,
not power-loss/FLUSH-loss behavior, complete A01, or runtime attestation.
No archive-selected path, observation, boolean or executable is trusted.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct
import sys

from boot_reboot_contract import SCENARIOS, verify_process, verify_transition
from check_prototype_evidence import read_json, safe_path, sha256
from check_v13_disk import inspect as inspect_disk
from verify_v13_boot_recovery import require
from verify_v13_boot_receipt import verify_receipt

VERSION = 'a01-reboot-chain-v1'


def verify_link(previous: dict | None, current: dict) -> None:
    """Facts are reconstructed by verify_chain, never loaded from producer summaries."""
    verify_process(current['process'])
    if previous is None:
        require(current['origin'] == {'kind': 'fresh'}, 'first boot is not a fresh disk')
    else:
        for name in ('image_sha256', 'source_sha256', 'build_sha256'):
            require(current[name] == previous[name], 'reboot changed source, image or node identity')
        require(current['run_nonce'] != previous['run_nonce'], 'reboot reused run identity')
        require(current['origin'] == dict(kind='handoff', parent_nonce=previous['run_nonce'],
                    parent_receipt_sha256=previous['receipt_sha256'],
                    disk_sha256=previous['disk_sha256'],
                    parent_exited_ns=previous['process']['exited_ns']),
                'reboot does not descend from the exact preceding receipt/disk')
        require(current['disk_before_sha256'] == previous['disk_sha256'], 'reboot reformatted/replaced disk')
        require(current['process']['started_ns'] > previous['process']['exited_ns'],
                'same-identity guest processes overlapped')
    verify_transition(None if previous is None else previous['disk'], current['disk'],
                      current['mode'], current['issued_epoch'])


def verify_chain(directory: Path, *, source_root: Path, qemu_source: Path) -> dict:
    root = Path(directory).resolve(strict=True)
    previous, nonces, results = None, set(), {}
    expected_dirs = {name for name, _ in SCENARIOS}
    require({p.name for p in root.iterdir() if p.is_dir()} == expected_dirs,
            'missing or extra reboot profiles')
    for name, mode in SCENARIOS:
        child = root / name
        require(not child.is_symlink(), 'redirected reboot profile')
        native = verify_receipt(child, source_root=source_root, qemu_source=qemu_source)
        require(native['mode'] == mode, 'wrong reboot fault order')
        get = lambda name: safe_path(child, name)
        inputs = read_json(get('input.json'))
        disk = inspect_disk(get('disk.raw'))
        words = struct.unpack('<64Q', get('last.bin').read_bytes())
        facts = dict(mode=mode, issued_epoch=words[6], disk=disk,
                     image_sha256=native['image_sha256'], source_sha256=native['source_sha256'],
                     build_sha256=sha256(get('build-manifest.json')),
                     run_nonce=native['run_nonce'], origin=inputs['disk_origin'],
                     disk_sha256=sha256(get('disk.raw')), receipt_sha256=sha256(get('summary.json')),
                     disk_before_sha256=read_json(get('disk-before.json'))['sha256'],
                     process=read_json(get('process-exit.json')))
        require(facts['run_nonce'] not in nonces, 'chain reused run nonce')
        verify_link(previous, facts)
        nonces.add(facts['run_nonce'])
        results[name] = dict(mode=mode, issued_epoch=words[6], recovered_disk_epoch=disk['boot_epoch'],
                             filesystem=disk['uuid'], run_nonce=facts['run_nonce'],
                             disk_sha256=facts['disk_sha256'], native_execution_verified=True)
        previous = facts
    return dict(verifier_version=VERSION, status='PASS', reboot_chain_verified=True,
                native_execution_verified=True, native_acceptance_status='NOT_RUN',
                full_v13_acceptance=False, runtime_truth_attested=False,
                scope='A01 eight-boot disk continuity only; not power-loss or full A01', boots=results)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('directory', 'source-root', 'qemu-source'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_chain(args.directory, source_root=args.source_root, qemu_source=args.qemu_source)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps(dict(status='FAIL', error=str(error), native_acceptance_status='NOT_RUN')))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__': sys.exit(main())
