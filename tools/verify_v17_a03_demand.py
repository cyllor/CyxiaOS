#!/usr/bin/env python3
"""Join ordinary demand to actual model-selected 1->2->1 ownership.

The raw join is architecture-neutral. Native custody currently uses the ARM
capture adapter; an x86 producer is still required. Trained Active provenance
is a separate gate, so even a valid applied chain is not full A03 PASS.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from build_sources import build_cache_context, code_source_map
from doctor import RUST_BIN, env
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
import v16_a03_demand as demand
from verify_v15_ownership import ROW_WORDS, WORDS, validate_structure

VERSION = 'v17-a03-applied-demand-v1'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def validate_binding(scene_raw, quiet_raw, owner_raw):
    scene = demand.decode_scene(scene_raw)
    demand.decode_quiet_record(quiet_raw, scene)
    chain = validate_structure(owner_raw)
    words = struct.unpack('<' + str(WORDS) + 'Q', owner_raw)
    first = words[128:128 + ROW_WORDS]
    at = 128 + (words[4] - 1) * ROW_WORDS
    last = words[at:at + ROW_WORDS]
    model = last[192:832]
    require(first[34] == 2 and first[8] == 6
            and scene['first_ns'] <= first[9] <= first[80] <= scene['withdrawn_ns'],
            'growth did not execute inside the ordinary high-load window')
    require(last[34] == 6 and last[8] == last[66] == last[82] == 2
            and last[14] == scene['quiet_job'] and last[12] == scene['quiet_version']
            and last[9] == scene['quiet_input_ns'] > scene['drained_ns']
            and model[28] == scene['quiet_observed_ns'] <= scene['complete_ns'],
            'quiet completion is not the matching actual contraction')
    require(quiet_raw == struct.pack('<640Q', *model),
            'retained quiet receipt differs from actual Applied owner model record')
    return dict(status='APPLIED_DEMAND_STRUCTURE_VALID', control_sets=chain['control_sets'],
                attempts=chain['attempts'], quiet_job=scene['quiet_job'],
                quiet_version=scene['quiet_version'], native_acceptance_status='NOT_RUN')


def replay_owners(source, directory):
    """Compile only caller-selected source; never execute archived checkers."""
    sources = code_source_map(source)
    cache = build_cache_context(source/'target/a03-v17-verifier', source, sources)
    environment = env()
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'):
        environment.pop(name, None)
    metadata = subprocess.check_output([str(RUST_BIN/'rustc'), '-vV'], env=environment,
                                       text=True, timeout=15)
    host = next(line.removeprefix('host: ') for line in metadata.splitlines() if line.startswith('host: '))
    require(host and all(c.isalnum() or c in '-_.' for c in host), 'invalid compiler host')
    target = Path(cache['effective'])
    command = [str(RUST_BIN/'cargo'), 'build', '--locked', '--offline', '--manifest-path',
               str(source/'Cargo.toml'), '--target-dir', str(target), '--target', host,
               '-p', 'cyxia-prototype', '--example', 'verify-ownership-evidence']
    built = subprocess.run(command, cwd=source, env=environment, capture_output=True,
                           text=True, timeout=180)
    require(built.returncode == 0, 'ownership model verifier build failed: '+built.stderr[-2000:])
    checker = target/host/'debug/examples/verify-ownership-evidence'
    require(checker.resolve(strict=True).is_relative_to(target.resolve()), 'external checker artifact')
    checked = subprocess.run([str(checker), str(directory/'ownership.bin'), str(directory/'model.bin')],
                             cwd=source, env=environment, capture_output=True, text=True, timeout=15)
    require(checked.returncode == 0, 'full ownership MLP/Plan replay failed: '+checked.stderr[-2000:])
    result = json.loads(checked.stdout)
    require(result.get('status') == 'MODEL_REPLAY_VALID' and result.get('full_integer_mlp') is True,
            'ownership replay lacks full MLP/Plan verification')
    require(code_source_map(source) == sources, 'source changed during ownership replay')
    return dict(result=result, checker_sha256=demand.sha(checker), build_command=command,
                build_log_sha256=hashlib.sha256((built.stdout+built.stderr).encode()).hexdigest())


def verify(directory, **context):
    root = Path(directory).resolve(strict=True)
    inventory = demand.bounded_inventory(root)
    # Native QMP/source/image/model custody and exact quiet-model replay remain
    # mandatory. No standalone structural fixture can reach the result below.
    receipt = demand.verify_capture(directory, **context)
    require(receipt.get('stimulus_verified') is True and receipt.get('model_replay') is not None,
            'ordinary native custody and model replay are mandatory')
    binding = validate_binding((root/'demand.bin').read_bytes(), (root/'quiet-model.bin').read_bytes(),
                               (root/'ownership.bin').read_bytes())
    owners = replay_owners(Path(context['source_root']).resolve(strict=True), root)
    require(owners['result'].get('replayed') == len(binding['attempts']), 'incomplete owner-model replay')
    require(demand.bounded_inventory(root) == inventory, 'capture changed during applied-demand verification')
    return dict(version=VERSION, status='APPLIED_DEMAND_VERIFIED',
                native_acceptance_status='NOT_RUN', A03_complete=False,
                trained_active_provenance_verified=False, x86_native_verified=False,
                ordinary_capture=receipt, applied_chain=binding, owner_model_replay=owners,
                verifier_sha256=demand.sha(Path(__file__)),
                scope='ARM native ordinary demand plus model/ApplyID/actual-owner roundtrip; trained Active and x86 native acceptance remain open')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('directory', 'source-root', 'build-manifest', 'formatter', 'qemu-binary', 'qemu-source'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--producer-tools-root', type=Path)
    parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    args = vars(parser.parse_args(argv))
    directory, lock = args.pop('directory'), args.pop('native_lock')
    try:
        with native_lease(lock):
            idle_native_host()
            result = verify(directory, **args)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError) as error:
        print(json.dumps(dict(version=VERSION, status='FAIL', native_acceptance_status='NOT_RUN',
                              A03_complete=False, error=str(error))))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
