#!/usr/bin/env python3
"""Benchmark actual x86 staging, page tables and runtime alias transactions.

Host CPU identity / PTE / IPI effects are fixtures. Correctness and separate
untimed work observations precede timing without the observation counter.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tests/host'), str(ROOT / 'tools')]
import test_page_map_batch as harness
from native_session import DEFAULT_NATIVE_LOCK, native_lease, idle_native_host


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--require-coalesced', action='store_true')
    parser.add_argument('--require-coalesced-retire', action='store_true')
    parser.add_argument('--require-direct-alias-counts', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    files, identity = harness.production_files(source_root=args.source_root)
    fixture = files['runtime-fixture.rs']
    old = 'fn cpu_slot() -> usize { CPU.load(Ordering::Relaxed) as usize }'
    assert fixture.count(old) == 1
    fixture = fixture.replace(old, '''static OWNER_READS: AtomicU64 = AtomicU64::new(0);
pub fn owner_reads() -> u64 { OWNER_READS.load(Ordering::Relaxed) }
fn cpu_slot() -> usize {
    #[cfg(ecc_owner_observation)]
    OWNER_READS.fetch_add(1, Ordering::Relaxed);
    CPU.load(Ordering::Relaxed) as usize
}''')
    arithmetic = '    let mut updated = 0;\n    for (flag, shift)'
    assert fixture.count(arithmetic) == 1
    fixture = fixture.replace(arithmetic, '''    #[cfg(ecc_owner_observation)]
    ALIAS_ARITHMETIC_PAGES.fetch_add(1, Ordering::Relaxed);
''' + arithmetic)
    fixture += '''
static ALIAS_ARITHMETIC_PAGES: AtomicU64 = AtomicU64::new(0);
pub fn alias_arithmetic_pages() -> u64 { ALIAS_ARITHMETIC_PAGES.load(Ordering::Relaxed) }
'''
    files['runtime-fixture.rs'] = fixture
    bench = ROOT / 'tests/host/cosmic_mapping_benchmark.rs'
    files['cases.rs'] += '\n' + bench.read_text()
    for name, content in files.items():
        (args.output / name).write_text(content)
    identity.update(benchmark_sha256=hashlib.sha256(bench.read_bytes()).hexdigest(),
        fixture_note='Owner and alias arithmetic counters enabled only in separate untimed observation binary',
        generated_sha256={n: hashlib.sha256(s.encode()).hexdigest() for n, s in files.items()})
    (args.output / 'source-identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    compiler = shutil.which('rustc')
    if compiler is None:
        raise RuntimeError('Rust compiler required on PATH')
    compiler = str(Path(compiler).resolve())
    env = os.environ.copy()
    env['RUST_MIN_STACK'] = '16777216'
    if args.require_coalesced:
        env['ECC_REQUIRE_COALESCED'] = '1'
    if args.require_coalesced_retire:
        env['SUPERPOWERS_REQUIRE_COALESCED_RETIRE'] = '1'
    if args.require_direct_alias_counts:
        env['MATT_REQUIRE_DIRECT_ALIAS_COUNTS'] = '1'
    result = dict(status='FAIL', scope='Host algorithm benchmark, not guest MMU/TLB timing',
        compiler=dict(path=compiler, sha256=hashlib.sha256(Path(compiler).read_bytes()).hexdigest()),
        rows=[], correctness=False)
    with native_lease(DEFAULT_NATIVE_LOCK):
        idle_native_host()
        result['compiler']['version'] = subprocess.check_output([compiler, '-Vv'], text=True)
        for observed in (False, True):
            binary = args.output / ('observed' if observed else 'timed')
            command = [compiler, '--edition=2024', '--test', '-O', '--cfg', 'feature="runtime"',
                       '-Dwarnings', str(args.output / 'transactions.rs'), '-o', str(binary)]
            if observed:
                command += ['--cfg', 'ecc_owner_observation']
            compiled = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
            (args.output / (binary.name + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
            if compiled.returncode:
                raise RuntimeError(compiled.stdout + compiled.stderr)
            if not observed:
                gates = subprocess.run([str(binary), 'runtime_batch_', '--test-threads=1'],
                    env=env, capture_output=True, text=True, timeout=30)
                (args.output / 'correctness.log').write_text(gates.stdout + gates.stderr)
                if gates.returncode:
                    raise RuntimeError(gates.stdout + gates.stderr)
                result['correctness'] = True
            ran = subprocess.run([str(binary), 'ecc_mapping_benchmark', '--nocapture', '--test-threads=1'],
                env=env, capture_output=True, text=True, timeout=60)
            (args.output / (binary.name + '-run.log')).write_text(ran.stdout + ran.stderr)
            for line in ran.stdout.splitlines():
                if 'ECC_MAPPING_BENCH ' in line:
                    result['rows'].append(json.loads(line.split('ECC_MAPPING_BENCH ', 1)[1]))
            if ran.returncode:
                (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                raise RuntimeError(ran.stdout + ran.stderr)
        result['status'] = 'PASS'
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'compiler'}, indent=2))


if __name__ == '__main__':
    main()
