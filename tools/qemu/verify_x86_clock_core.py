#!/usr/bin/env python3
"""Compile fault tests against the exact common timing code from attested source.

This validates accumulator logic, not real host/guest timing. It takes the native
build lease. Native busy/HLT/sibling observations remain a separate requirement.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from x86_accounting import HERE, attest_source, require, sha
sys.path.insert(0, str(HERE.parent))
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease

HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct CPUState {
    uint64_t cyxia_exec_ns, cyxia_exec_started_ns, cyxia_exec_last_clock_ns;
    bool cyxia_exec_active, cyxia_exec_initialized, cyxia_exec_failed;
} CPUState;
static CPUState *current_cpu;
static uint64_t fake_ns;
static bool fake_error;
static int fake_clock_gettime(clockid_t id, struct timespec *ts)
{
    assert(id == CLOCK_THREAD_CPUTIME_ID);
    if (fake_error) { return -1; }
    ts->tv_sec = fake_ns / 1000000000ULL;
    ts->tv_nsec = fake_ns % 1000000000ULL;
    return 0;
}
#define clock_gettime fake_clock_gettime
/* PRODUCTION_CLOCK_CODE */
#undef clock_gettime

static CPUState fresh(void)
{
    CPUState cpu = { 0 };
    fake_error = false;
    fake_ns = 100;
    return cpu;
}

int main(void)
{
    CPUState a = fresh(), b = { 0 };
    uint64_t out = 0;
    current_cpu = &a;
    assert(!cyxia_cpu_exec_time_ns(&a, &out)); /* no successful init */
    cyxia_cpu_exec_start(&a);
    fake_ns = 110;
    assert(cyxia_cpu_exec_time_ns(&a, &out) && out == 10);
    fake_ns = 120;
    cyxia_cpu_exec_stop(&a);
    assert(a.cyxia_exec_ns == 20 && !a.cyxia_exec_active);
    /* Between-TB host work never enters the accumulator. */
    fake_ns = 1000000;
    cyxia_cpu_exec_start(&a);
    fake_ns += 10;
    assert(cyxia_cpu_exec_time_ns(&a, &out) && out == 30);
    current_cpu = &b;
    assert(!cyxia_cpu_exec_time_ns(&a, &out));
    assert(!a.cyxia_exec_failed); /* non-owner query cannot poison the CPU */
    current_cpu = &a;
    cyxia_cpu_exec_stop(&a); /* same cleanup path used after longjmp */
    assert(a.cyxia_exec_ns == 30);
    cyxia_cpu_exec_stop(&a); /* cleanup outside a TB is idempotent */
    assert(a.cyxia_exec_ns == 30 && !a.cyxia_exec_failed);

    a = fresh(); current_cpu = &a; fake_error = true;
    cyxia_cpu_exec_start(&a);
    assert(a.cyxia_exec_failed && !a.cyxia_exec_active);
    fake_error = false;
    cyxia_cpu_exec_start(&a);
    assert(!cyxia_cpu_exec_time_ns(&a, &out)); /* error remains latched */

    a = fresh(); current_cpu = &a; cyxia_cpu_exec_start(&a);
    fake_error = true;
    cyxia_cpu_exec_stop(&a);
    assert(a.cyxia_exec_failed && !a.cyxia_exec_active);

    a = fresh(); current_cpu = &a; cyxia_cpu_exec_start(&a);
    fake_ns = 130;
    assert(cyxia_cpu_exec_time_ns(&a, &out) && out == 30);
    fake_ns = 125; /* after the last sample, but still above TB start */
    cyxia_cpu_exec_stop(&a);
    assert(a.cyxia_exec_failed);

    a = fresh(); current_cpu = &a; cyxia_cpu_exec_start(&a);
    a.cyxia_exec_ns = UINT64_MAX - 5;
    fake_ns += 6;
    assert(!cyxia_cpu_exec_time_ns(&a, &out) && a.cyxia_exec_failed);

    a = fresh(); current_cpu = &a; cyxia_cpu_exec_start(&a);
    cyxia_cpu_exec_start(&a);
    assert(a.cyxia_exec_failed); /* nested interval is a bug, never free credit */
    puts("X86_CLOCK_CORE_FAULT_TESTS_PASS");
    return 0;
}
'''


def run(source, compiler='cc', native_lock=DEFAULT_NATIVE_LOCK):
    source = Path(source).resolve(strict=True)
    proof = attest_source(source)
    text = (source / 'cpu-common.c').read_text()
    begin = '/* BEGIN CYXIA_EXEC_CLOCK: extracted unchanged by the focused fault harness. */'
    end = '/* END CYXIA_EXEC_CLOCK */'
    require(text.count(begin) == text.count(end) == 1, 'clock extraction markers differ')
    code = text.split(begin, 1)[1].split(end, 1)[0]
    selected = shutil.which(compiler)
    require(selected is not None, 'C compiler unavailable')
    with native_lease(native_lock):
        idle_native_host()
        with tempfile.TemporaryDirectory(prefix='cyxia-x86-clock-core-') as directory:
            root = Path(directory)
            (root / 'harness.c').write_text(HARNESS.replace('/* PRODUCTION_CLOCK_CODE */', code))
            argv = [selected, '-std=gnu11', '-Wall', '-Wextra', '-Werror', str(root / 'harness.c'), '-o', str(root / 'harness')]
            subprocess.run(argv, check=True, capture_output=True, timeout=30)
            result = subprocess.run([str(root / 'harness')], check=True, capture_output=True, text=True, timeout=10)
    require(result.stdout == 'X86_CLOCK_CORE_FAULT_TESTS_PASS\n', 'clock fault harness did not pass')
    return dict(status='ACCUMULATOR_FAULT_TESTS_PASS_NOT_NATIVE_TIMING', source=proof,
                harness_sha256=sha(Path(__file__)), compiler=str(Path(selected).resolve()), stdout=result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--compiler', default='cc')
    parser.add_argument('--native-lock', type=Path, default=DEFAULT_NATIVE_LOCK)
    args = parser.parse_args()
    print(json.dumps(run(args.source, args.compiler, args.native_lock), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
