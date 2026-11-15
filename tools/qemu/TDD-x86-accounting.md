# x86 accounting backend implementation evidence, 2026-11-14

Source plan: [Task 2](../../docs/superpowers/plans/2026-11-14-v017-x86-runtime.md).
The user authorized implementation directly; checkpoint commits are owned by the
integration controller and were not created by this worker.

The intended behavior is a paid runtime that rejects missing or failed execution
clocks, uses per-vCPU translated execution ns for debit, and uses a distinct
shared monotonic clock for deadlines.

| Check | Actual result | Scope |
| --- | --- | --- |
| `python3 -m unittest discover -s tools/qemu -p 'test_x86_accounting.py' -v` before backend | RED: absent `x86_accounting.py`, `FileNotFoundError` | Missing implementation |
| Same suite after backend and patch | GREEN, 7 tests | Exact ABI, identity/regression/overflow/profile/resource binding |
| New exact-version test before helper | RED: executed test raised `AttributeError` for absent `validate_version` | Fresh clones without tags must remain source-attested |
| Same complete suite after version correction | GREEN, 8 tests | Exact 10.2.2 strings; future/custom versions reject |
| `verify_x86_clock_core.py --source /private/tmp/cyxia-v017-x86-accounting-20261114` | `X86_CLOCK_CORE_FAULT_TESTS_PASS` | Exact extracted accumulator logic with fault provider, not native timing |
| `build_x86_accounting.py build --source /private/tmp/cyxia-v017-x86-accounting-20261114 --jobs 4` | Build exit 0, 1562/1562 steps | Fresh pinned x86 QEMU binary; no guest run |
| `x86_accounting.py --source ... --binary .../build/qemu-system-x86_64` | `SOURCE_AND_BINARY_BOUND_NOT_NATIVE_VERIFIED` | Commit/patch/source/dependency/binary/build provenance |

The initial strict version suffix check rejected the freshly built binary because
its local source clone had no tag refs and printed `QEMU emulator version 10.2.2`.
The x86 attestor now accepts that exact string or exact `v10.2.2-dirty` only after
source and binary binding. The suffix itself never proves patch support. The
historical Arm attestor and its pins were not changed.

The controller separately ran the four Rust accounting contract tests successfully
(`artifacts/v017-x86-runtime-20261114-r3/accounting-green.log`). The tests now import
the registered public module; that import-only edit was not rerun by this worker
because the controller holds the compilation lease for integration.

Build outputs and logs were copied to
`artifacts/v017-x86-accounting-backend-20261114/`, with an inventory of hashes.
The actual binary/source remain at `/private/tmp/cyxia-v017-x86-accounting-20261114`.
Binary SHA256: `3bbc41f1a69b9cddea7c02c926a8a4776e8b6b485054f633e5ec8b3e2064a234`.
Patch SHA256: `a78d5be7ddc346aa404499a36618d2df8caeba34055935b3d0f5d431ebee8f73`.

No guest busy/HLT/sibling/role-swap/exception or negative capability VM checks have
run in this worker. No native accounting, full-runtime, or A03 PASS is claimed.
Coverage percentage was not measured. The supported host clock was compiled on
macOS; genuine host/guest timing behavior still requires the native matrix.
