# Real musl detached-thread exit on x86

This continues the complete CyxiaOS/COSMIC plan from `0847553`, against
`docs/superpowers/specs/2026-11-15-x86-detached-thread-exit.md`.
The unchanged compositor's Fault139 is fixed. Its next observed failure is a
Mesa GLSL allocation assertion after anonymous-memory admission is denied;
complete desktop and complete OS verification remain false.

## Reproduction and cause

Evidence: `artifacts/v017-cosmic-egl-20261115-r1/`.
`reproduce.py` reruns the unchanged real compositor and rejects the original
Fault139. `baseline-01` reproduces it. Temporary boundary instrumentation in
`diagnostic-01` reports `resume` error Mapping at PC `0x02d04c97`, SP
`0x08a5c588`, TLS `0x08a5cb38`; there is no captured hardware fault.

The exact ELF maps that PC to `__unmapself+7`:

```text
0x02d04c90  b8 0b 00 00 00  mov eax,11       # munmap
0x02d04c95  0f 05           syscall
0x02d04c97  48 31 ff        xor rdi,rdi
0x02d04c9a  b8 3c 00 00 00  mov eax,60       # exit
0x02d04c9f  0f 05           syscall
```

Musl 1.2.6's detached `__pthread_exit` blocks signals, unregisters robust-list
storage and calls this sequence. It intentionally unmaps its own stack/TLS,
then exits without accessing either. The x86 resume guard incorrectly required
SP-1 to remain mapped RW/NX after every syscall. It rejected this legitimate
tail; the shared adapter converted that refusal to process Fault139. EGL's
preceding dmabuf warning was nonfatal and did not identify the cause.

`root-cause.json` binds the original ELF bytes, PC and musl assembly source to
the actual diagnostic UART. All temporary `DEBUG-egl139` code has been removed.

## Fix and protection

The architecture resume path now validates RSP against the existing lower-user
address range without requiring its backing page to exist. IRET restores the
register without accessing the user stack. Noncanonical and out-of-range RSP
values remain rejected before IRET, preventing an exception in kernel mode.
Instruction pages must still be executable and nonwritable. Actual CPL3 memory
accesses retain their page protections; address-space ownership, revocation,
FP/TLS save/restore and dispatch admission are unchanged. No ELF-PC exception,
replacement stack, retained mapping or libc instruction emulation is used.

## Actual regression

`thread_exit_probe.c` reduces the defect to actual musl pthread operations. Four
workers are held alive until pthread_detach succeeds, then released. Each cycle
requires native `tgkill(pid, tid, 0)` to return ESRCH, proving SYS_exit completed;
a worker-set flag would only prove execution before libc teardown. A normal
joined worker then verifies slot/backing reuse.

`thread-red-01` fails with the same Mapping/Fault139. The tightened
`thread-red-02` detects process death immediately instead of waiting for a marker
timeout. The same probe source/SDK/ELF is used for the final GREEN capture.

`thread-exit-01` passes a normal / invalid-stack / normal sequence. Both normal
runs admit five worker threads, peak at two live threads, complete all four
actual detached exits and join reuse, and exit 0 (105 and 115 syscalls).
The negative program sets noncanonical RSP and invokes getpid; unexpected resume
would exit 77 using registers only. It is instead safely refused as Fault139,
with no hardware-fault record or kernel panic. The following normal run passes.
All three processes reclaim their thread, image, heap and OFD resources.

Formal `os-build-01` source SHA256:
`415a9127aee7224f84e07f6adfeb66cf6d70a37510a5c26d4255b4ce6bc74aed`.
The capture binds probe source, SDK libc/driver, ELF layout and exact read-only
embedding, and rechecks inputs at completion. Host architecture/Shell tests
pass 38 cases; Python OS checks pass 10. ARM legacy compilation passes, without
claiming an ARM guest run. Native protection/FP/TLS, real COSMIC version,
inotify, nested epoll, flock and same-disk reboot regressions all pass using the
same final build. All native commands execute serially under the shared lease.

Standards and Spec reviews found no remaining implementation defect.

## Next observed boundary

The unchanged compositor SHA256 remains
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`.
`cosmic-startup-01` completes the original Fault139 regression, advances to 989
syscalls, then exits 134 with Mesa `src/compiler/glsl/ir.h` allocation assertion.
UART records an anonymous allocation request of 16 pages with 40 free pages.
The fixed private heap contains 4,096 pages (16 MiB); 4,056 pages are occupied.

This specific denial precedes VM placement: model 8194 receives features
`[1,2,1,0]`, evaluates the existing weights to -5 and refuses the allocation.
The anonymous receipt records 425 requests, 424 approvals, one denial and no
capacity/commit failure. This is not evidence of physical-RAM exhaustion or
fragmentation. Increasing host RAM alone does not enlarge that private arena.
The next work needs an explicit full-OS heap profile, validated model domain
and address-layout bounds, followed by the same real compositor replay.
The current model accepts at most 4,096 free pages, and a heap growing from
`0x08000000` reaches the main stack at `0x0a000000` after 32 MiB. Eight eagerly
reserved heap/image arenas already account for 640 MiB of the 1 GiB guest.
Increasing a page-count constant alone therefore cannot establish a valid
desktop memory profile. Measure live/peak use and mapping limits alongside
the profile change; cumulative granted pages include released/reused pages.
Configuration/assets, socket pathname lifecycle and complete desktop interaction
remain open; no memory-policy bypass is part of this fix.

## Reproduce and coverage lesson

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature full-os --feature cosmic-desktop \
  --sysroot artifacts/v017-cosmic-egl-20261115-r1/sysroot \
  --output artifacts/thread-exit-new-build
python3 tools/os_smoke.py --build artifacts/thread-exit-new-build \
  --scenario thread-exit --output artifacts/thread-exit-new-run
```

The older `thread_probe.c` covers detached teardown but embeds ARM assembly and
its verifier selects the ARM sysroot. It did not establish x86 coverage. Use the
new x86 `thread-exit` scenario for changes to resume/teardown; its negative case
also checks safe stack-pointer admission and kernel survival. The V0.17 CI
build/host checks do not run this native scenario, so CI success alone remains
insufficient runtime evidence. For Fault139 with zero ESR/FAR, first distinguish
entry refusal from a captured `USER_FAULT` before attributing the last library
warning as the fault cause.
