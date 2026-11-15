# Native x86 OS backend

`os-runtime` uses `0xffff800000000000 + physical_address`, a distinct physical
Multiboot bootstrap and the runtime linker. The legacy BSP/SMP mechanism builds
keep their entry and linker. This backend serves the shared OS process, desktop
and service policies; it does not create a second scheduler or successful empty
device adapters.

## Process boundary

`arch::user::Context` owns all enabled integer, x87/MMX/SSE and TLS state. Its
register layout is private. `UserAbi::CyxiaNative` uses int80 with native service
number in RAX, operation in R9 and arguments in RDI/RSI/RDX/R10/R8. `Linux64`
uses the actual Linux x86-64 SYSCALL convention and returns in RAX.

The shared process owner initializes a context with `initialize(entry, sp, abi)`,
uses `pc/set_pc`, `sp/set_sp`, `tls/set_tls`, `argument/set_argument`,
`set_result/set_results`, `restart_syscall` and `clone_for_thread`. It handles
`UserExit::Syscall`, `Preempted` or `Fault`, without interpreting ARM ESR or a
hardware trap frame. Signal-frame serialization remains an ISA-specific ABI.

`unsafe user::resume(&mut Context, &AddressSpace, deadline_ns)` executes the
actual private root with an armed local timer. On return the kernel root and
kernel FP/TLS are restored; no user context remains active. Context and table
storage must stay pinned throughout entry and return.

## Address-space boundary

The process allocator supplies `TableArena::from_raw(kernel_va, physical_base,
pages)` and retains its real frame ownership. `AddressSpace::new(arena,
&KernelMappings, SpaceId)` allocates four-level tables within that bounded arena.
`map`, `protect`, `unmap`, `translate`, `root_phys` operate on low canonical user
addresses. Upper-half kernel entries remain supervisor-only and shared.

`unmap` does not release frames. CPU residency, epoch-tagged TLB invalidation and
old-context retirement must complete before the memory owner reuses backing.
Executable frames must lose writable aliases before publication; a failed
shootdown retains their ownership instead of returning a reclaim permit.

## CPU and board boundary

The physical bootstrap validates Multiboot/ACPI and enters the high kernel.
`crate::os::run(&PcBootInfo)` receives real discovered RAM/reservations. Each AP
has private descriptor tables and guarded stacks and waits for
`runtime::release_aps(extern "C" fn(usize) -> !)`. That callback enters the shared
OS scheduler, not a mechanism workload.

`runtime::now_ns`, `arm_deadline`, `wake` and `cpu_slot` supply a global HPET
monotonic clock, local APIC timer and targeted wake delivery. They do not provide
CPU billing: the independently validated execution accounting backend does that.

The root composition owns syscall policy, scheduling, filesystem/device wiring,
PTY/terminal and the COSMIC/Smithay/Wayland desktop. Missing hardware capabilities
return errors; there is no success stub for an unavailable service.
