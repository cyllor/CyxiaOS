# CyxiaOS static-image spawn and wait

CyxiaOS creates a new, independently admitted EL0 process through the explicit
`0x43595810` Cyxia ABI. It does not report successful `fork`, `vfork`, or general
Linux `execve`. The opt-in GLib source port uses this mechanism for
`g_spawn_sync`, asynchronous spawning, and child watches.

The syscall's first argument points to this 64-byte little-endian structure:

| Offset | Field | Meaning |
| --- | --- | --- |
| 0 | `u32 size` | Must be 64 |
| 4 | `u32 flags` | Bit 0 requests automatic reaping; other bits are rejected |
| 8 | `u64 path` | NUL-terminated executable pathname |
| 16 | `u64 argv` | NUL-terminated array of pointers |
| 24 | `u64 envp` | Explicit NUL-terminated array of pointers |
| 32 | `u64 cwd` | Optional working directory; NULL inherits the parent |
| 40 | `u64 mappings` | Array of `{ i32 source, i32 target }` |
| 48 | `u32 mapping_count` | At most 16 |
| 52 | `u32 reserved` | Must be zero |
| 56 | `u64 reserved2` | Must be zero |

`argv` and `envp` each accept at most 32 entries, with a combined 4 KiB string
budget including NUL terminators. Argument and environment strings are arbitrary
bytes. Pathnames use the filesystem's UTF-8, 95-byte limit. `AT_EXECFN` identifies
the actual catalog executable separately from caller-selected `argv[0]`.
Executable catalog files have read/execute mode `0555` and can be inspected
through ordinary file APIs. Executable lookup enforces parent-directory search
permissions before matching the immutable catalog.

Only mapped child descriptors are open. Source `-1` closes a target; `-2` creates
a fresh read/write `/dev/null`; nonnegative sources refer to the parent's table.
Duplicate targets are rejected, and all sources read the unchanged parent table,
so cycles cannot overwrite another source. Mapped descriptors have close-on-exec
cleared. Null, console, pipe, and PTY descriptions are supported. File, directory,
socket, and event-counter inheritance returns `ENOSYS` until those objects have
shared cross-process open-description ownership.

Pipe and PTY mappings retain real global endpoints. Duplicated descriptors share
their description, including pipe status flags. Closing the parent cannot
prematurely close a child's inherited endpoint; EOF follows the last writer.
The child's cwd, umask, and calling thread's signal mask are inherited. Installed
signal handlers reset, and explicit ignored dispositions remain ignored.

The supervisor copies and validates the request before publication. Local model
8193 admits the process floor and bounded exit-receipt occupancy; model 8195
admits the actual ELF/stack pages. Each child owns its address space, heap, PID,
and normal scheduler grants. Any later loader or endpoint-sharing failure closes
the new child's endpoint grants and releases its pages. Parent descriptors and
memory are not modified by failure.

Linux-AArch64 `wait4` supports a specific child PID or `-1`, options zero or
`WNOHANG`, and a nullable status pointer. Non-null `rusage` is explicitly
unsupported. Exit status distinguishes normal exit from signal termination.
Ten fixed receipt records preserve the model's two-record floor, allowing eight
outstanding waitable children even after their former process slots are reused.
A failed status copy does not consume the receipt. Reaping twice or waiting for
a non-child returns `ECHILD`. Automatic-reap children are not waitable.

`SIGCHLD` uses the actual child PID, reason, and exit/signal status. GLib's opted-in
child-watch handler omits unsupported restart and alternate-stack flags. A parent
exit releases its wait receipts and reparents live children to the kernel PID 0;
independent child mappings and inherited endpoint references remain valid.

Blocking pipe, PTY, and Unix-socket calls keep a per-thread record that their
saved SVC must be retried. A readiness wake does not erase this record: a caught
signal arriving between readiness and the next dispatch still returns `EINTR`
from the original call. The record clears when the SVC actually executes again
or its signal frame commits. This closes the PTY Ctrl-C race where a handler
ran successfully but its return silently restarted the blocked `read`.
`SA_RESTART`, alternate signal stacks, and general process groups remain outside
this ABI subset.

Spawn staging and ELF launch are separate, non-inlined functions so argv/env
and child metadata do not stay on every dispatch's kernel stack. The 512 MiB
profile uses caller-owned pinned VM batches; doubling its page capacity does
not duplicate page-batch arrays on the 64 KiB kernel stack. Compiled-frame
inspection and real target probes validate these bounds for each release ELF.

Validation commands:

```sh
python3 tools/verify_spawn.py --elf PATH --output artifacts/spawn-check
python3 tools/verify_threads.py --elf PATH --output artifacts/thread-check
python3 tools/verify_pty.py --elf PATH --output artifacts/pty-check
python3 tools/verify_desktop_abi.py --elf PATH --output artifacts/abi-check
```

The first command requires the optional `spawn-test` feature's real GLib probe.
`--syscall-only` checks the smaller libc probe on a desktop image. Its checks
cover pipe/descriptor sharing, UTF-8 cwd, byte arguments, environment, auxiliary
executable identity, wait status, SIGCHLD metadata, errors without side effects,
orphan lifetime, process-slot reuse, and receipt exhaustion/reclamation. The GLib
probe checks synchronous capture and a real asynchronous child-watch callback.
These checks establish this bounded source-port interface, not general POSIX or
Linux process compatibility.
