# Native user boundary

The six runtime images share algorithm and protocol code. `calls.rs` selects
actual instructions for the compiled target; it does not translate ARM code or
expose a kernel exception frame.

| Value | AArch64 | x86-64 |
| --- | --- | --- |
| Entry | `extern "C" _start`, SP aligned to 16 | SysV `extern "C" _start`, RSP modulo 16 = 8 |
| Entry arguments | x0, x1, x2, ... | rdi, rsi, rdx, ... |
| Call instruction | `svc #NUMBER` | `int 0x80` |
| Logical call number | SVC immediate | rax, retained on return |
| Five argument slots | x0, x1, x2, x3, x4 | rdi, rsi, rdx, r10, r8 |
| Operation selector | x8 | r9 |
| Four result slots | x0, x1, x2, x3 | rdi, rsi, rdx, r10 |

This x86 boundary is a Cyxia native ABI, not Linux syscall compatibility. The
kernel must initialize all enabled register state and provide private guarded
stacks. An x86 entry stack can reserve an eight-byte zero return sentinel below
the aligned stack top. Entries never return normally.

The adapter conservatively declares the C volatile-register clobbers, accesses
memory, and makes no claim that flags survive a call. `release_shared` publishes
volatile shared data before its completed sequence. `fault` emits a real target
synchronous fault for service retirement probes.

`python3 -B user/build_runtime.py --arch x86_64 --output NEW_DIR --identity OWN_DIR`
builds the six images, inspects their emitted ELF machine, entry, segment bounds
and permissions, checks provisioned TLS inputs in the cluster image, and binds
the source and artifacts in `user-images.json`. Output must be new and is
private. It uses the shared native lease; callers must arrange the controller's
compiler grant and source freeze first. Its result is `BUILT_NOT_RUN`.

ARM retains its existing targets and default cluster build invocation. Protocol
tests containing an explicit ARM ISA continue to describe ARM fixtures; live
placement requests and quotes use the compiled target's ELF machine number.
