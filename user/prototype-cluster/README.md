# Protected native cluster service

This is a standalone Cargo workspace: EL0 uses standard `aarch64-unknown-none`
with FP/SIMD; EL1 remains `aarch64-unknown-none-softfloat`. The kernel must save
and restore SIMD registers across every exception/context switch and enable
EL0 FP/SIMD. No NEON assertions or crypto checks are disabled.

Provision outside the repository, then build each node separately:

```
python3 user/prototype-cluster/tools/provision.py /tmp/cyxia-identities
CYXIA_CLUSTER_IDENTITY=/tmp/cyxia-identities/a user/prototype-cluster/tools/build.sh
cp target/aarch64-unknown-none/release/cyxia-prototype-cluster /tmp/cyxia-identities/a/service.elf
CYXIA_CLUSTER_IDENTITY=/tmp/cyxia-identities/b user/prototype-cluster/tools/build.sh
cp target/aarch64-unknown-none/release/cyxia-prototype-cluster /tmp/cyxia-identities/b/service.elf
```

Each service image embeds its own certificate/private key and peer public key
and pin. The peer private key is never read by that node's build. These are
explicit development identities, with no measured-boot claim. A changed image
identity must fail persistent-volume identity validation. Keep provisioning
files and final images private. Host tests use separate test-only fixtures.

`src/abi.rs` is the kernel's reusable source of truth. All service pointers stay
inside its private address space. SVC 0x43 has no pointer arguments: the broker
reads a fixed request, validates the operation/count, performs one bounded
operation, and writes the reply before the context resumes. Status 1 means
would-block, 2 EOF, 3 failure, 4 missing record. No clock or counter entropy
fallback exists. Epoch/NodeIDs/UUID in the shared header are immutable broker
inputs. A transport connection-epoch change aborts TLS and protocol authority.

The ELF has disjoint RX, RO and RW load segments at >=0x01000000; the linker
reserves 0x01fc0000 onward for a separately mapped private stack, whose top is
0x01ff0000 and size is 128KiB. The shared region at 0x02000000 is 16KiB;
currently the repr(C) Shared structure uses 8192 bytes. The allocator is a fixed
8MiB reusable bitmap arena with 64-byte units. Allocation pressure cannot grow
this quota. OOM/panic stops progress and yields; it cannot manufacture grants.

Ring 0.17.14 is vendored solely for this standalone workspace. Its sole upstream
source change adds `target_os=none` to ELF assembly selection in build.rs;
without it upstream compiles Rust/C references without the AArch64 assembly
symbols. `RING_CORE_NOSTDLIBINC` uses upstream's freestanding header path and
preserves its builtin-trap debug assertion implementation. Crypto source,
assembly and NEON assertions remain upstream. macOS ar/ranlib can warn that
its ELF archive table is empty; rust-lld resolves the actual ELF members.

The TLS policy is TLS1.3/X25519/AES128GCM/Ed25519 with mutually pinned NodeIDs,
no resumption/tickets/0RTT, a five-second handshake deadline and bounded record
buffers. `TimeProvider` receives broker monotonic time plus a provisioned UTC
offset; dates are not a Web-PKI authority in this pinned model. Each reconnect
creates fresh X25519 state and must repeat HELLO/reconciliation before READY.

Trace arg0: 1 entry, 2 configured, 3 mutually authenticated, 4 disconnected;
0xff panic, 0xfe ABI mismatch, 0x101 missing BootEpoch, 0x102 peer pin mismatch,
0x103 TLS/entropy configuration failure, 0x104 local identity mismatch,
0x105 unavailable time. Protocol traces are documented with the driver.
