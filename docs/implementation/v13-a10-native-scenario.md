# Ordinary EL0 filesystem crash scenario for A10

Status: independent volume decoder/image regression, dedicated EL0 producer,
protected capture, shared kernel wiring and four-mode runner are implemented.
Mode 4 now implements the same-boot cache-eviction workload and strict receipt
verification described below. No ordinary-file native run is yet certified.
The four successful boot/journal COMMIT-FLUSH cuts do not complete A10.

## Workload and source ownership

Use the existing selftest-enabled unified image and real `svc #0x45` file ABI.
The current `prototype-client` file test deletes its file before exiting and has
one owner, so it cannot be reused unchanged as the durable crash oracle.

The dedicated workload belongs in `user/prototype-client/storage_fault.rs`.
Two independently admitted `CLIENT_PACKAGE` tasks receive separate ordinary file
capabilities. Their launch input identifies writer/reader role, scenario mode and
the actual BootEpoch. Startup uses the existing kernel caller and admission path;
it does not grant the host authority to execute file operations.

Shared integration requires coordinated changes to `kernel/build.rs`,
`user/prototype-client/main.rs`, `kernel/src/domain_tasks/execution.rs`,
`kernel/src/main.rs` and `kernel/src/unified.rs`. The dedicated build uses
`--selftest --storage-fault` (`CYXIA_STORAGE_FAULT_PROBE=1`); the default build
sets this flag to zero. `kernel/src/storage_fault_capture.rs` contains the
protected capture implementation. File-result hooks are in
`kernel/src/domain_file_abi.rs` after successful delivery, with no new
filesystem syscall or host implementation of recovery.

Role ownership is registered during ordinary task creation before the task can
run. The existing exit syscall snapshots the 13-word user progress page before
ordinary cleanup releases its memory. A failed progress read records zeros and
does not change task exit behavior. The writer's observed sequence includes its
last consumed FSYNC receipt: 2 in preparation and 3 in overwrite mode.

## Bounded first scenario

1. Preparation mode starts from a newly formatted disk. Writer creates
   `/a10/value`, writes a prescribed 4 KiB version 1, consumes FSYNC sequence 1,
   overwrites the same page with version 2, and consumes FSYNC sequence 2.
2. Reader, under a different task/file capability, opens the existing object,
   checks its durable sequence, reads and checks every word of version 2, and
   checks the object generation and sequence again. It creates an empty marker
   named for the current BootEpoch only after the complete read succeeds.
3. Capture and retain the acknowledged sequence-2 disk. A fresh overwrite-mode
   boot repeats the independent reader observation and creates a new epoch-named
   marker. Writer waits for that new marker, then overwrites the same 4 KiB home
   with version 3 and calls FSYNC. It never deletes the original file.
4. A clean native trace establishes operation boundaries. The fault runner cuts
   before/after real sector WRITE or FLUSH replies in the selected version-3
   transaction, including BEGIN/REDO/COMMIT and checkpoint/superblock boundaries.
   Lost or reordered unflushed sectors and reordered completions use the tested
   bounded NBD backend. No host action writes file metadata or replays the log.
5. Recovery mode reboots the exact damaged image. Ordinary EL0 reader reopens the
   original object and checks version, size, object generation and durable
   sequence. Version 2 must survive; version 3 is allowed only when the complete
   accepted COMMIT chain covers it. A second injected cut during native recovery
   must still leave that acknowledged prefix recoverable on a third boot.

An epoch-named ordinary file marker prevents the writer from mistaking a reader
observation from a previous boot for visibility in the new boot. Marker creation
is itself real filesystem I/O and is included in the transcript, rather than
hidden from transaction counts.

## Protected evidence contract

Capture the actual successful file-result delivery, not a user-supplied success
flag. Each bounded record retains the task object/generation, boot identity,
monotonic request ID, complete 640-byte file reply frame, current journal COMMIT
LSN, native I/O counters and a digest of the actual transferred READ/WRITE bytes.
READ records bind the bytes copied to the second task. FSYNC records bind object
identity and the exact returned write/durable sequence. User progress pages may
show that the compiled client consumed a reply, but cannot replace the protected
reply event or independent disk content.

The protected progress bank is published only on actual task exit. A separate
256-byte `A10_CONSUMPTION` bank now distinguishes pre-exit consumption for modes
1 and 2. After the selected writer FSYNC reply has been copied out, the kernel
retains its protected event and request identities. At the writer's next valid,
authorized file call it requires the immediately following request to be CLOSE,
copies the stopped task's complete 104-byte progress record, and publishes the
owner, native timestamp, FSYNC event/request, continuation request/operation and
progress bytes with a release-sealed magic. It accepts only stage 4/sequence 2 in
preparation mode or stage 7/sequence 3 in overwrite mode. The independent
verifier cross-links that bank to the exact successful protected FSYNC record,
object generation and durable sequence; reader-only modes require an all-zero
bank. Thus NBD `after-ack`, ABI delivery, EL0 consumption and eventual task exit
remain four separate facts. The source/ELF-bound implementation and negative
tests pass, but this boundary remains `BUILT_NOT_RUN` until native capture.

A matrix must still bind its sequence-2 starting disk to the earlier preparation
run's verified ABI, consumption and actual-exit receipts. No cut is promoted
merely because the new bank is present.

The immutable run input specifies mode, roles, expected payload versions and
nonce. The producer and runner bind that input to the source/build/ELF identity,
volume UUID and BootEpoch. Missing, duplicated, overflowed, stale or contradictory
capture remains incomplete or fails; neither a client stage nor a JSON PASS flag
can certify a case.

`tools/check_v13_filesystem.py` independently validates the accepted journal
prefix, inode CRCs and generations, extent bounds and ownership, exact bitmap,
parent ancestry, directory names/references and reserved boot/cluster objects.
It reports ordinary paths, durable sequence, extents and content SHA-256. A real
Rust filesystem image already verifies inode 5/generation 2, acknowledged sequence
2, highest COMMIT LSN 24 and payload `0x22`, while ignoring an uncommitted third
version after its final FLUSH was cut. The host decoder never modifies an image.

## Remaining full-case obligations

The first scenario does not by itself cover every A10 boundary. The final matrix
must enumerate and execute ordinary-file redo/COMMIT/superblock boundaries,
multiple versions of the same home, actual completion reordering, interruption
of replay, cross-endpoint visibility after the durable ACK, and a reread after
real cache eviction. Reboot creates a cold cache but will not be labeled as a
same-boot eviction test. That additional phase must pressure or reclaim the real
cache and prove a miss/backing read without changing mandatory policy budgets.

Mode 4 pressures the actual `FileSystem<4096>` cache with ordinary file ABI
writes: it warm-reads `value`, writes and FSYNCs two additional exact 8 MiB
files (4096 new pages total), then rereads `value` in the same boot. Each
pressure file is written in 128 ordered 64 KiB calls with independently known
bytes. The protected capture capacity is explicitly 384 events; the loaded ELF
publishes a 295,424-byte logical trace in a 299,008-byte page-aligned symbol.
The independent verifier checks every chunk offset/hash, both durable file
hashes and object identities, then requires positive per-call cache-miss and
NativeDisk-read deltas on the final original-file READ. A host execution of the
actual client and a 274-record tamper fixture cover the flow, but only a native
mode-4 run can establish those facts. The mode therefore remains
`BUILT_NOT_RUN` and A10 remains `NOT_RUN`.

The runner's diagnostic layout check was also corrected to the current complete
`DOMAIN_CONTROL_EVIDENCE` bank: 512 header words plus 64 records of 640 words,
331,776 bytes. The previous 4 KiB expectation would have rejected every current
A10 image before QEMU launch.

Continue using sparse disk files. New raw NBD logs can use lossless gzip with
both uncompressed and stored-byte digests; independently reconstructible disk
byte deltas may be added for larger matrices. Existing successful and failed
capture artifacts remain untouched. A10 stays NOT_RUN until the complete raw
contract and reviewed native receipt adapter cover every required outcome.

`run_v13_a10.py --artifact-cache PRIVATE_DIRECTORY` can share verified immutable
ELF/service/task bytes across cases. The private content-addressed store first
copies the original build, verifies its SHA, makes that cache entry read-only,
then creates hard links into each evidence directory (or a verified copy across
filesystems). It verifies cache bytes on every reuse and retains end-of-run
checks of the actual executed image. Mutable disk images never share hard links.

After independently checking a clean mode-2 NBD transcript and file trace,
`verify_v13_a10_faults.overwrite_window` derives the transaction's 50 device
mutation points from protected I/O counters: 48 sector writes and two FLUSHes.
The selector rejects merged/missing sectors, inconsistent counters or a window
other than the declared two-REDO overwrite. It produces only planned points;
there is no executed-matrix verdict until each actual cut/recovery is captured.

`tools/run_v13_a10_matrix.py` now supplies that complete orchestration layer.
Starting from one freshly formatted volume, it binds the verified preparation
disk, clean overwrite probe and same-boot mode-4 cache run. It then cuts at
**every observed overwrite mutation**, not merely the 50-point version-3
subwindow, for both `before`/`after-ack` phases and both `drop`/`reverse-half`
volatile-loss models. Every resulting damaged image gets an independent clean
recovery probe; every mutation observed in that recovery is in turn cut across
the same four combinations and followed by a third clean recovery boot.
Diagnostic `flushes` or explicit-point selectors are supported, but the
independent `verify_v13_a10_matrix.py` gate returns `NOT_RUN` for all such
subsets. `PASS` additionally requires actual reordered replies and at least one
cut capture that contains the protected EL0 FSYNC-consumption boundary.

The matrix is resumable because the exhaustive native cross-product is large.
`--resume` rehashes the frozen build, source, formatter output and complete tool
set. Each completed child is independently revalidated down to its initial-disk
hash and artifact inventory before it is skipped. A complete child written just
before an interrupted progress update may be adopted after the same checks; an
invalid partial attempt is moved under `_abandoned/` before a new attempt, so it
is preserved rather than overwritten. The orchestrator and gate are currently
host-tested but have not executed this native matrix. They therefore add no A10
acceptance evidence, and the catalogue remains `NOT_RUN`.

## Current host checks

The dedicated client was compiled for `aarch64-unknown-none-softfloat` and fits
the existing four RX pages. Eight host tests execute its actual control flow
against a deterministic ABI stand-in, including stale markers, wrong FSYNC
sequences, corrupted bytes and generation changes. These are regressions only.
The protected state rejects wrong boot/configuration identities, records only
registered owners, publishes complete rows before their count, and fails closed
on overflow. The Python decoder checks prepare/overwrite/recovery flows against
independent disk results and actual-exit progress, including stale versions and
wrong objects. None of these host checks establish native A10 acceptance.
