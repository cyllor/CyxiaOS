# V0.18 immutable snapshot file service

This interface serves the journal-backed business filesystem. It is separate
from the desktop RAMFS checkpoint mechanism and from AI observation snapshots.

## Transport and compatibility

The existing 640-byte file frame remains version 1, dispatched by `SVC 0x45`
with operation register `0x40`. Its `ALL_RIGHTS = 15` mask is unchanged.

`FileServiceSchemaV2` uses the same native SVC with operation register `0x50`:

| Register | Meaning |
| --- | --- |
| x0 | Complete authority's capability index |
| x1 | Request address |
| x2 | Complete authority's capability generation |
| x3 | Response address |
| x4 | Response buffer capacity, at most 2048 bytes |
| x8 | `0x50` |

The request's `target_cap_index` must equal x0. The broker checks both authority
fields against the protected owner record. The stopped caller's request and
response ranges are checked under one task-memory borrow. Request and response
buffers must not overlap. Response capacity must cover the opcode's largest
response before any operation executes. Success returns the signed status in
x0 and actual response length in x1.

Requests have a 64-byte header, maximum 1024 bytes, magic `0x43594632`, and
version 2. Responses have a 32-byte header and the same magic/version. All
integers are little endian; unknown versions, opcodes, lengths, and reserved
fields are rejected before side effects. The canonical implementation shared
between EL0 and EL1 is `user/prototype-task/snapshot_abi.rs`. The native caller
helper is `files_abi::snapshot_client::invoke`.

The 40-byte snapshot identity contains filesystem UUID, non-rewinding snapshot
ID, slot, zero reserved field, and slot generation. The 36-byte durable request
identity contains filesystem UUID, client slot, client generation, and strictly
consecutive request sequence. Public identities do not grant permission.

## Operations and separate permissions

| Opcode | Operation | Required permission |
| --- | --- | --- |
| 0x20 | SNAP_CREATE | CREATE |
| 0x21 | SNAP_EXTEND | EXTEND |
| 0x22 | SNAP_DELETE | DELETE_EXPIRED |
| 0x23 | SNAP_RESTORE | RESTORE |
| 0x24 | SNAP_LIST | LIST |
| 0x25 | SNAP_QUERY | LIST |
| 0x26 | SNAP_OPEN | HISTORY_READ |
| 0x27 | FREEZE_SET | PROTECTION |
| 0x28 | FREEZE_CLEAR | PROTECTION |
| 0x29 | OPEN_WRITES | PROTECTION |
| 0x2a | QUERY_REQUEST | Original durable principal or admitted recovery supervisor |
| 0x2b | ACK_REQUEST | Original durable principal or admitted recovery supervisor |

`grant_snapshots` is a kernel-root enrollment function for ordinary principals
0–13. It cannot issue RESTORE or PROTECTION. `grant_snapshot_recovery` is a
separate enrollment function for trusted principal 15, which cannot occupy an
ordinary on-demand creation slot. Principal 14 is reserved for internal timed
maintenance; there is no public issuer for it. No EL0 request can mint either
authority or widen its permissions.

CREATE, RESTORE, and OPEN_WRITES require the current live-view epoch. The other
operations set this field to zero. Mutation requests carry their durable
FileReqKey. Read-only requests and query/ACK transport headers use a zero
FileReqKey; query/ACK identify the target key in the payload. QUERY_REQUEST
returns the complete canonical 512-byte request record. ACK_REQUEST carries the
target key followed by its 32-byte terminal result digest.

LIST/QUERY return a 48-byte status header followed by at most eight 128-byte
snapshot summaries. The status reports cleanup freeze, conservative online
age, live-view epoch, protection generation, write gate, and restore phase.
Summaries include complete identity, capture boundary, retention deadline,
deletion boundary, metadata status, and actual open root references.

## Historical handles and restore publication

Each history grant binds a filesystem UUID and a canonical absolute path
prefix. SNAP_OPEN resolves the prefix and requested path in the historical
tree. Component boundaries are checked: `/team` does not authorize `/teamish`.
Empty components, dot components, trailing separators, and embedded NULs are
rejected. A missing historical prefix never expands to the live namespace.
The grant stores the prefix's byte length and domain-separated SHA-256 digest.
The broker checks the exact prefix slice of the copied canonical request,
including its component boundary, before passing that verified original slice
to historical resolution. This supports the full 512-byte path bound without
keeping a duplicate pathname buffer in every capability.

SNAP_OPEN returns an opaque 8-byte token. The existing READ, READDIR, and CLOSE
frames use it as `OFF_HANDLE_ID`, with `OFF_HANDLE_GENERATION = 0`, and must carry
the exact history authority that opened it. Normal v1 handles retain their
original index/generation encoding. WRITE and FSYNC on historical handles fail
with `EROFS`; GET_STAT_CAP cannot convert a historical handle into a live
service-vector capability.

There are 112 ordinary and 16 protected broker handles. Only the protected
recovery authority selects the recovery filesystem handle/frozen-view pools;
the request wire has no flag for that selection.
The core and broker slot records total 56 + 72 = 128 bytes, including empty-slot
discriminants. A compile-time assertion binds this budget to the actual types.

Restore changes only the business view. Live handles retain their original
epoch and become stale after publication. The runtime sets the old file-service
capability revocation barrier before releasing the filesystem owner, and cache
load/stat/validate callbacks recheck the barrier after acquiring that owner.
The next capability grant revokes all old file-service capabilities under the
task owner before issuing a new one. Pending vectors resolve their capabilities
again. A new revocation notification cannot be overwritten by processing an
older notification. Historical handles preserve their own view.

The broker retains a completed V2 response when copyout fails. It re-delivers
those exact bytes, without executing the operation again. Pre-effect custody
retries preserve all five captured input registers, including capability
identity. Repeated durable mutation keys are handled by the journal's request
records; an uncertain media error is not treated as cancellation.
V1 data and retained V2 responses share the existing bounded DATA buffer under
the same pending-owner gate; there is no additional response pool. The explicit
coordination account is 3,912 bytes normally and 4,040 bytes with the opt-in
128-byte probe evidence. It conservatively includes the complete core manager,
the authority bank, completion metadata, capture barrier, maintenance timestamp,
and streaming GC reference counters. It has a compile-time 4 KiB bound. Existing
CPU0 stack storage and transaction scratch are accounted separately.

## Opt-in native probe

`tools/build_unified.py --snapshot-probe --selftest` enables the separate
`CYXIA_SNAPSHOT_PROBE=1` profile. It rejects simultaneous storage/memory fault
profiles. The regular build keeps its existing capability grants.

The profile admits two real EL0 actors through the existing task admission and
file-service credit path:

1. The ordinary actor has normal file authority plus CREATE/LIST/HISTORY_READ
   for `/snapshot-probe`. It persists original bytes, creates a snapshot,
   persists changed live bytes, opens the historical file, and publishes a
   durable readiness marker.
2. The trusted recovery actor has only READ for ordinary file operations and
   a distinct LIST/RESTORE/PROTECTION authority. It consumes the marker,
   explicitly restores the chosen key, verifies original bytes through a new
   live handle, and explicitly opens the business write gate. The ordinary
   actor verifies that its old live handle is stale and its historical bytes
   remain unchanged.

The opt-in `SNAPSHOT_PROBE_EVIDENCE` symbol is 128 bytes: word 0 is
`0x4359534e415031`, word 1 is schema 2; words 2–3 are reserved zero;
words 4–7 contain the ordinary actor's
`(task_id, generation, exited, code)`, and words 8–11 contain the recovery
actor's tuple. Root admission binds the keys, and actual task cleanup publishes
the exit result. A runner must observe both real zero exits and independently
check the stopped v2 disk; a persistent DONE request alone does not prove that
the corresponding EL0 actor received its reply.

Words 12–15 retain the first consumed CPU0 budget failure: service stage,
dispatch sequence, measured CPU nanoseconds, and reserved nanoseconds. The
sequence is published last. The stage is captured for the exact completed bill,
including deferred settlement, and nested network progress restores the outer
stage. A `cpu_progress` boundary adds `0x10000` to the enclosing service stage
while invoking the existing paid progress callback. This evidence does not
increase the 2.5 ms service budget or suppress core quarantine.

This probe requires a freshly formatted v2 volume. Its fixed test principals
start from the formatter/bootstrap watermarks; it is not a management utility
for an existing disk. Build with separately provisioned development identities:

```sh
python3 user/prototype-cluster/tools/provision.py /absolute/new-dev-identities
python3 tools/build_unified.py \
  --identity-a /absolute/new-dev-identities/a \
  --identity-b /absolute/new-dev-identities/b \
  --output /absolute/new-snapshot-build \
  --selftest --snapshot-probe
```

The builder records `BUILT_NOT_RUN`, the selected profile, schema versions,
source hashes, native tool versions, image hashes, embedded probe bytes, and the
preparation-stack gate. A linked image is not a native execution or power-cut
receipt. The pinned QEMU/native acceptance environment must run and independently
verify it before reporting those gates as passed.

`tools/run_snapshot_probe.py` keeps `--scope full-unified` as its default,
connecting the two guest NICs. The explicit `--scope local-filesystem` option
attaches each real virtio NIC to a separate one-port internal hub. It keeps the
same ELF, four vCPUs, 1 GiB RAM, budget enforcement, initialization, maintenance,
actor completion checks, and independent disk oracle. The summary and launch
receipt record the selected scope; `full_unified_accepted` remains false. Every
run requires a new output directory and formats fresh, distinct UUIDs. An
isolated local result does not establish peer TCP or full unified acceptance.

The current final-source executions failed their unchanged CPU budget gates
before completing both actors: the connected run stopped in network IpcDrain;
the isolated run stopped in QueueIdleAck and also recorded a CPU1 control
overrun. The implementation's host regressions and native linking are verified,
but its native end-to-end create/history/restore result is not yet passed. See
the [validation record](v18-immutable-snapshot-validation.json) for exact scope
and source identities.

## Focused regression commands

```sh
python3 -B -m unittest tests.host.test_snapshot_file_abi
python3 -B -m unittest tests.host.test_snapshot_capability_custody
python3 -B -m unittest discover -s tools -p test_a09_file_backpressure.py
python3 -B -m unittest discover -s tools -p test_a10_write_backpressure.py
```

The wire tests use independent literal golden offsets and malformed inputs.
The broker test includes the actual kernel broker, actual filesystem and
journal, and a deterministic host block device; only CPU identity, clock, and
user-memory access are host seams. The capability test executes the production
publication callbacks and real ServiceBatch revocation. These tests provide
host regression evidence and do not claim QEMU execution.
