# v1.3 storage crash verification

This work supplies a native boot/journal fault mechanism. It does not complete
A10 or the complete filesystem crash matrix: ordinary filesystem operations,
application fsync acknowledgements, large transactions and the complete required
fault inventory still need native scenarios and reviewed acceptance receipts.

## Independent prefix decoder

`tools/check_v13_disk.py` previously rejected every incomplete visible transaction.
A real Rust-generated image reproduced the defect: BootEpoch 1 was checkpointed
at LSN 6; the next BootEpoch's BEGIN and REDOs reached a completed FLUSH, but its
COMMIT's FLUSH was cut. The stale prior-epoch bytes at the expected COMMIT location
caused `stale record identity`, although native journal recovery correctly keeps
BootEpoch 1 / LSN 6.

The decoder now discards an incomplete suffix only after searching every remaining
aligned block for a locally valid current-epoch COMMIT at or beyond the expected
LSN. It still rejects a damaged committed chain, incorrect ordered SHA-256 digest,
valid COMMIT after a gap, and corrupt middle COMMIT followed by a later COMMIT.
The report includes discarded-tail, distinct replayed-block and selected-superblock
generation fields for comparison with native recovery evidence. Its filesystem
layout scope remains the reserved boot and cluster files.

## Fault device and independent checks

`tools/v13_fault_disk.py` exports a local fixed-newstyle NBD device to QEMU. It
accepts bounded aligned reads/writes and FLUSH, and stores at most 16 MiB of pending
512-byte sectors. Reads observe pending writes. WRITE replies acknowledge volatile
visibility; FLUSH replies follow persistence of all pending sectors and host fsync.
No filesystem structure is interpreted or repaired by the backend.

Each selected mutation can stop before processing or immediately after sending its
reply. The latter is named `after-ack`: it establishes that the backend sent a
reply, not that the guest consumed it or returned fsync to an application. The
runner stops and SIGKILLs QEMU after observing the captured cut. Pending sectors
are either discarded or the upper half survives in reverse address order. Up to
16 pipelined replies can also be delivered in reverse order; FLUSH durability is
unchanged. The transcript records raw request bytes, request/completion/reply
events, exact survivors, run ID, starting-image digest and cut configuration.

`tools/check_v13_fault_disk.py` independently reads that transcript, reconstructs
volatile and durable sector states, checks reply identities and fault boundaries,
and compares every byte of the final image. It only computes an expected view in
memory and never writes the disk. Socket tests demonstrate loss before FLUSH,
durability after its reply, non-prefix sector survival and reversed replies.
Negative controls reject changed raw write data, a missing FLUSH acknowledgement
and loss of a durably flushed sector.

## Native execution

Build the dedicated profile:

```sh
python3 tools/build_v13_storage.py --output artifacts/storage-build
python3 tools/verify_v13_storage_faults.py \
  --elf artifacts/storage-build/storage.elf \
  --build-manifest artifacts/storage-build/build-manifest.json \
  --output artifacts/storage-faults --points flushes
```

The source/ELF-bound runner first boots a formatted disk and captures a clean
second-boot trace. It then injects before/after-ACK cuts at selected observed NBD
mutation boundaries in both survivor modes. Every damaged image is independently
decoded, rebooted natively, checked against native recovery counters and decoded
again. `--points all` selects every observed mutation boundary; an explicit list
such as `--points 1,9` supports bounded diagnostics. Output directories are never
overwritten. `--source-root` may identify a frozen checkout whose complete code
map exactly matches the build; formatting also uses that source. This permits
unrelated development without claiming the older ELF contains newer code.
Every case retains its initial reference, cut/recovered disk images,
raw NBD bytes, UART, QMP transcript, evidence page and artifact hashes.

The runner's `native_boot_fault_matrix_complete` field only describes this boot
scenario's observed mutation boundaries. `native_filesystem_fault_matrix_complete`
and `A10_complete` stay false, even if every boot boundary passes. No receipt is
registered in the full v1.3 catalogue.

## Verification ledger

- Preserved prior recovery-interruption tests: journal suite 20/20 passed before
  adding the independent generated-image regression.
- Generated-image regression: failed on the original checker with the expected
  stale COMMIT identity, then passed after the prefix-decoder correction.
- All `test_v13_*.py` host tests: 85 passed before the final native capture.
- Dedicated `storage-v13-selftest` build succeeded at
  `artifacts/v13-storage-build-20261025-faults`; its manifest binds source and ELF.
- Initial native point 1 capture at
  `artifacts/v13-storage-faults-20261025-point1` is diagnostic. Review found that
  QMP `stop` adds a host FLUSH, and pipelined DISC/FLUSH reply ordering needed
  stricter handling. Three failing regressions reproduced the backend/decoder
  defects before correction. Native captures now avoid QMP stop/quit at the
  halted completion marker, disable VirtIO request merging, and require exactly
  eight 512-byte requests per guest 4 KiB write and exactly the guest's FLUSH
  count. A selected fault must match the clean probe's entire mutation prefix.
- Final capture at `artifacts/v13-storage-faults-20261026-point92/summary.json`
  passed four native COMMIT-FLUSH cases. Its clean second boot recorded 92
  mutation boundaries, four FLUSHes, and reversed completions. Point 92 is the
  final COMMIT FLUSH, not a host-generated operation. Results were identical for
  `drop` and `reverse-half` cache-loss modes:

  | Cut boundary | Independently durable prefix | Native subsequent boot |
  | --- | --- | --- |
  | Before COMMIT FLUSH | BootEpoch 1, LSN 6, incomplete suffix discarded | BootEpoch 2, LSN 10 |
  | After FLUSH reply sent | BootEpoch 2, LSN 10, one committed transaction / two replay blocks | BootEpoch 3, LSN 14 |

  Raw request/reply reconstruction, full-image byte comparison, native replay
  counters, UUID, checkpoint generations and final independent decoding agreed
  in every case. Only one of 92 observed boot mutation boundaries was tested by
  this final capture. Full boot-matrix, filesystem-matrix and A10 flags remain
  false, and the catalogue was not promoted.
