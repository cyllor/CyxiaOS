# Stopped native-pair learning archive inspection

Input: `/Users/robin/CyxiaOS-V0.12/artifacts/v012-parallel-native-pair-20261029/node-{1,2}/disk.raw`.
Read-only inspection after both QEMU processes exited. No source or input disk was modified.

Both disks were decoded with the existing `tools/check_v13_filesystem.py::inspect` and `tools/check_v13_disk.py::committed_volume`. These validated superblock/log CRC32C, complete COMMIT chains and their ordered SHA-256 digests, inode CRCs, extent lengths, inode/directory identities and allocation bitmap ownership. Neither disk has a discarded current-epoch tail.

- Node 1: BootEpoch 1, 86 committed transactions, final LSN 801; `/lr-0000000000000001-0000`, inode 4 generation 3, extent `(logical=0,start=8216,blocks=277)`, 1,133,120 bytes. SHA-256 `b6001a7d6588e89d0259772df046265e11514dac5dde3575dfadd7f28ad7263a`.
- Node 2: BootEpoch 1, 29 committed transactions, final LSN 320; same pathname, inode 4 generation 3, extent `(0,8216,134)`, 545,280 bytes. SHA-256 `eef38186559d9958081f5cf5ae39e8f62079dd0dc5799d77e34c71302c62ba4a`.

Archive boundaries were derived from the actual producer format in `kernel/src/learning_replay/archive.rs`: 2,048-byte header + padded peer packet + history_count*6,144 + (local_interval_count+peer_interval_count+prewarm_count)*64 + request_count*128. All byte ranges begin with the exact `CYXIA_REPLAY_1.3\0` magic and fit exactly, with no unparsed suffix. All four ranges are baseline D01_WEIGHT, target `[12,1]`, seed 1, have no peer packet/prewarm rows, and retain a `CYCLOSE1` closing receipt.

| Node/trial | Offset | Bytes | History rows | CPU intervals | Requests | Capture / verification | Seal minus observation end |
|---|---:|---:|---:|---:|---:|---|---:|
| 1/1 | 0 | 545280 | 1 | 8192 | 100 | Capacity / Capacity (10/10) | 272490992 ns |
| 1/2 | 545280 | 42560 | 2 | 241 | 100 | Deadline / Deadline (16/16) | 8404986000 ns |
| 1/3 | 587840 | 545280 | 1 | 8192 | 100 | Capacity / Capacity (10/10) | 1547544992 ns |
| 2/1 | 0 | 545280 | 1 | 8192 | 100 | Capacity / Capacity (10/10) | 3867632000 ns |

The error tags above are the header's enum+1 fields, mapped through `crates/prototype/src/learning.rs::Error`. They are separate from replay-owner `error=14`, which is Conflict. Each archive reports 100 unique, issued and scheduled requests; four sources, all closed; and missing_events=0. Capacity is explicit even with missing_events=0 and must not be read as complete interval coverage.

Capacity records retain respectively 7,959 / 7,930 / 7,980 ExecutorWork intervals on CPU0, out of the fixed 8,192 total. Their stored local CPU rows have valid node/core/class identities and strictly positive durations. Their raw header EW totals exceed the retained-row sums, consistent with excluded capacity-limited capture, not accepted measurement. No same-class/core exactly adjacent intervals were present, so merely reusing the current last-row adjacency merge does not explain a repair.

Node 1 trial 2 retains 16 observation-window Completed, 45 TimedOut and 39 Pending request outcomes; the actual-outcome section has 55 Completed and 45 TimedOut. Its seal is 8.404986 seconds after the observation end, beyond the unchanged five-second cleanup bound. Capacity is not this trial's exclusion.

The history rows carry BASELINE|OBSERVED flags (40), with receipt sequences 403; 405/407; 409; and 318. They use the deterministic baseline receipt layout, not proposed-candidate input hashes. Treating their empty candidate input hash field as a failed proposal hash would be incorrect.

Per-record SHA-256 fingerprints:

- Node 1 trial 1: `2419b258e37382a0a792099be73d5bc11b7306ea9c46320dcb369ceac5ea13dd`.
- Node 1 trial 2: `04b264a62d52324e2198269449c7d788b0be3015fbcfa81caeb4b8ca2bdf9901`.
- Node 1 trial 3: `be412598345ec961d56f0aa48dde23ee846f72fe32de8d55f87ab470abde4eee`.
- Node 2 trial 1: `eef38186559d9958081f5cf5ae39e8f62079dd0dc5799d77e34c71302c62ba4a`.

These are byte identities, not a replay of the capture event hash or proof of model/candidate acceptance. No existing standalone complete learning-archive verifier was found; framing/row interpretation above follows the current producer and is diagnostic only.

The final protected replay snapshots report node 1 trial 3 / Archive, durable_archives=2, excluded=2, archive_complete=false; node 2 trial 2 / Drain, durable_archives=1, excluded=1, archive_complete=false. Node 1's third complete on-disk range therefore must not be promoted to a third successfully read-back-and-retired export. The Archive implementation performs fsync, per-chunk readback SHA equality and close before export; the phase still retains that obligation.

Narrow follow-ups, preserving current limits and acceptance rules:

1. Trace the actual CPU0 ExecutorWork source/owner that consumes nearly all 8,192 capture entries, including empty versus useful turns and exact physical interval identities. Then make a bounded source-side segmentation/retention correction with unchanged CPU union semantics; do not drop intervals, fill gaps, increase fixed workspace, or admit Capacity as complete coverage.
2. For node 1 trial 2 and node 2 trial 2, correlate the existing Work/Task/closing/drain banks with the exact trial/request/caller identities to locate the real cleanup delay or Conflict. No root cause is established from the archive headers alone.
3. Keep node 1 trial 3's pending readback/close/export custody explicit. Complete file bytes alone cannot replace its export receipt.

Overall native run failure remains the separately reported 580.357-second unified event trace overflow. These paired-side exclusions are additional independent obstacles. Zero labels, training and validation remain unchanged; no native or catalogue PASS is claimed.
