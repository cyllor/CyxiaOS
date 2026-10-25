# Native learning replay exclusion investigation

Date: 2026-10-25. Evidence: `artifacts/v01-diagnostic-icount/`.

The observed exclusions are justified by the retained evidence. They do not
establish a defect in replay acceptance. No production change or relaxed
acceptance threshold was made for this investigation.

## Durable journal observations

Both nodes report one verified side, one excluded side, two durable archives,
and zero paired labels after the 120-second host run. Both accepted sides are
baseline trial 1 for family `(1, 1)`, target `(12, 1)`, seed 1. Candidate trial 2
is excluded on each node. Neither candidate reports a capture exclusion or
missing capture events.

The following fields were decoded from `CYXIA_REPLAY_1.3` headers in the raw
disk and from their journal file contents. The archive layout is defined in
`kernel/src/learning_replay/archive.rs`. The replay file is inode 4, starting
at physical block 8216 on both disks; current blocks were reconstructed from
the redo images for diagnostic inspection. This inspection is not an
independent filesystem integrity or acceptance result.

| Node / side | File offset | Header offset in raw disk | First snapshot ns | Observation ns | Closing ns | History rows | Verification error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 baseline | 0 | 2,224,192 | 13,494,917,648 | 19,494,917,648 | 29,682,469,216 | 2 | none |
| 1 candidate | 191,168 | 5,888,768 | 41,787,851,280 | 47,787,851,280 | 57,932,495,072 | 3 | `Evidence` |
| 2 baseline | 0 | 2,142,272 | 13,680,797,904 | 19,680,797,904 | 29,790,417,440 | 2 | none |
| 2 candidate | 184,832 | 5,321,280 | 41,187,881,680 | 47,187,881,680 | 57,539,282,816 | 0 | `DataIncomplete` |

Header error words are enum discriminant plus one: `Evidence` is 8 and
`DataIncomplete` is 7. `seal.exclusion` and `missing_events` are zero in all
four headers. Node 1 candidate retained 2,567 CPU intervals and 100 requests;
node 2 candidate retained 2,413 intervals and 100 requests.

## Node 1: measured candidate CPU failures

`node-1/control-011.bin` and the final `DOMAIN_CONTROL_EVIDENCE.bin` retain
the same three candidate decisions. The journal preserves proposal-only
rows for 98 and 100, and a complete publication/execution row for 99.

| Decision | Snapshot ns | Encode ns | Inference CPU ns | Decode ns | Publication ns | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 98 | 41,787,851,280 | 1,312,240 | 675,728 | 15,968 | 16,048 | `Budget`, version 0 |
| 99 | 45,194,138,784 | 293,488 | 651,056 | 22,480 | 158,288 | Applied, version 48 |
| 100 | 53,219,393,344 | 543,712 | 1,824,656 | 36,416 | 36,416 | `Expired`, version 0 |

For decision 98, encode plus inference is 1,987,968 ns. Adding decoding gives
2,003,936 ns, exceeding the frozen 2,000,000 ns CPU limit by 3,936 ns. This is
the second CPU check in `domain_control::accept`.

For decision 100, encode plus inference is already 2,368,368 ns. The first
CPU check returns `Expired`; this error does not establish a wall deadline
miss. The recorded finish is 53,223,328,240 ns, only 3,934,896 ns after its
snapshot, below the separate 50 ms wall limit. Its decode field records the
elapsed rejected acceptance call because reply decoding was not reached.

Decision 99 is the only adopted action. Its snapshot differs from the
capture's first snapshot. `reward/bounded.rs::adoption_start` correctly
requires the first adoption snapshot to equal capture coverage `first_ns`.
It therefore cannot substitute this later adoption for decision 98.
Additionally, decision 99 expires at 55,194,138,784 ns, before the observation
end at 57,787,851,280 ns. The failed renewal cannot provide continuous policy
coverage. Neither requirement should be weakened.

## Node 2: proposal-generation boundary remains unidentified

The first callback bound capture at 41,187,881,680 ns, but no candidate
proposal was recorded during that trial. The retained history row count is
zero, so `learning_replay/owner.rs::verify` correctly returns
`DataIncomplete`. Ordinary proposals for other families resume around
59,947,339,408 ns after the excluded trial retires.

The retained replay root and producer diagnostic banks contain no permanent
failure. The available evidence cannot identify which post-callback,
pre-encoding gate prevented a proposal. In particular, transient task-owner
contention is a hypothesis, not an established cause.

## Next diagnostic gates

1. Retain the first candidate preparation attempt's stage timings across
   `replay::first`, the model publication gate, current-action lookup,
   observation lookup, execution-obligation check, stability/dependency
   lookup, legal-action enumeration, target feature lookup,
   `CandidateSet::new`, `core_replay::primary`, and `encode_job`.
2. For each transient exit, retain its real error, family, target, candidate
   sequence, original snapshot, and observed return time. A later successful
   attempt must not erase the first failed boundary.
3. Separate the existing first callback cost from the rest of measured
   encoding diagnostically. Keep its real CPU cost in the enforced budget.
4. Repeat the native run after any established producer optimization and
   inspect the original first adoption and every renewal. A host replay or
   baseline success alone cannot establish a paired learning label.

Existing relevant mechanism suites are `learning_replay_bounded`,
`learning_review_evidence`, and `learning_native_history`. No tests or native
runs were started by this investigation while the root agent owned build and
performance isolation. No new regression is claimed: no verifier defect was
demonstrated and no production fix was attempted.

The outstanding native acceptance requirement is actual paired labels under
the frozen budget, followed by the required family/split coverage and real
training/validation lifecycle. These artifacts prove neither paired replay
completion nor trained-model acceptance.
