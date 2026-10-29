# Recovery observation native checkpoint — 2026-10-29

The frozen `native-single-recovery-observation/` run fails after 601.305155 seconds. Ordinary client exits 0; no task overrun or quarantine is recorded. Engineering checks v46, both images and selected stacks pass before launch; compiled source remains `d5e08548cab4163dfd2e064f942a81c520554bd2a8be64c4c99c44aba1b48559`. No tests, builds or archive parsers run alongside QEMU.

Two baseline sides (trials 2 and 5) are kernel-verified, three sides excluded, and five records durably archived. Pair labels, training and validation remain zero. All 69 formal catalogue cases remain NOT_RUN and the filesystem matrix incomplete. This run does not establish complete prototype acceptance.

## Recovery observations

| Recipe | Full original ApplyId | Final supervisor result | Matching latest Task predicate |
| --- | --- | --- | --- |
| 1 | `[1,1,425,0,4152,12]` | Version 390, next generation 13; phase 3/issued → phase 4/not issued; running true; Applied at 240645474992 ns, 264.898 ms after start | New key `[4152,13]`, LifeReady, heartbeat and endpoint present, memory query Ok(3 pages) |
| 2 | `[1,1,435,0,4153,13]` | Version 398, next generation 14; same transition/result; Applied at 240848784000 ns, 336.945008 ms after start | New key `[4153,14]`, LifeReady, heartbeat and endpoint present, memory query Ok(3 pages) |

Raw banks, report counters and final watcher snapshot match. The independent Services/Task publications agree on scope, method and result; they are not an atomic pair or proof of the exact same call. First-Unknown latches reset on each complete ApplyId change. These latest healthy rows neither prove every earlier recovery healthy nor explain the previous Recovery 443 stall. No recovery scheduling repair was made.

## Remaining native failures

Candidate 6 has no first snapshot or capture. Admission records 11,793 visits and 9,122 denials, all reason 3 (`optimizerStopped`), on the same token 12 / target `[12,1]`. The accept-only stop latch is empty; other baseline/replay/governance stop paths are outside that latch. Do not interpret its absence as a healthy optimizer or clear the stop.

The CRC-committed archive is 793,280 bytes with SHA-256 `ac9595ee2db9c8e3e9ab6126d6f001311da7645c14ea66cac046ae8b31e704a9`. Extents, complete record boundaries, whole-file hash and truncated-append negative checks pass. All five records retain 100 requests with zero missing events. Capture/verification results are Evidence, None, Deadline, Capacity and None; trial 4 hits the unchanged 8,192-interval cap. Capture handoff loss is zero, retained = drained = 62,922, pending zero.

Candidate 3 opens its original first scope on job 409 at 188721780000 ns. Jobs 409–418 complete with Busy, version zero and no publication. First actual publication 419 uses snapshot 210128534000 ns, after the original observation ends at 204721780000 ns. It later fails Expired. Its closing 421 becomes Applied 73.694 ms after publication, 23.694 ms beyond its own deadline. The initial-progress cache correctly refuses to treat 419 as the original 409. The source gap is that retiring a failed first numerical job does not notify Root; a later sequence can use a fresh snapshot inside that already-open scope. This requires its own regression and narrow retirement fix; it cannot be repaired by refreshing the trial time.

Baseline 4 includes a **RejectedPublication**, flags 128, for plan 446. The dedicated rejection ABI yields family `[1,1]`, target `[12,1]`, version/published zero and Failed(Budget), observed 299442312992 ns before wall deadline 299490700000 ns. Original plan hash `d4e3ea8c4f89d4f1861e8c4bc7eecf3c640221ec7b96f3c8de2882e9eb4b5ab0` matches. This row has no adoption stamp or execution times. The generic history diagnostic decodes those fields incorrectly for flags 128; its family/stamp interpretation must not be used. The rejection does not identify the Budget origin, so it does not justify changing optimizer stop rules.

Stopped diagnostic outputs are retained under ignored `artifacts/v012-continuation/recovery-observation-*`, including separate recovery, admission, network, record-boundary and rejection-ABI reports. They explain a failed run; they are not acceptance receipts.
