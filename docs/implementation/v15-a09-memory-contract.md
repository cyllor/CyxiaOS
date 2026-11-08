# A09 ordinary anonymous memory under real file-cache pressure

`--memory-probe --selftest` builds an independent ordinary client package. It
uses the existing Spawn admission, scheduler, SVC14 reservation, lower-EL data
fault, `Memory::fault` and hardware `Pages::map` paths. Its file capability and
file requests use the ordinary authenticated file service. A10's file client is
unchanged. This profile uses the normal model, budgets, timer and page allocator.

Two tasks use the same private VAs. Each reads four fresh anonymous pages and
one read-only page, checking every u64 is zero. They later write different
run-nonce/role/page/word patterns into their four writable pages. Both retain
their anonymous mappings. One task then reads 4097 distinct 4KiB file pages,
checking each page's nonce-specific first and last word in existing MAX_IO
64KiB batches; the other blocks on its ordinary authenticated IPC endpoint and
retains its own sentinel. All eight sentinel pages are checked again at the end.
The three files are 8MiB, 8MiB and 4KiB, respecting the existing file-size limit.
The workload exceeds the actual 4096-page cache backing, regardless of the
current AI-selected cache grant. The existing clean replacement/reclaim sites
increment a read-only eviction fact; no replacement decision is changed.

The clients coordinate through ordinary file flags with a shared two-second
barrier at zero and filled stages. The host injects only the preboot run identity,
then performs stop/query-status/physical reads. Missing a stage fails the run.
The guest's protected A09 bank records actual task generations, roots, owner
quota/use, `Memory::resident` frame identities, actual PTEs and monotonic cache
facts. The runner independently walks and captures root/middle/leaf tables,
complete anonymous pages and the four immutable client code pages at each stage.
The frozen input records a 100ms collector polling cadence, independently checked
by the reader and bound through the boot input digest. The existing 4MiB JSON
limit remains unchanged.

The second task opens its real endpoint with op5; CPU0 grants it to the first
task through the existing owner/generation-checked `grant_endpoint`. At pressure
time the second task uses op22, an ordinary blocking receive variant sharing
op7's capability/endpoint/generation/buffer validation. Empty receive returns
AGAIN after waking, so the client retries. The original credit completes as
Blocked before waiting; only real authorized mailbox delivery wakes the receiver.
Op7 retains its existing nonblocking semantics. The first task sends a
nonce-bound completion only after verifying all 4097 pages. The new fixture has
a 600-second admission lifetime scoped to this kernel-launched package; normal
ordinary-task lifetimes, per-IO limits and scheduling budgets are unchanged.

READ backpressure follows the existing file ABI receipt contract. A transport
or retained-copyout retry keeps its request identity. Once a READ completion
reports AGAIN, that identity has been consumed; only the position-explicit READ
is retried with a fresh identity and unchanged offset/length. Writes, create and
fsync are never replayed by this loop. Actual attempts, completed AGAIN results,
maximum call latency and last result/count remain in the captured progress page.

The independent checker requires all three stopped stages and exact source,
build, ELF/client, QEMU, DTB, QMP, framed UART and normal process-exit custody.
It checks actual private table flags and leaf permissions, separate owner roots
and all private backing, exclusion of cache/table frames, retained physical
sentinel identity, initial zero bytes and exact final pattern bytes. The raw
decoder only returns `STRUCTURE_VALID/NOT_RUN`; a formal A09 PASS additionally
requires the reviewed live-capture adapter and caller-selected trusted build.
The entry point is `memory_v15_custody.verify_native(receipt, *, build,
source_root, qemu_source)`. Only after all checks it explicitly returns
`test_id=A09`, `native_acceptance_status=PASS`, `full_a09_verified=true` and
`actual_cache_pressure_verified=true`. Producer summary fields are never read
as authority. Raw decoding always retains both full/native authority as false.

The fixed 448-word bank contains 64 header words and two 192-word owner rows.
Header words0–7 are magic/version/seal/BootEpoch/stage/two owners/error/reserved;
8–21 copy nonce and image/input/source identities from the protected boot config;
22–28 hold actual cache backing/page count/evictions/misses/read bytes/frequency/
last observation. Owner words0–7 identify task/generation/role/root/registration/
four code pages/error/reserved. Three 48-word snapshots begin at owner+32:
seal/time/stage/client error/zero words/client sentinel check/file pages,
actual faults/zeroed/anonymous/free/cache/miss/reclaimed counts, owner use/quota;
seven actual leaf PTEs at16–22, four code PTEs at24–27 and seven actual
`Memory::resident(owner,VA)` physical frames at28–34. All reserved words are zero.

Validation:

```
python3 -B -m unittest discover -s tools -p test_verify_v15_memory.py
python3 -B tools/test_a09_blocking_receive.py
python3 -B tools/test_a09_file_backpressure.py
cargo test --locked --offline -p cyxia-prototype --test native_a09_memory
cargo build --locked --offline -p cyxia-prototype --example prototype-memory-disk
python3 -B tools/build_unified.py --selftest --memory-probe ...
python3 -B tools/run_v15_memory.py --build BUILD --formatter target/debug/examples/prototype-memory-disk --qemu QEMU --qemu-source TRUSTED_QEMU --output NEW_EVIDENCE --timeout 300
python3 -B tools/verify_v15_memory.py NEW_EVIDENCE --build BUILD --source-root TRUSTED_SOURCE --qemu-source TRUSTED_QEMU
```
