# Bounded persistent checkpoints

Updated 2026-10-18. CyxiaOS now writes its RAM filesystem to a dedicated raw
VirtIO block disk and restores committed files when a new guest boots.
This is explicit checkpoint persistence: closing a file or returning from
`write` does not imply that its contents have reached disk. `fsync`, automatic
periodic saves, and a mountable general-purpose filesystem remain unsupported.
The explicit desktop **Save Files** dialog is verified separately below.

## Run and save

```sh
# Creates 2 MiB of empty disk space; refuses to overwrite an existing file.
python3 tools/storage.py artifacts/cyxia-data.raw
python3 tools/shell.py --disk artifacts/cyxia-data.raw
```

Guest commands:

```text
mkdir /documents
write /documents/note saved-in-CyxiaOS
storage checkpoint
storage status
```

Wait for `STORAGE_DURABLE generation=N` before closing QEMU. Restart with the
same `--disk` to restore that generation. The console remains the real guest
Shell; the host only creates the initially empty disk and passes it to QEMU.
It never interprets guest filesystem commands or mirrors host files into the
snapshot. Use a dedicated image: this format has no partition table and uses
sectors at the start of the disk. The launcher requires an existing image of
at least 2 MiB and uses explicit raw-format block nodes.

Without a disk, the ordinary RAM-only Shell remains available and checkpoint
requests report `Absent`. Read-only disks can be recovered but reject saves.
Unrecognized/corrupt committed data is retained and reported; it is not
silently reformatted. Learning samples, model candidates and unsaved changes
are lost on restart.

## Driver and publication rules

`crates/driver-virtio/src/block.rs` implements modern MMIO block device ID 2,
one 512-byte operation in flight, stable capacity reads, read-only handling,
exact request/response status checks and a 250 ms operation deadline. It
requires `VERSION_1` and real `VIRTIO_BLK_F_FLUSH`; the implementation does not
claim legacy VirtIO support. A successful write completion alone is not
treated as durable: the VirtIO specification establishes durability through
a completed flush after the completed writes. See the
[VirtIO 1.2 block-device requirements](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html).

The five queue pages are permanently pinned. Malformed responses, errors and
timeouts quarantine the queue and require restart; setting FAILED is not a
DMA reset acknowledgement. A failed read does not publish partial data.

`snapshot.rs` defines two slots of 768 sectors each. Each slot begins with a
512-byte header containing magic, format version, checked monotonic generation,
payload length, payload CRC32 and header CRC32. The inactive slot is written
in this order:

1. Write every payload sector, zero padding the final sector.
2. Complete a real device flush.
3. Write the committed header.
4. Complete another real device flush, then publish `STORAGE_DURABLE`.

The preceding committed slot remains available. Recovery validates headers,
tries the newest generation, checks the entire payload and RAMFS schema, and
falls back to the older valid generation if needed. CRC protects against
accidental corruption; it is not authentication or a guarantee against an
arbitrary hostile disk. An interrupted operation may recover the old or new
complete generation; it must not expose a partially validated filesystem.

RAMFS serialization preserves linked directory/file paths, UTF-8 names,
file bytes, modes, inode serials and the filesystem revision. Open unlinked
files, live handles, access/cache counters and learning state are excluded.
The complete schema, duplicate identities, canonical paths and parent
topology are checked before any recovered node becomes visible. Restore is
allowed only into an empty filesystem before shell input or EL0 startup.
Readonly boot asset contents remain in the kernel catalog; they are not
copied into the user disk.

## AI, memory and asynchronous work

`kernel/src/storage.rs` owns a real 128-page pinned staging pool, separate
from process pools, within the kernel arena. A checkpoint obtains a 66-page
grant from local model 8194 and the core grant ledger before copying the
bounded filesystem snapshot. The successful and error paths clear staging
bytes before releasing the grant. Device DMA uses only queue-owned copies,
so quarantined queue backing never aliases released staging pages.

Bootstrap recovery is explicitly `BOOTSTRAP`. Current source uses local integer
model 20481 for a real new-submission allowance: at most one runnable work item
permits four new block operations in an 8 ms window; competing work permits one.
The observation comes from the CPU0 process/task state, bounded to 0..8. An
operation consumes the allowance only after the driver accepts it. A changed
observation revalidates the plan without refunding operations already spent in
the same window. A new checkpoint also cannot reset spent work. In-flight
completions always run before allowance checks, and recovery has no such gate.

`tools/train_storage_model.py --check` reproduces the model and its complete
nine-input synthetic target. This is policy distillation, not measured workload
superiority or online learning. The previous 12290 call measured inference time
alone and did not budget actual I/O; that claim and its `cpu_decisions` counter
have been removed. The current limit is **new operations per 8 ms**, not CPU time.
Protocol work still completes at most one sector per foreground turn. Flush
ordering, payload bytes, and recovery selection remain deterministic mechanisms.
Initial snapshot copy/CRC and recovery validation remain bounded synchronous CPU
work. `storage status` reports `io_plan_decisions`, actual `io_submitted`, deferred
polls, read/write/flush counts, and returned staging capacity. `ai system` exposes
the separate storage domain and its lack of online learning.

The three host policy tests check that both model outputs limit actual submitted
counts, expiration permits bounded progress, changing pressure never refunds
work, and invalid observations cannot mint allowance. The updated guest verifier
also compares idle versus two real runnable tasks and demands real deferral.
The current guest evidence below uses the new model. The older durability report
predates model 20481 and is retained under its original identity.

## Verified evidence

[Current AI storage report](../../artifacts/ai-system-r2/storage/summary.json):
**PASS**, frozen kernel SHA-256
`1a0f5534cdb50ab2e8e291ad0fd6890899f35e55ce536c6756ffc8c8e42aae81`,
preserved at `artifacts/ai-system-r2/cyxia-kernel.elf`. With runnable work zero,
model 20481 selected four operations per window: the first generation submitted
12 operations with zero deferred polls. With two real compute tasks, it selected
one operation: the second generation submitted 13 more operations and deferred
51 polls. Both saves completed their two flushes and returned all 128 staging
pages. This demonstrates changed allowance and actual backpressure, not improved
throughput or hard real-time latency. The same run passed three-generation
reboot recovery, 4 KiB/Unicode contents, persisted deletion, unsaved exclusion,
corrupt-newest fallback, read-only recovery, and absent-disk behavior.

[The same-kernel physical desktop menu gate](../../artifacts/ai-system-r2/menu/summary.json)
also **PASS**: PCManFM renamed a real file, the physical Save Files menu launched
the EL0 save dialog, and the GUI success indication followed 16 completed writes
plus two flushes. The save consumed 18 I/O allowances, deferred 13 polls, and
returned all staging pages. A fresh VM recovered the exact renamed file and
excluded a change made after saving. The retained
[save screenshot](../../artifacts/ai-system-r2/menu/desktop-saved.png) was visually
checked for the success message; durability is established by device receipts
and reboot contents, not by that message alone.

The first r1 menu run failed during window closing. Its unchanged evidence is
retained at [menu/summary.json](../../artifacts/ai-system-r1/menu/summary.json),
with [diagnostic findings](../../artifacts/ai-system-r1/menu-diagnosis.json).
The test had sent Escape after a constructor warning before observing the
actual chooser, and its window parser could silently omit log-interleaved JSON.
The final gate observes chooser map/unmap and a complete old-window absence
barrier. The r2 inspector declares its emitted window count; the host requires
that count, complete markers and valid JSON records to agree, retrying the whole
observation on contamination. Six host tests reject partial JSON, split prefixes,
missing/wrong/duplicate counts, invalid schemas and duplicate window IDs.

[Guest report](../../artifacts/storage-verified-r2/summary.json): **PASS**, kernel
SHA-256 `4b5f61d6bac511463e13e531ef823d6e7db83f1900176eaac276b5db5597a0b5`.
The preserved kernel is `artifacts/storage-verified-r2/cyxia-kernel.elf`.
This default 256 MiB ARM build is separate from later desktop profile builds.

The actual guest wrote three generations, including a 4096-byte file and a
Unicode pathname; new VMs restored bytes and a deletion, while omitting a
change made after the last checkpoint. Host fault injection corrupted only
the newest snapshot in a disk copy; the guest detected the CRC failure and
restored the older slot. Read-only and absent disks were tested. Each save
returned all 128 staging pages and recorded the actual two flush completions.
Console bytes, QEMU commands and raw disk artifacts accompany the report.

```sh
python3 tools/verify_storage.py \
  --elf artifacts/ai-system-r2/cyxia-kernel.elf \
  --output artifacts/storage-new-run
```

Host tests cover block bounds, read-only writes, wire layout, bad status,
short reads, DMA quarantine, every modeled crash boundary in publication,
corrupt newest-slot fallback, generation overflow and atomic schema rejection.
Driver/FS/Shell tests and host Clippy pass; target Clippy passes for
`graphics,openbox,large-memory`. Logs are `artifacts/storage-host-final.log`,
`storage-clippy-host-r2.log`, and `storage-clippy-target-r1.log`.
These original results establish the storage foundation. The newer GUI gate
above covers its stated explicit-save workflow, not general POSIX durability
or arbitrary Linux applications.
