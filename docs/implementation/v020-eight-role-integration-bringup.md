# Native eight-role integration / controlled bootstrap (WIP)
Baseline 418ab0b84a12b0d0aa9eb48516cccd84a0eaf9f1; integrates reviewed #69–71 on a dedicated development branch, not main.
The explicit v0199-control-bringup profile compiles eight independently linked native AArch64 ABI3 PIE clients and embeds an immutable role/package/relocation-hash inventory. It stages each image from an exclusive copied package, maps actual distinct TTBR roots and eight 32KiB stacks, checks guard/leaf permissions, seals RX/RO high aliases with BBM/TLBI, and uses actual SVC64 register capture. Each role is limited by the shared CPU0 budget ledger, with the pinned PMU patch and separate monotonic deadline. CPU1–3 remain business-only mechanism workers.

This is NOT the formal eight-service system. The clients only implement safe startup behavior and role-specific snapshot/audit/sleep calls; the startup profile explicitly has no verified durable BootEpoch, production object/cap registry or production file system/actual resource execution chain. Protected new publication, model enable, resource effect and audit ACK remain closed. No fake APPLIED, production G0, G4 or G5 success is authorized.

| Requested work | Current deliverable | Blocking production condition |
|---|---|---|
| Eight ABI3 packages/catalog | Native bootstrap binaries, pinned build catalog, verified static PIE/empty relocation inventory | Full role application behavior, offline model/config and authoritative startup manifest |
| Independent roots/32KiB stack/caps | Actual private static root and stack mapping, guard, narrow actual bootstrap capability table | Production allocator/whole physical frame ledger, entropy/randomization, all cap/object bindings and persistent startup gate |
| Shared CPU0 scheduling | Real EL0 entry/preemption, exact class/role reservation and per-vCPU accounting in diagnostic profile | Production scheduler integration, all mandatory/recovery/coordination CPU intervals, stress and measured acceptance |
| Advice -> decision -> publish -> APPLY | ABI3 trap dispatch, protected view/audit preflight; prior independent advisory and decision gates retained | Native authenticated work input, actual inference, RuleProfile evaluation, full control IPC and authoritative action effects/receipts |
| Fault/restart/persistent generations | Prior #72 fixture evidence separate | Real role reload, durable SecurityState/BootEpoch, stop/TLB/DMA/cap custody proof |
| Full native acceptance | New independent QMP/UART/ELF/hash verifier for eight-package bring-up | Actual CI results, eight operational production roles and full G0/G1/G4 gates |

No old CPU1 controller or hosted compatibility node is used. All 15 resource domains retain equal architectural standing.
