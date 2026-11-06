# CyxiaOS V0.14 — A01–A16 parallel engineering lanes

Date: 2026-11-05. **Software baseline:** `CyxiaOS-V0.14@c5fb398e21de3b56f7a89ca17c48b62205d671a4`, version `0.14.0-dev`. **Acceptance specification:** design configuration 1.3, not "design v0.14". **Source of truth:** `docs/implementation/v13-requirements.json`, `CyxiaOS_Minimal_Prototype_Design_Final.docx`, and independent runtime verifier. The approved Rust + AArch64 assembly deviation remains recorded in the catalogue; no functional safety or evidence requirement is relaxed.

## Current exact-baseline snapshot

At `c5fb398e`, the 16 A cases in `docs/implementation/v13-requirements.json` are **16 NOT_RUN, 0 PASS, 0 FAIL**, with null runtime evidence. This is *not* an estimate of source implementation progress. There are 51 formal A/T/E IDs plus 18 action families and the filesystem fault matrix. A source release or CI host test never upgrades native acceptance.

CI run [41876419329](https://github.com/cyllor/CyxiaOS/actions/runs/41876419329) at this exact source had: Rust PASS, Host PASS, Tools PASS, Static FAIL (`policy.rs:1332` Clippy collapsible-if, `-D warnings`). The separate [V0.14 source snapshot 41876419383](https://github.com/cyllor/CyxiaOS/actions/runs/41876419383) succeeded, but did not run the complete A matrix. The Clippy formatting-equivalent fix is in the accompanying integration branch/PR; the new CI result has not yet been independently observed.

## Six parallel, non-overlapping workstreams

| Lane / issue | Formal A IDs | Minimum evidence | Upstream gates |
|---|---|---|---|
| [W1 Boot, CoreSet and isolation](https://github.com/cyllor/CyxiaOS/issues/11) | A01–A04 | Four native vCPUs, durable BootEpoch/model boot gates, business/C isolation, actual 1→2→1 ownership and IRQ/DMA fault intersections | W3 credit/ledger, W4 FLUSH, W2 real scorer |
| [W2 16 domains / model and measurement](https://github.com/cyllor/CyxiaOS/issues/12) | A05, A08 | 18 families × 2 legal real APPLIED alternatives, full per-family DecisionKey/receipt, paired 5-seed 10s raw CPU/reward | W1/W3 execution, W4 storage, W5 D16 placement, W6 model generation |
| [W3 ABI / memory / credits / recovery](https://github.com/cyllor/CyxiaOS/issues/13) | A06, A07, A09, A11, A15 | 144B/64B/6464B and idempotency, FP/SIMD/TLB, page/credit ownership, SAFE_EXEC, recovery liveness | W1 owners, W4 redo, W2/W6 policy |
| [W4 Redo durability](https://github.com/cyllor/CyxiaOS/issues/14) | A10 | Real power-cut and torn/unflushed write matrices, latest COMMIT LSN, independent byte-level recovery, post-ACK visibility | W3 completion progress |
| [W5 Two native nodes](https://github.com/cyllor/CyxiaOS/issues/15) | A12–A14 | Per-node identity/disk, authentic TLS/READY, ContractID/TaskKey exact-once admission, RESULT/ACK, partition | W1/W3/W4; W2 D16 |
| [W6 Local learning / model lifecycle](https://github.com/cyllor/CyxiaOS/issues/16) | A16 | 144/72 grouped samples, exact last-layer update and full integer model, Shadow/Canary, promotion/rollback, generation race | W1/W2/W3 |

Coverage check: W1 has 4 IDs, W2 2, W3 5, W4 1, W5 3, W6 1 = **16 distinct A IDs** with no overlap. Parallelism applies to isolated source modifications and independent host/golden-vector tests; the native end-to-end gates may need serial access to the shared base image/fixture and explicit dependency closure. Workers must **not** all change the same `v13-requirements.json` in parallel.

## Coordination and integration

1. Each lane uses a separate `codex/v014-...` branch and cites exact A/T/E references in changes and tests. No direct push to V0.14 from a partial lane. A lane PR must preserve frozen software/source and spec identities.
2. Record each check as **static**, **host**, **native single**, or **native pair**. Keep raw QEMU command, tested source tree, patched-QEMU binary hash, guest image/model/Schema hash, seed, fault point, event sequence and independent verifier. Failed or incomplete probes remain available and never get silently converted to PASS.
3. Collect each lane's native evidence separately. A status can change to PASS only after all required faults and independent validation under the **same exact source**. Release gate remains closed with any FAIL/NOT_RUN.
4. Native resource grants are owned by a unique ledger, C/B/T/Q remain disjoint, no timeout implies quiescence/release, and the business hot path never waits synchronously for the model. All 16 domains are equally obligated; no CPU/memory/filesystem priority tier.
5. Cross-lane integration order is deterministic safety + boot/durable progress, live policy and 18 executors, learning/promotion, two native nodes, then combined fault replay. This orders prerequisites; it is **not** an exemption of any domain from native AI evidence.
6. V0.14's `post-arm-v1` A10 scope and `raw_mutation` preservation must be kept. Old absolute-cut receipts are not reinterpreted under v2; host arming coverage is not the native power-loss matrix.

## Required final interface

Use the existing `tools/prototype.py` `build`, `run-single`, `run-pair`, `test`, and `report` commands. `report --scope A` must remain nonzero until all 16 A records independently validate. The complete §14.5 release gate additionally requires T01–T20, E01–E15, all 18 action families and filesystem format fault coverage. A workstream issue being closed does **not** auto-promote a catalogue verdict.
