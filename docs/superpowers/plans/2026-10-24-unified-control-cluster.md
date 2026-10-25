# Unified native control and cluster completion

Spec: CyxiaOS_Minimal_Prototype_Design_Final.docx v1.3 (SHA256 01f8c315018d8117c0b43671add6527fe76d0b83caabe865b5d714a99fa135a0); extracted /tmp/cyxia-v13-current.txt. User asks to complete dynamic core allocation, guest TLS, persistent membership/contracts/execution, and one combined native runtime. The current 1.3 Rust revision incorporates the previously approved Rust language choice; the original C11 deviation remains recorded as history. Existing isolated proofs do not satisfy joint completion.

## Global Constraints
- Native CyxiaOS, Rust no_std/AArch64; no Linux guest or host protocol/crypto/task proxy. QEMU10.2.2 virt-10.2,cortex-a53,4CPU,1GiB,512MiB distinct disks,MAC/IP/NodeIDs.
- EL0 local model decides core/resource optimization; EL1 validates and executes. C/B/T/Q remain disjoint/cover online. DRAIN preserves old C/B; no-ACK is suspect, never proof of stop. Use actual gates/tasks/IRQ/DMA/TLB/reference ownership.
- Dynamic 1→2→1 control core path, minimum one healthy C/B, C overlap, one core per transition, at least1s between accepted proposals,200ms deadline. No forged stop completion.
- Persist BootEpoch once before grants; service restart reuses it. Real journal BEGIN/REDO→FLUSH→COMMIT→FLUSH. UnknownIO freezes new authority; recovery never autoformats.
- Guest mutual TLS1.3: Ed25519 pinned NodeIDs, X25519,AES128GCM, fresh guest entropy, no0RTT/resumption. Private identity pages inaccessible to other services; bounded allocation. Use FP/SIMD-compatible EL0 target, preserve current softfloat EL1 target.
- Protocol follows §§10–12:96B header,252B config/412B proof, durable monotonic formation, STANDALONE/CONFIRMED/BOUND/LEAVING distinct READY/ISOLATED; authenticated boot/session binding and reconcile before READY.
- Contracts QUOTE/PREPARE/COMMIT/ACTIVATE with final enqueue revalidation,32contracts/128results/4096contract+task tombstones,32KiB pure-task input/output, no remote device capabilities. Persist intent/terminal/ACK, ambiguous STARTED never reruns. Resource release waits real completion/quiescence.
- Tests before behavior; independent native evidence and fault negatives; false claims of full1.3/all16domains/learning prohibited. The requested four integration goals get their own evidence; unrelated full-system gates remain separate.
- Preserve all existing staged and working files; no git stage/commit/push. Continue current user project branch. Independent agents own disjoint files, root owns workspace/kernel Cargo/main/build integration. Native runs serialized after source freeze.

## Task 1: Dynamic core integration
Read prototype cores/runtime/smp/gates. Implement genuine AI requested 1→2→1 with actual per-core stop producers and ownership-bound context scheduling; model-generated proposals and execution receipts. CPU0 remains mechanism broker/B, CPU1 control anchor, CPU2 movable,CPU3 business anchor. Expose ongoing runtime coordinator hooks so network/disk work can progress in the same CPU0 loop. Tests cover delayed/no stop, stale requests, budgets, real role/context changes, ongoing business and network progress. Preserve standalone runtime profile.

## Task 2: Guest TLS service
Create protected EL0 FP/SIMD service with bounded allocator and narrow entropy/time/transport/persistent-store broker ABI. Cross-build rustls/ring to standard aarch64-unknown-none; do not remove NEON assertions. Guest CSPRNG backend calls real VirtIO entropy; identity provisioned per node and bound to persistent records, never both private keys in one image. Session can survive partialTCP, reconnect, timeouts, EOF revocation. Export reusable service engine for Task3 protocol driver; add exact build/mapping/ABI contract to report. Native evidence must prove TLS runs in guestEL0 and peer pin/replay/entropy failure rejects.

## Task 3: Durable member and contract state
Implement v1.3 bounded protocol engine in cyxia-prototype (crypto via trait, real guest implementation Task2). Journal-backed reserved regular-file volume for identity/member/contracts/results/tombstones; extend BootEpoch validation compatibly. Actual two-node formation/proof/reconcile/READY, contract/unique task lifecycle, result custody/ACK/close/leave and reboot recovery. Native service calls same engine, tests use real journal plus explicit lost-unflushed writes. API supports resumable effects so CPU0 broker does not hold global control locks while doing disk IO. Report exact APIs early.

## Task 4: Unified native runtime
Root integrates one feature unified-runtime: CPU0 bounded I/O broker and EL0 network/cluster turns, CPU1/2AI, CPU2/3business, nativeDisk retained. Reuse actual paging, timer preemption, sharedservice pages with capability bounds, no unsafe generic guest pointers. LocalAI keeps optimizing while authenticated cluster grants and pure tasks run; normal networking never blocks all business. All task effects/stop proofs come from actual mechanisms. Build separate node images with separate identities.

## Task 5: Joint acceptance
Independent runner starts two native guests and reads raw/serial/PCAP/disk evidence. Prove in SAME run dynamic1→2→1, EL0 TLS mutualauthentication, durableBOUND/READY, grant→unique puretask→durable result→durableACK/close, localbusiness during modelstall/linkloss, reconnect and reboot without duplicateexecution. Negative pin/entropy/proof/replay/noACK/expiredfinalgate/unknownIO paths failclosed. Audit source/images/provisioning and preserve failed runs. Taskreview then whole integration review; only evidence-supported goals markedcomplete.

## Completion evidence (2026-10-24)

Tasks 1–5 are implemented and the requested four integrations pass together in the explicit unified-runtime profile. Final source digest: 9bafff02df7f5386b9cf7ad1c417f774b326cfcdddda8870050d5c8377b65710. All eight final native scenarios pass: normal plus reconnect, original-disk reboot, signed leave, one model hang, missing stop ACK, wrong peer pin, missing entropy, and missing-entropy reboot preserving closed custody. Reports are artifacts/unified-final-*/summary.json; aggregate is artifacts/unified-final-evidence/summary.json. Full v1.3 and physical realtime are not certified. Implementation, reproduction commands, earlier failed captures and exact boundaries are in docs/implementation/unified-native-control-cluster.md.

Final regression: 622 Rust workspace tests, 19 standalone guest-service tests, 491 Python tests; zero failures. Reviewed R1–R15 fixes include real Gate/stop producers, source/image binding, final admission and custody identity, bounded durable reserve, acquire-before-metadata task expiry, and offline custody before network entropy dependency. Existing staged work is preserved; no commit or push was performed.
