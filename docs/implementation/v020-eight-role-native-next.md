# V0.20 eight-role native continuation — engineering candidate

Base: PR #79 head `b1c5f4e793070cd6a92c7e81410e4b9b8d2bc500`. Do not merge or advertise G0/G4 acceptance on the strength of this document.

## Prior observed evidence
- PR #78 native diagnostic CI run 45421769376: PASS.
- PR #79 native diagnostic CI run 45422803300: FAIL. The archived serial trace shows role2 restart and `V0199_BOOTSTRAP_OVERRUN a=2 b=326788 c=250000`. Same kernel ELF digest as #78, different QEMU build. This is a runtime stability failure, not grounds to loosen the decision reservation.
- Prior 256 MiB diagnostic success proves eight isolated ELF entrypoints/reloads, not functional native services or persistent identity.

## Changes in this candidate
- Native scheduling: boot-unique ASIDs for the immutable pinned role roots, retirement TLBI before frame reuse; one exception/trap per diagnostic decision turn. Continuous CPU0 PMU measurement during the diagnostic interval, including scheduling gaps and timer idle entry/return; fixed 2ms EL1 coordination subledger within the existing 8ms class, not an increase in the 70ms total. Cross-window gap attribution uses conservative endpoint upper bounds; exact per-window splitting is not yet proven. Pre-PMU initialization and post-final evidence output remain outside this diagnostic interval.
- Executor evidence: canonical ExecutorBinding v1 and per-target origin validation; D04 uses authenticated role12 endpoint, other fourteen domains EL1. Registered terminal settlement checks the complete report set before querying native effect evidence. No report alone proves application or releases retained work.
- Persistent epochs: independent baseline-v1 redo chain validation (CRC, ordering, exact home image, transaction and log identity, no duplicate home blocks); a new durable confirmation adapter requires this check plus independent native FLUSH/commit proof. No legacy v2 media reinterpretation, raw state write, or synthetic device completion.
- Native matrix: build both 256MiB regression and 1GiB normative RAM profiles; verify ELF profile against actual QMP memory size. Three independent runs per size; any failed run fails that matrix job. Preserve each run's raw evidence. This is still diagnostic, not production.
- Required proof inventory: `tools/v0199-required-proof-inventory.json` enumerates the 127 stable IDs and their 262 required G4 proof-class pairs plus 26 G5 hardware pairs, transcribed from the baseline 安§7.4 pp.171–172. Inventory entries are not verdicts.

## Open blockers
- Eight native programs still need their full role-specific service loops, verified operations/security model packages, actual snapshots/candidate bindings, policy/permit and feedback/validation channels. The old bootstrap clients remain deliberately fail-closed. Do not synthesize trained weights, target observations, plans, audit ACKs or model promotions.
- No production dispatcher connects every control execution path, including boot/finalization, to a proven exact 100ms ledger. New diagnostic accounting needs native CI verification; retain overrun failures.
- Real native executor completion and resource ownership must still be connected to all fifteen domains; callbacks must authenticate actual state, DMA/pins and accepted apply identities.
- Native baseline-v1 filesystem owner, protected state inode, actual device FLUSH ordering, verified recovery, shared controller epoch transition, and cross-process QEMU disk tests are not complete. The new redo checker is read-only; it cannot prove persistence by itself.
- The 1GiB diagnostic build and triple-run workflow are unverified until CI finishes. No new formal G4 Verdict v4 was generated. All 127 formal cases lack complete evidence on this candidate; no formal PASS is claimed. G5 remains separate.

Keep the eight roles [6,7,2,8,9,3,10,11], fixed CPU0, isolated EL0 roots, 32KiB stacks and independent capabilities. Business hot path never synchronously waits for inference. No dynamic core transfer and no D16 addition to the frozen V0.19.9 contract.
