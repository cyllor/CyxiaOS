# SDD ledger — plan: /Users/robin/CyxiaOS/CyxiaOS-code-m1-plan.md

User approved implementation with `/ecc 编写代码`.
Baseline: 1e78b7f. Tasks T1–T10 pending.
Ruling: work in the explicitly requested project directory on new m1-kernel branch; no separate checkout — no preexisting repository/code, preserve VSCode paths — costs no independent working copy.
Pre-flight T2→T3/T6: logical IDs and checked generations shared; CPU 0 valid, object 0 invalid.
Pre-flight T4→T5/T7: DTB bounded before 0x40200000; core receives BootInfo, never board addresses.
Pre-flight T3→T6: grants reserve capacity, page lifecycle independently proves clearing/revocation; M1 does not claim integrated AI allocation.
Pre-flight T5→T7: low entry and high body require distinct ELF VMA/LMA from first boot layout.
Pre-flight T7→T8/T9: high vectors and dedicated physical progress symbol required before removing TTBR0.

Ruling: installed stable is exact rustc 1.95.0; named duplicate installation ran out of disk. Use installed stable with mandatory doctor version guard instead of duplicate 1.95.0 directory — avoids ~1 GiB duplicate; stable changes must fail doctor before builds.
Ruling: T2/T3/T4 host work proceeded while T1 downloads ran, using verified same rustc 1.95.0 stable; no target success claimed.
Ruling: skill task-brief script only accepts numeric Task headings, plan uses T-prefixed headings; track full briefs directly in plan and completion evidence in this ledger.
T1 environment ready: doctor actual all ready; missing-target/version/path tests 3 PASS. exact QEMU sources checked and hashes saved.
T2 contracts 7 tests PASS (initial missing API failure in artifacts/environment/t2-red.log).
T3 grants 6 tests PASS (including generation exhaustion and test-only AI plan expiry); physical integration remains M5.
T4 real DTB and malformed inputs 6 tests PASS; additional adversarial fixture cases pending final validation.
T5 first boot PASS: artifacts/boot-first/summary.json; ELF checked. Temporary plain diagnostic markers will become validated transport frames in T9.
Ruling: ReleaseReceipt uses documented unsafe trusted-mechanism attestation because M1 has no real user mappings; no user-facing constructor or AI admission path. Incorrect caller attestation remains an unsafe boundary for M5 review.
T6 guest pages-first PASS; dirty/zero failure/wrong owner/duplicate revoke host tests PASS.
T7 mmu-fixed PASS; high PC/SP/VBAR, identity removal, guard translation fault and RX write permission fault verified. Initial failure had ESR=0x96000004: EPD0 produces level-0 fault, not level-3; corrected exact expected exception classification.
T8 timer-first all PASS; >100 ticks, foreground progress, WFI/register probe, actual SPI40 pending/masking. Host deadline/overflow tests PASS.
T9 pressure-first PASS: IRQ 110→832, foreground 110→22890, bytes 504→2146554; host missing 11567 records reported incomplete. Corruption and replay tests PASS. Independent RAM snapshots used.
Ruling: M1 transport uses session=1 within each fresh QEMU instance; run-id + ELF hash + dedicated socket separate captures — no restart/merged-session claim — future multi-boot protocol needs session allocator.
Ruling: fixed virt bootstrap maps its board geometry before high-level DTB parsing; DTB is then validated against geometry before hardware use — early boot is a platform adapter, not generic firmware support — second board requires new bootstrap adapter.
T10 initial verifier caught literal-pool disassembly misclassification; regression fixture reproduced it, scanner now respects .word mapping-symbol data rather than treating raw byte d0 as SIMD register.
T10 pre-review aggregate PASS: artifacts/m1-pre-review/summary.json, all required 23 checks incl. dev/release pressure and production boot. Rust 33 tests, Python 24. Ready for whole-branch independent review; no final completion claim until findings resolved.

Final: fixed invalid zero-memory ELF segment acceptance — test_nonempty_file_with_zero_memory_is_rejected RED→GREEN.
Final: fixed late pressure panic false PASS — test_panic_in_final_pressure_capture_cannot_pass RED→GREEN.
Final: fixed committed-grant redemption ID exhaustion — commit_reserves_redemption_ids_for_all_promised_pages RED→GREEN.
Final suite: artifacts/m1-final/summary.json PASS 22/22 aggregate checks; Rust 34, Python 26; scoped LLVM coverage 91.68%.
Final: Ruling: physical hardware, real user mapping/DMA attestations, AI/EL0/SMP/services, and assembly/MMIO proof from host coverage are outside M1 — record as unimplemented/unverified, not silently passed — later milestones need independent evidence.
Ruling: no integration menu or new base branch: this is the initial repository, user approved local-only work in the designated folder, and the plan explicitly excludes remote operations; preserve m1-kernel in place.
Tasks T1–T10 complete. Independent review 3 Important corrected in one fix pass; no reported Minor deferred. Historical architecture snapshots unchanged.
