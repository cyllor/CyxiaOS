// V0.19.9 advice-chain E2E fixture EL0 program (fixture scope, NOT a service).
// x0: private cookie; x1: private DATA base (0x20000); x7: mode.
//   mode 1: construct a valid AdviceEnvelope v1 in EL0 and submit via SVC 0x50.
//   mode 2: construct an ILLEGAL-domain (16) envelope and submit via SVC 0x50.
//   mode 3: construct a valid envelope but present a FORGED cap via SVC 0x50.
//   mode 4: trusted-byte carrier. EL1 pre-sets x8/x0..x5 in the saved context
//           (REGISTER 0x50 / PUBLISH 0x41); EL0 traps them across the boundary.
//           The DecisionRecord/Disposition/Plan payload bytes are trusted EL1
//           artifacts staged in the private page and read back by EL1 copyin.
// The advice envelope (modes 1-3) is genuinely assembled at EL0 from immediates
// into this context's private RW page; EL1 must copyin and verify it. The SVC
// return value is delivered in x0 by EL1 (canonical syscall return); EL0 records
// it and yields with SVC #4. No kernel address is ever dereferenced.
.section .rodata.v0199_advice_user,"a"
.arch armv8-a+fp+simd
.balign 4096
.global v0199_advice_user_start
v0199_advice_user_start:
 cmp x7, #4
 b.eq advice_carrier
 ldr x10, [x1]
 cmp x10, x0
 b.ne advice_bad
 mov x19, #0x20000           // private DATA base constant
 // ---- modes 1/2/3: build the 152-byte AdviceEnvelope v1 at DATA+64 ----
 add x9, x19, #64
 movz w10, #0x4131           // ADVICE_MAGIC 0x43594131
 movk w10, #0x4359, lsl #16
 str w10, [x9]
 mov w10, #1                 // version
 strh w10, [x9, #4]
 mov w10, #152               // total length
 strh w10, [x9, #6]
 mov x10, #1
 str x10, [x9, #8]           // advisor_epoch
 str x10, [x9, #16]          // advice_seq
 mov x10, #3
 str x10, [x9, #24]          // snapshot_seq
 mov x10, #17
 str x10, [x9, #32]          // target.id
 mov x10, #1
 str x10, [x9, #40]          // target.generation
 mov x10, #5
 str x10, [x9, #48]          // ledger_generation
 mov x10, #6
 str x10, [x9, #56]          // core_generation
 mov x10, #200
 str x10, [x9, #64]          // expires_ns
 mov x10, #9
 str x10, [x9, #72]          // active_model_generation
 cmp x7, #2
 b.eq advice_dom_bad
 mov w10, #1                 // legal domain D01
 b advice_dom_set
advice_dom_bad:
 mov w10, #16                // illegal domain (must never be adopted)
advice_dom_set:
 strh w10, [x9, #80]         // domain
 mov w10, #1
 strh w10, [x9, #82]         // action_kind
 strh w10, [x9, #84]         // recommended_index = 1 (ordinal 4)
 mov w10, #2
 strh w10, [x9, #86]         // candidate_count
 movz x10, #0x0303           // model_hash = [3; 32]
 movk x10, #0x0303, lsl #16
 movk x10, #0x0303, lsl #32
 movk x10, #0x0303, lsl #48
 stp x10, x10, [x9, #88]
 stp x10, x10, [x9, #104]
 movz x10, #0x0101           // candidate_set_hash = [1; 32]
 movk x10, #0x0101, lsl #16
 movk x10, #0x0101, lsl #32
 movk x10, #0x0101, lsl #48
 stp x10, x10, [x9, #120]
 stp x10, x10, [x9, #136]
 // ---- present the CONTROL_AUX 0x50 submit arguments ----
 cmp x7, #3
 b.eq advice_cap_bad
 mov x0, #66                 // registered operations advice cap
 b advice_cap_set
advice_cap_bad:
 mov x0, #67                 // forged cap (must be rejected)
advice_cap_set:
 add x1, x19, #64            // input VA = envelope
 mov x2, #152                // input length
 mov x3, #0
 add x4, x19, #384           // output buffer VA (disjoint; ABI preflight only)
 mov x5, #8                  // output capacity
 mov x8, #0x50
 svc #0
 // EL1 resumes here; x0 carries the syscall return (outcome).
 str x0, [x19, #768]         // record observed return for EL1 evidence
 svc #4                      // bounded yield
 b .
 // ---- mode 4: trusted-byte carrier (x8/x0..x5 pre-set by EL1) ----
advice_carrier:
 mov x19, #0x20000
 svc #0
 str x0, [x19, #768]         // record observed return for EL1 evidence
 svc #4
 b .
advice_bad:
 svc #3
 b .
.global v0199_advice_user_end
v0199_advice_user_end:
.balign 4096
