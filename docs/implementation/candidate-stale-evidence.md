# Candidate pre-executor Stale evidence

Two native renewals (371 and 466) are published and then fail Stale with no executor entry. The first-scope trace has already frozen on the preceding baseline, so it cannot attribute those candidate refusals. This diagnostic retains the first matching candidate Stale from the existing Control denial branch.

Control constructs its original `ControlDenial` once, forwards a borrow to Root, then passes the same value to the existing trace. Root requires a Running Candidate with matching token owner/boot, original first snapshot/initial namespace, target and family, a real published version and flags 1, 2 or 4 with the original Stale error. It copies the existing observed timestamp and generations. There is no new clock, resource query, lock, progress operation, changed context order or authority.

The existing `DOMAIN_CONTROL_EVIDENCE` header words **220–255** now belong to this lane. No bank or workspace allocation is added. All writes occur under the original Control gate. Relative words 0/1/2/3 contain magic `0x43595354414c0001`, schema 1, matched observation count and first-present. Words 4–34 retain the first payload; 35 (absolute 255) is the seqlock. Later observations increment the count without replacing the payload.

| Payload offset | Original fact |
| --- | --- |
| 0–4 | Token ID, boot, owner ID/generation, trial ID |
| 5–8 | First snapshot sequence/time/ledger/core |
| 9–14 | Full denied ApplyId: boot/controller/plan/action index/target ID/generation |
| 15–18 | Policy version, snapshot time, installed-until, original observed time |
| 19–22 | Expected/current core, expected/current ledger |
| 23–26 | Original denial flags, error discriminant + 1, family domain/kind |
| 27–30 | Original initial plan sequence, Root phase + 1, first-ready, initial action index |

Flags 1 mean the original core/ledger fence, 2 an original dependency-read error, 4 a changed dependency binding. This lane covers only pre-executor Stale in the matching candidate namespace. An empty lane does not certify health or classify an executor-returned error. A ledger mismatch does not identify which resource writer advanced it; admission, cleanup and recovery still require separate original-owner proof. The count represents matching hook observations, not a unique-job or all-denial count.

Behavioral RED observes missing facts in four actual Control paths. GREEN uses the actual Root filter and complete real evidence writer, checks all four branches, rejects thirteen foreign cases, preserves the first payload, and distinguishes an actual executor Stale. The broader fixture covers 18 Root/Control/publication/Activate cases, four paid cases and 20 negative controls, including deletion of both forwarding hooks, wrong current ledger and first-payload overwrite. Reply/Registry/resource dependency callbacks remain explicit controlled boundaries; the tests do not prove a particular native failure's cause or a scheduling bound. All nine v50 checks pass (702 host tests, two environment skips; 84 tools, Rust/TLS/formats/configured Clippy). Both images and selected stacks pass at 33,104/65,536 bytes. Compiled source matches `6cb00fa362e1ffc08f91562c10dfa0201d0cd65e89bddca336361549c2f33f4a`; fresh native diagnosis follows.
