# Candidate preparation admission evidence

The `e8c893d` native run ends FAIL after 600.856184 seconds. The ordinary
client exits 0; control retains 144 jobs, 135 publications and 115 Applied.
One baseline side is kernel-verified and durably archived. Candidate trial 2
remains Running without its first scope or capture generation, with zero
labels/training/validation. Both final control-entry rows reach phase 1 with
phase 2 zero: entry returns at the original early admission condition. This
does not identify which boolean closed admission.

The final retained ordinary job is 144, domain 2/target `[11,1]`, version 135,
Applied. Its measured decode is 107,832 ns and subsequent publication is
408,583 ns. Their nonoverlapping sum is 516,415 ns. Registry's final budget
check can retain an installed publication and stop subsequent optimization.
This is a concrete hypothesis for the missing candidate job, not proof that
this job changed that state. The new diagnostic records that transition.

The stopped committed-redo CRC/extents/hash/boundary reader validates one
48,896-byte archive, SHA-256
`f4d5c2b21480e4dc41372a35b0b0ca1528264ff3d88249bb2e9402dfedd24ac6`.
It contains trial 1, two histories, 340 intervals and 100 requests, with no
capture/verification error or missing event. Initial 145 reaches Applied
20.850 ms after its snapshot; renewal 147 is also timely. Closing 148 reaches
Applied 63.113008 ms after publication, 13.113008 ms past its approved bound.
The kernel's verified-side count is not complete closing or catalogue acceptance.
The exact closing-chain inspector matches identities with no conflicts and
sums raw EA to 447,458 ns; the retained closing probe never shows a successful
submit or a matching child. These remain separate defects.

Network raw/report/final observer comparisons pass: 1,590,514 completed pieces
match settlements, with zero binding/context/snapshot/identity errors and no
physical overrun. The previous network fatal is still unattributed. Final
capture handoff retains=drains 11,525 exits, pending=loss=0. Runtime source map
still equals the frozen build; overall native acceptance remains FAIL.

## Producer and layout

The new diagnostics reuse previously reserved words of the existing
`DOMAIN_CONTROL_EVIDENCE` 512-word header. No bank or workspace allocation is
added. All writers hold the existing Control gate. Existing record slots and
acceptance parsing remain unchanged. Ranges below include both endpoints;
Rust source comments use half-open `a..b` notation.

| Header words | Meaning |
| --- | --- |
| 128 / 129 | Admission magic `0x435941444d490001` / schema 1 |
| 130 / 131 | Candidate Running entry visits / denied visits |
| 132–135 | Counts for no boot, live job, stopped optimizer, governance reservation |
| 136–157 | Latest 22-word entry context |
| 159 | Admission publication seqlock |
| 192–213 / 218 | Immutable first denied candidate context / presence latch |
| 160 / 161 / 162 | Accept-stop magic `0x43594f5053540001` / schema / transitions |
| 164–183 | Immutable first stop transition **within accept** |
| 191 | Independent accept-stop publication seqlock |

Entry context offsets 0–21 are CPU, original wall entry, original first selected
reason, boot, state sequence, live job sequence, prepared count, token, trial,
Root phase+1, domain, kind, target id/generation, first sequence/time,
first-ready, initial plan sequence, token boot, owner id/generation, candidate=1.
Reason 0 means open; 1–4 follow the original short-circuit condition in order.
The original governance `now()` call occurs only if all preceding checks pass.
Root projection adds no owner or clock query and only covers Candidate/Running.

Accept-stop offsets 0–19 are source flags, original accept wall entry, boot,
controller epoch, job sequence, target id/generation, returned version, error+1,
read-only, original decode CPU, original subsequent publication CPU, their
checked sum, overflow, prior stopped flag, actual stopped flag, model generation,
state sequence, job CPU and original publication CPU origin in nanoseconds.
Flag 1 observes Registry already stopped at the return from its original path;
flag 2 observes the existing native post-decode meter's stop condition. Neither
flag identifies which internal Registry check fired. The sum is a lower bound
from original disjoint measurements, not a fresh full-duration measurement.
The wall entry is not the physical instant of the stop.

The stop row records only false→true transitions inside `accept`. Observer,
stability, replay and governance paths can also stop optimization. **Admission
reason 3 with an empty accept-stop row still means admission observed stopped.**
Later transitions increment a counter and cannot replace the first retained
context. The two lanes have independent seqlocks and do not constitute a single
atomic snapshot or authorize any work. Odd/missing lanes are unavailable facts,
never a healthy state. A stopped raw reader must compare lane headers/versions,
even publications and identities without changing the acceptance result.

## TDD evidence

Journeys are derived from the existing acceptance plan's requirement to retain
fresh budget-failure evidence. The actual-source command is
`python3 tests/host/test_preparation_admission.py`. Both targets compile and
fail behaviorally before implementation: missing admission evidence and missing
publication-stop provenance. RED checkpoint `782e8e0` and GREEN checkpoint
`7456ee0` are reachable on the same branch.

| Guarantee | Test boundary and result |
| --- | --- |
| Each of four real early gates retains its reason, owner identity and original entry | Actual `next_locked_inner` and Root projection; PASS |
| Original short circuit, one governance clock/query, no work when denied | Same fixture, counted owner/clock boundaries; PASS |
| Unauthorized entry leaves evidence unchanged; first denial survives later causes | Actual entry and header writer; PASS |
| First accept transition retains original costs/result/identity and remains immutable | Actual accept tail/header writer; Registry transition is an explicit facade; PASS |
| Already stopped does not invent a new transition; native meter still stops | Actual accept tail and original condition; PASS |

Eight independent negative controls remove or corrupt entry hooks, reasons,
target identity, first-denial freeze, original stop origin, first-stop freeze,
CPU sum and transition qualification. Each fails its named assertion. The real
Registry test `installed_publication_survives_overrun_and_blocks_new_optimization`
also passes separately, preserving its actual retained-stop contract. The host
tests do not prove SMP timing, WCET, the previous job's causality or candidate
progress. Full checks, frozen images and native evidence remain required.

Host LLVM instrumentation, run by the retained local
`run-preparation-admission-coverage.py`, measures line coverage of the three
added diagnostic functions at **90.91% / 100% / 100%** (Root projection / entry
header writer / accept-stop header writer). This exceeds the 80% target for
these new functions. It is not whole-kernel or branch coverage; the existing
full preparation and accept bodies have deliberate owner/Registry boundaries
outside these fixtures. Eight mutation controls and both positive groups also
pass during the coverage run. Raw reports remain in the local artifact folder.

All nine v45 configured checks pass, including 699 host tests (two environment
skips), 84 tooling tests, Rust/TLS, formats and configured Clippy. Both images
build and selected preparation stack peaks are 33,104/65,536 bytes. The frozen
compiled-source map is
`1a301087380efa1ffb837ce33b2dd8a60658363694454d932279009a90812be3`.
Independent review finds no Critical/Important issue. Its two documentation
Minors are resolved here by explicit inclusive header ranges and the
accept-only provenance scope. Fresh native diagnosis follows, with complete
prototype acceptance still open.
