# Native compositor tile capacity

This versioned patch uses the display ABI's advertised rectangle capacity in
the real resumable presentation cursor. The existing validator accepts at most
65,536 bytes, matching the kernel's unchanged 16,384-pixel maximum. The old
cursor additionally capped the buffer at 16,384 **bytes**: a 1024×768 frame
therefore required 192 completed submissions instead of 48.

The cursor owns one allocation, now bounded by the existing 64 KiB ABI limit.
This can use 48 KiB more compositor heap than the previous cursor; process heap,
stack, FD, thread, shared-object and kernel display limits are unchanged. Pixel
conversion, global flipping, the per-turn syscall budget, EAGAIN/EINTR retries,
terminal errors, no-progress timeout and fence-completion requirements retain
their existing implementations. Black scanout uses the same cursor.

`base/presentation.rs` is the complete GPL-3.0-only native backend translation
unit after the pinned phase-observation series, before this change. Its hash is
bound by the original phase manifest and this port's source policy. It is a
Cyxia backend source file, not a substitute compositor or an upstream COSMIC
implementation. The original series and all historical recipes remain intact.

`tools/cosmic_native_tiles_v1.py build` invokes the pinned v5 complete compositor
builder twice in one controlled build directory: first the original cursor,
then this single-file patch. Both retained source trees, raw linked ELFs,
commands and complete 468-package locked/offline dependency closures are kept.
The independent `tools/assemble_cosmic_native_tiles_v1.py` consumer re-exports
the canonical source and both
patch series, revalidates the source closures, SDK, compilers and ELF admission,
then replaces only `cosmic-comp.elf` in the normal clock-enabled catalog.

The host regression injects only the display submission boundary into the real
cursor. It verifies every output pixel, original completion protections, exact
submission work, retries and black scanout. Set `CYXIA_PRESENTATION_BASELINE=1`
to run the same assertions on the unmodified cursor. The observer-only feature
is disabled in this host harness; it remains enabled in the complete native
build. Host results do not prove guest GPU behavior or desktop responsiveness.

Real guest latency, first-frame gates and calendar behavior require separate
captures. No full OS or COSMIC-session acceptance is asserted by this port.
