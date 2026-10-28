# EL0 governance image integration

This source-bound checkpoint records the first unified-kernel integration of the
independent `prototype-governance` EL0 image.

The kernel build produces the exact AArch64 image, embeds and hashes its bytes,
validates an RX/RO-only ELF plan, allocates its code, observation, command, stack
and page-table pages from the existing control pool, and publishes stopped-state
identity evidence. The unified build manifest retains the same governance image
as an independently hashed artifact for both nodes.

This checkpoint deliberately stops before scheduling. The image registration is
not command authority, does not create a second publication path, and does not
create another 9 ms learning budget. Prepaid EL0 dispatch, trap-derived role and
credit identity, shared-surplus accounting, checked command application and
native A16 evidence remain required.
