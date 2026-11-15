# COSMIC nested epoll

Continue the approved complete OS / COSMIC plan from `4355cc5`. The unchanged
real compositor now exits at Wayland Display event-source registration because
the POSIX mechanism rejects epoll descriptors as monitored objects.

Implement nested epoll in the shared OFD mechanism, retaining weak generational
watches and existing quotas. The parent is readable when the child has an
event available for collection; observing the parent must not consume child
events, disarm child ONESHOT, or advance child fairness. Backend notifications
must propagate through nesting, including new events while a child is already
readable, without synthesizing repeated edges from ordinary sampling. Drain,
ONESHOT consumption, DEL and final close update ancestor readiness. Descriptor
aliases and inheritance preserve actual OFD lifetime; numeric FD/slot reuse
does not inherit a watch.

Reject self-monitoring (including aliases) with EINVAL, cycles and paths longer
than five epoll instances with ELOOP, counting disarmed watches and ancestors.
All graph operations use the existing bounded metadata; no recursive traversal
or new allocation policy. Backend polling occurs outside the OFD borrow because
the existing backend wrappers publish notifications into that same table.
Poll only the requested epoll's reachable subgraph.

Use the already authorized test seams: public Process/OFD interfaces with real
backends, actual musl Linux syscalls in the four-CPU/1-GiB guest, and the unchanged
COSMIC startup. Preserve RED/GREEN, negative graph/lifetime coverage, source and
ELF receipts, and raw guest failures. Native builds/tests/captures use the shared
lease serially; independent probe ownership and reviews follow the main plan.
Keep `.qwen/` untouched. Routine steps require no further confirmation.

This stage must produce real readiness behavior, not an epoll_ctl success stub.
Inotify, descriptor-capacity expansion and session services follow actual
startup evidence. Full OS and complete COSMIC session remain unverified until
their actual interaction and lifecycle requirements pass.
