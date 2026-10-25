# Same-boot EL0 service recovery contract

This records the next integration boundary for the v1.3 recovery work. It is
not a claim that the unified native service currently restarts. The current
`unified.rs` fault branch closes its TCP endpoint and enters `isolate()`;
same-BootEpoch custody lookup/reconciliation exists, but is not reached by a
fresh native service after that fault.

## Existing ownership that must survive

- `unified_task` owns reservations, execution tokens, actual task contexts and
  retained completions. A service fault is not a node reboot or proof that a
  remote pure-compute task stopped. Never call its boot initializer again.
- `unified_store` owns the already-open journal/record volume. Completed PUTs
  remain durable. An incomplete staged record is not a transaction and may be
  discarded only after the sole old service is proven stopped; an I/O poison
  remains latched. Do not reopen a poisoned journal as a repair operation.
- `domain_network::requests` owns the ordinary application's request payload
  until a matching durable submission is acknowledged. Replacing the EL0
  allocator must not erase these kernel-owned request records.
- The NIC, DMA pages and device queues retain their boot-time owner. Close the
  old TCP generation and reconcile/discard that generation's IPC ciphertext
  prefixes before another socket receives bytes. Do not reset DMA ownership
  merely because the userspace TLS session died.
- The BootEpoch, controller epoch, task/resource counters, deadlines and spent
  CPU windows remain monotonic. Service generation is a distinct checked
  counter and must appear in actual EL0 entry/capture identity.

## Bounded supervisor sequence

1. A synchronous EL0 fault or terminal service report closes new service
   admission and marks its generation stopped. Timer preemption alone is not
   a fault or stop proof. No old context can be entered after this point.
2. Invalidate the authenticated stream and close its endpoint through the
   current owner path. Keep transport unavailable to new grants/starts while
   existing task custody and recovery pumps continue.
3. Retire the service's policy executor generation. Retain old apply IDs and
   unresolved one-shot placement obligations; do not replay them into a new
   service as fresh actions. Clear copied observation readiness and effective
   volatile policy only after recording the old generation's disposition.
4. Reset only service-private mutable memory, stack, shared ABI and register
   context in bounded paid chunks. Existing code/RO mappings remain immutable.
   The current `load()` is a once-only mapper whose `map()` asserts empty PTEs;
   it must not simply be called a second time. If mappings change, complete
   the corresponding TLB protocol before reuse. Clear enabled FP/SIMD state
   through the real `Context::empty()` path.
5. Start a new nonzero service generation with the unchanged BootEpoch and
   trusted identities. Its first protocol work replays durable member,
   contract and task records and queries exact kernel custody. Same-boot
   STARTED plus a surviving token reattaches; missing or conflicting custody
   remains unresolved. It never grants START from a recovery query.
6. Readiness requires successful durable replay, exact custody reconciliation
   and the normal authenticated peer reconciliation. A fresh TLS connection
   or successful ELF load alone is insufficient. Repeated faults preserve
   obligations and use a bounded deterministic retry/isolation policy.

The coordinator may continue local scheduling, ordinary file work, I/O
completion, control recovery and historical query/close operations throughout.
None of these steps authorizes model-driven recovery recipes for an unregistered
service or permits old receipt generations to settle new actions.

## Required regressions and native evidence

Host regressions must cover incomplete PUT staging, poisoning persistence,
service-generation overflow, context reset, partial reset/retry, old feedback,
one-shot placement, returned-but-unconsumed results, and duplicate START/CLOSE.
The actual supervisor state machine must be tested, in addition to the custody
codec and driver reconciliation tests already present.

Native fault injection must stop the real service at START_PENDING, after task
enqueue, after completion before service consumption, and around durable result
recording/ACK. Evidence must show one execution owner, unchanged BootEpoch,
increasing service generation, retained result/obligation and successful exact
reconciliation. A later node reboot is a separate scenario: a durable STARTED
record without a complete terminal result becomes LOST at its authority and
must not use the same-boot reattachment rule.

Relevant files are `kernel/src/unified.rs`, `unified_store.rs`,
`unified_task.rs`, `domain_network.rs` and its `requests`/receipt adapters,
`crates/kernel-core/src/control_plane/service_image.rs`, and the existing
`user/prototype-cluster/src/driver/custody.rs`. Keep this integration separate
from the A02 permission capture and A10 ordinary file workload so each native
failure remains attributable to its actual scenario.
