# Native network service credit repair

This note records the bounded-network-service change made while completing the
CyxiaOS v0.1 native prototype.

## Failure that motivated the change

The protected two-node native replay rejected the previous source because the
control service thread consumed more than its reserved 2.5 ms CPU segment while
executing network service stage 4. The verifier correctly retained the sticky
credit-overrun receipt and quarantined the affected CPU instead of accepting a
later clean snapshot.

The repair does not increase the declared budget, weaken quarantine, or replace
the guest accounting clock. It makes the native network work preemptible at
safe ownership boundaries.

## Source change

- Native TCP polling now exposes safe checkpoints after the NIC service/flush,
  after the single ingress frame, and after each independently bounded egress
  descriptor-chain attempt.
- The unified runtime settles the current service receipt at each checkpoint,
  advances only deterministic mechanism work while no socket, device, task, or
  IPC lock is held, and reacquires a fresh service segment before continuing.
- Network IPC draining handles exactly one complete FIFO head per service
  segment. The remaining head retains queue ownership and wake state.
- Existing socket backpressure, retransmission, message framing, descriptor
  ownership, FIFO order, and failure-head semantics are unchanged.
- The evidence verifier now emits CPU, reservation, actual consumption, window,
  service-stage, and sticky-receipt details when a credit failure occurs.

## Focused validation

The formatted source at commit
`17242370f8122ce217fb819572e3d9a9378d73ba` passed:

- 47 native evidence/parser tests;
- 14 cluster transport network tests;
- 46 task, scheduler, and IPC tests; and
- the AArch64 kernel Clippy gate with warnings denied.

The fixed QEMU 10.2.2 two-node native replay remains the authoritative
end-to-end acceptance gate. A passing unit or static gate is not recorded as a
substitute for that run.
