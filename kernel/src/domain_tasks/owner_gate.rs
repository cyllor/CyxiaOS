//! Nonblocking task-owner exclusion with bounded per-CPU handoff. A failed
//! caller returns immediately. A bounded CPU turn permits admission/use/settle
//! sequences, then hands off to another waiter. An absent waiter expires.
use core::{
    marker::PhantomData,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

const CPUS: usize = 4;
const NONE: usize = CPUS;

#[repr(align(64))]
pub(super) struct Gate {
    held: AtomicBool,
    waiting: AtomicU64,
    preferred: AtomicUsize,
    until: AtomicU64,
    owner: AtomicUsize,
    turn_until: AtomicU64,
}

/// Linear, gate-bound permission. It cannot be cloned or moved to another CPU.
pub(super) struct Permit<'a> {
    gate: &'a Gate,
    cpu: usize,
    span: u64,
    _local: PhantomData<*mut ()>,
}

impl Gate {
    pub(super) const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            waiting: AtomicU64::new(0),
            preferred: AtomicUsize::new(NONE),
            until: AtomicU64::new(0),
            owner: AtomicUsize::new(NONE),
            turn_until: AtomicU64::new(0),
        }
    }

    fn enqueue(&self, cpu: usize) {
        let bit = 1 << cpu;
        // One request per CPU, rather than a shared RMW on every Busy retry.
        if self.waiting.load(Ordering::Relaxed) & bit == 0 {
            self.waiting.fetch_or(bit, Ordering::Release);
        }
    }

    fn next(&self, after: usize) -> usize {
        let waiting = self.waiting.load(Ordering::Acquire);
        (1..=CPUS)
            .map(|offset| (after + offset) % CPUS)
            .find(|cpu| waiting & (1 << cpu) != 0)
            .unwrap_or(NONE)
    }

    pub(super) fn try_acquire(&self, cpu: usize, now: u64, span: u64) -> Option<Permit<'_>> {
        if cpu >= CPUS {
            return None;
        }
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.enqueue(cpu);
            return None;
        }
        // Read the reservation only after acquiring exclusion: it was
        // published before the preceding owner's Release store to held.
        let preferred = self.preferred.load(Ordering::Relaxed);
        let until = self.until.load(Ordering::Relaxed);
        let owner = self.owner.load(Ordering::Relaxed);
        let span = span.max(1);
        if preferred < CPUS && preferred != cpu && now < until {
            self.enqueue(cpu);
            self.held.store(false, Ordering::Release);
            return None;
        }
        let handoff = preferred < CPUS && preferred != owner;
        if handoff && now >= until {
            // Expire the queued request as well. A stopped CPU must not be
            // selected again on every later release without another retry.
            self.waiting.fetch_and(!(1 << preferred), Ordering::AcqRel);
        }
        if owner == NONE || handoff && now < until {
            self.owner.store(cpu, Ordering::Relaxed);
            self.turn_until
                .store(now.saturating_add(span), Ordering::Relaxed);
        } else if now >= self.turn_until.load(Ordering::Relaxed) {
            // Select under exclusion even if a different claimant won CAS.
            // Continuous activity cannot renew ahead of a queued peer.
            self.enqueue(cpu);
            let next = self.next(owner);
            if next != cpu {
                self.preferred.store(next, Ordering::Relaxed);
                self.until
                    .store(now.saturating_add(span), Ordering::Relaxed);
                self.held.store(false, Ordering::Release);
                return None;
            }
            self.owner.store(cpu, Ordering::Relaxed);
            self.turn_until
                .store(now.saturating_add(span), Ordering::Relaxed);
        } else if owner != cpu {
            self.enqueue(cpu);
            self.held.store(false, Ordering::Release);
            return None;
        }
        self.waiting.fetch_and(!(1 << cpu), Ordering::AcqRel);
        self.preferred.store(NONE, Ordering::Relaxed);
        Some(Permit {
            gate: self,
            cpu,
            span,
            _local: PhantomData,
        })
    }
}

impl Permit<'_> {
    pub(super) fn release(self, now: u64) {
        let waiting = self.gate.waiting.load(Ordering::Acquire);
        let end = self.gate.turn_until.load(Ordering::Relaxed);
        let next = if waiting == 0 {
            self.gate.turn_until.store(0, Ordering::Relaxed);
            NONE
        } else if now < end {
            self.cpu
        } else {
            self.gate.next(self.cpu)
        };
        let until = if next == self.cpu {
            let end = if now < end {
                end
            } else {
                now.saturating_add(self.span)
            };
            self.gate.turn_until.store(end, Ordering::Relaxed);
            end
        } else {
            now.saturating_add(self.span)
        };
        self.gate.preferred.store(next, Ordering::Relaxed);
        self.gate.until.store(until, Ordering::Relaxed);
        self.gate.held.store(false, Ordering::Release);
    }
}
