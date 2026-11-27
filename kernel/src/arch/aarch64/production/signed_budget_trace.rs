//! One bounded PMU trace prefix for the signed scratch lifecycle verifier.
//! CPU0 owns all writes. EL0 has no mapping to this kernel-owned memory.

use super::{Sample, WINDOW_NS};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_kernel_core::control_plane::role_budget_v0199::{Class, Cpu0BudgetLedger, Turn};

const CAPACITY: usize = if cfg!(cyxia_startup_catalog) {
    4096
} else {
    1024
};
const VERSION: u64 = if cfg!(cyxia_startup_catalog) { 2 } else { 1 };
const MAGIC: u64 = 0x4359_5832_5342_5544;
const HEADER_WORDS: usize = 20;
const ROW_WORDS: usize = 8;
const CLASSES: [Class; 6] = [
    Class::Operations,
    Class::Security,
    Class::Decision,
    Class::Coordination,
    Class::Recovery,
    Class::Optional,
];

#[repr(C, align(4096))]
struct Evidence {
    header: [AtomicU64; HEADER_WORDS],
    rows: [[AtomicU64; ROW_WORDS]; CAPACITY],
}

#[unsafe(no_mangle)]
static V020_SIGNED_CPU_BUDGET_TRACE: Evidence = Evidence {
    header: [const { AtomicU64::new(0) }; HEADER_WORDS],
    rows: [const { [const { AtomicU64::new(0) }; ROW_WORDS] }; CAPACITY],
};

pub(super) struct Trace {
    next: usize,
    first_role_window: Option<u64>,
    opening_recovery: u64,
    sealed: bool,
}

impl Trace {
    pub(super) fn new(
        origin: Sample,
        boot_epoch: u64,
        opening_window: u64,
        opening_recovery: u64,
    ) -> Self {
        let header = &V020_SIGNED_CPU_BUDGET_TRACE.header;
        for (cell, word) in header[3..9].iter().zip([
            origin.wall,
            origin.cpu_tick,
            origin.before,
            boot_epoch,
            opening_window,
            opening_recovery,
        ]) {
            cell.store(word, Ordering::Relaxed);
        }
        Self {
            next: 0,
            first_role_window: None,
            opening_recovery,
            sealed: false,
        }
    }

    #[cfg(cyxia_startup_catalog)]
    pub(super) fn begin_media(&self) {
        // Version 2 begins at early startup. These two fields instead index
        // the contiguous span that owns exclusive use of the boot disk.
        V020_SIGNED_CPU_BUDGET_TRACE.header[7].store(self.next as u64, Ordering::Relaxed);
    }

    #[cfg(cyxia_startup_catalog)]
    pub(super) fn finish_media(&self, boot_epoch: u64) {
        let header = &V020_SIGNED_CPU_BUDGET_TRACE.header;
        header[6].store(boot_epoch, Ordering::Relaxed);
        header[8].store(self.next as u64, Ordering::Relaxed);
    }

    pub(super) fn record(&mut self, end: Sample, grant: Option<Turn>, returned: u64) {
        if self.sealed {
            return;
        }
        let Some(row) = V020_SIGNED_CPU_BUDGET_TRACE.rows.get(self.next) else {
            return;
        };
        let (quota, deadline, scope, id, generation) = grant.map_or((0, 0, 0, 0, 0), |grant| {
            let (class, role, domain) = grant.accounting_scope();
            let (slot, id, generation) = role.map_or((0, 0, 0), |(index, actor)| {
                self.first_role_window.get_or_insert(end.wall / WINDOW_NS);
                (index as u64 + 1, actor.id, actor.generation)
            });
            let scope =
                (class as u64 + 1) | (slot << 8) | (u64::from(domain) << 16) | (returned << 32);
            (
                grant.reserved_ns(),
                grant.deadline_ns(),
                scope,
                id,
                generation,
            )
        });
        for (cell, word) in row.iter().zip([
            end.wall,
            end.cpu_tick,
            quota,
            deadline,
            scope,
            end.before,
            id,
            generation,
        ]) {
            cell.store(word, Ordering::Relaxed);
        }
        self.next += 1;
    }

    /// Seal a settled prefix and leave the resident scheduler running.
    /// Its first partial role window is outside the full-window witness.
    pub(super) fn maybe_seal(
        &mut self,
        end: Sample,
        ledger: &Cpu0BudgetLedger,
        charged: u64,
        idle: u64,
    ) {
        if self.sealed
            || self.next == CAPACITY
            || self
                .first_role_window
                .is_none_or(|window| end.wall / WINDOW_NS <= window + 8)
        {
            return;
        }
        let header = &V020_SIGNED_CPU_BUDGET_TRACE.header;
        for (cell, word) in header[9..14].iter().zip([
            end.wall,
            end.cpu_tick,
            charged,
            ledger.max_window_upper_ns(),
            idle,
        ]) {
            cell.store(word, Ordering::Relaxed);
        }
        for (cell, class) in header[14..].iter().zip(CLASSES) {
            let mut debit = ledger.lifetime_spent(class);
            if class == Class::Recovery {
                debit -= self.opening_recovery;
            }
            cell.store(debit, Ordering::Relaxed);
        }
        header[0].store(MAGIC, Ordering::Relaxed);
        header[1].store(VERSION, Ordering::Relaxed);
        header[2].store(self.next as u64, Ordering::Release);
        self.sealed = true;
    }
}
