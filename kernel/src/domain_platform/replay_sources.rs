//! Exact platform identities for work outside a frozen trial's source roster.
use super::{IRQ_SLOTS, ObjectKey, Ordering, READY, TIMER_SERVICE, registered_irq};
use cyxia_prototype::learning::reward::CpuClass;

pub fn outside_source(key: ObjectKey, class: CpuClass) -> bool {
    if !READY.load(Ordering::Acquire) {
        return false;
    }
    if class == CpuClass::ExecutorWork && key == TIMER_SERVICE {
        return true;
    }
    // The collector resolves its frozen roster before this callback. An IRQ
    // registered there is always measured, including D04/D06 device work.
    // Other registered hardware IRQs still execute during unrelated trials;
    // both their hard-IRQ work and their owner actions have known provenance.
    matches!(class, CpuClass::ExecutorWork | CpuClass::ExecutorAction)
        && (0..IRQ_SLOTS)
            .filter_map(registered_irq)
            .any(|(actual, _, _)| actual == key)
}
