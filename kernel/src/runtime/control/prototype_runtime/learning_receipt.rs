//! An identity comparison cannot create a receipt. The native mailbox calls
//! this only for its exact stopped-context proof after both ledgers settled.
use cyxia_prototype::learning::governance::{Role, WorkIdentity, WorkReceipt};

pub(super) fn matches(
    expected: Option<WorkIdentity>,
    actual: &WorkReceipt,
    role: Role,
    core_generation: u64,
) -> bool {
    let actual = actual.identity();
    expected == Some(actual)
        && actual.ledger_id != 0
        && actual.serial != 0
        && actual.actual_ns != 0
        && actual.role == role
        && actual.cpu == 1
        && actual.core_generation == core_generation
}
