use cyxia_arch_aarch64::cpu;
use cyxia_prototype::domains::{ObjectKey, tasks::Dispatch};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Binding {
    pub sequence: u64,
    pub thread: ObjectKey,
    pub cpu: usize,
}
/// Non-copyable proof of a successful exact unstarted scheduler cancellation.
/// Only the task owner can construct it, after physical cancellation succeeds.
pub(crate) struct Cancellation {
    pub(super) binding: Binding,
}
impl Cancellation {
    pub(super) fn new(dispatch: Dispatch) -> Self {
        Self {
            binding: Binding {
                sequence: dispatch.sequence,
                thread: dispatch.thread,
                cpu: usize::from(dispatch.cpu),
            },
        }
    }
    pub(crate) fn matches(&self, owner: ObjectKey, core: u16) -> bool {
        self.binding.thread == owner
            && self.binding.cpu == usize::from(core)
            && cpu::slot() == self.binding.cpu
    }
}
