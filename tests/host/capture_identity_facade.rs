// Test-only measurement boundary for existing owner/lifecycle fixtures. These
// fixtures control physical capture; native_capture_provenance tests the real
// collector, identity publication, counters and original interval storage.
pub struct TaskIdentity {
    pub site: u64,
    pub caller: cyxia_prototype::domains::ObjectKey,
    pub request: u64,
    pub child: cyxia_prototype::domains::ObjectKey,
    pub recipe: u16,
}
pub fn measure_task<R>(
    _: cyxia_prototype::domains::ObjectKey,
    _: cyxia_prototype::learning::reward::CpuClass,
    _: TaskIdentity,
    body: impl FnOnce() -> R,
) -> R {
    body()
}
pub struct PaidEntry;
impl PaidEntry {
    pub fn observe(self, identity: impl FnOnce()->TaskIdentity) { let _=identity(); }
    pub fn observe_workload_poll(self) {}
}
pub fn measure_paid_task<R>(
    _:cyxia_prototype::domains::ObjectKey,
    _:cyxia_prototype::learning::reward::CpuClass,
    body:impl FnOnce(Option<PaidEntry>)->R,
)->R {body(Some(PaidEntry))}
