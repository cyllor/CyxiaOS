// Actual FileSystem/Journal operations for host builds of the native broker.
// Only CPU ownership, user memory, clock, and the block device are host seams.
#[path = "../../kernel/src/runtime/files/domain_storage/snapshot_wire.rs"]
mod snapshot_wire;
pub fn snapshot_uuid() -> Result<[u8; 16], Error> {
    with_fs(|f, _, _, _| f.snapshot_control().map(|c| c.fs_uuid))
}
pub fn snapshot_live_epoch() -> Result<u64, Error> {
    with_fs(|f, _, _, _| f.snapshot_control().map(|c| c.live_view_epoch))
}
pub fn snapshot_execute(
    r: cyxia_prototype::snapshot::Request, operation: u16, payload: &[u8], _: &mut dyn FnMut(),
) -> Result<cyxia_prototype::snapshot::RequestRecord, Error> {
    with_fs(|f, j, d, s| f.snapshot_execute(r, operation, payload, j, d, s))
}
pub fn snapshot_open(
    key: cyxia_prototype::snapshot::SnapshotKey, path: &str, prefix: &str, _: &mut dyn FnMut(),
) -> Result<Handle, Error> {
    with_fs(|f, j, d, s| f.snapshot_open(key, path, prefix, j, d, s))
}
pub fn snapshot_handle_object(h: Handle) -> Result<ObjectKey, Error> {
    with_fs(|f, _, _, _| f.snapshot_handle_object(h))
}
pub fn snapshot_open_recovery(
    key: cyxia_prototype::snapshot::SnapshotKey, path: &str, prefix: &str, _: &mut dyn FnMut(),
) -> Result<Handle, Error> {
    with_fs(|f, j, d, s| f.snapshot_open_recovery(key, path, prefix, j, d, s))
}
pub fn snapshot_query_request(
    key: cyxia_prototype::snapshot::FileReqKey, _: &mut dyn FnMut(),
) -> Result<cyxia_prototype::snapshot::RequestRecord, Error> {
    with_fs(|f, j, d, s| f.snapshot_query_request(key, j, d, s))
}
pub fn snapshot_ack(
    key: cyxia_prototype::snapshot::FileReqKey, digest: [u8; 32], _: &mut dyn FnMut(),
) -> Result<(), Error> {
    with_fs(|f, j, d, s| f.snapshot_ack(key, digest, j, d, s))
}
pub fn snapshot_status(out: &mut [u8]) -> Result<usize, Error> {
    with_fs(|f, _, _, _| snapshot_wire::encode(f, None, out))
}
pub fn snapshot_query(key: cyxia_prototype::snapshot::SnapshotKey, out: &mut [u8]) -> Result<usize, Error> {
    with_fs(|f, _, _, _| snapshot_wire::encode(f, Some(key), out))
}
