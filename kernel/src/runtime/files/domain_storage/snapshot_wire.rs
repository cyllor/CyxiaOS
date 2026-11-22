use cyxia_prototype::domains::{Error, filesystem::FileSystem};
#[path = "../../../../../user/prototype-task/snapshot_abi.rs"]
#[allow(dead_code)]
mod wire;

pub(super) fn encode<const CACHE: usize>(
    files: &FileSystem<CACHE>,
    selected: Option<cyxia_prototype::snapshot::SnapshotKey>,
    out: &mut [u8],
) -> Result<usize, Error> {
    use cyxia_prototype::snapshot::State;
    let control = files.snapshot_control()?;
    let entries = files.snapshot_entries()?;
    if let Some(key) = selected {
        if key.fs_uuid != control.fs_uuid
            || entries.get(key.slot as usize).is_none_or(|entry| {
                entry.state == State::Free || entry.key(control.fs_uuid, key.slot as usize) != key
            })
        {
            return Err(Error::Stale);
        }
    }
    let count = entries
        .iter()
        .enumerate()
        .filter(|(slot, entry)| {
            entry.state != State::Free && selected.is_none_or(|key| key.slot as usize == *slot)
        })
        .count();
    let length = wire::STATUS_BYTES + count * wire::SUMMARY_BYTES;
    if out.len() < length {
        return Err(Error::Range);
    }
    out[..length].fill(0);
    wire::put_u32(out, 0, count as u32);
    wire::put_u32(out, 4, u32::from(control.cleanup_freeze));
    wire::put_u64(out, 8, control.online_age_ns);
    wire::put_u64(out, 16, control.live_view_epoch);
    wire::put_u64(out, 24, control.protection_generation);
    wire::put_u32(out, 32, control.business_write_gate as u32);
    wire::put_u32(out, 36, control.restore_phase as u32);
    let mut at = wire::STATUS_BYTES;
    for (slot, entry) in entries.into_iter().enumerate() {
        if entry.state == State::Free || selected.is_some_and(|key| key.slot as usize != slot) {
            continue;
        }
        let summary = &mut out[at..at + wire::SUMMARY_BYTES];
        entry
            .key(control.fs_uuid, slot)
            .encode(&mut summary[..40])
            .map_err(|_| Error::Format)?;
        wire::put_u32(summary, 40, entry.slot_class as u32);
        wire::put_u32(summary, 44, entry.state as u32);
        for (offset, value) in [
            (48, entry.captured_live_view_epoch),
            (56, entry.capture_commit_lsn),
            (64, entry.created_online_age_ns),
            (72, entry.retain_until_ns),
            (80, entry.retention_generation),
            (88, entry.root_drop_commit_lsn),
        ] {
            wire::put_u64(summary, offset, value);
        }
        // A ready FileSystem has validated every active root at mount/publication.
        wire::put_u32(summary, 96, 1);
        wire::put_u32(summary, 100, files.snapshot_root_refs(slot)?);
        at += wire::SUMMARY_BYTES;
    }
    Ok(length)
}
