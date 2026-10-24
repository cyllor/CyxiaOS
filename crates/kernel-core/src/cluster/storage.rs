//! Required crash-consistent compare-and-swap store. A successful write means
//! recoverable durable bytes, NOT a network ACK, queued I/O or volatile cache.
//! On ANY ambiguous write failure the in-memory owner becomes poisoned. Reload
//! durable state; do not retry against the old revision. Protect against rollback.
use super::{
    Error, Result,
    codec::{Bytes, MAX, Reader},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub kind: u16,
    pub id: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stored {
    pub revision: u64,
    pub len: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Io,
    Conflict,
    Corrupt,
}
pub trait Store {
    fn load(
        &mut self,
        key: Key,
        out: &mut [u8],
    ) -> core::result::Result<Option<Stored>, StoreError>;
    /// Atomic durable replacement; compare expected revision, including 0 for
    /// an absent object. Never create an acknowledged gap or truncated snapshot.
    fn replace(
        &mut self,
        key: Key,
        expected: u64,
        next: u64,
        bytes: &[u8],
    ) -> core::result::Result<(), StoreError>;
}
pub(crate) fn load(store: &mut impl Store, key: Key) -> Result<Option<(u64, Bytes)>> {
    let mut b = Bytes::new();
    let Some(stored) = store.load(key, &mut b.data).map_err(|_| Error::Storage)? else {
        return Ok(None);
    };
    if stored.revision == 0 || stored.len == 0 || stored.len > MAX {
        return Err(Error::Corrupt);
    }
    b.len = stored.len;
    Ok(Some((stored.revision, b)))
}
pub(crate) fn save(
    store: &mut impl Store,
    key: Key,
    revision: &mut u64,
    poisoned: &mut bool,
    bytes: &Bytes,
) -> Result<()> {
    if *poisoned {
        return Err(Error::Reconcile);
    }
    let next = revision.checked_add(1).ok_or(Error::Exhausted)?;
    if store
        .replace(key, *revision, next, bytes.as_slice())
        .is_err()
    {
        *poisoned = true;
        return Err(Error::Storage);
    }
    *revision = next;
    Ok(())
}
pub(crate) fn header(b: &mut Bytes, kind: u16) -> Result<()> {
    b.put(b"CYXCLST1")?;
    b.u16(1)?;
    b.u16(kind)
}
pub(crate) fn read_header(r: &mut Reader<'_>, kind: u16) -> Result<()> {
    if r.get::<8>()? != *b"CYXCLST1" || r.u16()? != 1 || r.u16()? != kind {
        return Err(Error::Corrupt);
    }
    Ok(())
}
