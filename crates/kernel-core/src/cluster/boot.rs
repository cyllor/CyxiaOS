//! Allocate a durable monotonically increasing native BootEpoch before any
//! identity advertisement. Requires rollback-protected store; key loss or OS
//! reinstall is a new NodeId, never permission to reset a previous incarnation.
use super::{
    Error, Incarnation, NodeId, Result,
    codec::{Bytes, Reader},
    storage::{self, Key, Store},
};
const KIND: u16 = 7;
pub fn next(store: &mut impl Store, node: NodeId) -> Result<Incarnation> {
    if !node.valid() {
        return Err(Error::Invalid);
    }
    let key = Key {
        kind: KIND,
        id: node.0,
    };
    let mut revision = 0;
    let mut previous = 0;
    if let Some((rev, b)) = storage::load(store, key)? {
        let mut r = Reader::new(b.as_slice());
        storage::read_header(&mut r, KIND)?;
        if r.get::<32>()? != node.0 {
            return Err(Error::Corrupt);
        }
        previous = r.u64()?;
        r.end()?;
        if previous == 0 {
            return Err(Error::Corrupt);
        }
        revision = rev;
    }
    let boot = previous.checked_add(1).ok_or(Error::Exhausted)?;
    let mut b = Bytes::new();
    storage::header(&mut b, KIND)?;
    b.put(&node.0)?;
    b.u64(boot)?;
    let mut poisoned = false;
    storage::save(store, key, &mut revision, &mut poisoned, &b)?;
    Ok(Incarnation { node, boot })
}
