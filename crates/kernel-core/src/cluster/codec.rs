use super::{Error, Incarnation, NodeId, ObjectId, Quota, Result, Scope};
pub(crate) const MAX: usize = 8192;
#[derive(Clone)]
pub struct Bytes {
    pub(crate) data: [u8; MAX],
    pub(crate) len: usize,
}
impl Default for Bytes {
    fn default() -> Self {
        Self::new()
    }
}
impl Bytes {
    pub fn new() -> Self {
        Self {
            data: [0; MAX],
            len: 0,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
    pub(crate) fn put(&mut self, v: &[u8]) -> Result<()> {
        let end = self.len.checked_add(v.len()).ok_or(Error::Capacity)?;
        self.data
            .get_mut(self.len..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(v);
        self.len = end;
        Ok(())
    }
    pub(crate) fn u8(&mut self, v: u8) -> Result<()> {
        self.put(&[v])
    }
    pub(crate) fn u16(&mut self, v: u16) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
    pub(crate) fn u32(&mut self, v: u32) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
    pub(crate) fn u64(&mut self, v: u64) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
    pub(crate) fn incarnation(&mut self, i: Incarnation) -> Result<()> {
        self.put(&i.node.0)?;
        self.u64(i.boot)
    }
    pub(crate) fn scope(&mut self, s: Scope) -> Result<()> {
        self.put(&s.cluster.0)?;
        self.u64(s.config_epoch)?;
        self.put(&s.config_digest)?;
        self.u64(s.activation_epoch)
    }
    pub(crate) fn quota(&mut self, q: Quota) -> Result<()> {
        self.u64(q.cpu_ticks)?;
        self.u64(q.memory_pages)?;
        self.u64(q.io_units)
    }
}
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }
    pub fn get<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.at.checked_add(N).ok_or(Error::Corrupt)?;
        let value = self.data.get(self.at..end).ok_or(Error::Corrupt)?;
        self.at = end;
        let mut out = [0; N];
        out.copy_from_slice(value);
        Ok(out)
    }
    pub fn slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(len).ok_or(Error::Corrupt)?;
        let value = self.data.get(self.at..end).ok_or(Error::Corrupt)?;
        self.at = end;
        Ok(value)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.get::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.get()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.get()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.get()?))
    }
    pub fn incarnation(&mut self) -> Result<Incarnation> {
        Ok(Incarnation {
            node: NodeId(self.get()?),
            boot: self.u64()?,
        })
    }
    pub fn scope(&mut self) -> Result<Scope> {
        Ok(Scope {
            cluster: ObjectId(self.get()?),
            config_epoch: self.u64()?,
            config_digest: self.get::<32>()?,
            activation_epoch: self.u64()?,
        })
    }
    pub fn quota(&mut self) -> Result<Quota> {
        Ok(Quota {
            cpu_ticks: self.u64()?,
            memory_pages: self.u64()?,
            io_units: self.u64()?,
        })
    }
    pub fn end(self) -> Result<()> {
        if self.at == self.data.len() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
}
