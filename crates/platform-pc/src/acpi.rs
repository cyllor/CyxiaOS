//! Bounded firmware discovery. No pointer dereferences or allocation here.
pub const MAX_CPUS: usize = 4;
pub const MAX_TABLE_BYTES: usize = 65536;
pub const MAX_ROOT_ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Signature,
    Checksum,
    Length,
    Address,
    Capacity,
    Duplicate,
    MissingBsp,
    Unsupported,
}

#[derive(Clone, Copy, Debug)]
pub struct RootPointer {
    pub address: u64,
    pub xsdt: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct CpuTopology {
    pub lapic_base: u64,
    pub apic_ids: [u8; MAX_CPUS],
    pub count: usize,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn checksum(b: &[u8]) -> bool {
    b.iter().fold(0u8, |a, &b| a.wrapping_add(b)) == 0
}

pub fn parse_rsdp(b: &[u8]) -> Result<RootPointer, Error> {
    if b.len() < 20 {
        return Err(Error::Length);
    }
    if &b[..8] != b"RSD PTR " {
        return Err(Error::Signature);
    }
    if !checksum(&b[..20]) {
        return Err(Error::Checksum);
    }
    let pointer = if b[15] >= 2 {
        if b.len() < 36 {
            return Err(Error::Length);
        }
        let length = u32_at(b, 20) as usize;
        if !(36..=4096).contains(&length) || length != b.len() {
            return Err(Error::Length);
        }
        if !checksum(b) {
            return Err(Error::Checksum);
        }
        let address = u64_at(b, 24);
        if address != 0 {
            RootPointer {
                address,
                xsdt: true,
            }
        } else {
            RootPointer {
                address: u32_at(b, 16) as u64,
                xsdt: false,
            }
        }
    } else {
        if b.len() != 20 {
            return Err(Error::Length);
        }
        RootPointer {
            address: u32_at(b, 16) as u64,
            xsdt: false,
        }
    };
    if pointer.address < 4096 {
        return Err(Error::Address);
    }
    Ok(pointer)
}

fn header(b: &[u8]) -> Result<(), Error> {
    if !(36..=MAX_TABLE_BYTES).contains(&b.len()) || u32_at(b, 4) as usize != b.len() {
        return Err(Error::Length);
    }
    if !checksum(b) {
        return Err(Error::Checksum);
    }
    Ok(())
}
pub struct RootEntries<'a> {
    bytes: &'a [u8],
    stride: usize,
}
impl RootEntries<'_> {
    pub fn len(&self) -> usize {
        self.bytes.len() / self.stride
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<u64> {
        if index >= self.len() {
            return None;
        }
        let at = index * self.stride;
        Some(if self.stride == 8 {
            u64_at(self.bytes, at)
        } else {
            u32_at(self.bytes, at) as u64
        })
    }
}
pub fn parse_root(b: &[u8]) -> Result<RootEntries<'_>, Error> {
    header(b)?;
    let stride = match &b[..4] {
        b"RSDT" => 4,
        b"XSDT" => 8,
        _ => return Err(Error::Signature),
    };
    let bytes = &b[36..];
    if bytes.is_empty() || !bytes.len().is_multiple_of(stride) {
        return Err(Error::Length);
    }
    if bytes.len() / stride > MAX_ROOT_ENTRIES {
        return Err(Error::Capacity);
    }
    let entries = RootEntries { bytes, stride };
    for i in 0..entries.len() {
        if entries.get(i).unwrap() < 4096 {
            return Err(Error::Address);
        }
    }
    Ok(entries)
}

pub fn parse_madt(b: &[u8], bsp_apic_id: u8) -> Result<CpuTopology, Error> {
    header(b)?;
    if &b[..4] != b"APIC" {
        return Err(Error::Signature);
    }
    if b.len() < 44 {
        return Err(Error::Length);
    }
    let mut out = CpuTopology {
        lapic_base: u32_at(b, 36) as u64,
        apic_ids: [0; MAX_CPUS],
        count: 0,
    };
    let mut at = 44;
    let mut overridden = false;
    while at < b.len() {
        if b.len() - at < 2 {
            return Err(Error::Length);
        }
        let length = b[at + 1] as usize;
        if length < 2 || length > b.len() - at {
            return Err(Error::Length);
        }
        let r = &b[at..at + length];
        match r[0] {
            0 => {
                if length != 8 {
                    return Err(Error::Length);
                }
                if u32_at(r, 4) & 1 != 0 {
                    let id = r[3];
                    if out.apic_ids[..out.count].contains(&id) {
                        return Err(Error::Duplicate);
                    }
                    if id == 255 {
                        return Err(Error::Unsupported);
                    }
                    if out.count == MAX_CPUS {
                        return Err(Error::Capacity);
                    }
                    out.apic_ids[out.count] = id;
                    out.count += 1;
                }
            }
            5 => {
                if length != 12 {
                    return Err(Error::Length);
                }
                if overridden {
                    return Err(Error::Duplicate);
                }
                overridden = true;
                out.lapic_base = u64_at(r, 4);
            }
            9 => {
                if length != 16 {
                    return Err(Error::Length);
                }
                if u32_at(r, 8) & 1 != 0 {
                    return Err(Error::Unsupported);
                }
            }
            _ => {}
        }
        at += length;
    }
    if out.lapic_base < 4096 || out.lapic_base >= 1 << 32 || !out.lapic_base.is_multiple_of(4096) {
        return Err(Error::Address);
    }
    let bsp = out.apic_ids[..out.count]
        .iter()
        .position(|&id| id == bsp_apic_id)
        .ok_or(Error::MissingBsp)?;
    // Preserve firmware order for APs; logical slot zero is always the real BSP.
    let id = out.apic_ids[bsp];
    for i in (1..=bsp).rev() {
        out.apic_ids[i] = out.apic_ids[i - 1];
    }
    out.apic_ids[0] = id;
    Ok(out)
}
