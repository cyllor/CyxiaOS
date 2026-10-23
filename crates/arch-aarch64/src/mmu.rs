use cyxia_contracts::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAttr {
    Normal,
    Device,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingError {
    Address,
    Permissions,
}
pub fn encode_leaf(
    pa: PhysAddr,
    permissions: PagePermissions,
    attr: MemoryAttr,
) -> Result<u64, MappingError> {
    if !pa.0.is_multiple_of(4096) || pa.0 >= 1 << 48 {
        return Err(MappingError::Address);
    }
    if attr == MemoryAttr::Device && permissions.executable() {
        return Err(MappingError::Permissions);
    }
    let mut d = pa.0 | 3 | (1 << 10) | (1 << 54);
    if !permissions.writable() {
        d |= 1 << 7;
    }
    if !permissions.executable() {
        d |= 1 << 53;
    }
    if attr == MemoryAttr::Normal {
        d |= 3 << 8;
    } else {
        d |= 1 << 2;
    }
    Ok(d)
}

/// EL0 normal-memory leaf: kernel execute-never, W^X and no global TLB entry.
pub fn encode_user_leaf(
    pa: PhysAddr,
    writable: bool,
    executable: bool,
) -> Result<u64, MappingError> {
    if !pa.0.is_multiple_of(4096) || pa.0 >= 1 << 48 {
        return Err(MappingError::Address);
    }
    if writable && executable {
        return Err(MappingError::Permissions);
    }
    let mut d = pa.0 | 3 | (1 << 6) | (1 << 10) | (1 << 11) | (3 << 8) | (1 << 53);
    if !writable {
        d |= 1 << 7;
    }
    if !executable {
        d |= 1 << 54;
    }
    Ok(d)
}
