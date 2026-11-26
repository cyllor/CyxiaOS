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

/// Validate one already-pinned EL0 page fragment against the trusted owned
/// physical frame and this profile's exact leaf encoding. This does not
/// acquire a pin, walk ancestor tables, or prove lifetime on its own.
/// Reject unsupported attributes rather than interpreting arbitrary PTEs.
pub fn checked_user_leaf_span(
    pte: u64,
    owned: PhysAddr,
    offset: u64,
    bytes: usize,
    write: bool,
) -> Result<PhysAddr, MappingError> {
    let n = u64::try_from(bytes).map_err(|_| MappingError::Address)?;
    if n == 0 || offset >= 4096 || offset.checked_add(n).is_none_or(|end| end > 4096) {
        return Err(MappingError::Address);
    }
    let rw = encode_user_leaf(owned, true, false)?;
    if pte != rw
        && (write
            || (pte != encode_user_leaf(owned, false, false)?
                && pte != encode_user_leaf(owned, false, true)?))
    {
        return Err(MappingError::Permissions);
    }
    Ok(PhysAddr(
        owned.0.checked_add(offset).ok_or(MappingError::Address)?,
    ))
}

#[cfg(test)]
mod copy_tests {
    use super::*;
    #[test]
    fn copy_leaf_checks_exact_ownership_permission_and_fragment() {
        let pa = PhysAddr(0x4000);
        let rw = encode_user_leaf(pa, true, false).unwrap();
        let rx = encode_user_leaf(pa, false, true).unwrap();
        let ro = encode_user_leaf(pa, false, false).unwrap();
        assert_eq!(
            checked_user_leaf_span(rw, pa, 4095, 1, true),
            Ok(PhysAddr(0x4fff))
        );
        assert_eq!(checked_user_leaf_span(rx, pa, 0, 8, false), Ok(pa));
        assert_eq!(checked_user_leaf_span(ro, pa, 0, 8, false), Ok(pa));
        for invalid in [
            0,
            rw ^ (1 << 10),
            rw ^ (1 << 6),
            rw ^ (1 << 54),
            rw | (1 << 2),
            rw ^ (1 << 11),
            rw ^ 0x1000,
        ] {
            assert!(checked_user_leaf_span(invalid, pa, 0, 8, false).is_err());
        }
        assert!(checked_user_leaf_span(rx, pa, 0, 8, true).is_err());
        assert!(checked_user_leaf_span(ro, pa, 0, 8, true).is_err());
        assert!(checked_user_leaf_span(rw, pa, 4092, 8, false).is_err());
        assert!(checked_user_leaf_span(rw, pa, u64::MAX, 8, false).is_err());
        assert!(checked_user_leaf_span(rw, pa, 0, 0, false).is_err());
    }
}
