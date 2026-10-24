//! Bounded FDT v17 parser. Unknown nodes are skipped, required resources fail closed.
use cyxia_contracts::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdtError {
    Header,
    Bounds,
    Structure,
    String,
    Cells,
    Capacity,
    Overlap,
    Missing,
    Unsupported,
}
fn word(b: &[u8], at: usize) -> Result<u32, FdtError> {
    let x = b
        .get(at..at.checked_add(4).ok_or(FdtError::Bounds)?)
        .ok_or(FdtError::Bounds)?;
    Ok(u32::from_be_bytes(x.try_into().unwrap()))
}
fn wide(b: &[u8], at: usize) -> Result<u64, FdtError> {
    Ok(((word(b, at)? as u64) << 32) | word(b, at + 4)? as u64)
}
fn align(x: usize) -> Result<usize, FdtError> {
    x.checked_add(3).map(|x| x & !3).ok_or(FdtError::Bounds)
}
fn zstr(b: &[u8], at: usize) -> Result<(&[u8], usize), FdtError> {
    let tail = b.get(at..).ok_or(FdtError::String)?;
    let n = tail.iter().position(|x| *x == 0).ok_or(FdtError::String)?;
    Ok((&tail[..n], at + n + 1))
}
#[derive(Clone, Copy)]
struct Node<'a> {
    name: &'a [u8],
    compat: &'a [u8],
    reg: &'a [u8],
    irq: &'a [u8],
    device_type: &'a [u8],
    enable_method: &'a [u8],
    method: &'a [u8],
    cpu_child: bool,
    seen: u16,
    ac: u32,
    sc: u32,
    pac: u32,
    psc: u32,
    reserved: bool,
    child_seen: bool,
    enabled: bool,
    direct: bool,
}
impl Node<'_> {
    const EMPTY: Self = Self {
        name: &[],
        compat: &[],
        reg: &[],
        irq: &[],
        device_type: &[],
        enable_method: &[],
        method: &[],
        cpu_child: false,
        seen: 0,
        ac: 2,
        sc: 1,
        pac: 2,
        psc: 1,
        reserved: false,
        child_seen: false,
        enabled: true,
        direct: false,
    };
}
fn has(list: &[u8], s: &[u8]) -> bool {
    list.split(|x| *x == 0).any(|x| x == s)
}
fn number(b: &[u8], cells: u32) -> Result<u64, FdtError> {
    match cells {
        1 => Ok(word(b, 0)? as u64),
        2 => wide(b, 0),
        _ => Err(FdtError::Cells),
    }
}
fn regions(
    node: Node<'_>,
    mut put: impl FnMut(u64, u64) -> Result<(), FdtError>,
) -> Result<(), FdtError> {
    if !(1..=2).contains(&node.pac) || !(1..=2).contains(&node.psc) {
        return Err(FdtError::Cells);
    }
    let stride = ((node.pac + node.psc) * 4) as usize;
    if node.reg.is_empty() || !node.reg.len().is_multiple_of(stride) {
        return Err(FdtError::Cells);
    }
    for chunk in node.reg.chunks(stride) {
        let a = number(chunk, node.pac)?;
        let n = number(&chunk[node.pac as usize * 4..], node.psc)?;
        if n == 0 || a.checked_add(n).is_none() {
            return Err(FdtError::Bounds);
        };
        put(a, n)?;
    }
    Ok(())
}
fn push(
    list: &mut [MemoryRegion],
    count: &mut usize,
    a: u64,
    n: u64,
    kind: RegionKind,
) -> Result<(), FdtError> {
    if n == 0 || a.checked_add(n).is_none() {
        return Err(FdtError::Bounds);
    }
    let r = MemoryRegion {
        start: PhysAddr(a),
        len: n,
        kind,
    };
    if list[..*count].iter().any(|x| x.overlaps(r)) {
        return Err(FdtError::Overlap);
    }
    if *count == list.len() {
        return Err(FdtError::Capacity);
    };
    list[*count] = r;
    *count += 1;
    Ok(())
}
fn finish(n: Node<'_>, info: &mut BootInfo) -> Result<(), FdtError> {
    if !n.enabled {
        return Ok(());
    }
    if n.device_type == b"cpu\0" || (n.cpu_child && n.name.starts_with(b"cpu@")) {
        if !n.cpu_child
            || n.device_type != b"cpu\0"
            || n.psc != 0
            || !(1..=2).contains(&n.pac)
            || n.reg.len() != n.pac as usize * 4
        {
            return Err(FdtError::Unsupported);
        }
        let affinity = number(n.reg, n.pac)?;
        if affinity & !0x0000_00ff_00ff_ffff != 0 {
            return Err(FdtError::Unsupported);
        }
        if info.cpus[..info.cpu_count]
            .iter()
            .any(|c| c.affinity == affinity)
        {
            return Err(FdtError::Overlap);
        }
        if info.cpu_count == info.cpus.len() {
            return Err(FdtError::Capacity);
        }
        if !n.enable_method.is_empty() && n.enable_method != b"psci\0" {
            return Err(FdtError::Unsupported);
        }
        info.cpus[info.cpu_count] = CpuResource {
            affinity,
            psci: n.enable_method == b"psci\0",
        };
        info.cpu_count += 1;
    } else if has(n.compat, b"arm,psci-0.2") || has(n.compat, b"arm,psci-1.0") {
        if !n.direct || info.psci.is_some() {
            return Err(FdtError::Unsupported);
        }
        info.psci = Some(match n.method {
            b"hvc\0" => PsciConduit::Hvc,
            b"smc\0" => PsciConduit::Smc,
            _ => return Err(FdtError::Unsupported),
        });
    } else if n.name.starts_with(b"memory@") {
        regions(n, |a, l| {
            push(&mut info.ram, &mut info.ram_count, a, l, RegionKind::Ram)
        })?;
    } else if n.reserved && !n.reg.is_empty() {
        regions(n, |a, l| {
            push(
                &mut info.reserved,
                &mut info.reserved_count,
                a,
                l,
                RegionKind::Reserved,
            )
        })?;
    } else if has(n.compat, b"arm,pl011") {
        if info.uart.is_some() {
            return Err(FdtError::Overlap);
        }
        let mut count = 0;
        regions(n, |a, l| {
            count += 1;
            if count > 1 || l < 0x1000 {
                return Err(FdtError::Unsupported);
            }
            info.uart = Some(UartResource {
                base: PhysAddr(a),
                len: l,
            });
            Ok(())
        })?;
    } else if has(n.compat, b"arm,pl031") {
        if info.rtc.is_some() || !n.direct {
            return Err(FdtError::Unsupported);
        }
        regions(n, |a, len| {
            if info.rtc.is_some() || len < 4096 || !a.is_multiple_of(4096) {
                return Err(FdtError::Unsupported);
            }
            info.rtc = Some(RtcResource {
                base: PhysAddr(a),
                len,
            });
            Ok(())
        })?;
    } else if has(n.compat, b"arm,cortex-a15-gic") {
        if info.gic.is_some() {
            return Err(FdtError::Overlap);
        }
        let mut regs = [(0, 0); 2];
        let mut i = 0;
        regions(n, |a, l| {
            if i >= 2 || l < 0x1000 {
                return Err(FdtError::Unsupported);
            }
            regs[i] = (a, l);
            i += 1;
            Ok(())
        })?;
        if i != 2 {
            return Err(FdtError::Missing);
        }
        info.gic = Some(GicResource {
            distributor: PhysAddr(regs[0].0),
            distributor_len: regs[0].1,
            cpu: PhysAddr(regs[1].0),
            cpu_len: regs[1].1,
        });
    } else if has(n.compat, b"virtio,mmio") {
        // This board profile supports root-level resources only: no silent bus translation.
        if !n.direct
            || n.irq.len() != 12
            || word(n.irq, 0)? != 0
            || word(n.irq, 4)? > 987
            || !matches!(word(n.irq, 8)?, 1 | 4)
        {
            return Err(FdtError::Unsupported);
        }
        let mut resource = None;
        regions(n, |a, len| {
            if resource.is_some() || len < 0x200 || !a.is_multiple_of(0x200) {
                return Err(FdtError::Unsupported);
            }
            resource = Some(VirtioMmioResource {
                base: PhysAddr(a),
                len,
                irq: word(n.irq, 4)? + 32,
            });
            Ok(())
        })?;
        if info.virtio_count == info.virtio.len() {
            return Err(FdtError::Capacity);
        }
        info.virtio[info.virtio_count] = resource.ok_or(FdtError::Missing)?;
        info.virtio_count += 1;
    } else if has(n.compat, b"arm,armv8-timer") {
        if info.timer_irq.is_some() || n.irq.len() < 24 || !n.irq.len().is_multiple_of(12) {
            return Err(FdtError::Unsupported);
        }
        // GIC binding order: secure physical, non-secure physical, virtual, hypervisor.
        if word(n.irq, 12)? != 1 || word(n.irq, 16)? > 15 || word(n.irq, 20)? & 15 != 4 {
            return Err(FdtError::Unsupported);
        }
        info.timer_irq = Some(word(n.irq, 16)? + 16);
    }
    Ok(())
}
pub fn parse_fdt(blob: &[u8]) -> Result<BootInfo, FdtError> {
    if blob.len() < 40
        || word(blob, 0)? != 0xd00dfeed
        || word(blob, 20)? != 17
        || word(blob, 24)? > 17
    {
        return Err(FdtError::Header);
    }
    let total = word(blob, 4)? as usize;
    if !(40..=0x200000).contains(&total) || total > blob.len() {
        return Err(FdtError::Bounds);
    }
    let b = &blob[..total];
    let so = word(b, 8)? as usize;
    let st = word(b, 12)? as usize;
    let ro = word(b, 16)? as usize;
    let sl = word(b, 36)? as usize;
    let tl = word(b, 32)? as usize;
    let se = so.checked_add(sl).ok_or(FdtError::Bounds)?;
    let te = st.checked_add(tl).ok_or(FdtError::Bounds)?;
    if so < 40
        || st < 40
        || ro < 40
        || !so.is_multiple_of(4)
        || !ro.is_multiple_of(8)
        || se > total
        || te > total
        || so < te && st < se
    {
        return Err(FdtError::Bounds);
    }
    let mut info = BootInfo {
        dtb_len: total,
        ..BootInfo::EMPTY
    };
    let mut ri = ro;
    loop {
        if ri >= so.min(st) {
            return Err(FdtError::Bounds);
        }
        let a = wide(b, ri)?;
        let n = wide(b, ri + 8)?;
        ri += 16;
        if ri > so.min(st) {
            return Err(FdtError::Bounds);
        }
        if a == 0 && n == 0 {
            break;
        }
        push(
            &mut info.reserved,
            &mut info.reserved_count,
            a,
            n,
            RegionKind::Reserved,
        )?;
    }
    let s = &b[so..se];
    let strings = &b[st..te];
    let mut stack = [Node::EMPTY; 32];
    let mut depth = 0usize;
    let mut p = 0;
    let mut root_seen = false;
    let mut ended = false;
    while p < s.len() {
        let token = word(s, p)?;
        p += 4;
        match token {
            1 => {
                if depth == 32 {
                    return Err(FdtError::Capacity);
                }
                let (name, next) = zstr(s, p)?;
                p = align(next)?;
                if depth == 0 {
                    if root_seen || !name.is_empty() {
                        return Err(FdtError::Structure);
                    }
                    root_seen = true;
                    stack[0] = Node::EMPTY;
                } else {
                    let parent = &mut stack[depth - 1];
                    parent.child_seen = true;
                    let node = Node {
                        pac: parent.ac,
                        psc: parent.sc,
                        reserved: parent.reserved || parent.name == b"reserved-memory",
                        enabled: parent.enabled,
                        direct: depth == 1,
                        cpu_child: parent.direct && parent.name == b"cpus",
                        ..Node::EMPTY
                    };
                    stack[depth] = node;
                }
                stack[depth].name = name;
                depth += 1;
            }
            2 => {
                if depth == 0 {
                    return Err(FdtError::Structure);
                }
                depth -= 1;
                finish(stack[depth], &mut info)?;
            }
            3 => {
                if depth == 0 {
                    return Err(FdtError::Structure);
                }
                let len = word(s, p)? as usize;
                let nameoff = word(s, p + 4)? as usize;
                p += 8;
                let end = p.checked_add(len).ok_or(FdtError::Bounds)?;
                let v = s.get(p..end).ok_or(FdtError::Bounds)?;
                p = align(end)?;
                let (name, _) = zstr(strings, nameoff)?;
                let n = &mut stack[depth - 1];
                if n.child_seen {
                    return Err(FdtError::Structure);
                }
                let bit = match name {
                    b"reg" => 1,
                    b"compatible" => 2,
                    b"device_type" => 4,
                    b"enable-method" => 8,
                    b"method" => 16,
                    b"#address-cells" => 32,
                    b"#size-cells" => 64,
                    b"status" => 128,
                    _ => 0,
                };
                if bit != 0 && n.seen & bit != 0 {
                    return Err(FdtError::Structure);
                }
                n.seen |= bit;
                match name {
                    b"#address-cells" => {
                        if len != 4 {
                            return Err(FdtError::Cells);
                        }
                        n.ac = word(v, 0)?;
                    }
                    b"#size-cells" => {
                        if len != 4 {
                            return Err(FdtError::Cells);
                        }
                        n.sc = word(v, 0)?;
                    }
                    b"compatible" => {
                        if v.last() != Some(&0) {
                            return Err(FdtError::String);
                        }
                        n.compat = v;
                    }
                    b"device_type" | b"enable-method" | b"method" => {
                        if v.last() != Some(&0) || v[..v.len() - 1].contains(&0) {
                            return Err(FdtError::String);
                        }
                        match name {
                            b"device_type" => n.device_type = v,
                            b"enable-method" => n.enable_method = v,
                            _ => n.method = v,
                        }
                    }
                    b"reg" => n.reg = v,
                    b"interrupts" => n.irq = v,
                    b"status" => {
                        if v.last() != Some(&0) {
                            return Err(FdtError::String);
                        }
                        n.enabled &= v == b"okay\0" || v == b"ok\0";
                    }
                    _ => {}
                }
            }
            4 => {}
            9 => {
                if depth != 0 || !root_seen {
                    return Err(FdtError::Structure);
                }
                ended = true;
                break;
            }
            _ => return Err(FdtError::Structure),
        }
    }
    if !ended
        || info.ram_count == 0
        || info.uart.is_none()
        || info.gic.is_none()
        || info.timer_irq.is_none()
    {
        return Err(FdtError::Missing);
    }
    let mut pages = 0u64;
    for r in &info.ram[..info.ram_count] {
        if !r.start.0.is_multiple_of(4096) || !r.len.is_multiple_of(4096) {
            return Err(FdtError::Bounds);
        }
        pages = pages.checked_add(r.len / 4096).ok_or(FdtError::Capacity)?;
    }
    if pages > crate::RAM_MIB * 256 {
        return Err(FdtError::Capacity);
    }
    let u = info.uart.unwrap();
    let g = info.gic.unwrap();
    let dev = [
        (u.base.0, u.len),
        (g.distributor.0, g.distributor_len),
        (g.cpu.0, g.cpu_len),
        info.rtc.map(|r| (r.base.0, r.len)).unwrap_or((0, 0)),
    ];
    for (i, (a, l)) in dev.iter().enumerate() {
        if *l == 0 {
            continue;
        }
        let r = MemoryRegion {
            start: PhysAddr(*a),
            len: *l,
            kind: RegionKind::Device,
        };
        if !a.is_multiple_of(4096) || info.ram[..info.ram_count].iter().any(|x| x.overlaps(r)) {
            return Err(FdtError::Overlap);
        }
        for (b, n) in &dev[..i] {
            if r.overlaps(MemoryRegion {
                start: PhysAddr(*b),
                len: *n,
                kind: RegionKind::Device,
            }) {
                return Err(FdtError::Overlap);
            }
        }
    }
    for (index, v) in info.virtio[..info.virtio_count].iter().enumerate() {
        let r = MemoryRegion {
            start: v.base,
            len: v.len,
            kind: RegionKind::Device,
        };
        if info.ram[..info.ram_count]
            .iter()
            .chain(info.reserved[..info.reserved_count].iter())
            .any(|x| x.overlaps(r))
            || dev.iter().any(|(a, n)| {
                r.overlaps(MemoryRegion {
                    start: PhysAddr(*a),
                    len: *n,
                    kind: RegionKind::Device,
                })
            })
            || info.virtio[..index].iter().any(|x| {
                r.overlaps(MemoryRegion {
                    start: x.base,
                    len: x.len,
                    kind: RegionKind::Device,
                })
            })
        {
            return Err(FdtError::Overlap);
        }
    }
    Ok(info)
}
