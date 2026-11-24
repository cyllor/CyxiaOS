//! Actual 1GiB RAM/pool reservation used by the formatted-mount profile.
//! All three physical regions come from DTB-constrained board reservation;
//! the old pinned 64MiB boot/kernel/DMA arena stays excluded. This is
//! initial inventory and a real secret-page lifecycle diagnostic, not a
//! complete task allocator or complete CPU0 accounting claim.
use super::*;
use cyxia_contracts::{MemoryRegion,RegionKind};
use cyxia_kernel_core::frame_meta_v0199::{self as fm,FrameMeta,Ledger,Owner,Inventory};
use cyxia_kernel_core::security::Error as SecError;
pub(super) struct Pools{
    pub control_pa:u64,pub progress_pa:u64,pub metadata_pa:u64,
    pub inventory:Inventory,pub sample_pa:u64,pub sample_generation:u64,
}
impl Pools{
    pub fn control_va(&self)->u64{super::super::HIGH+self.control_pa}
    pub fn progress_va(&self)->u64{super::super::HIGH+self.progress_pa}
}
fn zero_page(pa:u64)->Result<(),SecError>{
    if pa%fm::PAGE!=0||!(cyxia_platform_virt::KERNEL_POOL_END..cyxia_platform_virt::USER_RAM_END).contains(&pa){
        return Err(SecError::Invalid);
    }
    // Only the serialized owner may call this after reserving a free
    // frame, or after quarantine with no EL0 or DMA reference.
    unsafe{
        let p=(super::super::HIGH+pa) as *mut u8;
        core::ptr::write_bytes(p,0,fm::PAGE as usize);
        core::arch::asm!("dsb ish",options(nostack));
        if !(0..fm::PAGE as usize).all(|i|p.add(i).read_volatile()==0){return Err(SecError::Unknown);}
    }
    Ok(())
}
pub(super) fn initialize(info:&BootInfo)->Pools{
    assert_eq!(cpu::slot(),0);assert_eq!(info.ram_count,1);
    let ram=info.ram[0];
    assert_eq!(ram.start.0,cyxia_platform_virt::RAM_BASE);
    assert_eq!(ram.len,fm::RAM_BYTES);
    let arena=MemoryRegion{start:ram.start,len:cyxia_platform_virt::KERNEL_POOL_END-ram.start.0,kind:RegionKind::Reserved};
    let mut reserved=*info;
    let metadata=cyxia_platform_virt::reserve_user_pool(&mut reserved,fm::TABLE_BYTES as u64).unwrap();
    let control=cyxia_platform_virt::reserve_user_pool(&mut reserved,fm::POOL_BYTES).unwrap();
    let progress=cyxia_platform_virt::reserve_user_pool(&mut reserved,fm::POOL_BYTES).unwrap();
    // The entire physical table has the exact canonical 40B row layout;
    // initialize from real allocated RAM, not a host or static byte count.
    let rows=unsafe{
        let p=(super::super::HIGH+metadata.start.0) as *mut FrameMeta;
        core::ptr::write_bytes(p,0,fm::COUNT);
        core::slice::from_raw_parts_mut(p,fm::COUNT)
    };
    let mut ledger=Ledger::initialize(rows,ram,[arena,metadata,control,progress],
        &info.reserved[..info.reserved_count]).unwrap();
    let before=ledger.inventory().unwrap();
    assert_eq!((before.metadata,before.control,before.progress),(2560,2048,2048));
    // The owner uses one real ordinary page; no EL0 or DMA mappings are
    // installed. Demonstrate secret scrub, stale generation rejection
    // and a second actual allocation of the same reclaimed frame.
    let h=ledger.reserve(Owner{slot:0,generation:1}).unwrap();
    let pa=ledger.address(h);
    ledger.commit(h,true,zero_page).unwrap();
    assert_eq!(ledger.inventory().unwrap().allocated,1);
    unsafe{
        let p=(super::super::HIGH+pa) as *mut u64;
        p.write_volatile(0x4359585345435245);
        assert_eq!(p.read_volatile(),0x4359585345435245);
    }
    ledger.quarantine(h).unwrap();
    assert_eq!(ledger.inventory().unwrap().quarantined,1);
    ledger.reclaim(h,zero_page).unwrap();
    let next=ledger.reserve(Owner{slot:0,generation:2}).unwrap();
    assert_eq!(ledger.address(next),pa);
    assert_eq!(ledger.commit(h,true,|_|panic!("stale frame")),Err(SecError::Stale));
    ledger.commit(next,true,zero_page).unwrap();
    ledger.quarantine(next).unwrap();ledger.reclaim(next,zero_page).unwrap();
    assert_eq!(ledger.inventory().unwrap(),before);
    // Both real reserved pools begin scrubbed. The native loader and
    // redo workspace take their backing from these exclusive regions.
    unsafe{
        for r in [control,progress]{
            core::ptr::write_bytes((super::super::HIGH+r.start.0) as *mut u8,0,r.len as usize);
        }
        core::arch::asm!("dsb ish",options(nostack));
    }
    report("V0199_FRAME_LEDGER",fm::COUNT as u64,u64::from(before.permanent),u64::from(before.free));
    Pools{control_pa:control.start.0,progress_pa:progress.start.0,metadata_pa:metadata.start.0,
        inventory:before,sample_pa:pa,sample_generation:next.generation()}
}
