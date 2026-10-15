use cyxia_contracts::*;
use cyxia_kernel_core::frames::*;
fn owner()->TaskId{TaskId::new(1).unwrap()}
fn info()->BootInfo{let mut i=BootInfo::EMPTY;i.ram[0]=MemoryRegion{start:PhysAddr(0x1000),len:3*4096,kind:RegionKind::Ram};i.ram_count=1;i}
struct Zero{bytes:[u8;12288]}
impl PageZeroer for Zero{fn zero(&mut self,page:PhysAddr)->Result<(),FrameError>{let offset=(page.0-0x1000)as usize;self.bytes[offset..offset+4096].fill(0);Ok(())}}
#[test] fn dirty_pages_not_reissued_and_reserved_never_allocated(){
 let mut meta=[FrameMeta::EMPTY;3];let reserved=[MemoryRegion{start:PhysAddr(0x1000),len:8192,kind:RegionKind::Reserved}];let mut pool=FramePool::from_regions(&info(),&reserved,&mut meta).unwrap();let mut z=Zero{bytes:[0xa5;12288]};
 assert_eq!(pool.alloc_clean(owner()),Err(FrameError::Again));pool.clean_one(&mut z).unwrap();let h=pool.alloc_clean(owner()).unwrap();assert_eq!(h.address().0,0x3000);assert!(z.bytes[8192..].iter().all(|x|*x==0));
 z.bytes[8192..].fill(0x7f);pool.begin_revoke(h,owner()).unwrap();assert!(pool.alloc_clean(owner()).is_err());pool.finish_revoke(h,unsafe{RevokeComplete::after_unmap(h)}).unwrap();assert_eq!(pool.alloc_clean(owner()),Err(FrameError::Again));pool.clean_one(&mut z).unwrap();let next=pool.alloc_clean(owner()).unwrap();assert_ne!(next,h);assert!(z.bytes[8192..].iter().all(|x|*x==0));assert!(pool.begin_revoke(h,owner()).is_err());
}
#[test] fn wrong_owner_and_duplicate_revoke_leave_state_unchanged(){let mut m=[FrameMeta::EMPTY;3];let mut p=FramePool::from_regions(&info(),&[],&mut m).unwrap();let mut z=Zero{bytes:[1;12288]};p.clean_one(&mut z).unwrap();let h=p.alloc_clean(owner()).unwrap();assert!(p.begin_revoke(h,TaskId::new(2).unwrap()).is_err());p.begin_revoke(h,owner()).unwrap();assert!(p.begin_revoke(h,owner()).is_err());}
#[test] fn failed_zero_does_not_publish_page(){struct Bad;impl PageZeroer for Bad{fn zero(&mut self,_:PhysAddr)->Result<(),FrameError>{Err(FrameError::ZeroFailed)}}let mut m=[FrameMeta::EMPTY;3];let mut p=FramePool::from_regions(&info(),&[],&mut m).unwrap();assert!(p.clean_one(&mut Bad).is_err());assert_eq!(p.alloc_clean(owner()),Err(FrameError::Again));}
