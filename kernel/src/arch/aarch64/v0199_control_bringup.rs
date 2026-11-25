//! Native CPU0 ABI3 package bring-up, NOT a full production control plane.
//! Eight separately linked PIE images are copied, verified and loaded onto
//! private TTBR roots and 32KiB guarded stacks. Only the initialized
//! bootstrap syscall subset can run; missing durable BootEpoch and real
//! service authority explicitly deny new side effects. The workflow uses
//! the repository's pinned per-vCPU PMU patch, not stock QEMU accounting.
use super::*;
use cyxia_kernel_core::control_plane::{
    Identity,Error,
    role_manifest_v0199::{NativeRoleManifest,ValidatedRoleManifest,NativeRole,Role,ROLES,ROLE_COUNT,PrivateRegion,
        SnapshotView,AuxOperation,CONTROL_MASK,REQUIRED_ONLINE_MASK},
    pie_image_v0199::{RolePackageSpec,RolePackageInput,VerifiedRolePackage,RelativeRelocation,ROLE_STACK_BYTES},
    role_budget_v0199::{Class,Cpu0BudgetLedger,Turn,Settlement,WINDOW_NS,KERNEL_COORDINATION_LIMIT_NS},
};
use cyxia_kernel_core::security::syscall::{Syscall,StableCopy};
use cyxia_kernel_core::security::syscall_v3::decode_aarch64_svc_v3;

const PAGE:usize=4096;
const IMAGE:usize=64*1024;
const COPY:usize=128*1024;
const BASE:u64=0x10000;
const STACK_BASE:u64=0x30000;
const STACK_END:u64=STACK_BASE+ROLE_STACK_BYTES as u64;
const ROLE_QUOTAS:[u64;8]=[30_000_000,8_000_000,4_000_000,3_500_000,
    4_000_000,3_000_000,4_500_000,3_000_000];
const OTHER_CPU_NS:u64=10_000_000; // 8ms recovery + 2ms kernel coordination
// Diagnostic timer margin, not a certified WCET. The prior 25us margin
// failed with 271476ns charged against a 250000ns controller reservation.
// Leave headroom for EL0 exit, SVC dispatch and accounting settlement;
// never extend the reservation or discard any observed execution time.
const TURN_EXIT_GUARD_NS:u64=100_000;
// PR88 capture-3, role2: 253984ns against a 250000ns reservation,
// before the initial eight-role milestone. A validated manifest borrow
// alone did not eliminate the overrun. Shorten only the diagnostic
// execution slice and retain all measured trap/dispatch overhead.
// PR90 capture-2: role2 443074ns / 250000ns. Keep the same
// reservation, reduce the diagnostic EL0 wall slice and reserve more
// exit/dispatch headroom. This is not a physical WCET claim.
const DECISION_SLICE_NS:u64=20_000;
const DECISION_EXIT_GUARD_NS:u64=150_000;
const E_AUTH:i64=-1;const E_FORMAT:i64=-2;const E_UNSUPPORTED:i64=-11;
const EFAULT:i64=-12;const EAGAIN:i64=-13;
const MAGIC:u64=0x4359_5838_424f_4f54;

struct BootPackage {role_id:u16,bytes:&'static[u8],image_sha256:[u8;32],relative_sha256:[u8;32],relative:&'static[RelativeRelocation]}
static CATALOG:[BootPackage;ROLE_COUNT]=include!(concat!(env!("OUT_DIR"),"/v0199-role-catalog.rs"));
#[repr(C,align(4096))]
struct Backing {image:[u8;IMAGE],stack:[u8;ROLE_STACK_BYTES]}
impl Backing{const ZERO:Self=Self{image:[0;IMAGE],stack:[0;ROLE_STACK_BYTES]};}
#[repr(C,align(4096))]
struct Tables {root:Page,mid:Page,leaf:Page}
impl Tables{const ZERO:Self=Self{root:Page::ZERO,mid:Page::ZERO,leaf:Page::ZERO};}
#[repr(align(4096))]
struct CopyBuffer([u8;COPY]);
#[cfg(not(feature="v0199-epoch-disk-selftest"))]
static mut BACKING:[Backing;ROLE_COUNT]=[const{Backing::ZERO};ROLE_COUNT];
// A replacement uses a different physical root; the retired bank stays unmapped.
#[cfg(not(feature="v0199-epoch-disk-selftest"))]
static mut TABLES:[Tables;2*ROLE_COUNT]=[const{Tables::ZERO};2*ROLE_COUNT];
#[cfg(not(feature="v0199-epoch-disk-selftest"))]
static mut COPY_BUFFER:CopyBuffer=CopyBuffer([0;COPY]);
#[cfg(feature="v0199-epoch-disk-selftest")]
static DISK_CONTROL_BASE:AtomicU64=AtomicU64::new(0);
const DISK_TABLE_OFFSET:usize=core::mem::size_of::<[Backing;ROLE_COUNT]>();
const DISK_COPY_OFFSET:usize=DISK_TABLE_OFFSET+core::mem::size_of::<[Tables;2*ROLE_COUNT]>();
const _:()=assert!(DISK_COPY_OFFSET+COPY<=8*1024*1024&&DISK_COPY_OFFSET%4096==0);
#[cfg(feature="v0199-epoch-disk-selftest")]
pub(super) fn install_disk_control_pool(va:u64){
    assert!(va>=super::super::HIGH&&va%4096==0);
    assert!(DISK_CONTROL_BASE.compare_exchange(0,va,Ordering::AcqRel,Ordering::Acquire).is_ok());
}
#[cfg(feature="v0199-epoch-disk-selftest")]
fn disk_pool()->u64{
    let va=DISK_CONTROL_BASE.load(Ordering::Acquire);assert_ne!(va,0);va
}
/// Exclusive diagnostic metadata tail, after all role backing, page
/// tables and copy scratch. No additional physical pool is allocated.
#[cfg(feature="v0199-epoch-disk-selftest")]
pub(super) fn disk_fixture_metadata(bytes:usize)->(u64,usize){
    assert_eq!(cpu::slot(),0);
    let offset=(DISK_COPY_OFFSET+COPY).next_multiple_of(PAGE);
    assert!(bytes!=0&&bytes%PAGE==0&&offset.checked_add(bytes).unwrap()<=8*1024*1024);
    (disk_pool().checked_add(offset as u64).unwrap(),offset)
}
const _:()=assert!(core::mem::size_of::<Backing>()==IMAGE+ROLE_STACK_BYTES);
const _:()=assert!(core::mem::size_of::<Tables>()==3*PAGE);

#[derive(Clone,Copy,PartialEq,Eq)]
enum CapKind{None,Snapshot(SnapshotView),Audit}
#[derive(Clone,Copy)]
struct Cap {selector:u64,holder:Identity,endpoint:u64,kind:CapKind}
struct Running {
    context:user::Context,
    cap:Cap,
    abi:u16,
    bank:usize,
    entry:u64,
    wake_ns:u64,
    clocks:u64,
    role_calls:u64,
    yields:u64,
    charges:u64,
    turns:u64,
    last_status:i64,
    preemptions:u64,
    fault_esr:u64,
    fault_far:u64,
}
// Read CNTFRQ once on the serialized CPU0 diagnostic owner. The
// architectural frequency is fixed for this boot; a second profile entry
// rechecks it rather than silently reusing a different scale.
static TIMER_FREQUENCY:AtomicU64=AtomicU64::new(0);
static TIMER_INTEGRAL_NS_PER_TICK:AtomicU64=AtomicU64::new(0);
fn init_timer_frequency(){
    let f=timer::frequency();assert!(f!=0);
    let old=TIMER_FREQUENCY.swap(f,Ordering::Relaxed);
    assert!(old==0||old==f);
    // The same serialized CPU0 owner initializes and uses this exact
    // cached integer scale. Non-integral frequencies retain wide conversion.
    let scale=if 1_000_000_000%f==0{1_000_000_000/f}else{0};
    TIMER_INTEGRAL_NS_PER_TICK.store(scale,Ordering::Relaxed);
}
#[inline]
fn timer_frequency()->u64{
    let f=TIMER_FREQUENCY.load(Ordering::Relaxed);assert!(f!=0);f
}
#[inline]
fn ns_from_ticks(t:u64)->u64{
    let scale=TIMER_INTEGRAL_NS_PER_TICK.load(Ordering::Relaxed);
    if scale!=0{return t.checked_mul(scale).expect("monotonic ns");}
    let f=timer_frequency();
    u64::try_from(u128::from(t)*1_000_000_000/u128::from(f)).expect("monotonic ns")
}
#[inline]
fn now_ns()->u64{ns_from_ticks(timer::ticks())}
#[inline]
fn ticks_for(ns:u64)->u64{
    let scale=TIMER_INTEGRAL_NS_PER_TICK.load(Ordering::Relaxed);
    if scale!=0{return ns.div_ceil(scale).max(1);}
    let f=timer_frequency();
    u64::try_from((u128::from(ns)*u128::from(f)).div_ceil(1_000_000_000))
        .expect("timer ticks").max(1)
}
/// Continuous attribution from BEFORE the first role package load through
/// the final UART output. Every interval is charged exactly once: admitted
/// role/recovery work or the protected EL1 coordination envelope.
/// Earlier architecture/SMP initialization and the tiny final evidence seal
/// remain outside this diagnostic interval; no full production claim.
struct BudgetMeter {
    ledger:Cpu0BudgetLedger,
    initial_tick:u64,
    initial_ns:u64,
    cursor:u64,
    wall:u64,
    crossed_gaps:u64,
}
impl BudgetMeter {
    fn new()->Self{
        let wall=now_ns();let tick=timer::cpu_ticks();
        let mut ledger=Cpu0BudgetLedger::new();
        ledger.start_continuous(cpu::slot(),wall,||Ok(())).expect("native accounting origin");
        Self{ledger,initial_tick:tick,initial_ns:wall,cursor:tick,wall,crossed_gaps:0}
    }
    fn sample_gap(&mut self)->(u64,u64){
        let wall=now_ns();let tick=timer::cpu_ticks();
        let actual=timer::cpu_ns(tick.checked_sub(self.cursor).expect("PMU counter regressed"));
        let receipt=self.ledger.account_coordination_gap(cpu::slot(),self.wall,wall,actual)
            .expect("continuous EL1 coordination interval");
        self.cursor=tick;self.wall=wall;
        if receipt.crossed_window{self.crossed_gaps+=1;}
        if receipt.overrun{
            report("V0199_BOOTSTRAP_OVERRUN",0,self.ledger.kernel_coordination_spent(),KERNEL_COORDINATION_LIMIT_NS);
            fatal(687);
        }
        (wall,tick)
    }
    fn settle(&mut self,token:Turn,began:u64)->Settlement{
        assert_eq!(began,self.cursor);
        let wall=now_ns();let tick=timer::cpu_ticks();
        let actual=timer::cpu_ns(tick.checked_sub(began).expect("PMU counter regressed"));
        let receipt=self.ledger.settle(cpu::slot(),token,actual,wall).expect("same CPU0 owner");
        self.cursor=tick;self.wall=wall;receipt
    }
    /// No work was admitted. Use a real masked physical timer wakeup rather
    /// than repeatedly burning CPU0's uncharged execution time in a busy loop.
    /// The diagnostic profile keeps EL1 IRQs masked outside EL0 entry.
    fn idle_until(&mut self,deadline_ns:u64){
        let (now,_)=self.sample_gap();
        let daif:u64;
        unsafe {
            core::arch::asm!("mrs {}, daif",out(reg)daif,options(nomem,nostack));
            assert_ne!(daif&(1<<7),0);
            timer::arm(timer::ticks().checked_add(ticks_for(deadline_ns.saturating_sub(now).max(1))).unwrap());
            timer::idle();
            cpu::disable_timer();
        }
        self.sample_gap();
    }
    // The previous 1ms polling loop exhausted the 2ms EL1 coordination
    // envelope in all three 1GiB runs (run 45428678180). On a complete
    // no-admission pass, wait for the next aligned replenishment instead.
    // This is bounded diagnostic scheduling, not a production latency SLA.
    fn idle_retry(&mut self){
        let now=now_ns();
        let next=(now/WINDOW_NS).checked_add(1).and_then(|w|w.checked_mul(WINDOW_NS)).unwrap();
        self.idle_until(next);
    }
    // Startup has no admitted roles. Initial loader work uses the same
    // fixed EL1 coordination sub-budget, not the protected recovery quota.
    // No estimate is substituted for the actual PMU debit.
    fn reserve_coordination(&mut self)->(Turn,u64){
        let until=now_ns().checked_add(5_000_000_000).unwrap();
        loop{
            let (now,began)=self.sample_gap();
            if now>=until{fatal(689);}
            let remaining=KERNEL_COORDINATION_LIMIT_NS.saturating_sub(self.ledger.kernel_coordination_spent());
            // Keep explicit headroom for settlement and idle-entry work.
            if remaining<1_500_000 || now%WINDOW_NS>WINDOW_NS-5_000_000{
                self.idle_retry();continue;
            }
            match self.ledger.reserve_kernel_with_wall(0,Class::Coordination,remaining-200_000,50_000_000,now){
                Ok(t)=>return (t,began),
                Err(Error::Exhausted|Error::Busy)=>{self.idle_retry();},
                Err(e)=>panic!("initial role load budget: {e:?}"),
            }
        }
    }
    fn settle_coordination(&mut self,token:Turn,began:u64)->u64{
        let receipt=self.settle(token,began);
        if receipt.overrun||receipt.crossed_window{
            report("V0199_BOOTSTRAP_OVERRUN",0,receipt.actual_ns,token.reserved_ns());
            fatal(690);
        }
        receipt.actual_ns
    }
    fn load_initial(&mut self,index:usize)->(NativeRole,Running){
        let (mut token,mut began)=self.reserve_coordination();
        let mut total=0u64;let mut largest=0u64;let mut slices=0u64;
        let pair=load_checkpointed(index,1,0,|_|{
            // The verified copy and unpublished backing stay exclusively
            // owned by the loader across these cooperative boundaries.
            if timer::cpu_elapsed_ns(began)>=450_000
                || token.deadline_ns().saturating_sub(now_ns())<2_000_000{
                let cost=self.settle_coordination(token,began);
                total=total.checked_add(cost).unwrap();largest=largest.max(cost);slices+=1;
                (token,began)=self.reserve_coordination();
            }
        });
        let cost=self.settle_coordination(token,began);
        total=total.checked_add(cost).unwrap();largest=largest.max(cost);slices+=1;
        SMP_EVIDENCE.words[32+index].store(total,Ordering::Relaxed);
        SMP_EVIDENCE.words[48+index].store(slices,Ordering::Relaxed);
        report("V0199_INITIAL_LOAD",u64::from(ROLES[index].id()),total,largest);
        pair
    }
    // Recovery of a stopped role is resumable between independently
    // verified copy/relocation/seal/scrub checkpoints. Reserve from the
    // same 8ms recovery class, never from another role or the business CPUs.
    fn reserve_recovery_slice(&mut self,until:u64)->(Turn,u64){
        loop{
            let (now,began)=self.sample_gap();if now>=until{fatal(682);}
            let remaining=8_000_000u64.saturating_sub(self.ledger.spent(Class::Recovery));
            if remaining<2_000_000||now%WINDOW_NS>WINDOW_NS-5_000_000{
                self.idle_retry();continue;
            }
            match self.ledger.reserve_kernel_with_wall(0,Class::Recovery,2_000_000,50_000_000,now){
                Ok(t)=>return(t,began),
                Err(Error::Exhausted|Error::Busy)=>self.idle_retry(),
                Err(e)=>panic!("recovery slice: {e:?}"),
            }
        }
    }
    fn settle_recovery_slice(&mut self,role:Role,t:Turn,began:u64,phase:u64,part:u64)->u64{
        let receipt=self.settle(t,began);
        if receipt.overrun||receipt.crossed_window{
            report("V0199_RECOVERY_OVERRUN_PHASE",phase,part,receipt.actual_ns);
            report("V0199_BOOTSTRAP_OVERRUN",role.id() as u64,receipt.actual_ns,t.reserved_ns());
            fatal(683);
        }
        receipt.actual_ns
    }
    /// Reserve before an individual bounded coordination operation. For
    /// final evidence, do not burn an entire window in a long UART burst.
    fn coordinated<T>(&mut self,work:impl FnOnce()->T)->T{
        let (token,began)=self.reserve_coordination();
        let result=work();
        self.settle_coordination(token,began);
        result
    }
    fn wait_for(&mut self,mut ready:impl FnMut()->bool){
        let until=now_ns().checked_add(5_000_000_000).unwrap();
        while !ready(){
            check_failures();
            if now_ns()>=until{fatal(688);}
            self.idle_retry();
        }
    }
}
fn cap_kind(role:Role)->CapKind{
    match role{
        Role::Operations=>CapKind::Snapshot(SnapshotView::Operations),
        Role::Security=>CapKind::Snapshot(SnapshotView::RedactedSecurity),
        Role::DeterministicController=>CapKind::Snapshot(SnapshotView::ControllerRawEvidence),
        Role::Supervisor=>CapKind::Audit,
        _=>CapKind::None,
    }
}
/// CPU0 exclusively owns these static frames. They are never assigned to B
/// or a DMA queue. No EL0 context can exist during initial stage/seal.
fn backing(index:usize)->*mut Backing{
    assert!(index<ROLE_COUNT);
    #[cfg(feature="v0199-epoch-disk-selftest")]
    {unsafe{(disk_pool() as *mut Backing).add(index)}}
    #[cfg(not(feature="v0199-epoch-disk-selftest"))]
    {unsafe{core::ptr::addr_of_mut!(BACKING).cast::<Backing>().add(index)}}
}
fn tables(index:usize,bank:usize)->*mut Tables{
    assert!(index<ROLE_COUNT&&bank<2);
    #[cfg(feature="v0199-epoch-disk-selftest")]
    {unsafe{((disk_pool()+DISK_TABLE_OFFSET as u64) as *mut Tables).add(bank*ROLE_COUNT+index)}}
    #[cfg(not(feature="v0199-epoch-disk-selftest"))]
    {unsafe{core::ptr::addr_of_mut!(TABLES).cast::<Tables>().add(bank*ROLE_COUNT+index)}}
}
fn root_pa(index:usize,bank:usize)->u64{
    phys(tables(index,bank) as u64)
}
// This exclusive bootstrap profile uses ASIDs 0x90..0x9f, separate from
// the mechanism probes (0x80..0x83) and their ordinary ASID 0.
// A stopped/reloaded role always moves to bank 1; no root/ASID is reused.
fn role_asid(index:usize,bank:usize)->u8{
    assert!(index<ROLE_COUNT&&bank<2);
    (0x90+bank*ROLE_COUNT+index) as u8
}
/// The high half direct-map descriptor for a reserved RAM page. The original
/// boot map uses normal EL1 RW-XN. Seal RO/RX image pages *before* publishing
/// the low user mapping; no writable alias of executable code remains.
fn high_leaf(pa:u64)->*mut u64{
    assert!(pa%PAGE as u64==0 && pa>=cyxia_platform_virt::RAM_BASE);
    let offset=(pa-cyxia_platform_virt::RAM_BASE)/PAGE as u64;
    assert!(offset<(cyxia_platform_virt::RAM_MIB*1024*1024/PAGE as u64));
    unsafe{((core::ptr::addr_of!(ram_l3) as u64+super::super::HIGH) as *mut u64).add(offset as usize)}
}
fn clean_code(addr:u64,bytes:usize){
    let ctr:u64;
    unsafe{core::arch::asm!("mrs {}, ctr_el0",out(reg)ctr,options(nomem,nostack));}
    let line=4usize<<((ctr>>16)&15);
    assert!(line.is_power_of_two() && line<=PAGE);
    for off in (0..bytes).step_by(line){
        unsafe{core::arch::asm!("dc cvau, {}",in(reg)addr+off as u64,options(nostack));}
    }
    unsafe{core::arch::asm!("dsb ish",options(nostack));}
}
fn invalidate_code(){
    unsafe{core::arch::asm!("dsb ish","ic ialluis","dsb ish","isb",options(nostack));}
}
/// The high RAM direct map is a global 4KiB leaf mapping. Invalidate
/// the changed VA for ALL ASIDs in the inner-shareable domain, not
/// every unrelated RAM translation on every seal/unseal. Keep the full
/// BBM barriers and do not use a last-level-only TLBI shortcut.
fn invalidate_high_page(pa:u64){
    let va=pa.checked_add(super::super::HIGH).expect("direct map VA");
    assert_eq!(va%4096,0);
    // AArch64 VAAE1IS operand VA[55:12], bits[63:44] RES0.
    let operand=(va>>12)&((1u64<<44)-1);
    unsafe{core::arch::asm!("dsb ishst","tlbi vaae1is, {}","dsb ish","isb",
        in(reg)operand,options(nostack));}
}
/// Low user leaves are all nG and the role ASID is boot-unique.
/// The architectural root disconnection still precedes this broadcast
/// all-level invalidation, and all barriers precede any frame reuse.
fn invalidate_role_root(index:usize,bank:usize){
    let tcr:u64;
    unsafe{core::arch::asm!("mrs {}, tcr_el1",out(reg)tcr,options(nomem,nostack));}
    // This locked 39-bit/4KiB profile selects an 8-bit TTBR0 ASID.
    assert_eq!(tcr&((1<<36)|(1<<22)),0,"TTBR0 8-bit ASID contract");
    let operand=u64::from(role_asid(index,bank))<<48;
    unsafe{core::arch::asm!("dsb ishst","tlbi aside1is, {}","dsb ish","isb",
        in(reg)operand,options(nostack));}
}
fn seal_page(pa:u64,mut checkpoint:impl FnMut(u64)){
    let leaf=high_leaf(pa);
    let old=unsafe{core::ptr::read_volatile(leaf)};
    assert_eq!(old,pa|0x0060_0000_0000_0703);
    // Real break-before-make, globally shared high VA invalidation.
    // No user root is published while a page is being sealed.
    unsafe{core::ptr::write_volatile(leaf,0);}
    invalidate_high_page(pa);
    // The unpublished page has no active user mapping or DMA. It is
    // safe to pause here after completed break, before the new make.
    checkpoint(15);
    unsafe{core::ptr::write_volatile(leaf,old|(1<<7));}
    invalidate_high_page(pa);
    checkpoint(16);
}
fn load(index:usize,generation:u64,bank:usize)->(NativeRole,Running){
    load_checkpointed(index,generation,bank,|_|{})
}
fn load_checkpointed(index:usize,generation:u64,bank:usize,mut checkpoint:impl FnMut(u64))->(NativeRole,Running){
    let role=ROLES[index];let pkg=&CATALOG[index];
    assert_eq!(pkg.role_id,role.id());
    assert!(pkg.bytes.len()<=COPY);
    let actor=Identity{id:u64::from(role.id()),generation}; // local diagnostic generation only
    let endpoint=0xC000+index as u64;
    let kind=cap_kind(role);
    let cap=Cap{selector:if kind==CapKind::None{0}else{0x1000+index as u64*0x100+generation},holder:actor,endpoint,kind};
    let b=backing(index);let t=tables(index,bank);
    // SAFETY: CPU0 is the only loader and none of these contexts has been
    // published. The exclusive source scratch is scrubbed after each image.
    #[cfg(feature="v0199-epoch-disk-selftest")]
    let scratch=unsafe{&mut *((disk_pool()+DISK_COPY_OFFSET as u64) as *mut [u8;COPY])};
    #[cfg(not(feature="v0199-epoch-disk-selftest"))]
    let scratch=unsafe{&mut *core::ptr::addr_of_mut!(COPY_BUFFER.0)};
    for (dst,src) in scratch[..pkg.bytes.len()].chunks_mut(PAGE).zip(pkg.bytes.chunks(PAGE)){
        dst.copy_from_slice(src);checkpoint(10);
    }
    let spec=RolePackageSpec{role,package_id:u64::from(role.id()),abi:3,image_bytes:pkg.bytes.len(),
        image_sha256:pkg.image_sha256,relative_count:pkg.relative.len(),relative_sha256:pkg.relative_sha256,
        stack_bytes:ROLE_STACK_BYTES};
    let verified=VerifiedRolePackage::verify_checkpointed(spec,RolePackageInput{package_id:spec.package_id,
        bytes:&scratch[..pkg.bytes.len()],relative:pkg.relative},||checkpoint(11)).expect("trusted ABI3 role package");
    let relro=verified.relro();
    checkpoint(11);
    let image=unsafe{&mut *core::ptr::addr_of_mut!((*b).image)};
    let entry=verified.stage_checkpointed(image,BASE,BASE,BASE+IMAGE as u64,||checkpoint(12)).expect("private PIE stage");
    checkpoint(12);
    let stack=unsafe{&mut *core::ptr::addr_of_mut!((*b).stack)};
    // Diagnostic startup payload is program-specific, not an added ABI
    // field. The generic ABI3 contract supplies arg_va/args_len and SP.
    let mut args=[0u8;24];
    args[..8].copy_from_slice(&cap.selector.to_le_bytes());
    args[8..16].copy_from_slice(&0u64.to_le_bytes()); // no live target
    args[16..24].copy_from_slice(&actor.generation.to_le_bytes());
    let startup=cyxia_kernel_core::security::syscall_v3::stage_spawn_args(stack,STACK_BASE,&args)
        .expect("private ABI3 startup arguments");
    assert_eq!(startup.sp,STACK_END-32);
    assert!(stack[..ROLE_STACK_BYTES-32].iter().all(|&v|v==0));
    assert_eq!(&stack[ROLE_STACK_BYTES-32..ROLE_STACK_BYTES-8],&args);
    assert!(stack[ROLE_STACK_BYTES-8..].iter().all(|&v|v==0));
    checkpoint(13);
    let mut map=[0u8;IMAGE/PAGE];
    for seg in verified.load_segments(){
        let start=seg.virtual_address as usize/PAGE;
        let end=(seg.virtual_address+seg.memory_bytes).div_ceil(PAGE as u64) as usize;
        assert!(start<end&&end<=map.len());
        for page in &mut map[start..end]{assert_eq!(*page,0);*page=seg.flags as u8;}
    }
    if let Some((start,len))=relro{
        assert_eq!(start%PAGE as u64,0,"RELRO start not page-aligned");
        let end=start.checked_add(len).unwrap().div_ceil(PAGE as u64);
        assert!(end<=map.len() as u64);
        for page in &mut map[start as usize/PAGE..end as usize]{
            assert_eq!(*page,6,"RELRO must originate in private RW LOAD");
            *page=4; // stage already applied verified relocations; seal now
        }
    }
    for chunk in scratch.chunks_mut(PAGE){chunk.fill(0);checkpoint(14);}
    let image_base=b as u64;
    for (i,flags) in map.iter().copied().enumerate(){
        if flags&1!=0{clean_code(image_base+i as u64*PAGE as u64,PAGE);checkpoint(14);}
    }
    // One complete broadcast I-cache invalidation after all D-cache
    // cleans, before any executable low mapping is entered.
    invalidate_code();checkpoint(14);
    unsafe{
        (*t).root.0[0]=phys(core::ptr::addr_of!((*t).mid) as u64)|3;
        (*t).mid.0[0]=phys(core::ptr::addr_of!((*t).leaf) as u64)|3;
    }
    for (i,flags) in map.into_iter().enumerate(){
        if flags==0{continue;}
        let pa=phys(image_base+i as u64*PAGE as u64);
        let write=flags&2!=0;let execute=flags&1!=0;
        if !write{seal_page(pa,&mut checkpoint);}
        let desc=mmu::encode_user_leaf(PhysAddr(pa),write,execute).unwrap();
        unsafe{(*t).leaf.0[BASE as usize/PAGE+i]=desc;}
    }
    let stack_base=unsafe{core::ptr::addr_of!((*b).stack) as u64};
    for i in 0..ROLE_STACK_BYTES/PAGE{
        let pa=phys(stack_base+i as u64*PAGE as u64);
        unsafe{(*t).leaf.0[STACK_BASE as usize/PAGE+i]=mmu::encode_user_leaf(PhysAddr(pa),true,false).unwrap();}
    }
    checkpoint(17);
    // Guard and image holes have never had user mappings.
    assert_eq!(unsafe{(*t).leaf.0[STACK_BASE as usize/PAGE-1]},0);
    // No low global mapping is admitted by this loader.
    assert!(unsafe{(*t).leaf.0.iter().all(|&p|p==0||p&(1<<11)!=0)});
    invalidate_role_root(index,bank);
    checkpoint(18);
    let member=NativeRole{role,actor,ttbr0_root:root_pa(index,bank),
        // Charge the full physically reserved image, including its RX/RO
        // pages and holes, not only mapped RW bytes.
        private_rw:PrivateRegion{base:phys(b as u64),bytes:core::mem::size_of::<Backing>() as u64},
        caps:role.allowed_caps(),control_ns_per_100ms:ROLE_QUOTAS[index],
        cpu_mask:CONTROL_MASK,thread_count:1,endpoint_id:endpoint};
    let mut context=user::Context::empty();
    context.pc=entry;context.sp=startup.sp;
    context.regs[0]=startup.x0;context.regs[1]=startup.x1;
    assert!(context.regs[2..].iter().all(|&v|v==0));
    assert!(context.simd.iter().flatten().all(|&v|v==0));
    (member,Running{context,cap,abi:spec.abi,bank,entry,wake_ns:0,clocks:0,role_calls:0,yields:0,
        charges:0,turns:0,last_status:0,preemptions:0,fault_esr:0,fault_far:0})
}

/// The sole accepted pointer range in this initial native adapter is the
/// current private stack. Walk and compare every actual leaf with the owned
/// physical page. There is no concurrent thread in the role and the stopped
/// context's static backing cannot be reclaimed. No mutable input is reread.
fn stack_span(index:usize,bank:usize,va:u64,n:usize,write:bool)->Option<u64>{
    if n==0{return None;}
    let end=va.checked_add(n as u64)?;
    if va<STACK_BASE||end>STACK_END{return None;}
    let t=tables(index,bank);let b=backing(index);
    let stack=unsafe{core::ptr::addr_of!((*b).stack) as u64};
    let root=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*t).root.0[0]))};
    let mid=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*t).mid.0[0]))};
    if root!=(phys(unsafe{core::ptr::addr_of!((*t).mid)} as u64)|3)
        || mid!=(phys(unsafe{core::ptr::addr_of!((*t).leaf)} as u64)|3){return None;}
    let mut cur=va;
    while cur<end{
        let page=cur&!4095;
        let owned=PhysAddr(phys(stack+page-STACK_BASE));
        let pte=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*t).leaf.0[(page/PAGE as u64) as usize]))};
        let length=(end-cur).min(PAGE as u64-(cur&4095)) as usize;
        mmu::checked_user_leaf_span(pte,owned,cur&4095,length,write).ok()?;
        cur+=length as u64;
    }
    Some(stack+va-STACK_BASE)
}
fn copied<const N:usize>(index:usize,bank:usize,va:u64)->Option<StableCopy<N>>{
    let src=stack_span(index,bank,va,N,false)?;
    let mut bytes=[0u8;N];
    for (i,byte) in bytes.iter_mut().enumerate(){
        *byte=unsafe{core::ptr::read_volatile((src+i as u64) as *const u8)};
    }
    StableCopy::from_validated(&bytes).ok()
}
fn valid_audit_request(b:&[u8],actor:Identity,now:u64)->bool{
    let u16at=|i|u16::from_le_bytes(b[i..i+2].try_into().unwrap());
    let u32at=|i|u32::from_le_bytes(b[i..i+4].try_into().unwrap());
    let u64at=|i|u64::from_le_bytes(b[i..i+8].try_into().unwrap());
    b.len()==64 && u32at(0)==0x43594351 && u16at(4)==1 && u16at(6)==48
        && u16at(8)==1 && u16at(10)==0 && u32at(12)==16 && u64at(16)==1
        && u64at(24)==0 && u64at(32)==actor.generation && u64at(48)==actor.generation
        && u64at(56)==0 && now<u64at(40) && u64at(40)-now<=500_000_000
}
// Native model arithmetic evidence from an independently linked brain's
// actual private RW page, captured while its EL0 context is stopped at CLOCK.
// This fixture never converts the result to an authorized model or suggestion.
fn model_probe_row(index:usize,r:&Running,actor:Identity)->[u64;4]{
    assert!(index<2&&actor.generation!=0);
    const OFFSET:usize=0xf000;
    let address=backing(index) as u64+OFFSET as u64;
    let t=tables(index,r.bank);
    let pte=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*t).leaf.0[(BASE as usize+OFFSET)/PAGE]))};
    mmu::checked_user_leaf_span(pte,PhysAddr(phys(address)),0,32,true).expect("private probe result ownership");
    let row:[u64;4]=core::array::from_fn(|i|unsafe{((address as *const u64).add(i)).read_volatile()});
    assert_eq!(row[0],0x4359_4d4c_5052_4f42);
    assert_eq!(row[1],actor.generation);
    row
}
fn capture_model_probe(index:usize,r:&Running,actor:Identity){
    assert!(matches!(actor.generation,1|2));
    let row=model_probe_row(index,r,actor);
    let at=493+index*8+(actor.generation as usize-1)*4;
    assert_eq!(SMP_EVIDENCE.words[at].load(Ordering::Relaxed),0);
    for(i,v)in row.into_iter().enumerate(){SMP_EVIDENCE.words[at+i].store(v,Ordering::Relaxed);}
}
/// Actual SVC64 dispatch for this deliberately restricted bootstrap profile.
/// Full production cap issuance, boot identity, IPC and service backend
/// are absent, so no publication, inference authorization or audit ACK is
/// fabricated. Identity derives from the selected EL1 context, never x0.
fn dispatch(index:usize,m:&ValidatedRoleManifest<'_>,r:&mut Running)->bool{
    let member=m.manifest().members[index];
    assert_eq!(r.cap.holder,member.actor);
    let Ok(call)=decode_aarch64_svc_v3(r.abi,r.context.esr,&r.context.regs) else {
        r.context.regs[0]=E_FORMAT as u64;return false;
    };
    let a=call.args;
    let now=now_ns();
    let mut park=false;
    let result=match call.operation{
        Syscall::Clock=>{
            if index<2&&r.clocks==0{capture_model_probe(index,r,member.actor);}
            r.clocks+=1;i64::try_from(now).unwrap_or(E_FORMAT)
        }
        Syscall::Yield=>{r.yields+=1;park=true;0}
        Syscall::Sleep=>{
            r.role_calls+=1;r.wake_ns=a[0].max(now);park=true;0
        }
        Syscall::ReadSnapshot=>{
            let authorized=match r.cap.kind{
                CapKind::Snapshot(view)=>a[0]==r.cap.selector
                    && m.check_snapshot_view(member.actor,r.cap.endpoint,cpu::slot(),view).is_ok()
                    && ((view==SnapshotView::RedactedSecurity&&a[1]==12)
                        ||(view!=SnapshotView::RedactedSecurity&&a[1]==1)),
                _=>false,
            };
            if !authorized{E_AUTH}
            else if usize::try_from(a[4]).ok().and_then(|len|stack_span(index,r.bank,a[3],len,true)).is_none(){EFAULT}
            else {r.role_calls+=1;EAGAIN} // no persistent boot identity or target registry yet
        }
        Syscall::ServiceCall=>{
            if r.cap.kind!=CapKind::Audit||a[0]!=r.cap.selector||a[3]!=0
                ||m.check_aux(member.actor,r.cap.endpoint,cpu::slot(),AuxOperation::AuditRead).is_err(){E_AUTH}
            else if a[2]!=64||a[5]<192{E_FORMAT}
            else if usize::try_from(a[5]).ok().and_then(|len|stack_span(index,r.bank,a[4],len,true)).is_none(){EFAULT}
            else if let Some(req)=copied::<64>(index,r.bank,a[1]){
                if !valid_audit_request(req.bytes(),member.actor,now){E_FORMAT}
                else {r.role_calls+=1;EAGAIN} // no accepted audit request/ACK credit
            }else{EFAULT}
        }
        Syscall::SubmitPlan|Syscall::ReportResult=>E_AUTH,
        _=>E_UNSUPPORTED,
    };
    if matches!(call.operation,Syscall::ReadSnapshot|Syscall::ServiceCall|Syscall::Sleep){r.last_status=result;}
    r.context.regs[0]=result as u64;
    park
}
fn class(role:Role)->(Class,u16,u64){
    match role{
        Role::Operations=>(Class::Operations,1,2_000_000),
        Role::Security=>(Class::Security,12,2_000_000),
        Role::DeterministicController|Role::Publisher=>(Class::Decision,1,250_000),
        Role::ModelManager|Role::Supervisor=>(Class::Coordination,0,500_000),
        Role::Validator|Role::Learner=>(Class::Optional,0,500_000),
    }
}
fn turn(index:usize,m:&ValidatedRoleManifest<'_>,r:&mut Running,budget:&mut BudgetMeter,expect_fault:bool)->bool{
    let (now,began)=budget.sample_gap();if now<r.wake_ns{return false;}
    let member=m.manifest().members[index];
    let (class,domain,quota)=class(member.role);
    let token=match budget.ledger.reserve_indexed_role_with_wall(m,index,member.actor,cpu::slot(),class,domain,quota,50_000_000,now){
        Ok(t)=>t,
        Err(Error::Exhausted|Error::Busy)=>return false,
        Err(e)=>panic!("native control budget refused: {e:?}"),
    };
    let mut parked=false;
    // One prepaid role turn may traverse several real SVCs; the advisory
    // slot is not refilled per syscall or timer preemption.
    // The 0.25ms diagnostic decision slice may only service one trap;
    // additional work must be independently admitted under the same 0.5ms
    // combined decision/publication limit for this domain and window.
    let trap_limit=if class==Class::Decision{1}else{32};
    let exit_guard=if class==Class::Decision{DECISION_EXIT_GUARD_NS}else{TURN_EXIT_GUARD_NS};
    // Failure localization: these are cumulative PMU offsets from the
    // same prepaid turn, not new accounting grants. Their own cost is
    // included in final settlement. Zero means the phase was not reached.
    let mut before_enter=0;let mut after_exit=0;let mut after_dispatch=0;
    for _ in 0..trap_limit{
        // Prepare immutable root identity BEFORE the final admission
        // sample. The same PMU sample drives the guard and diagnostics;
        // the old path checked an earlier sample, then measured 109384ns
        // before entering despite only 100000ns of entry headroom.
        let root=member.ttbr0_root;
        assert_eq!(root,root_pa(index,r.bank));
        let asid=role_asid(index,r.bank);
        let wall_ticks=timer::ticks();
        let wall=ns_from_ticks(wall_ticks);
        let actual=timer::cpu_elapsed_ns(began);
        let cpu_left=quota.saturating_sub(actual);
        let wall_left=token.deadline_ns().saturating_sub(wall);
        if cpu_left<=exit_guard||wall_left<=exit_guard{break;}
        let mut interval=(cpu_left-exit_guard).min(wall_left-exit_guard);
        if class==Class::Decision{
            interval=interval.min(DECISION_SLICE_NS);
            before_enter=actual;
        }
        unsafe{
            // Anchor to the sampled physical timer, not a later reading
            // that would silently extend the original wall allowance.
            timer::arm(wall_ticks.checked_add(ticks_for(interval)).unwrap());
            // Each live root is immutable, private, and all leaves are nG.
            // Retire_root disconnects it and completes TLBI before reclaim.
            user::enter_pinned_until_retired(&mut r.context,root,asid);
            // The dedicated SMP timer IRQ handler has already disabled
            // CNT(P)_CTL before returning kind9. Sync traps still need it.
            if cfg!(feature="unified-runtime")||r.context.kind!=9{cpu::disable_timer();}
        }
        if class==Class::Decision{after_exit=timer::cpu_elapsed_ns(began);}
        // Settle immediately after a timer exit instead of re-entering in
        // the same prepaid turn; all measured cost is retained by the ledger.
        if r.context.kind==9{r.preemptions+=1;break;}
        if expect_fault{
            let guard=STACK_BASE-PAGE as u64;
            if r.context.kind!=8||r.context.esr>>26!=0x20
                ||r.context.esr&0x3f!=7||r.context.far!=guard{fatal(660+index as u64);}
            r.fault_esr=r.context.esr;r.fault_far=r.context.far;
            parked=true;break;
        }
        if r.context.kind!=8 || r.context.esr>>26!=0x15{fatal(600+index as u64);}
        parked=dispatch(index,m,r);
        if class==Class::Decision{after_dispatch=timer::cpu_elapsed_ns(began);}
        if parked{break;}
    }
    let receipt=budget.settle(token,began);
    r.charges=r.charges.checked_add(receipt.actual_ns).unwrap();r.turns+=1;
    if receipt.overrun||receipt.crossed_window{
        if class==Class::Decision{
            report("V0199_DECISION_OVERRUN_PHASES",before_enter,after_exit,after_dispatch);
            report("V0199_DECISION_OVERRUN_TRAP",r.context.kind as u64,r.context.esr,r.context.regs[8]);
        }
        report("V0199_BOOTSTRAP_OVERRUN",member.role.id() as u64,receipt.actual_ns,quota);
        fatal(620+index as u64);
    }
    // Actual accounting, not elapsed host wall or a model-provided scalar.
    assert!(!budget.ledger.ordinary_closed());
    parked
}
/// Quiescent CPU0 owner only. First revoke the selected context and all
/// its old low mappings. Only after the architectural TLBI completion can
/// the old image be made writable again. These static frames are never
/// attached to DMA or another address space in this diagnostic profile.
fn retire_root(index:usize,bank:usize){
    retire_root_checkpointed(index,bank,|_|{});
}
fn retire_root_checkpointed(index:usize,bank:usize,mut checkpoint:impl FnMut(u64)){
    let t=tables(index,bank);
    assert!(unsafe{(*t).leaf.0.iter().all(|&p|p==0||p&(1<<11)!=0)});
    unsafe{core::ptr::write_volatile(core::ptr::addr_of_mut!((*t).root.0[0]),0);}
    invalidate_role_root(index,bank);
    checkpoint(1);
    // Root disconnected and context returned; all former leaf entries are
    // now inaccessible. This is not proof of a general production DMA join.
    unsafe{
        core::ptr::write_bytes(core::ptr::addr_of_mut!((*t).mid.0).cast::<u8>(),0,PAGE);
        core::ptr::write_bytes(core::ptr::addr_of_mut!((*t).leaf.0).cast::<u8>(),0,PAGE);
    }
    checkpoint(2);
    let b=backing(index) as u64;
    for offset in (0..IMAGE).step_by(PAGE){
        let pa=phys(b+offset as u64);
        let leaf=high_leaf(pa);
        let rw=pa|0x0060_0000_0000_0703;
        let old=unsafe{core::ptr::read_volatile(leaf)};
        assert!(old==rw||old==rw|(1<<7));
        if old!=rw{
            unsafe{core::ptr::write_volatile(leaf,0);}invalidate_high_page(pa);
            checkpoint(3);
            unsafe{core::ptr::write_volatile(leaf,rw);}invalidate_high_page(pa);
            checkpoint(4);
        }
        checkpoint(4);
    }
    let bytes=unsafe{core::slice::from_raw_parts_mut(b as *mut u8,IMAGE+ROLE_STACK_BYTES)};
    for page in bytes.chunks_exact_mut(PAGE){
        page.fill(0);assert!(page.iter().all(|&v|v==0));checkpoint(5);
    }
}
fn restart_each(manifest:&mut NativeRoleManifest,running:&mut[Running;ROLE_COUNT],
    budget:&mut BudgetMeter)
{
    use cyxia_kernel_core::control_plane::service_restart::{Lifecycle,RestartDecision};
    let until=now_ns().checked_add(15_000_000_000).unwrap();
    for i in 0..ROLE_COUNT{
        let checked=manifest.validated().expect("current survivor inventory");
        let old=manifest.members[i];
        let old_cap=running[i].cap;
        let old_root=old.ttbr0_root;
        let old_bank=running[i].bank;
        assert_eq!(old_bank,0);
        let before:[(u64,u64,u64,u64);ROLE_COUNT]=core::array::from_fn(|j|
            (running[j].clocks,running[j].role_calls,manifest.members[j].actor.generation,
             manifest.members[j].ttbr0_root));
        // An injected PC in the actual guard page produces a genuine EL0
        // instruction abort. Never continue the faulted saved context.
        report("V0199_RESTART_BEGIN",old.role.id() as u64,old.actor.generation,old_root);
        running[i].context.pc=STACK_BASE-PAGE as u64;
        running[i].wake_ns=0;
        while running[i].fault_esr==0{
            if now_ns()>=until{fatal(680);}
            if now_ns()%WINDOW_NS>WINDOW_NS-5_000_000{budget.idle_retry();continue;}
            let turns=running[i].turns;
            let _=turn(i,&checked,&mut running[i],budget,true);
            if running[i].turns==turns{budget.idle_retry();}
        }
        let esr=running[i].fault_esr;let far=running[i].fault_far;
        report("V0199_RESTART_GUARD_FAULT",old.role.id() as u64,esr,far);
        // These are *volatile* diagnostic generations. No durable epoch
        // exists, so the production publication gate stays closed.
        let mut life=Lifecycle::new(1,old.actor.generation).unwrap();
        life.peer_ready(1,old.actor.generation).unwrap();
        let next=match life.fault(1,old.actor.generation).unwrap(){
            RestartDecision::Restart{generation}=>generation,
            RestartDecision::Isolate=>fatal(681),
        };
        assert!(!life.accepts(1,old.actor.generation)&&!life.accepts(1,next));
        // Close the old cap immediately, before reclaiming any pages.
        running[i].cap.selector=0;running[i].cap.kind=CapKind::None;
        // The faulted diagnostic client remains stopped with its old cap
        // revoked. Before any reload, require every other EL0 role to make
        // a real clock AND role-specific SVC through the same CPU0 ledger.
        // No recovery reservation is held while the survivors execute.
        let survivor_mask=((1u64<<ROLE_COUNT)-1)&!(1u64<<i);
        let mut progressed=0u64;
        while progressed!=survivor_mask{
            if now_ns()>=until{fatal(685);}
            let mut ran=false;
            for j in 0..ROLE_COUNT{
                if j==i||progressed&(1u64<<j)!=0{continue;}
                if now_ns()%WINDOW_NS>WINDOW_NS-5_000_000{continue;}
                let turns=running[j].turns;
                let _=turn(j,&checked,&mut running[j],budget,false);
                ran|=running[j].turns!=turns;
                if running[j].clocks>before[j].0&&running[j].role_calls>before[j].1{
                    progressed|=1u64<<j;
                }
            }
            if !ran{budget.idle_retry();}
        }
        let mut total_delta=0u64;
        SMP_EVIDENCE.words[400+i*9].store(progressed,Ordering::Relaxed);
        for j in 0..ROLE_COUNT{
            let delta=if j==i{0}else{running[j].role_calls.checked_sub(before[j].1).unwrap()};
            total_delta=total_delta.checked_add(delta).unwrap();
            SMP_EVIDENCE.words[400+i*9+1+j].store(delta,Ordering::Relaxed);
        }
        report("V0199_RESTART_SURVIVORS",old.role.id() as u64,progressed,total_delta);
        let (mut credit,mut start)=budget.reserve_recovery_slice(until);
        let mut actual=0u64;let mut slices=0u64;let mut largest=0u64;
        let mut part=0u64;
        let mut checkpoint=|phase:u64|{
            part=part.checked_add(1).unwrap();
            if timer::cpu_elapsed_ns(start)>=450_000
                || credit.deadline_ns().saturating_sub(now_ns())<2_000_000{
                let cost=budget.settle_recovery_slice(old.role,credit,start,phase,part);
                actual=actual.checked_add(cost).unwrap();slices+=1;largest=largest.max(cost);
                (credit,start)=budget.reserve_recovery_slice(until);
            }
        };
        // Old context remains stopped and new mappings are not published
        // during pauses. Every BBM operation completes before yielding.
        retire_root_checkpointed(i,old_bank,&mut checkpoint);
        let (member,new)=load_checkpointed(i,next,1,&mut checkpoint);
        drop(checkpoint);
        assert!(member.ttbr0_root!=old_root&&member.actor.generation==next);
        assert_eq!(unsafe{(*tables(i,old_bank)).root.0[0]},0);
        assert!(old_cap.selector==0||new.cap.selector!=old_cap.selector);
        manifest.members[i]=member;
        let checked=manifest.validated().expect("replacement inventory");
        let cost=budget.settle_recovery_slice(old.role,credit,start,19,part+1);
        actual=actual.checked_add(cost).unwrap();slices+=1;largest=largest.max(cost);
        SMP_EVIDENCE.words[56+i].store(slices,Ordering::Relaxed);
        SMP_EVIDENCE.words[64+i].store(largest,Ordering::Relaxed);
        report("V0199_RESTART_RECOVERY_SLICES",old.role.id() as u64,slices,largest);
        life.reset_complete(1,next).unwrap();
        running[i]=new;
        while running[i].clocks<2||running[i].role_calls<2{
            if now_ns()>=until{fatal(684);}
            if now_ns()%WINDOW_NS>WINDOW_NS-5_000_000{budget.idle_retry();continue;}
            let turns=running[i].turns;
            let _=turn(i,&checked,&mut running[i],budget,false);
            if running[i].turns==turns{budget.idle_retry();}
        }
        // READY here means only the actual diagnostic client reentered.
        // Formal service replay/READY is deliberately not advertised.
        life.peer_ready(1,next).unwrap();
        assert!(life.accepts(1,next)&&!life.accepts(1,old.actor.generation));
        for j in 0..ROLE_COUNT{
            if j!=i{
                assert!(running[j].clocks>before[j].0&&running[j].role_calls>before[j].1);
                assert_eq!((manifest.members[j].actor.generation,manifest.members[j].ttbr0_root),
                    (before[j].2,before[j].3));
            }
        }
        let row=[old.role.id() as u64,old.actor.generation,next,old_root,member.ttbr0_root,
            old_cap.selector,running[i].cap.selector,esr,far,actual,
            (IMAGE+ROLE_STACK_BYTES) as u64,u64::from(life.ready())];
        for(j,value)in row.into_iter().enumerate(){SMP_EVIDENCE.words[304+i*12+j].store(value,Ordering::Relaxed);}
        report("V0199_PACKAGE_RELOAD",old.role.id() as u64,old_root,member.ttbr0_root);
    }
}
/// Dedicated durable scratch-disk profile uses the actual role7 ELF and
/// the same verified relocation/W^X/32KiB stack loader as eight-role boot.
/// It does not grant an Active model or live snapshot: the diagnostic
/// snapshot call must remain EAGAIN. Disk I/O is not covered by this probe.
#[cfg(feature="v0199-epoch-disk-selftest")]
pub(super) struct DiskSecurityRun{
    pub root:u64,pub stack:u64,pub generation:u64,pub clocks:u64,pub snapshots:u64,
    pub score:u64,pub severity:u64,pub esr:u64,pub far:u64,pub image_sha256:[u8;32],
}
#[cfg(feature="v0199-epoch-disk-selftest")]
pub(super) fn disk_security_run(generation:u64,bank:usize,stop:bool)->DiskSecurityRun{
    assert_eq!(cpu::slot(),0);
    init_timer_frequency();
    let i=1usize;
    let (m,mut r)=load(i,generation,bank);
    assert_eq!(m.role,Role::Security);assert_eq!(m.actor.generation,generation);
    let enter=|r:&mut Running|{
        unsafe{
            timer::arm(timer::ticks().checked_add(ticks_for(1_000_000)).unwrap());
            user::enter_pinned_until_retired(&mut r.context,m.ttbr0_root,role_asid(i,bank));
            cpu::disable_timer();
        }
    };
    let mut probe=None;let mut yielded=false;
    for _ in 0..128{
        enter(&mut r);
        if r.context.kind==9{continue;}
        assert_eq!(r.context.kind,8);
        let call=decode_aarch64_svc_v3(r.abi,r.context.esr,&r.context.regs).expect("actual role7 ABI3");
        let result=match call.operation{
            Syscall::Clock=>{
                if r.clocks==0{probe=Some(model_probe_row(i,&r,m.actor));}
                r.clocks+=1;i64::try_from(now_ns()).unwrap()
            }
            Syscall::ReadSnapshot=>{
                let a=call.args;
                assert!(r.cap.holder==m.actor&&r.cap.kind==CapKind::Snapshot(SnapshotView::RedactedSecurity)
                    &&a[0]==r.cap.selector&&a[1]==12&&a[2]==0&&a[4]==264);
                assert!(stack_span(i,bank,a[3],264,true).is_some());
                r.role_calls+=1;EAGAIN
            }
            Syscall::Yield=>{r.yields+=1;yielded=true;0}
            _=>panic!("unexpected role7 diagnostic syscall"),
        };
        r.context.regs[0]=result as u64;
        if yielded&&r.role_calls>0{break;}
    }
    assert!(yielded&&r.clocks>0&&r.role_calls>0);
    let row=probe.expect("role7 actually executed integer probe");
    let root=m.ttbr0_root;
    let stack=phys(unsafe{core::ptr::addr_of!((*backing(i)).stack)} as u64);
    let mut esr=0;let mut far=0;
    if stop{
        r.context.pc=STACK_BASE-PAGE as u64;
        for _ in 0..128{
            enter(&mut r);
            if r.context.kind==9{continue;}
            assert_eq!(r.context.kind,8);assert_eq!(r.context.esr>>26,0x20);
            assert_eq!(r.context.esr&0x3f,7);assert_eq!(r.context.far,STACK_BASE-PAGE as u64);
            esr=r.context.esr;far=r.context.far;break;
        }
        assert_ne!(esr,0);
        // This stopped diagnostic instance has no DMA, accepted work or
        // issued production caps. Do not publish another old context.
        r.cap.selector=0;retire_root(i,bank);
        assert_eq!(unsafe{(*tables(i,bank)).root.0[0]},0);
    }
    DiskSecurityRun{root,stack,generation,clocks:r.clocks,snapshots:r.role_calls,
        score:row[2],severity:row[3],esr,far,image_sha256:CATALOG[i].image_sha256}
}

pub(super) fn run()->!{
    assert_eq!(cpu::slot(),0);assert_eq!(ONLINE.load(Ordering::Acquire),15);
    gic().enable(TIMER_IRQ.load(Ordering::Acquire) as u32).unwrap();
    unsafe{timer::init_cpu_accounting();}
    init_timer_frequency();
    let mut budget=BudgetMeter::new();
    let pairs:[(NativeRole,Running);ROLE_COUNT]=core::array::from_fn(|i|budget.load_initial(i));
    let members=core::array::from_fn(|i|pairs[i].0);
    let mut running=pairs.map(|(_,r)|r);
    let mut manifest=NativeRoleManifest{
        online_mask:REQUIRED_ONLINE_MASK,members,
        // Full statically reserved pages, copy scratch and a conservative
        // one-MiB bootstrap metadata allowance inside the control pool.
        other_protected_pool_bytes:core::mem::size_of::<[Tables;2*ROLE_COUNT]>()+COPY+1024*1024,
        other_control_ns_per_100ms:OTHER_CPU_NS,
    };
    let checked=manifest.validated().expect("complete eight role physical inventory");
    budget.wait_for(||(1..REQUIRED).all(|slot|PROGRESS[slot*2].load(Ordering::Acquire)>=2));
    let until=now_ns().checked_add(5_000_000_000).unwrap();
    // Controller/publisher/supervisor before optional model/learning work.
    let order=[2usize,3,7,1,0,5,4,6];
    while !running.iter().all(|r|r.clocks>=2&&r.role_calls>=2){
        if now_ns()>=until{fatal(650);}
        let mut ran=false;
        for i in order{
            if running[i].clocks>=2&&running[i].role_calls>=2{continue;}
            // Do not begin an evaluation in a near-expired 100ms window.
            if now_ns()%WINDOW_NS>WINDOW_NS-5_000_000{continue;}
            let turns=running[i].turns;
            let _=turn(i,&checked,&mut running[i],&mut budget,false);
            ran|=running[i].turns!=turns;
        }
        if !ran{budget.idle_retry();}
    }
    report("V0199_BOOTSTRAP_INITIAL_ROLES",ROLE_COUNT as u64,0,0);
    restart_each(&mut manifest,&mut running,&mut budget);
    let checked=manifest.validated().expect("post-restart inventory");
    // Exercise every reloaded diagnostic context in a common post-restart
    // round. They remain live together on the one fixed control CPU; the
    // evidence must not be a union of eight independent one-process boots.
    let start:[(u64,u64);ROLE_COUNT]=core::array::from_fn(|i|(running[i].clocks,running[i].role_calls));
    let until=now_ns().checked_add(5_000_000_000).unwrap();
    let mask=(1u64<<ROLE_COUNT)-1;
    let mut progressed=0u64;
    while progressed!=mask{
        if now_ns()>=until{fatal(686);}
        let mut ran=false;
        for i in order{
            if progressed&(1u64<<i)!=0{continue;}
            if now_ns()%WINDOW_NS>WINDOW_NS-5_000_000{continue;}
            let turns=running[i].turns;
            let _=turn(i,&checked,&mut running[i],&mut budget,false);
            ran|=running[i].turns!=turns;
            if running[i].clocks>start[i].0&&running[i].role_calls>start[i].1{
                progressed|=1u64<<i;
            }
        }
        if !ran{budget.idle_retry();}
    }
    SMP_EVIDENCE.words[472].store(progressed,Ordering::Relaxed);
    let mut total_delta=0u64;
    for i in 0..ROLE_COUNT{
        assert_eq!(manifest.members[i].actor.generation,2);
        let delta=running[i].role_calls.checked_sub(start[i].1).unwrap();
        total_delta=total_delta.checked_add(delta).unwrap();
        SMP_EVIDENCE.words[473+i].store(delta,Ordering::Relaxed);
    }
    report("V0199_BOOTSTRAP_ALL_LIVE",ROLE_COUNT as u64,progressed,total_delta);
    for (i,role) in ROLES[..2].iter().enumerate(){
        for generation in 1..=2{
            let at=493+i*8+(generation-1)*4;
            budget.coordinated(||report("V0199_MODEL_PROBE",u64::from(role.id()),generation as u64,
                SMP_EVIDENCE.words[at+2].load(Ordering::Relaxed)));
        }
    }
    // All eight independently linked diagnostic clients have executed, faulted,
    // reloaded under a new root and reentered. No real service effect is claimed.
    for (i,r) in running.iter().enumerate(){
        let m=manifest.members[i];
        let stack=phys(unsafe{core::ptr::addr_of!((*backing(i)).stack)} as u64);
        let guard=unsafe{(*tables(i,r.bank)).leaf.0[STACK_BASE as usize/PAGE-1]};
        let row=[u64::from(m.role.id()),m.ttbr0_root,m.private_rw.base,stack,
            r.entry,r.cap.selector,r.clocks,r.role_calls,r.yields,r.charges,r.turns,
            r.last_status as u64,guard,r.preemptions];
        for (j,value) in row.into_iter().enumerate(){
            SMP_EVIDENCE.words[128+i*20+j].store(value,Ordering::Relaxed);
        }
        for (j,chunk) in CATALOG[i].image_sha256.chunks_exact(8).enumerate(){
            SMP_EVIDENCE.words[128+i*20+14+j].store(u64::from_le_bytes(chunk.try_into().unwrap()),Ordering::Relaxed);
        }
        SMP_EVIDENCE.words[128+i*20+18].store(u64::from(role_asid(i,r.bank)),Ordering::Relaxed);
        SMP_EVIDENCE.words[128+i*20+19].store(CATALOG[i].relative.len() as u64,Ordering::Relaxed);
        budget.coordinated(||report("V0199_BOOTSTRAP_ROLE",u64::from(m.role.id()),m.ttbr0_root,r.clocks));
        budget.coordinated(||report("V0199_BOOTSTRAP_CHARGE",u64::from(m.role.id()),r.charges,r.turns));
    }
    for slot in 1..REQUIRED{
        assert!(PROGRESS[slot*2].load(Ordering::Acquire)>=2);
        assert_eq!(PROGRESS[slot*2+1].load(Ordering::Acquire),0);
        budget.coordinated(||report("V0199_BOOTSTRAP_BUSINESS",slot as u64,PROGRESS[slot*2].load(Ordering::Acquire),0));
    }
    for gate in GATES.iter().take(REQUIRED).skip(1){close_gate(gate);}
    budget.wait_for(||(1..REQUIRED).all(|i|GATES[i].quiescent()));
    QUIT.store(true,Ordering::Release);
    budget.wait_for(||STOPPED.load(Ordering::Acquire)==14);
    check_failures();
    for slot in 1..REQUIRED{
        for (i,value) in [AFFINITIES[slot].load(Ordering::Acquire),
            PROGRESS[slot*2].load(Ordering::Acquire),PROGRESS[slot*2+1].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire)].into_iter().enumerate(){
            SMP_EVIDENCE.words[16+slot*4+i].store(value,Ordering::Relaxed);
        }
    }
    // Record a prefix, output all UART evidence (including the completion
    // marker), then take the terminal sample. The checker waits for the
    // post-output memory seal, not merely the UART marker.
    let (_,prefix_end)=budget.sample_gap();
    let prefix=timer::cpu_ns(prefix_end.checked_sub(budget.initial_tick).unwrap());
    let prefix_accounted=budget.ledger.lifetime_total().unwrap();
    let prefix_upper=budget.ledger.max_window_upper_ns();
    assert_eq!(prefix,prefix_accounted);
    for (i,v) in [prefix,prefix_accounted,prefix_upper].into_iter().enumerate(){
        SMP_EVIDENCE.words[40+i].store(v,Ordering::Relaxed);
    }
    budget.coordinated(||report("V0199_BOOTSTRAP_ACCOUNTING",prefix,prefix_accounted,prefix_upper));
    let summary=[MAGIC,9,0,15,1,14,8,0,0,0];
    for (i,v) in summary.into_iter().enumerate(){SMP_EVIDENCE.words[i].store(v,Ordering::Relaxed);}
    budget.coordinated(||super::super::log(b"V0199_EIGHT_PACKAGE_BOOTSTRAP_PASS cpus=4 roles=8 production=false\n"));
    let (sample_end_ns,end)=budget.sample_gap();
    let elapsed=timer::cpu_ns(end.checked_sub(budget.initial_tick).unwrap());
    let accounted=budget.ledger.lifetime_total().unwrap();
    let upper=budget.ledger.max_window_upper_ns();
    assert_eq!(elapsed,accounted);
    assert!(upper<=70_000_000&&!budget.ledger.ordinary_closed());
    let ledger_row=[elapsed,accounted,upper,budget.crossed_gaps,budget.initial_ns,sample_end_ns,
        budget.ledger.lifetime_spent(Class::Operations),budget.ledger.lifetime_spent(Class::Security),
        budget.ledger.lifetime_spent(Class::Decision),budget.ledger.lifetime_spent(Class::Coordination),
        budget.ledger.lifetime_spent(Class::Recovery),budget.ledger.lifetime_spent(Class::Optional)];
    for(i,value)in ledger_row.into_iter().enumerate(){SMP_EVIDENCE.words[481+i].store(value,Ordering::Relaxed);}
    SMP_EVIDENCE.words[2].store(1,Ordering::Release);
    super::super::halt()
}
