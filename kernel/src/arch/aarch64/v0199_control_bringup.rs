//! Native CPU0 ABI3 package bring-up, NOT a full production control plane.
//! Eight separately linked PIE images are copied, verified and loaded onto
//! private TTBR roots and 32KiB guarded stacks. Only the initialized
//! bootstrap syscall subset can run; missing durable BootEpoch and real
//! service authority explicitly deny new side effects. The workflow uses
//! the repository's pinned per-vCPU PMU patch, not stock QEMU accounting.
use super::*;
use cyxia_kernel_core::control_plane::{
    Identity,Error,
    role_manifest_v0199::{NativeRoleManifest,NativeRole,Role,ROLES,ROLE_COUNT,PrivateRegion,
        SnapshotView,AuxOperation,CONTROL_MASK,REQUIRED_ONLINE_MASK},
    pie_image_v0199::{RolePackageSpec,RolePackageInput,VerifiedRolePackage,ROLE_STACK_BYTES},
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
const DECISION_SLICE_NS:u64=100_000;
const E_AUTH:i64=-1;const E_FORMAT:i64=-2;const E_UNSUPPORTED:i64=-11;
const EFAULT:i64=-12;const EAGAIN:i64=-13;
const MAGIC:u64=0x4359_5838_424f_4f54;

struct BootPackage {role_id:u16,bytes:&'static[u8],image_sha256:[u8;32],relative_sha256:[u8;32]}
static CATALOG:[BootPackage;ROLE_COUNT]=include!(concat!(env!("OUT_DIR"),"/v0199-role-catalog.rs"));
#[repr(C,align(4096))]
struct Backing {image:[u8;IMAGE],stack:[u8;ROLE_STACK_BYTES]}
impl Backing{const ZERO:Self=Self{image:[0;IMAGE],stack:[0;ROLE_STACK_BYTES]};}
#[repr(C,align(4096))]
struct Tables {root:Page,mid:Page,leaf:Page}
impl Tables{const ZERO:Self=Self{root:Page::ZERO,mid:Page::ZERO,leaf:Page::ZERO};}
#[repr(align(4096))]
struct CopyBuffer([u8;COPY]);
static mut BACKING:[Backing;ROLE_COUNT]=[const{Backing::ZERO};ROLE_COUNT];
// A replacement uses a different physical root; the retired bank stays unmapped.
static mut TABLES:[Tables;2*ROLE_COUNT]=[const{Tables::ZERO};2*ROLE_COUNT];
static mut COPY_BUFFER:CopyBuffer=CopyBuffer([0;COPY]);
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
fn now_ns()->u64{
    let f=timer::frequency();
    assert!(f!=0);
    u64::try_from(u128::from(timer::ticks())*1_000_000_000/u128::from(f)).expect("monotonic ns")
}
fn ticks_for(ns:u64)->u64{
    u64::try_from((u128::from(ns)*u128::from(timer::frequency())).div_ceil(1_000_000_000))
        .expect("timer ticks").max(1)
}
/// Continuous attribution from the first post-bootstrap PMU sample through
/// the final diagnostic sample. Every interval is charged exactly once:
/// admitted role/recovery work or the protected EL1 coordination envelope.
/// Initial loading before PMU initialization and the final evidence writer
/// remain outside this explicitly bounded diagnostic measurement.
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
        Self{ledger:Cpu0BudgetLedger::new(),initial_tick:tick,initial_ns:wall,
            cursor:tick,wall,crossed_gaps:0}
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
    fn wait_for(&mut self,mut ready:impl FnMut()->bool){
        let until=now_ns().checked_add(5_000_000_000).unwrap();
        while !ready(){
            check_failures();
            if now_ns()>=until{fatal(688);}
            self.idle_until(now_ns().checked_add(1_000_000).unwrap());
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
    unsafe{core::ptr::addr_of_mut!(BACKING).cast::<Backing>().add(index)}
}
fn tables(index:usize,bank:usize)->*mut Tables{
    assert!(index<ROLE_COUNT&&bank<2);
    unsafe{core::ptr::addr_of_mut!(TABLES).cast::<Tables>().add(bank*ROLE_COUNT+index)}
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
fn sync_code(addr:u64,bytes:usize){
    let ctr:u64;
    unsafe{core::arch::asm!("mrs {}, ctr_el0",out(reg)ctr,options(nomem,nostack));}
    let line=4usize<<((ctr>>16)&15);
    assert!(line.is_power_of_two() && line<=PAGE);
    for off in (0..bytes).step_by(line){
        unsafe{core::arch::asm!("dc cvau, {}",in(reg)addr+off as u64,options(nostack));}
    }
    unsafe{core::arch::asm!("dsb ish","ic ialluis","dsb ish","isb",options(nostack));}
}
fn tlbi(){
    unsafe{core::arch::asm!("dsb ishst","tlbi vmalle1is","dsb ish","isb",options(nostack));}
}
fn seal_page(pa:u64){
    let leaf=high_leaf(pa);
    let old=unsafe{core::ptr::read_volatile(leaf)};
    assert_eq!(old,pa|0x0060_0000_0000_0703);
    // Real break-before-make; secondary business cores never own these
    // pages, but stale direct-map translations are invalidated globally.
    unsafe{core::ptr::write_volatile(leaf,0);}
    tlbi();
    unsafe{core::ptr::write_volatile(leaf,old|(1<<7));}
    tlbi();
}
fn load(index:usize,generation:u64,bank:usize)->(NativeRole,Running){
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
    let scratch=unsafe{&mut *core::ptr::addr_of_mut!(COPY_BUFFER.0)};
    scratch[..pkg.bytes.len()].copy_from_slice(pkg.bytes);
    let spec=RolePackageSpec{role,package_id:u64::from(role.id()),abi:3,image_bytes:pkg.bytes.len(),
        image_sha256:pkg.image_sha256,relative_count:0,relative_sha256:pkg.relative_sha256,
        stack_bytes:ROLE_STACK_BYTES};
    let verified=VerifiedRolePackage::verify(spec,RolePackageInput{package_id:spec.package_id,
        bytes:&scratch[..pkg.bytes.len()],relative:&[]}).expect("trusted ABI3 role package");
    assert!(verified.relro().is_none(),"bootstrap loader cannot silently skip RELRO");
    let image=unsafe{&mut *core::ptr::addr_of_mut!((*b).image)};
    let entry=verified.stage(image,BASE,BASE,BASE+IMAGE as u64).expect("private PIE stage");
    let stack=unsafe{&mut *core::ptr::addr_of_mut!((*b).stack)};
    stack.fill(0);
    assert!(stack.iter().all(|&v|v==0));
    let mut map=[0u8;IMAGE/PAGE];
    for seg in verified.load_segments(){
        let start=seg.virtual_address as usize/PAGE;
        let end=(seg.virtual_address+seg.memory_bytes).div_ceil(PAGE as u64) as usize;
        assert!(start<end&&end<=map.len());
        for page in &mut map[start..end]{assert_eq!(*page,0);*page=seg.flags as u8;}
    }
    scratch.fill(0);
    let image_base=b as u64;
    sync_code(image_base,IMAGE);
    unsafe{
        (*t).root.0[0]=phys(core::ptr::addr_of!((*t).mid) as u64)|3;
        (*t).mid.0[0]=phys(core::ptr::addr_of!((*t).leaf) as u64)|3;
    }
    for (i,flags) in map.into_iter().enumerate(){
        if flags==0{continue;}
        let pa=phys(image_base+i as u64*PAGE as u64);
        let write=flags&2!=0;let execute=flags&1!=0;
        if !write{seal_page(pa);}
        let desc=mmu::encode_user_leaf(PhysAddr(pa),write,execute).unwrap();
        unsafe{(*t).leaf.0[BASE as usize/PAGE+i]=desc;}
    }
    let stack_base=unsafe{core::ptr::addr_of!((*b).stack) as u64};
    for i in 0..ROLE_STACK_BYTES/PAGE{
        let pa=phys(stack_base+i as u64*PAGE as u64);
        unsafe{(*t).leaf.0[STACK_BASE as usize/PAGE+i]=mmu::encode_user_leaf(PhysAddr(pa),true,false).unwrap();}
    }
    // Guard and image holes have never had user mappings.
    assert_eq!(unsafe{(*t).leaf.0[STACK_BASE as usize/PAGE-1]},0);
    tlbi();
    let member=NativeRole{role,actor,ttbr0_root:root_pa(index,bank),
        // Charge the full physically reserved image, including its RX/RO
        // pages and holes, not only mapped RW bytes.
        private_rw:PrivateRegion{base:phys(b as u64),bytes:core::mem::size_of::<Backing>() as u64},
        caps:role.allowed_caps(),control_ns_per_100ms:ROLE_QUOTAS[index],
        cpu_mask:CONTROL_MASK,thread_count:1,endpoint_id:endpoint};
    let mut context=user::Context::empty();
    context.pc=entry;context.sp=STACK_END;
    context.regs[0]=cap.selector;
    context.regs[1]=0; // no authorized target exists before persistent boot verification
    context.regs[2]=actor.generation;
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
fn capture_model_probe(index:usize,r:&Running,actor:Identity){
    assert!(index<2&&matches!(actor.generation,1|2));
    const OFFSET:usize=0xf000;
    let address=backing(index) as u64+OFFSET as u64;
    let t=tables(index,r.bank);
    let pte=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*t).leaf.0[(BASE as usize+OFFSET)/PAGE]))};
    mmu::checked_user_leaf_span(pte,PhysAddr(phys(address)),0,32,true).expect("private probe result ownership");
    let row:[u64;4]=core::array::from_fn(|i|unsafe{((address as *const u64).add(i)).read_volatile()});
    assert_eq!(row[0],0x4359_4d4c_5052_4f42);
    assert_eq!(row[1],actor.generation);
    let at=493+index*8+(actor.generation as usize-1)*4;
    assert_eq!(SMP_EVIDENCE.words[at].load(Ordering::Relaxed),0);
    for(i,v)in row.into_iter().enumerate(){SMP_EVIDENCE.words[at+i].store(v,Ordering::Relaxed);}
}
/// Actual SVC64 dispatch for this deliberately restricted bootstrap profile.
/// Full production cap issuance, boot identity, IPC and service backend
/// are absent, so no publication, inference authorization or audit ACK is
/// fabricated. Identity derives from the selected EL1 context, never x0.
fn dispatch(index:usize,m:&NativeRoleManifest,r:&mut Running)->bool{
    let member=m.members[index];
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
fn turn(index:usize,m:&NativeRoleManifest,r:&mut Running,budget:&mut BudgetMeter,expect_fault:bool)->bool{
    let (now,began)=budget.sample_gap();if now<r.wake_ns{return false;}
    let (class,domain,quota)=class(m.members[index].role);
    let token=match budget.ledger.reserve_role_with_wall(m,m.members[index].actor,cpu::slot(),class,domain,quota,50_000_000,now){
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
    for _ in 0..trap_limit{
        let actual=timer::cpu_elapsed_ns(began);
        let wall=now_ns();
        let cpu_left=quota.saturating_sub(actual);
        let wall_left=token.deadline_ns().saturating_sub(wall);
        if cpu_left<=TURN_EXIT_GUARD_NS||wall_left<=TURN_EXIT_GUARD_NS{break;}
        let mut interval=(cpu_left-TURN_EXIT_GUARD_NS).min(wall_left-TURN_EXIT_GUARD_NS);
        if class==Class::Decision{interval=interval.min(DECISION_SLICE_NS);}
        unsafe{
            timer::arm(timer::ticks().checked_add(ticks_for(interval)).unwrap());
            let root=m.members[index].ttbr0_root;
            assert_eq!(root,root_pa(index,r.bank));
            // Each live root is immutable, private, and all leaves are nG.
            // Retire_root disconnects it and completes TLBI before reclaim.
            user::enter_pinned_until_retired(&mut r.context,root,role_asid(index,r.bank));
            cpu::disable_timer();
        }
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
        if parked{break;}
    }
    let receipt=budget.settle(token,began);
    r.charges=r.charges.checked_add(receipt.actual_ns).unwrap();r.turns+=1;
    if receipt.overrun||receipt.crossed_window{
        report("V0199_BOOTSTRAP_OVERRUN",m.members[index].role.id() as u64,receipt.actual_ns,quota);
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
    let t=tables(index,bank);
    unsafe{core::ptr::write_volatile(core::ptr::addr_of_mut!((*t).root.0[0]),0);}
    tlbi();
    // Root disconnected and context returned; all former leaf entries are
    // now inaccessible. This is not proof of a general production DMA join.
    unsafe{
        core::ptr::write_bytes(core::ptr::addr_of_mut!((*t).mid.0).cast::<u8>(),0,PAGE);
        core::ptr::write_bytes(core::ptr::addr_of_mut!((*t).leaf.0).cast::<u8>(),0,PAGE);
    }
    let b=backing(index) as u64;
    for offset in (0..IMAGE).step_by(PAGE){
        let pa=phys(b+offset as u64);
        let leaf=high_leaf(pa);
        let rw=pa|0x0060_0000_0000_0703;
        let old=unsafe{core::ptr::read_volatile(leaf)};
        assert!(old==rw||old==rw|(1<<7));
        if old!=rw{
            unsafe{core::ptr::write_volatile(leaf,0);}tlbi();
            unsafe{core::ptr::write_volatile(leaf,rw);}tlbi();
        }
    }
    let bytes=unsafe{core::slice::from_raw_parts_mut(b as *mut u8,IMAGE+ROLE_STACK_BYTES)};
    bytes.fill(0);
    assert!(bytes.iter().all(|&v|v==0));
}
fn restart_each(manifest:&mut NativeRoleManifest,running:&mut[Running;ROLE_COUNT],
    budget:&mut BudgetMeter)
{
    use cyxia_kernel_core::control_plane::service_restart::{Lifecycle,RestartDecision};
    let until=now_ns().checked_add(15_000_000_000).unwrap();
    for i in 0..ROLE_COUNT{
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
            let _=turn(i,manifest,&mut running[i],budget,true);
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
                let _=turn(j,manifest,&mut running[j],budget,false);
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
        let (credit,start)=loop{
            let (now,start)=budget.sample_gap();if now>=until{fatal(682);}
            if now%WINDOW_NS>WINDOW_NS-10_000_000{budget.idle_retry();continue;}
            match budget.ledger.reserve_kernel_with_wall(0,Class::Recovery,8_000_000,50_000_000,now){
                Ok(t)=>break (t,start),
                Err(Error::Exhausted|Error::Busy)=>{budget.idle_retry();continue;},
                Err(e)=>panic!("recovery reservation: {e:?}"),
            }
        };
        retire_root(i,old_bank);
        let (member,new)=load(i,next,1);
        assert!(member.ttbr0_root!=old_root&&member.actor.generation==next);
        assert_eq!(unsafe{(*tables(i,old_bank)).root.0[0]},0);
        assert!(old_cap.selector==0||new.cap.selector!=old_cap.selector);
        manifest.members[i]=member;
        manifest.validate().unwrap();
        let receipt=budget.settle(credit,start);
        let actual=receipt.actual_ns;
        if receipt.overrun||receipt.crossed_window{
            report("V0199_BOOTSTRAP_OVERRUN",old.role.id() as u64,receipt.actual_ns,8_000_000);
            fatal(683);
        }
        life.reset_complete(1,next).unwrap();
        running[i]=new;
        while running[i].clocks<2||running[i].role_calls<2{
            if now_ns()>=until{fatal(684);}
            if now_ns()%WINDOW_NS>WINDOW_NS-5_000_000{budget.idle_retry();continue;}
            let turns=running[i].turns;
            let _=turn(i,manifest,&mut running[i],budget,false);
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
pub(super) fn run()->!{
    assert_eq!(cpu::slot(),0);assert_eq!(ONLINE.load(Ordering::Acquire),15);
    let pairs:[(NativeRole,Running);ROLE_COUNT]=core::array::from_fn(|i|load(i,1,0));
    let members=core::array::from_fn(|i|pairs[i].0);
    let mut running=pairs.map(|(_,r)|r);
    let mut manifest=NativeRoleManifest{
        online_mask:REQUIRED_ONLINE_MASK,members,
        // Full statically reserved pages, copy scratch and a conservative
        // one-MiB bootstrap metadata allowance inside the control pool.
        other_protected_pool_bytes:core::mem::size_of::<[Tables;2*ROLE_COUNT]>()+COPY+1024*1024,
        other_control_ns_per_100ms:OTHER_CPU_NS,
    };
    manifest.validate().expect("complete eight role physical inventory");
    wait(||(1..REQUIRED).all(|slot|PROGRESS[slot*2].load(Ordering::Acquire)>=2));
    gic().enable(TIMER_IRQ.load(Ordering::Acquire) as u32).unwrap();
    unsafe{timer::init_cpu_accounting();}
    let mut budget=BudgetMeter::new();
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
            let _=turn(i,&manifest,&mut running[i],&mut budget,false);
            ran|=running[i].turns!=turns;
        }
        if !ran{budget.idle_retry();}
    }
    report("V0199_BOOTSTRAP_INITIAL_ROLES",ROLE_COUNT as u64,0,0);
    restart_each(&mut manifest,&mut running,&mut budget);
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
            let _=turn(i,&manifest,&mut running[i],&mut budget,false);
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
            report("V0199_MODEL_PROBE",u64::from(role.id()),generation as u64,
                SMP_EVIDENCE.words[at+2].load(Ordering::Relaxed));
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
        report("V0199_BOOTSTRAP_ROLE",u64::from(m.role.id()),m.ttbr0_root,r.clocks);
        report("V0199_BOOTSTRAP_CHARGE",u64::from(m.role.id()),r.charges,r.turns);
    }
    for slot in 1..REQUIRED{
        assert!(PROGRESS[slot*2].load(Ordering::Acquire)>=2);
        assert_eq!(PROGRESS[slot*2+1].load(Ordering::Acquire),0);
        report("V0199_BOOTSTRAP_BUSINESS",slot as u64,PROGRESS[slot*2].load(Ordering::Acquire),0);
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
    report("V0199_BOOTSTRAP_ACCOUNTING",elapsed,accounted,upper);
    let summary=[MAGIC,6,0,15,1,14,8,0,0,0]; // durable BootEpoch / actual publish / G0 all false
    for (i,v) in summary.into_iter().enumerate(){SMP_EVIDENCE.words[i].store(v,Ordering::Relaxed);}
    SMP_EVIDENCE.words[2].store(1,Ordering::Release);
    super::super::log(b"V0199_EIGHT_PACKAGE_BOOTSTRAP_PASS cpus=4 roles=8 production=false\n");
    super::super::halt()
}
