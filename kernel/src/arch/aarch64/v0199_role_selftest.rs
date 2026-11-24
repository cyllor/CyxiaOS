//! G0 *mechanism-only* real guest EL0 role/TTBR fixture.
//!
//! This proves CPU0 actually enters 8 distinct native EL0 address spaces
//! while CPU1..3 run only business fixtures, under the pinned four-vCPU QEMU.
//! Every role executes the SAME audited read-only counter program, not the
//! full operating/safety/controller/learner application binaries. The test
//! does NOT establish an actual 8-service boot, full AI control budget, SVC
//! ABI v3, G4's 127 IDs or real A53 architecture correctness.
use super::*;
use cyxia_kernel_core::control_plane::{
    Identity,
    cpu0_v0199 as profile,
    role_manifest_v0199::{
        NativeRole, NativeRoleManifest, PrivateRegion, ROLES, ROLE_COUNT,
    },
};

const FIRST_ROLE_SPACE: usize = C * 2;

// The fixture exclusively owns all three page-table levels and its data/
// stack pages. This bounded adapter checks their actual descriptors before
// constructing a high-half kernel address. It is NOT a production VA walker:
// only the three statically registered fixture pages may be accessed.
fn copy_address(space:usize,va:u64,bytes:usize,write:bool)->Option<(u64,u64)>{
    if space>=PRIVATE_SPACES{return None;}
    let page=va & !4095;
    let offset=va & 4095;
    let (root,mid,leaf,base)=unsafe{
        let root=core::ptr::addr_of!(ROOTS).cast::<Page>().add(space);
        let mid=core::ptr::addr_of!(MIDDLES).cast::<Page>().add(space);
        let leaf=core::ptr::addr_of!(LEAVES).cast::<Page>().add(space);
        let base=match page {
            CODE=>core::ptr::addr_of!(smp_user_start) as u64,
            DATA=>core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(space) as u64,
            STACK=>core::ptr::addr_of!(USER_STACKS).cast::<Page>().add(space) as u64,
            _=>return None,
        };
        (root,mid,leaf,base)
    };
    let root_desc=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*root).0[0]))};
    let mid_desc=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*mid).0[0]))};
    if root_desc!=(phys(mid as u64)|3) || mid_desc!=(phys(leaf as u64)|3){return None;}
    let desc=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*leaf).0[(page/4096) as usize]))};
    let pa=mmu::checked_user_leaf_span(desc,PhysAddr(phys(base)),offset,bytes,write).ok()?;
    Some((base.checked_add(offset)?,pa.0))
}

pub(super) fn run() -> ! {
    assert_eq!(cpu::slot(), 0, "only boot CPU0 can own control EL0 role turns");
    assert_eq!(PRIVATE_SPACES, FIRST_ROLE_SPACE + ROLE_COUNT);
    assert_eq!(ONLINE.load(Ordering::Acquire), profile::ONLINE);
    report("V0199_STAGE",1,0,0);
    let fixed_limits = Limits {
        resource_epoch: 1,
        min_control_cores: 1,
        min_control_capacity: 1,
        min_business_capacity: 3,
        committed_business_capacity: 3,
        protected_control: profile::CONTROL_MASK,
        protected_business: profile::BUSINESS_MASK,
        cooldown_ticks: 0,
    };
    // BOOT_CPUS is the 8-slot platform capacity table. The QEMU contract is
    // exactly REQUIRED=4 online vCPUs; do not pass the larger slot capacity
    // as the instantiated native SMP ownership topology.
    let ownership = Ownership::<REQUIRED>::new_v0199_cpu0(
        profile::ONLINE, [1;REQUIRED], core::array::from_fn(|i|1<<i),
        fixed_limits,
    ).expect("fixed CPU0 control ownership");
    let snapshot=ownership.snapshot();
    profile::validate_snapshot(snapshot).expect("single CPU0 + three business cores");
    report("V0199_STAGE",2,snapshot.control,snapshot.business);
    assert_eq!(snapshot.control, 1);
    assert_eq!(snapshot.business, 14);

    // The role manifests are created from EL1-owned actual physical TTBR
    // tables and exclusive data pages, never from model/advice bytes.
    let members = core::array::from_fn(|index| {
        let space=FIRST_ROLE_SPACE+index;
        let root=unsafe {
            core::ptr::addr_of!(ROOTS).cast::<Page>().add(space) as u64
        };
        let data=unsafe {
            core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(space) as u64
        };
        NativeRole {
            role:ROLES[index],
            actor:Identity {
                id:ROLES[index].id() as u64, generation:1,
            },
            ttbr0_root:phys(root),
            private_rw:PrivateRegion {
                base:phys(data), bytes:4096,
            },
            caps:ROLES[index].allowed_caps(),
            control_ns_per_100ms:2_000_000,
            cpu_mask:profile::CONTROL_MASK,
            thread_count:1,
            endpoint_id:0xC000+index as u64,
        }
    });
    let manifest=NativeRoleManifest {
        online_mask:profile::ONLINE,
        members,
        other_protected_pool_bytes:5*1024*1024,
        other_control_ns_per_100ms:45_000_000,
    };
    manifest.validate().expect("8 distinct native TTBR/role/capability entries");
    report("V0199_STAGE",3,manifest.members[0].ttbr0_root,manifest.members[0].private_rw.base);
    // Unlike the legacy CPU1 fixture, the controller is CPU0 itself.
    // CPU1..3 are already running their own guest EL0 business loop.
    wait(||(1..REQUIRED).all(|slot| {
        PROGRESS[slot*2].load(Ordering::Acquire)>=2
    }));
    report("V0199_STAGE",4,PROGRESS[2].load(Ordering::Acquire),PROGRESS[4].load(Ordering::Acquire));
    gic().enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 native timer PPI must be enabled");
    report("V0199_STAGE",5,TIMER_IRQ.load(Ordering::Acquire),0);

    for index in 0..ROLE_COUNT {
        let space=FIRST_ROLE_SPACE+index;
        let m=manifest.members[index];
        manifest.can_act(m.role,m.actor,m.caps & m.caps.wrapping_neg(),0)
            .expect("real CPU0 role endpoint admission");
        let mut ctx=context(space);
        ctx.regs[2]=4; // immutable bounded EL0 loop + SVC #4 yield
        let root=m.ttbr0_root;
        assert!(root!=0 && root%4096==0);
        // Dedicated per-role TTBR0 + writable data and stack, shared RX code.
        report("V0199_STAGE",10+index as u64,m.role.id() as u64,m.ttbr0_root);
        let mut finished=false;
        for turn in 0..32 {
            // A real per-core PPI may preempt a user context before its
            // bounded SVC #4. The context/TTBR/FP bank must be restored,
            // not treated as an EL0 failure or restarted from its entry PC.
            execute(&mut ctx,space);
            if ctx.kind==9 {
                report("V0199_CPU0_PREEMPT",m.role.id() as u64,turn as u64,IRQS[0].load(Ordering::Acquire));
                continue;
            }
            if ctx.kind==8 && ctx.esr>>26==0x15 && ctx.esr&0xffff==4 {
                finished=true;
                break;
            }
            fatal(101+index as u64);
        }
        report("V0199_STAGE",20+index as u64,ctx.kind,ctx.esr);
        if !finished || ctx.regs[0]!=cookie(space)
            || ctx.tpidr_el0!=cookie(space)
        {fatal(101+index as u64);}
        let data=unsafe {
            core::ptr::addr_of!(DATA_PAGES)
                .cast::<Page>().add(space)
        };
        let count=unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!((*data).0[1]))
        };
        if count==0 {fatal(121+index as u64);}
        // A role must not observe or mutate another role's private DATA page.
        for other in index+1..ROLE_COUNT {
            let other_page=unsafe {
                core::ptr::addr_of!(DATA_PAGES).cast::<Page>()
                    .add(FIRST_ROLE_SPACE+other)
            };
            let observed=unsafe {
                core::ptr::read_volatile(core::ptr::addr_of!((*other_page).0[1]))
            };
            if observed!=0 {fatal(140+other as u64);}
        }
        let position=128+index*8;
        for (at,value) in [
            m.role.id() as u64,
            m.actor.id,
            m.ttbr0_root,
            m.private_rw.base,
            m.endpoint_id,
            ctx.kind,
            ctx.esr,
            count,
        ].into_iter().enumerate() {
            SMP_EVIDENCE.words[position+at].store(value,Ordering::Relaxed);
        }
        report("V0199_CPU0_EL0_ROLE",m.role.id() as u64,root,count);
    }


    // Physical SVC64 boundary smoke: each case enters the actual EL0
    // operations-role address space, writes x8/arguments in assembly,
    // traps back through the exception vector and uses the saved context.
    // No userspace pointer is dereferenced and no service is executed.
    use cyxia_kernel_core::security::{syscall::Syscall, syscall_v3::decode_aarch64_svc_v3};
    for case in 0..7usize {
        let mut probe=context(FIRST_ROLE_SPACE);
        probe.regs[2]=6;
        probe.regs[3]=case as u64;
        let abi=if case==4 {1} else {3};
        let mut trapped=false;
        for _ in 0..32 {
            execute(&mut probe,FIRST_ROLE_SPACE);
            if probe.kind==9 {continue;}
            if probe.kind!=8 || probe.esr>>26!=0x15 {fatal(170+case as u64);}
            trapped=true;
            break;
        }
        if !trapped {fatal(180+case as u64);}
        let decoded=decode_aarch64_svc_v3(abi,probe.esr,&probe.regs);
        let accepted=matches!(decoded,Ok(call) if call.operation==Syscall::Clock);
        if accepted!=(case==0) || (case!=0 && decoded.is_ok()) {fatal(190+case as u64);}
        let offset=224+case*5;
        for (i,value) in [case as u64,u64::from(abi),probe.esr,probe.regs[8],u64::from(accepted)].into_iter().enumerate(){
            SMP_EVIDENCE.words[offset+i].store(value,Ordering::Relaxed);
        }
        report("V0199_SVC_PREFLIGHT",case as u64,probe.esr,u64::from(accepted));
    }

    // Four real SVC64 copy cases. Register preflight succeeds in all four;
    // only the actual writable/owned leaf proof permits the fixture echo.
    // No production file endpoint or control capability is granted.
    for case in 7..11usize{
        let mut probe=context(FIRST_ROLE_SPACE);
        probe.regs[2]=6;probe.regs[3]=case as u64;
        let mut trapped=false;
        for _ in 0..32{
            execute(&mut probe,FIRST_ROLE_SPACE);
            if probe.kind==9{continue;}
            if probe.kind!=8 || probe.esr>>26!=0x15{fatal(210+case as u64);}
            trapped=true;break;
        }
        if !trapped{fatal(220+case as u64);}
        let call=decode_aarch64_svc_v3(3,probe.esr,&probe.regs).expect("fixture copy SVC preflight");
        assert_eq!(call.operation,Syscall::ServiceCall);
        let input=copy_address(FIRST_ROLE_SPACE,call.args[1],8,false);
        let output=copy_address(FIRST_ROLE_SPACE,call.args[4],8,true);
        let mut evidence=[case as u64,probe.esr,0,0,0,0];
        if let (Some((src,ipa)),Some((dst,opa)))=(input,output){
            assert!(ipa+8<=opa || opa+8<=ipa);
            // Both mappings belong to this stopped context. Read and write
            // exclusively through the verified high-half aliases.
            let mut raw=[0u8;8];
            for (i,byte) in raw.iter_mut().enumerate(){
                *byte=unsafe{core::ptr::read_volatile((src+i as u64) as *const u8)};
            }
            let stable=cyxia_kernel_core::security::syscall::StableCopy::<8>::from_validated(&raw).unwrap();
            assert_eq!(stable.bytes(),&0x1234u64.to_le_bytes());
            for (i,&byte) in stable.bytes().iter().enumerate(){
                unsafe{core::ptr::write_volatile((dst+i as u64) as *mut u8,byte);}
            }
            let actual=unsafe{core::ptr::read_volatile(dst as *const u64)};
            assert_eq!(actual,0x1234);
            evidence=[case as u64,probe.esr,1,ipa,opa,actual];
        }
        assert_eq!(evidence[2],u64::from(case==7));
        for (at,value) in evidence.into_iter().enumerate(){
            SMP_EVIDENCE.words[272+(case-7)*6+at].store(value,Ordering::Relaxed);
        }
        report("V0199_SVC_COPY",case as u64,evidence[2],evidence[5]);
    }

    // Exercise all eight existing hardware address spaces, not only the
    // operations role. Each negative access must trap with the exact ESR/FAR;
    // then stop the old context, scrub exclusive data/stack and reenter.
    // This is a SAME-ROOT STATIC FIXTURE, not the production fault/rebuild
    // protocol (no durable epoch or capability registry is claimed).
    use cyxia_kernel_core::control_plane::service_restart::{Lifecycle,RestartDecision};
    let kernel_address=(core::ptr::addr_of!(BOOT_READY) as u64)&!7;
    for index in 0..ROLE_COUNT{
        let space=FIRST_ROLE_SPACE+index;
        let member=manifest.members[index];
        let role=u64::from(member.role.id());
        let mut life=Lifecycle::new(1,member.actor.generation).unwrap();
        life.peer_ready(1,member.actor.generation).unwrap();
        let before:[u64;ROLE_COUNT]=core::array::from_fn(|i|unsafe{
            let p=core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(FIRST_ROLE_SPACE+i);
            core::ptr::read_volatile(core::ptr::addr_of!((*p).0[1]))
        });
        for (case,(mode,address,ec,fsc)) in [
            (1,kernel_address,0x24,0x0f),
            (1,0x40000,0x24,0x07),
            (2,CODE,0x24,0x4f),
            (3,DATA,0x20,0x0f),
            (2,STACK-4096,0x24,0x47),
        ].into_iter().enumerate(){
            let mut ctx=context(space);ctx.regs[1]=address;ctx.regs[2]=mode;
            let mut trapped=false;
            for _ in 0..32{
                execute(&mut ctx,space);
                if ctx.kind==9{continue;}
                if ctx.kind!=8 || ctx.esr>>26!=ec || ctx.far!=address || ctx.esr&0x7f!=fsc{
                    fatal(300+index as u64);
                }
                trapped=true;break;
            }
            if !trapped{fatal(310+index as u64);}
            let at=304+index*15+case*3;
            for (i,value) in [ctx.kind,ctx.esr,ctx.far].into_iter().enumerate(){
                SMP_EVIDENCE.words[at+i].store(value,Ordering::Relaxed);
            }
            report("V0199_ROLE_FAULT",role,case as u64,ctx.esr);
        }
        // The old context has returned through the real exception vector,
        // and the fixture never dispatches it again. No other CPU owns its
        // static private pages. A component generation transition does not
        // certify real production device/capability/epoch reconciliation.
        let old=member.actor.generation;
        let next=match life.fault(1,old).unwrap(){
            RestartDecision::Restart{generation}=>generation,
            RestartDecision::Isolate=>fatal(320+index as u64),
        };
        assert_eq!(next,old+1);
        assert!(!life.accepts(1,old) && !life.accepts(1,next));
        assert!(life.reset_complete(1,old).is_err());
        let (data,stack)=unsafe{
            let data=core::ptr::addr_of_mut!(DATA_PAGES).cast::<Page>().add(space);
            let stack=core::ptr::addr_of_mut!(USER_STACKS).cast::<Page>().add(space);
            // These pages are exclusive to the stopped CPU0 fixture context;
            // write and independently read back every physical word.
            for word in 0..512{
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*data).0[word]),0);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*stack).0[word]),0);
            }
            (data,stack)
        };
        let mut scrubbed=0u64;
        for word in 0..512{
            let pair=unsafe{
                (core::ptr::read_volatile(core::ptr::addr_of!((*data).0[word])),
                 core::ptr::read_volatile(core::ptr::addr_of!((*stack).0[word])))
            };
            if pair!=(0,0){fatal(330+index as u64);}
            scrubbed+=16;
        }
        unsafe{
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data).0[0]),cookie(space));
            core::arch::asm!("dsb ishst",options(nostack));
        }
        life.reset_complete(1,next).unwrap();
        let mut restarted=context(space);restarted.regs[2]=4;
        let mut resumed=false;
        for _ in 0..32{
            execute(&mut restarted,space);
            if restarted.kind==9{continue;}
            if restarted.kind!=8 || restarted.esr>>26!=0x15 || restarted.esr&0xffff!=4{
                fatal(340+index as u64);
            }
            resumed=true;break;
        }
        if !resumed || restarted.regs[0]!=cookie(space) || restarted.tpidr_el0!=cookie(space){
            fatal(350+index as u64);
        }
        life.peer_ready(1,next).unwrap();
        assert!(life.ready() && life.accepts(1,next) && !life.accepts(1,old));
        let count=unsafe{core::ptr::read_volatile(core::ptr::addr_of!((*data).0[1]))};
        assert_eq!(count,16);
        for other in 0..ROLE_COUNT{
            if other!=index{
                let observed=unsafe{
                    let p=core::ptr::addr_of!(DATA_PAGES).cast::<Page>().add(FIRST_ROLE_SPACE+other);
                    core::ptr::read_volatile(core::ptr::addr_of!((*p).0[1]))
                };
                assert_eq!(observed,before[other]);
            }
        }
        let row=[role,old,next,scrubbed,restarted.kind,restarted.esr,count,
            member.ttbr0_root,u64::from(life.ready())];
        for (i,value) in row.into_iter().enumerate(){
            SMP_EVIDENCE.words[424+index*9+i].store(value,Ordering::Relaxed);
        }
        report("V0199_ROLE_RESTART",role,next,count);
    }

    // Prove all three business CPUs progressed while CPU0 owned the only
    // control EL0 role sequence. Do not promote CPU1 even if CPU0 stops.
    for slot in 1..REQUIRED {
        assert!(PROGRESS[slot*2].load(Ordering::Acquire)>=2);
        assert_eq!(PROGRESS[slot*2+1].load(Ordering::Acquire),0);
    }
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(||(1..REQUIRED).all(|slot| GATES[slot].quiescent()));
    QUIT.store(true,Ordering::Release);
    wait(||STOPPED.load(Ordering::Acquire)==14);
    check_failures();
    for slot in 1..REQUIRED {
        let at=16+slot*4;
        for (offset,value) in [
            AFFINITIES[slot].load(Ordering::Acquire),
            PROGRESS[slot*2].load(Ordering::Acquire),
            PROGRESS[slot*2+1].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
        ].into_iter().enumerate(){
            SMP_EVIDENCE.words[at+offset].store(value,Ordering::Relaxed);
        }
        report(
            "V0199_CPU0_BUSINESS",
            slot as u64,
            PROGRESS[slot*2].load(Ordering::Acquire),
            PROGRESS[slot*2+1].load(Ordering::Acquire)
        );
    }
    let summary=[
        0x4359_5856_3139_3939u64, // "CYXV1999" fixture marker
        1,
        0, // marked PASS only at the end
        15, // four online
        1, // fixed C
        14, // three business
        8, // EL0 role slots actually entered on CPU0
        0, // no business promotion
    ];
    for (i,value) in summary.into_iter().enumerate(){
        SMP_EVIDENCE.words[i].store(value,Ordering::Relaxed);
    }
    SMP_EVIDENCE.words[2].store(1,Ordering::Release);
    super::super::log(
        b"V0199_CPU0_EL0_ROLE_FIXTURE_SCOPE identical_fixture_code=true real_services=false\n"
    );
    super::super::log(b"V0199_CPU0_EL0_ROLE_FIXTURE_PASS cpus=4 roles=8\n");
    super::super::halt()
}
