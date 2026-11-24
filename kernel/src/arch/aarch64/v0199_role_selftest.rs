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
    let ownership = Ownership::<C>::new_v0199_cpu0(
        profile::ONLINE, [1;C], core::array::from_fn(|i|1<<i),
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
        execute(&mut ctx,space);
        report("V0199_STAGE",20+index as u64,ctx.kind,ctx.esr);
        if ctx.kind!=8 || ctx.esr>>26!=0x15 || ctx.esr&0xffff!=4
            || ctx.regs[0]!=cookie(space)
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
