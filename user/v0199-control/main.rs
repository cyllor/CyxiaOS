#![no_std]
#![no_main]
//! Native ABI v3 bootstrap clients. No historical SVC-immediate ABI.
//! These are the first independently linked role entrypoints. The unready
//! control service does not manufacture observations, models, plans or audit
//! ACKs. Production work must arrive through a verified input/service path.
use core::arch::asm;
#[cfg(control_role="11")]
mod audit;
#[cfg(all(snapshot_catalog_probe, any(control_role = "6", control_role = "11")))]
mod catalog;
#[cfg(all(file_read_probe, any(control_role = "6", control_role = "11")))]
mod file_read;
#[cfg(all(any(file_receipt_query_probe, file_fsync_probe), control_role = "11"))]
mod file_receipt;
#[cfg(all(file_fsync_probe, control_role = "11"))]
mod file_fsync;
#[cfg(model_operator_probe)]
#[path="../../crates/control-model/src/native_v0199.rs"]
mod brain;
#[cfg(model_operator_probe)]
#[path="../../crates/prototype/src/learning/seed.rs"]
mod probe_seed;

// Only this explicitly diagnostic package build contains test seed bytes.
// They are never admitted as a verified/trained Active model.
#[cfg(all(model_operator_probe,control_role="6"))]
static PROBE_PARAMETERS:[u8;2772]=probe_seed::UNTRAINED_SEED0_BYTES;
#[cfg(all(model_operator_probe,control_role="7"))]
static PROBE_PARAMETERS:[u8;2772]=probe_seed::untrained_seed_bytes(1);
#[cfg(model_operator_probe)]
#[used]
#[unsafe(link_section=".role_probe")]
static mut PROBE_RESULT:[u64;4]=[0;4];

#[cfg(model_operator_probe)]
fn model_probe(generation:u64){
    // Internal operator/codec test vector, NOT a live snapshot or durable
    // boot identity. Never submit it through Advice/Finding/Plan endpoints.
    let snapshot=brain::SnapshotReplyV3{
        snapshot_seq:2,boot_epoch:3,ledger_generation:4,core_generation:5,
        target_id:6,target_generation:7,sampled_ns:100,domain:if ROLE==6{1}else{12},
        fields:[Some(500),Some(1000),Some(32),Some(250),Some(750),None,Some(50000),None,
            Some(32),Some(64),Some(1),Some(1)],
    };
    let wire=snapshot.encode().unwrap();
    let snapshot=brain::SnapshotReplyV3::decode(core::hint::black_box(&wire)).unwrap();
    let parameters=core::hint::black_box(&PROBE_PARAMETERS);
    #[cfg(control_role="6")]
    let (scores,selection)={
        let a=brain::Candidate{a1:1,a2:None,cpu:[None;4]};
        let out=brain::score_operations(&snapshot,&[a,brain::Candidate{a1:8,..a}],parameters).unwrap();
        (u64::from(out.scores[0] as u16)|(u64::from(out.scores[1] as u16)<<16),
            u64::from(out.recommended_index))
    };
    #[cfg(control_role="7")]
    let (scores,selection)={
        let (score,severity)=brain::score_security(&snapshot,1,0xf00,parameters).unwrap();
        (u64::from(score as u16),u64::from(severity))
    };
    // The stopped role's actual RW page is observed by the native checker.
    // No extra SVC or production ABI field is introduced by this probe.
    let row=[0x4359_4d4c_5052_4f42,generation,scores,selection];
    let p=core::ptr::addr_of_mut!(PROBE_RESULT).cast::<u64>();
    for (i,v) in row.into_iter().enumerate(){unsafe{p.add(i).write_volatile(v)}}
}
#[cfg(any(control_role="6",control_role="7",control_role="11"))]
#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dst:*mut u8,src:*const u8,n:usize)->*mut u8{
    for i in 0..n{unsafe{dst.add(i).write_volatile(src.add(i).read_volatile())}}
    dst
}
#[cfg(any(control_role="6",control_role="7",control_role="11"))]
#[unsafe(no_mangle)]
unsafe extern "C" fn memset(dst:*mut u8,v:i32,n:usize)->*mut u8{
    for i in 0..n{unsafe{dst.add(i).write_volatile(v as u8)}}
    dst
}
#[cfg(control_role="11")]
#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(a:*const u8,b:*const u8,n:usize)->i32{
    for i in 0..n {
        let x=unsafe {a.add(i).read_volatile()};
        let y=unsafe {b.add(i).read_volatile()};
        if x!=y {return i32::from(x)-i32::from(y);}
    }
    0
}
#[cfg(control_role="11")]
#[unsafe(no_mangle)]
unsafe extern "C" fn bcmp(a:*const u8,b:*const u8,n:usize)->i32{
    unsafe {memcmp(a,b,n)}
}
#[cfg(control_role="6")] const ROLE:u16=6;
#[cfg(control_role="7")] const ROLE:u16=7;
#[cfg(control_role="2")] const ROLE:u16=2;
#[cfg(control_role="8")] const ROLE:u16=8;
#[cfg(control_role="9")] const ROLE:u16=9;
#[cfg(control_role="3")] const ROLE:u16=3;
#[cfg(control_role="10")] const ROLE:u16=10;
#[cfg(control_role="11")] const ROLE:u16=11;
// Build artifact identity, not authorization. It is pinned by the trusted
// manifest hash; the kernel never derives the current actor from this word.
#[used]
#[unsafe(link_section=".rodata.role")]
static ROLE_NOTE:[u8;8]=[b'C',b'Y',b'R',b'3',ROLE as u8,3,0,0];

#[inline(always)]
fn call(no:u64,a:[u64;6])->i64{
    let [mut x0,x1,x2,x3,x4,x5]=a;
    // The frozen ABI returns a single signed x0 and has an explicit memory
    // clobber for stable copy-in/out. No pointer is passed to a host agent.
    unsafe{asm!("svc #0",inlateout("x0")x0,in("x1")x1,in("x2")x2,
        in("x3")x3,in("x4")x4,in("x5")x5,in("x8")no,options(nostack));}
    x0 as i64
}
fn clock()->i64{call(4,[0;6])}
fn yield_now(){let _=call(2,[0;6]);}
fn put16(b:&mut[u8],at:usize,v:u16){b[at..at+2].copy_from_slice(&v.to_le_bytes());}
fn put32(b:&mut[u8],at:usize,v:u32){b[at..at+4].copy_from_slice(&v.to_le_bytes());}
fn put64(b:&mut[u8],at:usize,v:u64){b[at..at+8].copy_from_slice(&v.to_le_bytes());}
fn snapshot(cap:u64,target:u64,domain:u64)->i64{
    let mut reply=[0u8;264];
    let result=call(0x40,[cap,domain,target,reply.as_mut_ptr() as u64,264,0]);
    // No model inference is started until a production snapshot, immutable
    // model/config and a frozen candidate/evidence context are all available.
    // This bootstrap deliberately does not accept a partially filled reply.
    core::hint::black_box((result,reply[0])).0
}
#[cfg(control_role="6")]
fn role_step(cap:u64,target:u64,_generation:u64,_now:u64){snapshot(cap,target,1);}
#[cfg(control_role="7")]
fn role_step(cap:u64,target:u64,_generation:u64,_now:u64){snapshot(cap,target,12);}
#[cfg(control_role="2")]
fn role_step(cap:u64,target:u64,_generation:u64,_now:u64){snapshot(cap,target,1);}
#[cfg(control_role="8")]
fn role_step(_cap:u64,_target:u64,_generation:u64,now:u64){
    // Publication requires a real registered PlanKey/sidecar from role2.
    // There is no key at bootstrap: wait, do not publish an empty plan.
    let _=call(3,[now.saturating_add(1_000_000),0,0,0,0,0]);
}
#[cfg(control_role="9")]
fn role_step(_cap:u64,_target:u64,_generation:u64,now:u64){
    // No frozen candidate input/validation token yet.
    let _=call(3,[now.saturating_add(2_000_000),0,0,0,0,0]);
}
#[cfg(control_role="3")]
fn role_step(_cap:u64,_target:u64,_generation:u64,now:u64){
    // Never request promotion or D15 trial without an actual permit.
    let _=call(3,[now.saturating_add(3_000_000),0,0,0,0,0]);
}
#[cfg(control_role="10")]
fn role_step(_cap:u64,_target:u64,_generation:u64,now:u64){
    // No authorized replay/feedback or candidate memory allocation.
    let _=call(3,[now.saturating_add(4_000_000),0,0,0,0,0]);
}
#[cfg(all(control_role="11", not(file_receipt_query_probe)))]
fn role_step(cap:u64,_target:u64,generation:u64,now:u64){
    // Canonical AUDIT_READ op1. Read is non-consuming; an unready boot
    // has no durable audit identity. No fabricated ACK or cursor advance.
    let mut req=[0u8;64];let mut out=[0u8;192];
    put32(&mut req,0,0x43594351);put16(&mut req,4,1);put16(&mut req,6,48);
    put16(&mut req,8,1);put32(&mut req,12,16);put64(&mut req,16,1);
    put64(&mut req,32,generation);put64(&mut req,40,now.saturating_add(50_000_000));
    put64(&mut req,48,generation);
    let result=call(0x50,[cap,req.as_ptr() as u64,64,0,out.as_mut_ptr() as u64,192]);
    core::hint::black_box((result,out[0]));
}
#[unsafe(no_mangle)]
#[unsafe(link_section=".text.entry")]
extern "C" fn _start(arg_va:u64,args_len:u64)->!{
    // x0/x1 follow ABI3 SpawnRequest. This package's 24-byte startup
    // payload is copied to the owned stack by EL1; the data itself is
    // never proof of authority. Copy before the first syscall.
    // Avoid formatting/assert_eq! paths from the non-PIC prebuilt core
    // in this freestanding PIE entry. Invalid args terminate fail-closed.
    if args_len!=24||arg_va==0||arg_va%16!=0{reject_startup();}
    let p=arg_va as *const u64;
    let cap=u64::from_le(unsafe{p.read_volatile()});
    let target=u64::from_le(unsafe{p.add(1).read_volatile()});
    let generation=u64::from_le(unsafe{p.add(2).read_volatile()});
    if generation==0{reject_startup();}
    #[cfg(model_operator_probe)]
    model_probe(generation);
    #[cfg(all(control_role = "6", file_read_probe))]
    file_read::probe_operations(cap, target);
    #[cfg(all(control_role = "6", snapshot_catalog_probe))]
    catalog::probe_operations(cap, target);
    #[cfg(all(file_fsync_probe, control_role = "11"))]
    {
        if target != 0 {
            // Preserve the early audit refusal in a combined live-control run.
            let now = clock();
            if now >= 0 { role_step(cap,target,generation,now as u64); }
        }
        file_fsync::run();
    }
    #[cfg(control_role="11")]
    if target != 0 { audit::run(cap,target,generation); }
    #[cfg(all(file_receipt_query_probe, control_role = "11"))]
    file_receipt::run();
    #[cfg(not(all(file_receipt_query_probe, control_role = "11")))]
    loop{
        if cfg!(audit_full_idle) {
            // The full audit fixture only drives the Supervisor. Keep the
            // other signed roles resident without unrelated RPC traffic.
            let _ = call(3, [u64::MAX, 0, 0, 0, 0, 0]);
            continue;
        }
        let now=clock();
        if now>=0 {role_step(cap,target,generation,now as u64);}
        yield_now();
    }
}
#[inline(never)]
fn reject_startup()->!{
    let _=call(1,[u64::MAX,0,0,0,0,0]);
    loop{core::hint::spin_loop();}
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo)->!{
    let _=call(1,[u64::MAX,0,0,0,0,0]);
    loop{core::hint::spin_loop();}
}
