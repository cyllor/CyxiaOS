#![no_std]
#![no_main]
//! Native ABI v3 bootstrap clients. No historical SVC-immediate ABI.
//! These are the first independently linked role entrypoints. The unready
//! control service does not manufacture observations, models, plans or audit
//! ACKs. Production work must arrive through a verified input/service path.
use core::arch::asm;
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
fn snapshot(cap:u64,target:u64,domain:u64){
    let mut reply=[0u8;264];
    let result=call(0x40,[cap,domain,target,reply.as_mut_ptr() as u64,264,0]);
    // No model inference is started until a production snapshot, immutable
    // model/config and a frozen candidate/evidence context are all available.
    // This bootstrap deliberately does not accept a partially filled reply.
    core::hint::black_box((result,reply[0]));
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
#[cfg(control_role="11")]
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
extern "C" fn _start(cap:u64,target:u64,generation:u64)->!{
    loop{
        let now=clock();
        if now>=0 {role_step(cap,target,generation,now as u64);}
        yield_now();
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo)->!{
    let _=call(1,[u64::MAX,0,0,0,0,0]);
    loop{core::hint::spin_loop();}
}
