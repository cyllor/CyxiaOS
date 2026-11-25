//! ControlRPC v1 protected transport (V0.19.9 §2.2.3).
//! The serialized EL1 owner authenticates the current task and endpoint cap,
//! preflights/pins the output, copies the entire request, and reserves the
//! actual completion credit before calling this component. No payload grants
//! authority. No callback here can substitute for native effects.
use super::Identity;
use sha2::{Digest,Sha256};
pub const FRAME_BYTES:usize=512;
pub const HEADER_BYTES:usize=48;
pub const NORMAL_SLOTS:usize=10;
pub const RECOVERY_SLOTS:usize=6;
pub const MAX_WAIT_NS:u64=500_000_000;
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
#[repr(i32)]
pub enum Error{Auth=-1,Format=-2,Schema=-3,Stale=-4,Conflict=-5,Timeout=-6,
    Expired=-7,Capacity=-8,Budget=-9,Busy=-10,Unsupported=-11,Fault=-12,
    Again=-13,NoMemory=-14,NoSpace=-15,Io=-16}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
#[repr(u16)]
pub enum Op{AuditRead=1,AuditAck=2,Promote=3,Rollback=4,EpochAllocate=5,
    TrialInstantiate=6,ValidationRegister=7,CandidateSubmit=8,DecisionRead=9,
    AdviceDisposition=10,ExecutorFetch=11,Ack=12}
impl Op{
    fn decode(v:u16)->Result<Self,Error>{
        Ok(match v{1=>Self::AuditRead,2=>Self::AuditAck,3=>Self::Promote,4=>Self::Rollback,
            5=>Self::EpochAllocate,6=>Self::TrialInstantiate,7=>Self::ValidationRegister,
            8=>Self::CandidateSubmit,9=>Self::DecisionRead,10=>Self::AdviceDisposition,
            11=>Self::ExecutorFetch,12=>Self::Ack,_=>return Err(Error::Unsupported)})
    }
    pub const fn request_len(self)->usize{
        match self{Self::AuditRead=>16,Self::AuditAck=>48,Self::Promote|Self::Rollback=>96,
            Self::EpochAllocate=>48,Self::TrialInstantiate=>64,Self::ValidationRegister=>120,
            Self::CandidateSubmit=>88,Self::DecisionRead=>24,Self::AdviceDisposition=>240,
            Self::ExecutorFetch=>24,Self::Ack=>0}
    }
    pub const fn max_reply_len(self)->usize{HEADER_BYTES+match self{
        Self::AuditRead=>144,Self::AuditAck|Self::AdviceDisposition|Self::Ack=>0,
        Self::Promote|Self::Rollback|Self::ValidationRegister=>40,
        Self::EpochAllocate=>16,Self::TrialInstantiate|Self::DecisionRead=>256,
        Self::CandidateSubmit=>48,Self::ExecutorFetch=>336}}
    pub fn permits_role(self,role:u16)->bool{match self{
        Self::AuditRead|Self::AuditAck|Self::EpochAllocate=>role==11,
        Self::Promote|Self::Rollback=>role==3,
        Self::TrialInstantiate=>matches!(role,2|3),
        Self::ValidationRegister=>role==9,Self::CandidateSubmit=>role==10,
        Self::DecisionRead=>role==8,Self::AdviceDisposition=>role==2,
        Self::ExecutorFetch=>role==12,
        Self::Ack=>matches!(role,2|3|8|9|10|11|12),
    }}
}
fn u16at(b:&[u8],i:usize)->u16{u16::from_le_bytes(b[i..i+2].try_into().unwrap())}
fn u32at(b:&[u8],i:usize)->u32{u32::from_le_bytes(b[i..i+4].try_into().unwrap())}
fn u64at(b:&[u8],i:usize)->u64{u64::from_le_bytes(b[i..i+8].try_into().unwrap())}
fn put16(b:&mut[u8],i:usize,v:u16){b[i..i+2].copy_from_slice(&v.to_le_bytes())}
fn put32(b:&mut[u8],i:usize,v:u32){b[i..i+4].copy_from_slice(&v.to_le_bytes())}
fn put64(b:&mut[u8],i:usize,v:u64){b[i..i+8].copy_from_slice(&v.to_le_bytes())}
#[derive(Clone,Copy,Debug)]
pub struct Request<'a>{
    pub op:Op,pub seq:u64,pub ack:u64,pub expected_generation:u64,pub deadline_ns:u64,
    pub payload:&'a[u8],
}
impl<'a> Request<'a>{
    pub fn decode(b:&'a[u8])->Result<Self,Error>{
        if !(HEADER_BYTES..=FRAME_BYTES).contains(&b.len())||u32at(b,0)!=0x43594351
            ||u16at(b,6)!=48||u16at(b,10)!=0{return Err(Error::Format);}
        if u16at(b,4)!=1{return Err(Error::Schema);}
        let op=Op::decode(u16at(b,8))?;
        let n=op.request_len();
        if u32at(b,12) as usize!=n||b.len()!=HEADER_BYTES+n{return Err(Error::Format);}
        let r=Self{op,seq:u64at(b,16),ack:u64at(b,24),expected_generation:u64at(b,32),
            deadline_ns:u64at(b,40),payload:&b[48..]};
        if r.seq==0||r.expected_generation==0||r.deadline_ns==0{return Err(Error::Format);}
        if (op==Op::Ack&&r.ack!=r.seq)||(op!=Op::Ack&&r.ack>=r.seq){return Err(Error::Format);}
        let p=r.payload;
        let zero=|a:usize,z:usize|p[a..z].iter().all(|v|*v==0);
        let nonzero=|a:usize,z:usize|!zero(a,z);
        let valid=match op{
            Op::AuditRead=>u64at(p,0)==r.expected_generation,
            Op::AuditAck=>u64at(p,0)==r.expected_generation&&u64at(p,8)!=0&&nonzero(16,48),
            Op::Promote|Op::Rollback=>u64at(p,0)!=0&&u64at(p,8)!=0
                &&u64at(p,16)==r.expected_generation
                &&(if op==Op::Promote{u64at(p,24)!=0}else{u64at(p,24)==0})
                &&nonzero(32,64)&&nonzero(64,96),
            Op::EpochAllocate=>matches!(u16at(p,0),1..=10|12..=16)&&zero(2,8)
                &&u64at(p,8)==r.expected_generation&&nonzero(16,48),
            Op::TrialInstantiate=>u64at(p,0)!=0&&u64at(p,8)!=0&&u64at(p,16)!=0,
            Op::ValidationRegister=>u64at(p,0)!=0&&u64at(p,8)==r.expected_generation
                &&nonzero(16,48)&&nonzero(48,80)&&nonzero(80,112)
                &&matches!(u16at(p,112),1|2)&&zero(114,120),
            Op::CandidateSubmit=>u64at(p,0)!=0&&(2772..=32768).contains(&u32at(p,8))
                &&u32at(p,12)==0&&u64at(p,16)==r.expected_generation
                &&nonzero(24,56)&&nonzero(56,88),
            Op::DecisionRead=>u64at(p,0)!=0&&u64at(p,8)==r.expected_generation&&u64at(p,16)!=0,
            Op::AdviceDisposition=>super::advice_disposition_v1::AdviceDispositionV1::decode(p)
                .is_ok_and(|d|(3..=6).contains(&d.state)),
            Op::ExecutorFetch=>u16at(p,0)==4&&zero(2,8)&&u64at(p,8)!=0&&u64at(p,16)!=0,
            Op::Ack=>true,
        };
        if !valid{return Err(Error::Format);}Ok(r)
    }
}
/// All fields come from the protected boot/task/cap registry, never EL0.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Caller{pub boot_epoch:u64,pub holder:Identity,pub role:u16,pub endpoint:u64,pub cap:u64}
impl Caller{fn valid(self)->bool{
    self.boot_epoch!=0&&self.holder.valid()&&self.endpoint!=0&&self.cap!=0
        &&matches!(self.role,2|3|8|9|10|11|12)
}}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
#[repr(u16)]
pub enum State{Done=1,Pending=2,Unknown=3}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Frame{bytes:[u8;FRAME_BYTES],len:u16}
impl Frame{
    pub fn bytes(&self)->&[u8]{&self.bytes[..usize::from(self.len)]}
    pub fn state(&self)->State{match u16at(&self.bytes,10){1=>State::Done,2=>State::Pending,_=>State::Unknown}}
    fn reply(c:Caller,op:Op,seq:u64,state:State,result:i32,observed:u64,payload:&[u8])->Result<Self,Error>{
        if observed==0||!(-16..=0).contains(&result){return Err(Error::Format);}
        let success=state==State::Done&&result==0;
        let shape=if success{
            if op==Op::ExecutorFetch{
                super::apply_work_v1::ApplyWorkV1::decode(payload).is_ok()
            }else{payload.len()==op.max_reply_len()-48}
        }else{payload.is_empty()};
        if !shape||payload.len()>FRAME_BYTES-48{return Err(Error::Format);}
        let mut bytes=[0;FRAME_BYTES];
        put32(&mut bytes,0,0x43594352);put16(&mut bytes,4,1);put16(&mut bytes,6,48);
        put16(&mut bytes,8,op as u16);put16(&mut bytes,10,state as u16);put32(&mut bytes,12,result as u32);
        put64(&mut bytes,16,seq);put64(&mut bytes,24,c.holder.generation);put64(&mut bytes,32,observed);
        put32(&mut bytes,40,payload.len() as u32);bytes[48..48+payload.len()].copy_from_slice(payload);
        Ok(Self{bytes,len:(48+payload.len()) as u16})
    }
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Ticket{caller:Caller,seq:u64,request_hash:[u8;32]}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum Admission{Execute(Ticket),Replay(Frame),Acknowledged(Frame)}
struct Entry{ticket:Ticket,request:[u8;FRAME_BYTES],len:u16,op:Op,reply:Frame}
struct Slot{caller:Option<Caller>,closed:bool,retired:u64,entry:Option<Entry>,rebind_ready:bool}
impl Slot{const fn empty()->Self{Self{caller:None,closed:false,retired:0,entry:None,rebind_ready:false}}}
/// Ten ordinary reservations and six independent recovery reservations.
/// Per-holder flow is unique across ALL slots; one endpoint cannot gain
/// another sequence stream by replacing its cap or opening a recovery slot.
pub struct RpcTable{boot_epoch:u64,slots:[Slot;NORMAL_SLOTS+RECOVERY_SLOTS]}
impl RpcTable{
    pub const fn new()->Self{Self{boot_epoch:0,slots:[const{Slot::empty()};NORMAL_SLOTS+RECOVERY_SLOTS]}}
    pub fn bind(&mut self,caller:Caller,recovery:bool)->Result<(),Error>{
        if !caller.valid()||(self.boot_epoch!=0&&self.boot_epoch!=caller.boot_epoch)
            ||self.slots.iter().filter_map(|s|s.caller).any(|c|
                c.holder.id==caller.holder.id||c.cap==caller.cap){
            return Err(Error::Auth);
        }
        let range=if recovery{
            // The EL1 caller must authenticate the separately reserved
            // recovery allocation; ordinary endpoint creation never uses it.
            NORMAL_SLOTS..NORMAL_SLOTS+RECOVERY_SLOTS
        }else if caller.role==12{
            8..10
        }else{
            let i=super::role_manifest_v0199::ROLES.iter()
                .position(|r|r.id()==caller.role).ok_or(Error::Auth)?;
            i..i+1
        };
        let i=range.into_iter().find(|&i|self.slots[i].caller.is_none()).ok_or(Error::Capacity)?;
        self.boot_epoch=caller.boot_epoch;self.slots[i].caller=Some(caller);Ok(())
    }
    fn slot(&mut self,caller:Caller)->Result<&mut Slot,Error>{
        self.slots.iter_mut().find(|s|s.caller==Some(caller)).ok_or(Error::Auth)
    }
    /// Input is a stable copied request; output span and real completion
    /// resource reservation are independently checked by the caller. On
    /// new admission, authorize_operation must check the actual cap label,
    /// current generation and operand owner before any state is changed.
    pub fn admit(&mut self,caller:Caller,wire:&[u8],reply_cap:usize,now:u64,parent_deadline:u64,
        observed_generation:u64,authorize_operation:impl FnOnce(&Request<'_>)->Result<(),Error>)
        ->Result<Admission,Error>{
        let slot=self.slot(caller)?;
        if slot.closed{return Err(Error::Stale);}
        let r=Request::decode(wire)?;
        if !r.op.permits_role(caller.role){return Err(Error::Auth);}
        if reply_cap<r.op.max_reply_len(){return Err(Error::Fault);}
        // Exact retry is a read-only query, not renewed authority/lease.
        if r.op!=Op::Ack{
            if let Some(e)=&slot.entry{
                if e.ticket.seq==r.seq{
                    if e.request[..usize::from(e.len)]!=*wire{return Err(Error::Conflict);}
                    return Ok(Admission::Replay(e.reply));
                }
            }
        }
        if r.op==Op::Ack{
            if r.expected_generation!=caller.holder.generation{return Err(Error::Stale);}
            if r.seq==slot.retired&&slot.retired!=0{
                return Ok(Admission::Acknowledged(Frame::reply(caller,Op::Ack,r.seq,State::Done,0,caller.holder.generation,&[])?));
            }
            let e=slot.entry.as_ref().ok_or(Error::Stale)?;
            if e.ticket.seq!=r.seq{return Err(if r.seq<e.ticket.seq{Error::Stale}else{Error::Again});}
            if e.reply.state()!=State::Done{return Err(Error::Busy);}
            let out=Frame::reply(caller,Op::Ack,r.seq,State::Done,0,caller.holder.generation,&[])?;
            slot.retired=r.seq;slot.entry=None;return Ok(Admission::Acknowledged(out));
        }
        if r.seq<=slot.retired{return Err(Error::Stale);}
        let (next,ack)=if let Some(e)=&slot.entry{
            if e.reply.state()!=State::Done{return Err(Error::Busy);}
            (e.ticket.seq.checked_add(1).ok_or(Error::Capacity)?,e.ticket.seq)
        }else{(slot.retired.checked_add(1).ok_or(Error::Capacity)?,0)};
        if r.seq!=next{return Err(Error::Again);}
        // After an explicit ACK either zero or the exact retired watermark
        // is allowed. No other watermark silently acknowledges work.
        if r.ack!=ack&&!(slot.entry.is_none()&&r.ack==slot.retired){return Err(Error::Conflict);}
        if r.deadline_ns<=now{return Err(Error::Timeout);}
        if r.deadline_ns>parent_deadline||r.deadline_ns-now>MAX_WAIT_NS{return Err(Error::Format);}
        if r.expected_generation!=observed_generation{return Err(Error::Stale);}
        authorize_operation(&r)?;
        let ticket=Ticket{caller,seq:r.seq,request_hash:Sha256::digest(wire).into()};
        let reply=Frame::reply(caller,r.op,r.seq,State::Pending,0,observed_generation,&[])?;
        let mut request=[0;FRAME_BYTES];request[..wire.len()].copy_from_slice(wire);
        if ack!=0{slot.retired=ack;}
        slot.entry=Some(Entry{ticket,request,len:wire.len() as u16,op:r.op,reply});
        Ok(Admission::Execute(ticket))
    }
    /// The ordinary native backend reports actual completion for a live
    /// pending request. Once UNKNOWN or fenced, only independent recovery
    /// can establish a new terminal result. Exact terminal replay is read-only.
    pub fn complete(&mut self,ticket:Ticket,state:State,result:i32,observed:u64,payload:&[u8],
        verify_native:impl FnOnce()->Result<(),Error>)->Result<Frame,Error>{
        let slot=self.slot(ticket.caller)?;
        let e=slot.entry.as_mut().ok_or(Error::Stale)?;
        if e.ticket!=ticket{return Err(Error::Stale);}
        let next=Frame::reply(ticket.caller,e.op,ticket.seq,state,result,observed,payload)?;
        if e.reply.state()==State::Done{
            return if e.reply==next{Ok(e.reply)}else{Err(Error::Conflict)};
        }
        if slot.closed||e.reply.state()==State::Unknown{
            return Err(Error::Busy);
        }
        if state==State::Pending{return Err(Error::Busy);}
        verify_native()?;
        e.reply=next;Ok(next)
    }
    /// Serialized protected recovery entry, not reachable through a user's
    /// retry or ACK. Verify exact original request, old retained reply and
    /// proposed terminal bytes against independent current native evidence.
    /// A failed verifier leaves the original obligation unchanged.
    pub fn reconcile(&mut self,ticket:Ticket,result:i32,observed:u64,payload:&[u8],
        verify_independent:impl FnOnce(Caller,&[u8],&Frame,&Frame)->Result<(),Error>,
    )->Result<Frame,Error>{
        let slot=self.slot(ticket.caller)?;
        let e=slot.entry.as_mut().ok_or(Error::Stale)?;
        if e.ticket!=ticket{return Err(Error::Stale);}
        let next=Frame::reply(ticket.caller,e.op,ticket.seq,State::Done,result,observed,payload)?;
        if e.reply.state()==State::Done{
            return if e.reply==next{Ok(e.reply)}else{Err(Error::Conflict)};
        }
        if !slot.closed&&e.reply.state()!=State::Unknown{return Err(Error::Busy);}
        verify_independent(ticket.caller,&e.request[..usize::from(e.len)],&e.reply,&next)?;
        e.reply=next;Ok(next)
    }
    /// Old caller cannot submit or ACK once fenced. Its accepted
    /// obligation survives until a trusted stopped-owner recovery proves
    /// and retains the terminal request/reply evidence.
    pub fn close(&mut self,caller:Caller)->Result<(),Error>{self.slot(caller)?.closed=true;Ok(())}
    pub fn retire_closed(&mut self,caller:Caller,
        verify_stop_and_custody:impl FnOnce(Option<(&[u8],Frame)>)->Result<(),Error>)->Result<(),Error>{
        let slot=self.slot(caller)?;
        if !slot.closed{return Err(Error::Busy);}
        if slot.entry.as_ref().is_some_and(|e|e.reply.state()!=State::Done){return Err(Error::Busy);}
        verify_stop_and_custody(slot.entry.as_ref().map(|e|(&e.request[..usize::from(e.len)],e.reply)))?;
        slot.entry=None;slot.rebind_ready=true;Ok(())
    }
    /// Keep the retired identity as a tombstone; it must not regain a
    /// sequence stream via bind(). Native registry proves durable next
    /// generation and new endpoint ownership before replacing this slot.
    pub fn replace_closed(&mut self,old:Caller,new:Caller,
        verify_replacement:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        if !new.valid()||new.boot_epoch!=old.boot_epoch||new.role!=old.role
            ||new.holder.id!=old.holder.id||old.holder.generation.checked_add(1)!=Some(new.holder.generation)
            ||new.cap==old.cap{return Err(Error::Auth);}
        if self.slots.iter().filter_map(|s|s.caller).any(|c|c!=old&&c.cap==new.cap){return Err(Error::Auth);}
        let slot=self.slot(old)?;
        if !slot.closed||!slot.rebind_ready||slot.entry.is_some(){return Err(Error::Busy);}
        verify_replacement()?;
        *slot=Slot::empty();slot.caller=Some(new);Ok(())
    }
}
const _:()=assert!(core::mem::size_of::<Slot>()<=2048);
const _:()=assert!(core::mem::size_of::<RpcTable>()<=16*2048);
#[cfg(test)]
mod tests{
    use super::*;
    fn caller()->Caller{Caller{boot_epoch:1,holder:Identity{id:11,generation:7},role:11,endpoint:2,cap:9}}
    fn req(op:Op,seq:u64,ack:u64)->([u8;FRAME_BYTES],usize){
        let mut b=[0;FRAME_BYTES];let n=48+op.request_len();
        put32(&mut b,0,0x43594351);put16(&mut b,4,1);put16(&mut b,6,48);put16(&mut b,8,op as u16);
        put32(&mut b,12,op.request_len() as u32);put64(&mut b,16,seq);put64(&mut b,24,ack);
        put64(&mut b,32,7);put64(&mut b,40,1000);
        if op==Op::AuditRead{put64(&mut b,48,7);}
        (b,n)
    }
    #[test]
    fn exactly_once_lost_reply_ack_and_next_sequence(){
        let mut t=RpcTable::new();let c=caller();t.bind(c,false).unwrap();
        let (r,n)=req(Op::AuditRead,1,0);
        assert_eq!(t.admit(c,&r[..n],191,10,1000,7,|_|panic!()),Err(Error::Fault));
        let Admission::Execute(k)=t.admit(c,&r[..n],192,10,1000,7,|_|Ok(())).unwrap()else{panic!()};
        let f=t.complete(k,State::Done,0,7,&[0;144],||Ok(())).unwrap();
        assert_eq!(t.admit(c,&r[..n],192,2000,1000,8,|_|panic!()),Ok(Admission::Replay(f)));
        let mut changed=r;put64(&mut changed,40,2000);
        assert_eq!(t.admit(c,&changed[..n],192,10,2000,7,|_|panic!()),Err(Error::Conflict));
        let (ack,m)=req(Op::Ack,1,1);
        assert!(matches!(t.admit(c,&ack[..m],48,2000,1000,9,|_|panic!()),Ok(Admission::Acknowledged(_))));
        assert!(matches!(t.admit(c,&ack[..m],48,2000,1000,9,|_|panic!()),Ok(Admission::Acknowledged(_))));
        assert_eq!(t.admit(c,&r[..n],192,10,1000,7,|_|panic!()),Err(Error::Stale));
        let (r2,n2)=req(Op::AuditRead,2,1);
        assert!(matches!(t.admit(c,&r2[..n2],192,10,1000,7,|_|Ok(())),Ok(Admission::Execute(_))));
    }
    #[test]
    fn pending_unknown_and_old_holder_cannot_release_or_reexecute(){
        let mut t=RpcTable::new();let c=caller();t.bind(c,false).unwrap();
        let (r,n)=req(Op::AuditRead,1,0);
        let Admission::Execute(k)=t.admit(c,&r[..n],192,10,1000,7,|_|Ok(())).unwrap()else{panic!()};
        let unknown=t.complete(k,State::Unknown,-16,7,&[],||Ok(())).unwrap();
        let (ack,m)=req(Op::Ack,1,1);let (next,x)=req(Op::AuditRead,2,1);
        assert_eq!(t.admit(c,&ack[..m],48,10,1000,7,|_|panic!()),Err(Error::Busy));
        assert_eq!(t.admit(c,&next[..x],192,10,1000,7,|_|panic!()),Err(Error::Busy));
        assert_eq!(t.admit(c,&r[..n],192,2000,1000,7,|_|panic!()),Ok(Admission::Replay(unknown)));
        t.close(c).unwrap();
        let replacement=Caller{holder:Identity{generation:8,..c.holder},cap:10,..c};
        assert_eq!(t.bind(replacement,false),Err(Error::Auth));
        assert_eq!(t.admit(c,&r[..n],192,10,1000,7,|_|panic!()),Err(Error::Stale));
        assert_eq!(t.retire_closed(c,|_|panic!()),Err(Error::Busy));
        assert_eq!(t.complete(k,State::Done,-16,7,&[],||panic!()),Err(Error::Busy));
        assert_eq!(t.reconcile(k,-16,7,&[],|_,_,_,_|Err(Error::Io)),Err(Error::Io));
        let done=t.reconcile(k,-16,7,&[],|actor,request,prior,proposed|{
            assert_eq!(actor,c);assert_eq!(request,&r[..n]);assert_eq!(*prior,unknown);
            assert_eq!(proposed.state(),State::Done);Ok(())
        }).unwrap();
        assert_eq!(t.reconcile(k,-16,7,&[],|_,_,_,_|panic!()),Ok(done));
        assert_eq!(t.retire_closed(c,|_|Err(Error::Io)),Err(Error::Io));
        t.retire_closed(c,|e|{assert!(e.is_some());Ok(())}).unwrap();
        assert_eq!(t.bind(c,false),Err(Error::Auth));
        assert_eq!(t.replace_closed(c,replacement,||Err(Error::Io)),Err(Error::Io));
        t.replace_closed(c,replacement,||Ok(())).unwrap();
        assert_eq!(t.admit(c,&r[..n],192,10,1000,7,|_|panic!()),Err(Error::Auth));
    }
    #[test]
    fn live_unknown_and_stopped_pending_require_independent_reconciliation(){
        for close in [false,true]{
            let mut t=RpcTable::new();let c=caller();t.bind(c,false).unwrap();
            let (r,n)=req(Op::AuditRead,1,0);
            let Admission::Execute(k)=t.admit(c,&r[..n],192,10,1000,7,|_|Ok(())).unwrap()else{panic!()};
            assert_eq!(t.reconcile(k,-16,7,&[],|_,_,_,_|panic!()),Err(Error::Busy));
            if close{t.close(c).unwrap();}
            else{t.complete(k,State::Unknown,-16,7,&[],||Ok(())).unwrap();}
            assert_eq!(t.complete(k,State::Done,0,7,&[0;144],||panic!()),Err(Error::Busy));
            let done=t.reconcile(k,0,7,&[0;144],|actor,wire,prior,next|{
                assert_eq!(actor,c);assert_eq!(wire,&r[..n]);
                assert_eq!(prior.state(),if close{State::Pending}else{State::Unknown});
                assert_eq!(next.state(),State::Done);Ok(())
            }).unwrap();
            assert_eq!(t.reconcile(k,-16,7,&[],|_,_,_,_|panic!()),Err(Error::Conflict));
            assert_eq!(t.complete(k,State::Done,0,7,&[0;144],||panic!()),Ok(done));
        }
    }
    #[test]
    fn ordinary_role_slots_and_executor_capacity_do_not_borrow_recovery(){
        let mut t=RpcTable::new();let c=caller();t.bind(c,false).unwrap();
        assert_eq!(t.bind(Caller{holder:Identity{id:111,generation:1},cap:100,..c},false),Err(Error::Capacity));
        for i in 0..2{
            t.bind(Caller{boot_epoch:1,holder:Identity{id:120+i,generation:1},role:12,
                endpoint:20+i,cap:200+i},false).unwrap();
        }
        assert_eq!(t.bind(Caller{boot_epoch:1,holder:Identity{id:122,generation:1},role:12,
            endpoint:22,cap:202},false),Err(Error::Capacity));
        assert_eq!(t.bind(Caller{boot_epoch:2,holder:Identity{id:99,generation:1},role:8,
            endpoint:23,cap:203},false),Err(Error::Auth));
    }
    #[test]
    fn unauthorized_or_invalid_new_request_does_not_consume_sequence(){
        let mut t=RpcTable::new();let c=caller();t.bind(c,false).unwrap();
        let (r,n)=req(Op::AuditRead,1,0);
        assert_eq!(t.admit(c,&r[..n],192,10,1000,6,|_|panic!()),Err(Error::Stale));
        assert_eq!(t.admit(c,&r[..n],192,10,1000,7,|_|Err(Error::Auth)),Err(Error::Auth));
        assert_eq!(t.admit(c,&r[..n],192,1000,1000,7,|_|panic!()),Err(Error::Timeout));
        let (jump,m)=req(Op::AuditRead,3,0);
        assert_eq!(t.admit(c,&jump[..m],192,10,1000,7,|_|panic!()),Err(Error::Again));
        let (mut malformed,m)=req(Op::AuditRead,1,0);malformed[10]=1;
        assert_eq!(t.admit(c,&malformed[..m],192,10,1000,7,|_|panic!()),Err(Error::Format));
        assert!(matches!(t.admit(c,&r[..n],192,10,1000,7,|_|Ok(())),Ok(Admission::Execute(_))));
    }
}
