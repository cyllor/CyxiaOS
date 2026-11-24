//! Ordinary native IPC receive v3 (§2.2.2): one reserved receive per
//! authenticated endpoint generation, with exact frozen bytes and ACK.
//! Queue entries are copied by the protected owner after authenticating
//! the actual send cap. Never expose sender identity from user payload.
//! Serialized owner calls reserve/copy/finish under its lock protocol;
//! copyout occurs with no queue lock held, and rechecks the pinned span.
use crate::control_plane::{Identity,control_rpc_v1::Error};
pub const PAYLOAD_BYTES:usize=512;
pub const HEADER_BYTES:usize=40;
pub const FRAME_BYTES:usize=552;
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Endpoint{pub id:u64,pub generation:u64,pub receiver:Identity}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Message{
    bytes:[u8;FRAME_BYTES],len:u16,
}
impl Message{
    pub fn copied(sender:Identity,request_id:u64,endpoint_generation:u64,payload:&[u8])->Result<Self,Error>{
        if !sender.valid()||request_id==0||endpoint_generation==0||payload.len()>PAYLOAD_BYTES{
            return Err(Error::Format);
        }
        let mut bytes=[0;FRAME_BYTES];
        for (i,v) in [sender.id,sender.generation,request_id,endpoint_generation].into_iter().enumerate(){
            bytes[i*8..i*8+8].copy_from_slice(&v.to_le_bytes());
        }
        bytes[32..36].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[40..40+payload.len()].copy_from_slice(payload);
        Ok(Self{bytes,len:(40+payload.len()) as u16})
    }
    pub fn bytes(&self)->&[u8]{&self.bytes[..usize::from(self.len)]}
    pub fn sender(&self)->Identity{Identity{id:self.u64_at(0),generation:self.u64_at(8)}}
    pub fn request_id(&self)->u64{self.u64_at(16)}
    pub fn endpoint_generation(&self)->u64{self.u64_at(24)}
    fn u64_at(&self,at:usize)->u64{u64::from_le_bytes(self.bytes[at..at+8].try_into().unwrap())}
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct ReceiveTicket{endpoint:Endpoint,seq:u64,message:Message}
impl ReceiveTicket{pub fn message(&self)->&Message{&self.message}}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
enum Phase{Reserved,Done}
#[derive(Clone,Copy)]
struct Reservation{ticket:ReceiveTicket,phase:Phase}
const _:()=assert!(core::mem::size_of::<Reservation>()<=1024);
/// Queue is fixed and separately accounted. Send deduplication survives
/// dequeue through a bounded per-sender stream (one actual send holder in
/// this restricted directional channel); old keys are stale, not requeued.
pub struct DirectionalEndpoint<const N:usize>{
    identity:Endpoint,sender:Identity,closed:bool,queue:[Option<Message>;N],head:usize,len:usize,
    hi:u64,retired:u64,reservation:Option<Reservation>,
    last_send:Option<Message>,send_hi:u64,
}
impl<const N:usize> DirectionalEndpoint<N>{
    pub fn new(identity:Endpoint,sender:Identity)->Result<Self,Error>{
        if N==0||N>128||identity.id==0||identity.generation==0||!identity.receiver.valid()
            ||!sender.valid()||sender==identity.receiver{return Err(Error::Format);}
        Ok(Self{identity,sender,closed:false,queue:[None;N],head:0,len:0,hi:0,retired:0,
            reservation:None,last_send:None,send_hi:0})
    }
    fn auth_receive(&self,actor:Identity,generation:u64)->Result<(),Error>{
        if actor.id!=self.identity.receiver.id{return Err(Error::Auth);}
        if actor!=self.identity.receiver||generation!=self.identity.generation||self.closed{return Err(Error::Stale);}
        Ok(())
    }
    /// Sender id is kernel-authenticated, not parsed from the payload.
    /// Retains the last exact accepted send; older ids never enqueue again.
    /// A native owner may supply additional protected outstanding custody
    /// before calling. Restrict this channel to a single producer.
    pub fn send(&mut self,actor:Identity,generation:u64,request:u64,payload:&[u8])->Result<(),Error>{
        if actor.id!=self.sender.id{return Err(Error::Auth);}
        if actor!=self.sender||generation!=self.identity.generation||self.closed{return Err(Error::Stale);}
        let message=Message::copied(actor,request,generation,payload)?;
        // Retained pending messages and a DONE-but-unacknowledged
        // receive are not evictable even after later sends succeed.
        if let Some(old)=self.queue.iter().flatten().chain(self.reservation.as_ref().map(|r|&r.ticket.message))
            .find(|m|m.request_id()==request){
            return if *old==message{Ok(())}else{Err(Error::Conflict)};
        }
        if request==self.send_hi{
            return if self.last_send==Some(message){Ok(())}else{Err(Error::Conflict)};
        }
        if request<self.send_hi{return Err(Error::Stale);}
        if self.len==N{return Err(Error::Again);}
        self.queue[(self.head+self.len)%N]=Some(message);self.len+=1;
        self.send_hi=request;self.last_send=Some(message);Ok(())
    }
    pub fn pending(&self)->usize{self.len}
    pub fn endpoint(&self)->Endpoint{self.identity}
    /// The actual SVC adapter first validates the full user writable span.
    /// No waiting message: do not consume sequence, pin memory or credit.
    /// Credit callback reserves a real completion slot before reservation.
    pub fn reserve_receive(&mut self,actor:Identity,generation:u64,seq:u64,reply_cap:usize,
        nonblocking:bool,deadline:u64,now:u64,credit:impl FnOnce()->Result<(),Error>)->Result<ReceiveTicket,Error>{
        self.auth_receive(actor,generation)?;
        if seq==0{return Err(Error::Format);}
        if reply_cap<FRAME_BYTES{return Err(Error::Fault);}
        if let Some(r)=self.reservation{
            return if r.ticket.seq==seq{Ok(r.ticket)}
                else if seq<=self.retired{Err(Error::Stale)}else if seq<r.ticket.seq{Err(Error::Stale)}
                else{Err(Error::Busy)};
        }
        if seq<=self.retired{return Err(Error::Stale);}
        if self.hi.checked_add(1)!=Some(seq){return Err(Error::Again);}
        if !nonblocking&&deadline<=now{return Err(Error::Timeout);}
        let Some(message)=self.queue[self.head]else{
            return Err(Error::Again); // scheduler owns blocking wait/deadline
        };
        credit()?;
        let ticket=ReceiveTicket{endpoint:self.identity,seq,message};
        self.hi=seq;self.reservation=Some(Reservation{ticket,phase:Phase::Reserved});
        Ok(ticket)
    }
    /// Only after actual successful copyout. A fault leaves both the
    /// reservation and queue head intact. Recopying DONE never dequeues.
    pub fn finish_copy(&mut self,ticket:ReceiveTicket,copy_ok:bool)->Result<usize,Error>{
        if self.closed||ticket.endpoint!=self.identity{return Err(Error::Stale);}
        let r=self.reservation.as_mut().ok_or(Error::Stale)?;
        if r.ticket!=ticket{return Err(Error::Stale);}
        if !copy_ok{return Err(Error::Fault);}
        if r.phase==Phase::Reserved{
            if self.queue[self.head]!=Some(ticket.message){return Err(Error::Conflict);}
            self.queue[self.head]=None;self.head=(self.head+1)%N;self.len-=1;
            r.phase=Phase::Done;
        }
        Ok(ticket.message.bytes().len())
    }
    pub fn ack(&mut self,actor:Identity,generation:u64,seq:u64,
        release_credit:impl FnOnce()->Result<(),Error>)->Result<(),Error>{
        self.auth_receive(actor,generation)?;
        if seq==self.retired&&seq!=0{return Ok(());}
        let r=self.reservation.ok_or(Error::Stale)?;
        if r.ticket.seq!=seq{return Err(if seq<r.ticket.seq{Error::Stale}else{Error::Again});}
        if r.phase!=Phase::Done{return Err(Error::Busy);}
        release_credit()?;
        self.retired=seq;self.reservation=None;Ok(())
    }
    pub fn fence(&mut self){self.closed=true;}
    /// The actual supervisor proves the stopped holder, pending output
    /// pins and retained obligation. Old endpoints never reopen here.
    /// For Reserved, the old queue head is untouched; Done needs exact
    /// evidence custody. This can be called only by protected recovery.
    pub fn recover_receive(&mut self,verify:impl FnOnce(ReceiveTicket,bool)->Result<(),Error>)->Result<(),Error>{
        if !self.closed{return Err(Error::Busy);}
        let r=self.reservation.ok_or(Error::Stale)?;
        verify(r.ticket,r.phase==Phase::Done)?;
        self.retired=r.ticket.seq;self.reservation=None;Ok(())
    }
    /// After recovery has reconciled any retained receive, a closed
    /// endpoint may transfer an exact queued head to the independent
    /// custody owner. No other removal path drops pending payloads.
    pub fn recover_head(&mut self,verify_custody:impl FnOnce(&Message)->Result<(),Error>)->Result<(),Error>{
        if !self.closed||self.reservation.is_some(){return Err(Error::Busy);}
        let message=self.queue[self.head].as_ref().ok_or(Error::Again)?;
        verify_custody(message)?;
        self.queue[self.head]=None;self.head=(self.head+1)%N;self.len-=1;Ok(())
    }
    pub fn drained(&self)->bool{self.closed&&self.reservation.is_none()&&self.len==0}
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn fault_retry_done_recopy_ack_and_recovery_preserve_exact_queue(){
        let sender=Identity{id:6,generation:2};let receiver=Identity{id:2,generation:3};
        let mut q=DirectionalEndpoint::<2>::new(Endpoint{id:9,generation:4,receiver},sender).unwrap();
        assert_eq!(q.reserve_receive(receiver,4,1,552,true,0,1,||panic!()),Err(Error::Again));
        q.send(sender,4,1,b"first").unwrap();q.send(sender,4,2,b"second").unwrap();
        assert_eq!(q.send(sender,4,1,b"first"),Ok(()));
        assert_eq!(q.send(sender,4,1,b"changed"),Err(Error::Conflict));
        assert_eq!(q.send(sender,4,3,b"third"),Err(Error::Again));
        assert_eq!(q.reserve_receive(receiver,4,1,551,true,0,1,||panic!()),Err(Error::Fault));
        let t=q.reserve_receive(receiver,4,1,552,true,0,1,||Ok(())).unwrap();
        assert_eq!(&t.message().bytes()[40..],b"first");
        assert_eq!(t.message().sender(),sender);
        assert_eq!(q.finish_copy(t,false),Err(Error::Fault));assert_eq!(q.pending(),2);
        assert_eq!(q.ack(receiver,4,1,||panic!()),Err(Error::Busy));
        assert_eq!(q.reserve_receive(receiver,4,1,552,true,0,2,||panic!()),Ok(t));
        assert_eq!(q.finish_copy(t,true),Ok(45));assert_eq!(q.pending(),1);
        assert_eq!(q.finish_copy(t,true),Ok(45));assert_eq!(q.pending(),1);
        assert_eq!(q.ack(receiver,4,1,||Ok(())),Ok(()));
        assert_eq!(q.ack(receiver,4,1,||panic!()),Ok(()));
        assert_eq!(q.reserve_receive(receiver,4,1,552,true,0,3,||panic!()),Err(Error::Stale));
        let t=q.reserve_receive(receiver,4,2,552,true,0,3,||Ok(())).unwrap();
        assert_eq!(&t.message().bytes()[40..],b"second");q.fence();
        assert_eq!(q.finish_copy(t,true),Err(Error::Stale));
        assert_eq!(q.recover_receive(|_,_|Err(Error::Io)),Err(Error::Io));
        q.recover_receive(|retained,done|{assert_eq!(retained,t);assert!(!done);Ok(())}).unwrap();
        assert_eq!(q.pending(),1);assert!(!q.drained());
        assert_eq!(q.recover_head(|_|Err(Error::Io)),Err(Error::Io));
        q.recover_head(|m|{assert_eq!(m.request_id(),2);Ok(())}).unwrap();assert!(q.drained());
    }
}
