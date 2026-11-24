//! Ordinary IPC receive v3 over the actual FIFO and send-reservation owner.
//! This is an opt-in protected EL1 component, not the legacy receive path.
//! The trap adapter authenticates holders, reserves real completion credits,
//! pins the full output range, copies outside the queue lock and revalidates
//! mappings/identity before commit. No user-provided pointer is trusted here.
use super::*;

pub const RECEIVE_V3_HEADER:usize=40;
pub const RECEIVE_V3_MAX_PAYLOAD:usize=512;
pub const RECEIVE_V3_REPLY_CAP:usize=552;

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct ReceiveTicket {
    endpoint:ObjectKey,
    holder:ObjectKey,
    recv_seq:u64,
    head_sequence:u64,
    completion_credit:u64,
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum ReceivePrepared { New(ReceiveTicket), Existing(ReceiveTicket) }
impl ReceivePrepared {
    pub fn ticket(self)->ReceiveTicket {
        match self {Self::New(t)|Self::Existing(t)=>t}
    }
}
#[derive(Clone,Copy)]
struct ReceiveRecord {
    ticket:ReceiveTicket,
    bytes:[u8;RECEIVE_V3_REPLY_CAP],
    len:u16,
    done:bool,
}
#[derive(Clone,Copy)]
struct ReceiveSlot {
    high:u64,
    retired:u64,
    closed:bool,
    record:Option<ReceiveRecord>,
}
impl ReceiveSlot {
    const EMPTY:Self=Self{high:0,retired:0,closed:false,record:None};
}
const _:()=assert!(core::mem::size_of::<ReceiveSlot>()<=1024);
const _:()=assert!(core::mem::size_of::<[ReceiveSlot;MAX_ENDPOINTS]>()<=32*1024);

/// Separately instantiated owner so the legacy Ipc memory layout and
/// unversioned receive entrypoints are not silently changed. No mutable
/// reference to the wrapped FIFO escapes (there is no alternate dequeue).
pub struct IpcV3<const B:usize=512> {
    fifo:Ipc<B>,
    receivers:[ReceiveSlot;MAX_ENDPOINTS],
}
impl<const B:usize> Default for IpcV3<B>{
    fn default()->Self{Self::new()}
}
impl<const B:usize> IpcV3<B>{
    pub const fn new()->Self{
        Self{fifo:Ipc::new(),receivers:[ReceiveSlot::EMPTY;MAX_ENDPOINTS]}
    }
    pub fn open(&mut self,holder:ObjectKey)->Result<ObjectKey,Error>{
        if B==0 || B>RECEIVE_V3_MAX_PAYLOAD{return Err(Error::Range);}
        let key=self.fifo.open(holder,false)?;
        let at=self.fifo.index(key)?;
        self.receivers[at]=ReceiveSlot::EMPTY;
        Ok(key)
    }
    fn index(&self,endpoint:ObjectKey)->Result<usize,Error>{
        let at=self.fifo.index(endpoint)?;
        if at>=MAX_ENDPOINTS{return Err(Error::Auth);}
        Ok(at)
    }
    fn authorized(&self,holder:ObjectKey,endpoint:ObjectKey,backend:&mut impl IpcBackend<B>)
        ->Result<usize,Error>
    {
        let at=self.index(endpoint)?;
        if self.fifo.endpoints[at].as_ref().ok_or(Error::Stale)?.owner!=holder{
            return Err(Error::Auth);
        }
        if self.receivers[at].closed{return Err(Error::Stale);}
        backend.authorize(holder,endpoint,IpcOperation::Receive)?;
        Ok(at)
    }
    pub fn reserve_send(&mut self,sender:ObjectKey,endpoint:ObjectKey,request_id:u64,now:u64,
        backend:&mut impl IpcBackend<B>)->Result<SendGrant,Error>
    {
        let at=self.index(endpoint)?;
        if self.receivers[at].closed{return Err(Error::Stale);}
        self.fifo.reserve_send(sender,endpoint,request_id,now,backend)
    }
    pub fn send_reserved(&mut self,grant:SendGrant,request_id:u64,bytes:&[u8],now:u64,
        backend:&mut impl IpcBackend<B>)->Result<u64,Error>
    {
        // Previously admitted send grants retain their exact custody.
        self.fifo.send_reserved(grant,request_id,bytes,now,backend)
    }
    pub fn cancel_send(&mut self,grant:SendGrant)->Result<(),Error>{self.fifo.cancel_send(grant)}
    pub fn stats(&self,endpoint:ObjectKey)->Result<IpcStats,Error>{self.fifo.stats(endpoint)}

    /// Under the serialized owner lock, reserve one fixed receipt and the
    /// external completion credit. The callback is invoked only on a new,
    /// ready head, after every fallible admission check; Err is no-effect.
    /// No head means no sequence advancement and no output-page pin.
    pub fn prepare(&mut self,holder:ObjectKey,endpoint:ObjectKey,recv_seq:u64,reply_cap:usize,
        now:u64,backend:&mut impl IpcBackend<B>,reserve_credit:impl FnOnce()->Result<u64,Error>)
        ->Result<ReceivePrepared,Error>
    {
        self.fifo.time(now)?;
        let at=self.authorized(holder,endpoint,backend)?;
        if recv_seq==0 || reply_cap<RECEIVE_V3_REPLY_CAP{return Err(Error::Range);}
        let slot=&self.receivers[at];
        if recv_seq<=slot.retired{return Err(Error::Stale);}
        if let Some(r)=slot.record{
            return if r.ticket.recv_seq==recv_seq{Ok(ReceivePrepared::Existing(r.ticket))}
                else {Err(Error::Busy)};
        }
        if slot.high.checked_add(1).ok_or(Error::Overflow)?!=recv_seq{return Err(Error::Again);}
        let e=self.fifo.endpoints[at].as_ref().ok_or(Error::Stale)?;
        if e.len==0{return Err(Error::Again);}
        let cell=usize::from(e.order[e.head]);
        let m=&self.fifo.messages[at][cell];
        if !e.owns(cell) || m.sequence==0 || m.sender.id==0 || m.sender.generation==0
            || m.request_id==0 || m.len>B || m.len>RECEIVE_V3_MAX_PAYLOAD{
            return Err(Error::Conflict);
        }
        let mut bytes=[0;RECEIVE_V3_REPLY_CAP];
        for (offset,value) in [(0,m.sender.id),(8,m.sender.generation),(16,m.request_id),
            (24,endpoint.generation)] {
            bytes[offset..offset+8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[32..36].copy_from_slice(&(m.len as u32).to_le_bytes());
        bytes[40..40+m.len].copy_from_slice(&m.bytes[..m.len]);
        let length=(40+m.len) as u16;
        let head_sequence=m.sequence;
        let completion_credit=reserve_credit()?;
        // The trusted pool must never return a zero or aliased credit.
        // A violated adapter contract fails closed before any FIFO change.
        if completion_credit==0{return Err(Error::Conflict);}
        let ticket=ReceiveTicket{endpoint,holder,recv_seq,head_sequence,completion_credit};
        let slot=&mut self.receivers[at];
        slot.high=recv_seq;
        slot.record=Some(ReceiveRecord{ticket,bytes,len:length,done:false});
        Ok(ReceivePrepared::New(ticket))
    }
    fn record(&self,ticket:ReceiveTicket,at:usize)->Result<&ReceiveRecord,Error>{
        self.receivers[at].record.as_ref().filter(|r|r.ticket==ticket).ok_or(Error::Stale)
    }
    /// Copy to private *kernel* staging under the owner lock. The adapter
    /// then drops the lock and performs actual checked copyout. An EFAULT or
    /// timeout does not call commit and leaves the exact same queue head.
    pub fn stage(&self,ticket:ReceiveTicket,out:&mut [u8;RECEIVE_V3_REPLY_CAP],
        backend:&mut impl IpcBackend<B>)->Result<usize,Error>
    {
        let at=self.authorized(ticket.holder,ticket.endpoint,backend)?;
        let r=self.record(ticket,at)?;
        out.copy_from_slice(&r.bytes);
        Ok(usize::from(r.len))
    }
    /// Called only after verified complete copyout to the actual holder and
    /// revalidation of its pinned mapping/generation. A retry after a lost
    /// return reuses DONE bytes; it never consumes a second queue head.
    pub fn commit_copied(&mut self,ticket:ReceiveTicket,copied_bytes:usize,now:u64,
        backend:&mut impl IpcBackend<B>)->Result<usize,Error>
    {
        self.fifo.time(now)?;
        let at=self.authorized(ticket.holder,ticket.endpoint,backend)?;
        let record=self.record(ticket,at)?;
        let len=usize::from(record.len);
        if copied_bytes!=len{return Err(Error::Range);}
        if record.done{return Ok(len);}
        let e=self.fifo.endpoints[at].as_mut().ok_or(Error::Stale)?;
        if e.len==0{return Err(Error::Conflict);}
        let cell=usize::from(e.order[e.head]);
        if !e.owns(cell) || self.fifo.messages[at][cell].sequence!=ticket.head_sequence{
            return Err(Error::Conflict);
        }
        // All fallible head/identity checks precede this single owner commit.
        e.stats.receive_wait_ns=e.stats.receive_wait_ns.saturating_add(now.saturating_sub(e.since[cell]));
        self.fifo.messages[at][cell]=Message::EMPTY;
        e.set_owned(cell,false);
        e.head=(e.head+1)%MAX_MESSAGES;
        e.len-=1;
        e.stats.delivered=e.stats.delivered.saturating_add(1);
        if e.stamp.live(now){e.applied_version=e.applied_version.max(e.stamp.version);}
        if e.len!=0{e.wake=true;}
        self.receivers[at].record.as_mut().unwrap().done=true;
        // Independent notification failure never undoes the committed receive.
        self.fifo.notify_endpoint(at,backend);
        Ok(len)
    }
    /// Credit release is a protected, serialized callback. It must return
    /// Err without effect; a successful callback and slot retirement are
    /// one owner operation. Exact latest ACK replay does not release again.
    pub fn ack(&mut self,holder:ObjectKey,endpoint:ObjectKey,recv_seq:u64,
        backend:&mut impl IpcBackend<B>,release:impl FnOnce(u64)->Result<(),Error>)
        ->Result<(),Error>
    {
        let at=self.authorized(holder,endpoint,backend)?;
        let slot=&mut self.receivers[at];
        if recv_seq==0{return Err(Error::Range);}
        if recv_seq==slot.retired{return Ok(());}
        if recv_seq<slot.retired{return Err(Error::Stale);}
        let r=slot.record.as_ref().ok_or(Error::Again)?;
        if r.ticket.recv_seq!=recv_seq{return Err(Error::Again);}
        if !r.done{return Err(Error::Busy);}
        release(r.ticket.completion_credit)?;
        slot.retired=recv_seq;
        slot.record=None;
        Ok(())
    }
    /// Protected lifecycle owner closes the receive/send admission gate.
    /// Existing grants/records remain owned; no caller can reuse the slot.
    pub fn close_admission(&mut self,holder:ObjectKey,endpoint:ObjectKey)->Result<(),Error>{
        let at=self.index(endpoint)?;
        if self.fifo.endpoints[at].as_ref().ok_or(Error::Stale)?.owner!=holder{return Err(Error::Auth);}
        self.receivers[at].closed=true;
        Ok(())
    }
    /// EL1 supervisor supplies real stop/no-in-flight-copy proof. For DONE,
    /// audit must have taken custody before release. A reserved head is not
    /// dequeued here. These booleans are adapter observations, not wire fields.
    pub fn retire_closed(&mut self,endpoint:ObjectKey,stopped:bool,done_audited:bool,
        release:impl FnOnce(u64)->Result<(),Error>)->Result<(),Error>
    {
        let at=self.index(endpoint)?;
        let slot=&mut self.receivers[at];
        if !slot.closed || !stopped{return Err(Error::Busy);}
        let Some(r)=slot.record else{return Ok(());};
        if r.done && !done_audited{return Err(Error::Busy);}
        release(r.ticket.completion_credit)?;
        slot.retired=r.ticket.recv_seq;
        slot.record=None;
        Ok(())
    }
    /// Only completely drained closed endpoints are reusable. A nonempty
    /// abandoned FIFO needs a separate supervised transfer/discard protocol.
    pub fn close_empty(&mut self,holder:ObjectKey,endpoint:ObjectKey,
        backend:&mut impl IpcBackend<B>)->Result<(),Error>
    {
        let at=self.index(endpoint)?;
        if !self.receivers[at].closed || self.receivers[at].record.is_some(){return Err(Error::Busy);}
        let stats=self.fifo.stats(endpoint)?;
        if stats.depth!=0 || stats.reserved!=0{return Err(Error::Busy);}
        self.fifo.close(holder,endpoint,backend)?;
        self.receivers[at]=ReceiveSlot::EMPTY;
        Ok(())
    }
}
