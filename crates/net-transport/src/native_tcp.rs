//! SEC-N native socket bridge: one bounded, nonblocking TLS/Echo turn.
//!
//! The only application operation is read-only Echo; encrypted bytes cross the
//! socket boundary only through rustls. No cluster RPC, membership or model
//! controls are present. TCP queued bytes, remote ACKs and NIC DMA completion
//! are separate; this bridge never uses a socket send as a completion proof.
#![forbid(unsafe_code)]
use crate::{admission::{ActiveTicket, Admission, Error as AdmissionError}, tls::Session};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketError { Again, Closed, Device }
/// Implement only on a trusted native local TCP owner. The peer cannot
/// manufacture admission tickets, TLS proofs or privileged completion events.
pub trait NativeSocket {
    /// One bounded smoltcp/VirtIO service turn, no blocking.
    fn poll_native(&mut self, now_ms: u64) -> Result<(), SocketError>;
    /// Return only actual TLS ciphertext from this socket, never application
    /// plaintext or a buffer copied from an untrusted service.
    fn read_ciphertext(&mut self, out: &mut [u8]) -> Result<usize, SocketError>;
    /// Return the count actually accepted into the native TCP send queue;
    /// it does not imply TCP ACK, device used-ring or DMA retirement.
    fn queue_ciphertext(&mut self, bytes: &[u8]) -> Result<usize, SocketError>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error { Socket(SocketError), Tls, Admission(AdmissionError) }
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    pub received_ciphertext: usize,
    pub queued_ciphertext: usize,
    pub echo_queued: usize,
}
fn send<S: NativeSocket>(
    socket: &mut S, tls: &mut Session<'_>, progress: &mut Progress,
) -> Result<(), Error> {
    let pending=tls.pending_tls();
    if pending.is_empty() {return Ok(());}
    let queued=match socket.queue_ciphertext(pending) {
        Ok(n) => n,
        Err(SocketError::Again) => 0,
        Err(error) => return Err(Error::Socket(error)),
    };
    if queued > pending.len() {return Err(Error::Socket(SocketError::Device));}
    tls.consume_tls(queued).map_err(|_|Error::Tls)?;
    progress.queued_ciphertext += queued;
    Ok(())
}
/// Max one native device poll, one TLS receive, one Echo dispatch and two TLS
/// queue attempts per call. Incomplete records/frames and output backpressure
/// retain exact ownership for a later turn. Never waits or allocates.
pub fn turn<S: NativeSocket>(
    socket: &mut S,
    admission: &mut Admission,
    active: ActiveTicket,
    tls: &mut Session<'_>,
    scratch: &mut [u8],
    now_ms: u64,
) -> Result<Progress, Error> {
    let mut progress=Progress::default();
    if let Err(error)=socket.poll_native(now_ms) {
        if error != SocketError::Again {
            let _=admission.begin_drain(active);
            tls.abort();
            return Err(Error::Socket(error));
        }
    }
    if let Err(error)=send(socket,tls,&mut progress) {
        let _=admission.begin_drain(active);
        tls.abort();
        return Err(error);
    }
    let capacity=tls.receive_capacity().min(scratch.len());
    if capacity!=0 {
        match socket.read_ciphertext(&mut scratch[..capacity]) {
            Ok(0) | Err(SocketError::Again) => {},
            Ok(n) if n <= capacity => {
                let accepted=tls.receive_tls(&scratch[..n]).map_err(|_|Error::Tls)?;
                if accepted!=n {return Err(Error::Tls);}
                progress.received_ciphertext=n;
            },
            Ok(_) => return Err(Error::Socket(SocketError::Device)),
            Err(error) => {
                let _=admission.begin_drain(active);
                tls.abort();
                return Err(Error::Socket(error));
            },
        }
    }
    tls.pump(now_ms).map_err(|_|Error::Tls)?;
    if !tls.plaintext().is_empty() {
        match admission.dispatch_echo(active,tls) {
            Ok(n)=>progress.echo_queued=n,
            Err(AdmissionError::Busy)=>{},
            Err(error)=>{
                // A malformed authenticated request terminates admission
                // without dropping the native socket/DMA completion debt.
                let _=admission.begin_drain(active);
                return Err(Error::Admission(error));
            },
        }
    }
    tls.pump(now_ms).map_err(|_|Error::Tls)?;
    if let Err(error)=send(socket,tls,&mut progress) {
        let _=admission.begin_drain(active);
        tls.abort();
        return Err(error);
    }
    if !tls.has_pending_plaintext() && tls.pending_tls().is_empty() {
        match admission.confirm_tls_output_drained(active,tls) {
            Ok(()) | Err(AdmissionError::Stale) => {},
            Err(AdmissionError::Busy) => {},
            Err(error) => return Err(Error::Admission(error)),
        }
    }
    Ok(progress)
}
