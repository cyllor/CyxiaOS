//! V0.19 isolated readonly Echo adapter over the existing native smoltcp TCP
//! implementation. This reuses *only* TCP/TLS transport, never cluster wire,
//! membership, remote placement, resource grants or cluster discovery.
use crate::{device::Port, tcp::{self, Tcp}};
use cyxia_net_transport::native_tcp::{NativeSocket, SocketError};
fn map_error(error: tcp::Error) -> SocketError {
    match error {
        tcp::Error::WouldBlock => SocketError::Again,
        tcp::Error::Closed => SocketError::Closed,
        _ => SocketError::Device,
    }
}
impl<P: Port> NativeSocket for Tcp<'_, P> {
    fn poll_native(&mut self, now_ms: u64) -> Result<(), SocketError> {
        let state=self.poll(now_ms).map_err(map_error)?;
        if state==tcp::State::Closed {
            Err(SocketError::Closed)
        } else {
            Ok(())
        }
    }
    fn read_ciphertext(&mut self, out: &mut [u8]) -> Result<usize, SocketError> {
        self.receive_tls(out).map_err(map_error)
    }
    fn queue_ciphertext(&mut self, bytes: &[u8]) -> Result<usize, SocketError> {
        self.send_tls(bytes).map_err(map_error)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn requires_native_adapter<T: NativeSocket>() {}
    #[test] fn v019_sec_n_native_smoltcp_implements_readonly_encrypted_socket_contract() {
        // Compile-time proof of the actual native TCP type-level adapter.
        requires_native_adapter::<Tcp<'static, DummyPort>>();
        // Unsupported ports must not manufacture a TX quiescence witness.
        assert!(!DummyPort.tx_quiescent());
    }
    struct DummyPort;
    impl Port for DummyPort {
        fn send(&mut self, _: &[u8]) -> Result<(), crate::device::Error> { Ok(()) }
        fn receive(&mut self, _: &mut [u8; crate::device::MTU])
            -> Result<Option<usize>,crate::device::Error> { Ok(None) }
    }
}
