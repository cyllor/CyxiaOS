//! Explicit EL1 Ethernet bring-up, not TLS, cluster admission, or an EL0 service.
//! The fixed test frames never grant resources or authenticate another node.

const FRAME_BYTES: usize = 64;
const COMPLETE: u16 = u16::MAX;
const WIRE_MAGIC: [u8; 8] = *b"CYXNET13";

fn mac(node: u8) -> [u8; 6] {
    [2, 0, 0, 0, 0, node]
}

fn frame(node: u8, sequence: u8, received: u16, ordinal: u64) -> [u8; FRAME_BYTES] {
    assert!((1..=2).contains(&node) && sequence < 16 && ordinal & 15 == u64::from(sequence));
    let mut bytes = [0; FRAME_BYTES];
    bytes[..6].copy_from_slice(&mac(3 - node));
    bytes[6..12].copy_from_slice(&mac(node));
    bytes[12..14].copy_from_slice(&[0x88, 0xb5]);
    bytes[14..22].copy_from_slice(&WIRE_MAGIC);
    bytes[22] = 1;
    bytes[23] = node;
    bytes[24] = 3 - node;
    bytes[25] = sequence;
    bytes[26..28].copy_from_slice(&received.to_le_bytes());
    bytes[28..36].copy_from_slice(&ordinal.to_le_bytes());
    for offset in 36..FRAME_BYTES {
        // Diagnostic pattern only. This is not a cryptographic integrity tag.
        bytes[offset] =
            node ^ sequence ^ bytes[26] ^ bytes[27] ^ bytes[28 + (offset - 36) % 8] ^ offset as u8;
    }
    bytes
}

fn parse(bytes: &[u8], node: u8) -> Option<(u8, u16)> {
    if bytes.len() != FRAME_BYTES || !(1..=2).contains(&node) {
        return None;
    }
    let peer = 3 - node;
    if bytes[..6] != mac(node)
        || bytes[6..12] != mac(peer)
        || bytes[12..14] != [0x88, 0xb5]
        || bytes[14..22] != WIRE_MAGIC
        || bytes[22] != 1
        || bytes[23] != peer
        || bytes[24] != node
        || bytes[25] >= 16
    {
        return None;
    }
    let sequence = bytes[25];
    let received = u16::from_le_bytes([bytes[26], bytes[27]]);
    let ordinal = u64::from_le_bytes(bytes[28..36].try_into().ok()?);
    if ordinal & 15 != u64::from(sequence) || bytes != frame(peer, sequence, received, ordinal) {
        return None;
    }
    Some((sequence, received))
}

#[cfg(not(test))]
pub use runtime::run;

#[cfg(not(test))]
mod runtime {
    use super::{COMPLETE, frame, mac, parse};
    use crate::virtio_platform::Board;
    use core::{
        fmt::Write,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use cyxia_contracts::BootInfo;
    use cyxia_driver_virtio::{
        Platform, QueueMemory, Transport,
        net::{MAX_FRAME, Net},
    };

    const EVIDENCE_MAGIC: u64 = 0x4359584e45543133;
    const TIMEOUT_MS: u64 = 10_000;
    const SEND_PERIOD_MS: u64 = 10;
    const FINISH_GRACE_MS: u64 = 1_000;
    static STARTED: AtomicBool = AtomicBool::new(false);
    static mut RX: QueueMemory = QueueMemory::zeroed();
    static mut TX: QueueMemory = QueueMemory::zeroed();

    #[repr(C, align(4096))]
    pub struct Evidence {
        pub words: [AtomicU64; 512],
    }
    #[used]
    #[unsafe(no_mangle)]
    pub static NET_EVIDENCE: Evidence = Evidence {
        words: [const { AtomicU64::new(0) }; 512],
    };

    fn line(args: core::fmt::Arguments<'_>) {
        struct Text {
            bytes: [u8; 160],
            len: usize,
        }
        impl Write for Text {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.len.checked_add(s.len()).ok_or(core::fmt::Error)?;
                self.bytes
                    .get_mut(self.len..end)
                    .ok_or(core::fmt::Error)?
                    .copy_from_slice(s.as_bytes());
                self.len = end;
                Ok(())
            }
        }
        let mut text = Text {
            bytes: [0; 160],
            len: 0,
        };
        text.write_fmt(args).expect("bounded net diagnostic");
        crate::log(&text.bytes[..text.len]);
    }

    fn fail(code: u64) -> ! {
        NET_EVIDENCE.words[9].store(code, Ordering::Release);
        line(format_args!("NET_PAIR_FAIL code={code}\n"));
        // No reset, DMA reclamation, completed marker, or success receipt.
        crate::halt()
    }

    fn dump_failed_rx() {
        // Read-only diagnostics after Net returned an error and poisoned itself.
        // The pools remain pinned; this does not assert DMA cessation or reuse.
        // The driver already synchronized used/header storage before validating.
        let base = core::ptr::addr_of!(RX).cast::<u8>();
        for (label, offset, len) in [("HEADER", 16384usize, 12usize), ("USED", 8192, 68)] {
            for start in (0..len).step_by(32) {
                let count = (len - start).min(32);
                let mut hex = [0u8; 64];
                for byte in 0..count {
                    // SAFETY: both bounded ranges lie within the static RX
                    // QueueMemory; volatile reads never change DMA ownership.
                    let value =
                        unsafe { core::ptr::read_volatile(base.add(offset + start + byte)) };
                    hex[byte * 2] = b"0123456789abcdef"[usize::from(value >> 4)];
                    hex[byte * 2 + 1] = b"0123456789abcdef"[usize::from(value & 15)];
                }
                let value = core::str::from_utf8(&hex[..count * 2]).unwrap();
                line(format_args!("NET_RX_{label} offset={start} hex={value}\n"));
            }
        }
    }

    fn attach(info: &BootInfo) -> Net {
        let mut selected = None;
        let Some(resources) = info.virtio.get(..info.virtio_count) else {
            fail(1)
        };
        for resource in resources {
            if resource.base.0 < 0x0a000000
                || resource
                    .base
                    .0
                    .checked_add(resource.len)
                    .is_none_or(|end| end > 0x0a200000)
            {
                continue;
            }
            // SAFETY: only CPU0 probes DTB resources inside the mapped Device
            // window. No other profile/device driver is active on this path.
            let Ok(transport) = (unsafe {
                Transport::attach(
                    (crate::HIGH + resource.base.0) as usize,
                    resource.len as usize,
                )
            }) else {
                continue;
            };
            if transport.device_id() == 1 {
                if selected.is_some() {
                    fail(2)
                }
                selected = Some(transport);
            }
        }
        let Some(transport) = selected else { fail(3) };
        // SAFETY: run claims STARTED once on CPU0. These separate static DMA
        // pages are never freed/reused, including initialization/runtime failure.
        let result = unsafe {
            Net::initialize(
                transport,
                &mut *core::ptr::addr_of_mut!(RX),
                &mut *core::ptr::addr_of_mut!(TX),
                &Board,
            )
        };
        match result {
            Ok(net) => net,
            Err(error) => {
                line(format_args!("NET_INIT_ERROR {error:?}\n"));
                fail(4)
            }
        }
    }

    /// CPU0 EL1 driver test with actual four-core startup; no production
    /// ownership, authenticated membership, transport security or task grant.
    pub fn run(info: &BootInfo) -> ! {
        if cyxia_arch_aarch64::cpu::slot() != 0 || STARTED.swap(true, Ordering::AcqRel) {
            fail(5)
        }
        let mut net = attach(info);
        let address = net.mac();
        let node = address[5];
        if !(1..=2).contains(&node) || address != mac(node) {
            fail(6)
        }
        let peer = 3 - node;
        let started = Board.now_ms();
        let mut next_send = started;
        let mut received = 0u16;
        let mut peer_ack = 0u16;
        let mut rx_count = 0u64;
        let mut queued = 0u64;
        let mut completed = 0u64;
        let mut pending_full_ack = false;
        let mut completed_full_ack = false;
        let mut finish_at = None;
        let mut input = [0u8; MAX_FRAME];
        line(format_args!(
            "NET_PAIR_START node={node} peer={peer} EL1_ETHERNET_ONLY\n"
        ));
        loop {
            crate::smp::check_failures();
            let now = Board.now_ms();
            if now.wrapping_sub(started) >= TIMEOUT_MS {
                line(format_args!(
                    "NET_PAIR_TIMEOUT node={node} received={received} ack={peer_ack} queued={queued} tx={completed} rx={rx_count}\n"
                ));
                fail(7)
            }
            match net.poll_tx(&Board) {
                Ok(true) => {
                    completed += 1;
                    completed_full_ack |= pending_full_ack;
                }
                Ok(false) => {}
                Err(error) => {
                    line(format_args!("NET_TX_ERROR {error:?}\n"));
                    fail(8)
                }
            }
            match net.receive(&mut input, &Board) {
                Ok(Some(len)) => {
                    if let Some((sequence, acknowledgment)) = parse(&input[..len], node) {
                        received |= 1 << sequence;
                        peer_ack = acknowledgment;
                        rx_count += 1;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    line(format_args!("NET_RX_ERROR {error:?}\n"));
                    dump_failed_rx();
                    fail(9)
                }
            }
            let ready = received == COMPLETE
                && peer_ack == COMPLETE
                && completed >= 64
                && completed_full_ack;
            if !ready {
                finish_at = None;
            } else if finish_at.is_none() {
                finish_at = Some(now + FINISH_GRACE_MS);
            }
            if finish_at.is_some_and(|at| now >= at) && queued == completed {
                let values = [
                    1,
                    1,
                    u64::from(node),
                    u64::from(peer),
                    u64::from(received),
                    u64::from(peer_ack),
                    completed,
                    rx_count,
                    0,
                ];
                for (word, value) in NET_EVIDENCE.words[1..10].iter().zip(values) {
                    word.store(value, Ordering::Relaxed);
                }
                // Commit after all evidence fields, then emit the serial receipt.
                NET_EVIDENCE.words[0].store(EVIDENCE_MAGIC, Ordering::Release);
                line(format_args!(
                    "NET_PAIR_READY node={node} peer={peer} received=65535\n"
                ));
                crate::halt()
            }
            if queued == completed && now >= next_send {
                let packet = frame(node, (queued & 15) as u8, received, queued);
                if let Err(error) = net.send(&packet, &Board) {
                    line(format_args!("NET_SEND_ERROR {error:?}\n"));
                    fail(10)
                }
                pending_full_ack = received == COMPLETE;
                queued += 1;
                next_send = now + SEND_PERIOD_MS;
            }
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_checks_all_sixteen_sequences_and_both_roles() {
        for node in [1, 2] {
            for sequence in 0..16 {
                let packet = frame(node, sequence, 1 << sequence, sequence as u64);
                assert_eq!(packet.len(), 64);
                assert_eq!(&packet[..6], &mac(3 - node));
                assert_eq!(&packet[6..12], &mac(node));
                assert_eq!(&packet[12..14], &[0x88, 0xb5]);
                assert_eq!(parse(&packet, 3 - node), Some((sequence, 1 << sequence)));
                assert_eq!(parse(&packet, node), None, "self traffic is not a peer");
            }
        }
    }

    #[test]
    fn malformed_packets_cannot_contribute_a_sequence_or_acknowledgment() {
        let packet = frame(1, 5, COMPLETE, 37);
        assert_eq!(parse(&packet, 2), Some((5, COMPLETE)));
        for len in 0..FRAME_BYTES {
            assert_eq!(parse(&packet[..len], 2), None);
        }
        let mut oversized = packet.to_vec();
        oversized.push(0);
        assert_eq!(parse(&oversized, 2), None);
        for offset in 0..FRAME_BYTES {
            let mut corrupted = packet;
            corrupted[offset] ^= 0x80;
            assert_eq!(parse(&corrupted, 2), None, "changed byte {offset}");
        }
        let mut wrong_ordinal = packet;
        wrong_ordinal[28] ^= 1;
        assert_eq!(parse(&wrong_ordinal, 2), None);
    }

    #[test]
    fn invalid_local_identity_is_rejected_without_arithmetic_underflow() {
        let packet = frame(1, 0, COMPLETE, 0);
        for node in [0, 3, 255] {
            assert_eq!(parse(&packet, node), None);
        }
    }
}
