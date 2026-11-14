//! Native TCP bring-up after durable BootEpoch allocation. Diagnostic bytes are
//! deliberately plaintext; this profile grants no cluster membership/resources.
use crate::virtio_platform::Board;
use core::{
    fmt::Write,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use cyxia_cluster_transport::{
    device::VirtioPort,
    tcp::{BUFFER_SIZE, Config, Error, Storage, Tcp},
};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{Platform, QueueMemory, Transport, net::Net};

const BODY: usize = 65536;
const PREFIX: usize = 64;
const TOTAL: usize = PREFIX + BODY + 16;
const MAGIC: u64 = 0x4359585443503133;
static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut RX: QueueMemory = QueueMemory::zeroed();
static mut TX: QueueMemory = QueueMemory::zeroed();
static mut TCP_RX: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static mut TCP_TX: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static mut SOCKET: [Storage<'static>; 1] = [Storage::EMPTY];

#[repr(C, align(4096))]
pub struct Evidence {
    words: [AtomicU64; 512],
}
#[used]
#[unsafe(no_mangle)]
pub static TCP_V13_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 512],
};

fn line(args: core::fmt::Arguments<'_>) {
    struct Text {
        bytes: [u8; 192],
        len: usize,
    }
    impl Write for Text {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
            self.bytes
                .get_mut(self.len..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(text.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    let mut text = Text {
        bytes: [0; 192],
        len: 0,
    };
    text.write_fmt(args).expect("bounded TCP diagnostic");
    crate::log(&text.bytes[..text.len]);
}
fn fail(code: u64) -> ! {
    TCP_V13_EVIDENCE.words[16].store(code, Ordering::Release);
    line(format_args!("TCP_V13_FAIL code={code}\n"));
    crate::halt()
}
fn mac(node: u8) -> [u8; 6] {
    [2, 0, 0, 0, 0, node]
}
fn attach(info: &BootInfo) -> Net {
    let mut selected = None;
    for resource in info.virtio.get(..info.virtio_count).expect("DTB count") {
        if resource.base.0 < 0x0a000000
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|end| end > 0x0a200000)
        {
            continue;
        }
        // SAFETY: boot CPU alone probes DTB MMIO in the mapped Device window.
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
                fail(1)
            }
            selected = Some(transport);
        }
    }
    // SAFETY: CLAIMED admits CPU0 once; private pinned DMA pages are never
    // reclaimed, including device initialization or protocol failures.
    unsafe {
        Net::initialize(
            selected.unwrap_or_else(|| fail(2)),
            &mut *core::ptr::addr_of_mut!(RX),
            &mut *core::ptr::addr_of_mut!(TX),
            &Board,
        )
    }
    .unwrap_or_else(|_| fail(3))
}
fn pattern(node: u8, at: usize) -> u8 {
    (at as u8).wrapping_mul(17) ^ node ^ (at >> 8) as u8
}

pub fn run(info: &BootInfo) -> ! {
    if cyxia_arch_aarch64::cpu::slot() != 0 || CLAIMED.swap(true, Ordering::AcqRel) {
        fail(4)
    }
    let identity = crate::prototype_storage::boot(info);
    crate::entropy::init(info);
    let mut entropy = [0; 24];
    crate::entropy::fill(&mut entropy).unwrap_or_else(|_| fail(5));
    let seed = u64::from_le_bytes(entropy[..8].try_into().unwrap());
    if seed == 0 {
        fail(6)
    }
    let mut net = attach(info);
    let node = net.mac()[5];
    if !(1..=2).contains(&node) || net.mac() != mac(node) {
        fail(7)
    }
    let peer = 3 - node;
    let mut header = [0; PREFIX];
    header[..8].copy_from_slice(b"CYXTCP13");
    header[8] = 1;
    header[10] = node;
    header[11] = peer;
    header[16..24].copy_from_slice(&identity.epoch.to_le_bytes());
    header[24..40].copy_from_slice(&identity.filesystem);
    header[40..56].copy_from_slice(&entropy[8..]);
    header[56..60].copy_from_slice(&(BODY as u32).to_le_bytes());
    entropy.fill(0);
    let now = Board.now_ms();
    let config = Config {
        mac: mac(node),
        local: [10, 42, 0, node],
        peer: [10, 42, 0, peer],
        prefix_len: 24,
        local_port: if node == 1 { 40001 } else { 8443 },
        peer_port: if node == 1 { 8443 } else { 40001 },
        random_seed: seed,
    };
    // SAFETY: single CPU0 foreground owner, static per-stream buffers and
    // sockets remain exclusively borrowed for this profile's entire lifetime.
    let mut tcp = unsafe {
        Tcp::new(
            VirtioPort {
                net: &mut net,
                platform: &Board,
            },
            config,
            now,
            &mut *core::ptr::addr_of_mut!(TCP_RX),
            &mut *core::ptr::addr_of_mut!(TCP_TX),
            &mut *core::ptr::addr_of_mut!(SOCKET),
        )
    }
    .unwrap_or_else(|_| fail(8));
    if node == 1 {
        tcp.connect()
    } else {
        tcp.listen()
    }
    .unwrap_or_else(|_| fail(9));
    line(format_args!(
        "TCP_V13_START node={node} peer={peer} boot={} EL1_TCP_PLAINTEXT_ONLY\n",
        identity.epoch
    ));
    let mut received = 0;
    let mut sent = 0;
    let mut peer_header = [0; PREFIX];
    let mut peer_ack = [0; 16];
    let mut finish = None;
    let mut block = [0; 1024];
    let start = Board.now_ms();
    loop {
        crate::smp::check_failures();
        let now = Board.now_ms();
        if now - start >= 20_000 {
            line(format_args!(
                "TCP_V13_TIMEOUT sent={sent} received={received}\n"
            ));
            fail(10)
        }
        tcp.poll(now).unwrap_or_else(|e| {
            line(format_args!("TCP_V13_POLL_ERROR {e:?}\n"));
            fail(11)
        });
        if sent < TOTAL && (sent < PREFIX + BODY || received >= PREFIX + BODY) {
            let end = if sent < PREFIX {
                PREFIX
            } else if sent < PREFIX + BODY {
                PREFIX + BODY
            } else {
                TOTAL
            };
            let count = (end - sent).min(block.len());
            for (i, byte) in block[..count].iter_mut().enumerate() {
                let at = sent + i;
                *byte = if at < PREFIX {
                    header[at]
                } else if at < PREFIX + BODY {
                    pattern(node, at - PREFIX)
                } else {
                    let ack = at - PREFIX - BODY;
                    if ack < 8 {
                        b"CYXACK13"[ack]
                    } else {
                        (BODY as u64).to_le_bytes()[ack - 8]
                    }
                };
            }
            match tcp.send_tls(&block[..count]) {
                Ok(count) => sent += count,
                Err(Error::WouldBlock | Error::Closed) => {}
                Err(_) => fail(12),
            }
        }
        match tcp.receive_tls(&mut block) {
            Ok(count) => {
                for &byte in &block[..count] {
                    if received < PREFIX {
                        peer_header[received] = byte;
                    } else if received < PREFIX + BODY {
                        if byte != pattern(peer, received - PREFIX) {
                            fail(13)
                        }
                    } else if received < TOTAL {
                        peer_ack[received - PREFIX - BODY] = byte;
                    } else {
                        fail(14)
                    }
                    received += 1;
                    if received == PREFIX {
                        if peer_header[..8] != *b"CYXTCP13"
                            || peer_header[8..16] != [1, 0, peer, node, 0, 0, 0, 0]
                            || u64::from_le_bytes(peer_header[16..24].try_into().unwrap()) == 0
                            || peer_header[24..40] == identity.filesystem
                            || peer_header[24..40] == [0; 16]
                            || peer_header[40..56] == header[40..56]
                            || peer_header[40..56] == [0; 16]
                            || peer_header[56..60] != (BODY as u32).to_le_bytes()
                            || peer_header[60..] != [0; 4]
                        {
                            fail(15)
                        }
                    }
                }
            }
            Err(Error::WouldBlock | Error::Closed) => {}
            Err(_) => fail(16),
        }
        if received == TOTAL && sent == TOTAL {
            if peer_ack[..8] != *b"CYXACK13" || peer_ack[8..] != (BODY as u64).to_le_bytes() {
                fail(17)
            }
            let end = finish.get_or_insert(now + 1000);
            if now >= *end {
                let words = [
                    1,
                    1,
                    u64::from(node),
                    u64::from(peer),
                    identity.epoch,
                    u64::from_le_bytes(identity.filesystem[..8].try_into().unwrap()),
                    u64::from_le_bytes(identity.filesystem[8..].try_into().unwrap()),
                    u64::from_le_bytes(peer_header[16..24].try_into().unwrap()),
                    u64::from_le_bytes(peer_header[24..32].try_into().unwrap()),
                    u64::from_le_bytes(peer_header[32..40].try_into().unwrap()),
                    sent as u64,
                    received as u64,
                    BODY as u64,
                    1,
                    now - start,
                ];
                for (index, word) in words.into_iter().enumerate() {
                    TCP_V13_EVIDENCE.words[index + 1].store(word, Ordering::Relaxed);
                }
                TCP_V13_EVIDENCE.words[0].store(MAGIC, Ordering::Release);
                line(format_args!(
                    "TCP_V13_READY node={node} peer={peer} bytes={TOTAL}\n"
                ));
                crate::halt()
            }
        }
        core::hint::spin_loop();
    }
}
