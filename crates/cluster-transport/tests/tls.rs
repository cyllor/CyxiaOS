#![cfg(feature = "tls")]
use cyxia_cluster_transport::tls::{
    Buffers, Error, HANDSHAKE_TIMEOUT_MS, Pairing, Session, node_id,
};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
    time_provider::TimeProvider,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Debug)]
struct Time(AtomicBool);
impl TimeProvider for Time {
    fn current_time(&self) -> Option<UnixTime> {
        self.0
            .load(Ordering::Relaxed)
            .then(|| UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)))
    }
}
fn fixtures() -> [(&'static [u8], &'static [u8]); 2] {
    let mut fixtures = [
        (
            &include_bytes!("fixtures/a-test-cert.der")[..],
            &include_bytes!("fixtures/a-test-key.der")[..],
        ),
        (
            &include_bytes!("fixtures/b-test-cert.der")[..],
            &include_bytes!("fixtures/b-test-key.der")[..],
        ),
    ];
    fixtures.sort_by_key(|(cert, _)| node_id(&CertificateDer::from(*cert)).unwrap());
    fixtures
}
fn pairings(clock: Arc<Time>) -> [Pairing; 2] {
    let f = fixtures();
    let id0 = node_id(&CertificateDer::from(f[0].0)).unwrap();
    let id1 = node_id(&CertificateDer::from(f[1].0)).unwrap();
    [
        Pairing::new(
            CertificateDer::from(f[0].0),
            PrivatePkcs8KeyDer::from(f[0].1).into(),
            id1,
            clock.clone(),
        )
        .unwrap(),
        Pairing::new(
            CertificateDer::from(f[1].0),
            PrivatePkcs8KeyDer::from(f[1].1).into(),
            id0,
            clock,
        )
        .unwrap(),
    ]
}
fn transfer(a: &mut Session<'_>, b: &mut Session<'_>, fragment: usize) -> Result<(), Error> {
    let bytes = a.pending_tls();
    let count = bytes.len().min(fragment);
    let accepted = b.receive_tls(&bytes[..count])?;
    a.consume_tls(accepted)
}
fn handshake(a: &mut Session<'_>, b: &mut Session<'_>) -> Result<(), Error> {
    for _ in 0..20000 {
        a.pump(0)?;
        b.pump(0)?;
        transfer(a, b, 37)?;
        transfer(b, a, 71)?;
        if a.authenticated_peer().is_some() && b.authenticated_peer().is_some() {
            return Ok(());
        }
    }
    panic!("bounded handshake failed to progress");
}
#[test]
fn real_mutual_tls13_and_bidirectional_encrypted_records() {
    let [small, large] = pairings(Arc::new(Time(AtomicBool::new(true))));
    let mut ab = Box::new(Buffers::new());
    let mut bb = Box::new(Buffers::new());
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    assert!(matches!(
        a.send_plaintext(b"forbidden"),
        Err(Error::Handshake)
    ));
    handshake(&mut a, &mut b).unwrap();
    assert_eq!(a.authenticated_peer(), Some(large.local_node()));
    assert_eq!(b.authenticated_peer(), Some(small.local_node()));
    let message: Vec<u8> = (0..16000).map(|i| (i * 23) as u8).collect();
    a.send_plaintext(&message).unwrap();
    b.send_plaintext(b"response").unwrap();
    let mut received = Vec::new();
    let mut reply = Vec::new();
    for _ in 0..20000 {
        a.pump(0).unwrap();
        b.pump(0).unwrap();
        transfer(&mut a, &mut b, 113).unwrap();
        transfer(&mut b, &mut a, 53).unwrap();
        received.extend_from_slice(b.plaintext());
        let count = b.plaintext().len();
        b.consume_plaintext(count).unwrap();
        reply.extend_from_slice(a.plaintext());
        let count = a.plaintext().len();
        a.consume_plaintext(count).unwrap();
        if received.len() == message.len() && reply.len() == 8 {
            break;
        }
    }
    assert_eq!(received, message);
    assert_eq!(reply, b"response");
}
#[test]
fn fixed_record_capacity_does_not_require_record_sized_stack_temporaries() {
    // The isolated native role has a guarded 128 KiB stack. Two 96 KiB
    // buffer bundles must be initialized on the allocator, including while
    // a real TLS handshake is running on this deliberately bounded stack.
    assert!(core::mem::size_of::<Buffers>() <= 64);
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let [small, large] = pairings(Arc::new(Time(AtomicBool::new(true))));
            let mut first = Buffers::new();
            let mut second = Buffers::new();
            let mut client = small.client(&mut first, 0).unwrap();
            let mut server = large.server(&mut second, 0).unwrap();
            handshake(&mut client, &mut server).unwrap();
            let message = vec![0x5a; 16_384];
            let mut received = Vec::with_capacity(message.len());
            client.send_plaintext(&message).unwrap();
            for _ in 0..20000 {
                client.pump(0).unwrap();
                server.pump(0).unwrap();
                transfer(&mut client, &mut server, 113).unwrap();
                transfer(&mut server, &mut client, 53).unwrap();
                received.extend_from_slice(server.plaintext());
                let accepted = server.plaintext().len();
                server.consume_plaintext(accepted).unwrap();
                if received.len() == message.len() {
                    break;
                }
            }
            assert_eq!(received.len(), message.len());
            assert!(received == message);
        })
        .unwrap()
        .join()
        .unwrap();
}
#[test]
fn authentication_rejects_unpaired_client_even_with_valid_signature() {
    let clock = Arc::new(Time(AtomicBool::new(true)));
    let f = fixtures();
    let [small, _] = pairings(clock.clone());
    // A different, smaller fingerprint preserves transport direction; it must
    // never accept the actual client's perfectly valid Ed25519 signature.
    let wrong = Pairing::new(
        CertificateDer::from(f[1].0),
        PrivatePkcs8KeyDer::from(f[1].1).into(),
        [1; 32],
        clock,
    )
    .unwrap();
    let mut ab = Box::new(Buffers::new());
    let mut bb = Box::new(Buffers::new());
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = wrong.server(&mut bb, 0).unwrap();
    assert!(handshake(&mut a, &mut b).is_err());
    assert_eq!(b.authenticated_peer(), None);
    assert!(matches!(b.pump(0), Err(Error::Closed)));
    assert!(b.plaintext().is_empty());
}
#[test]
fn corrupted_record_revokes_authentication_and_exposes_no_plaintext() {
    let [small, large] = pairings(Arc::new(Time(AtomicBool::new(true))));
    let mut ab = Box::new(Buffers::new());
    let mut bb = Box::new(Buffers::new());
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    handshake(&mut a, &mut b).unwrap();
    a.send_plaintext(b"do not expose altered data").unwrap();
    a.pump(0).unwrap();
    let mut record = a.pending_tls().to_vec();
    assert!(!record.is_empty());
    let last = record.len() - 1;
    record[last] ^= 1;
    b.receive_tls(&record).unwrap();
    assert!(b.pump(0).is_err());
    assert_eq!(b.authenticated_peer(), None);
    assert!(b.plaintext().is_empty());
}
#[test]
fn no_time_no_identity_and_reversed_primary_are_rejected() {
    let f = fixtures();
    let peer = node_id(&CertificateDer::from(f[1].0)).unwrap();
    assert!(matches!(
        Pairing::new(
            CertificateDer::from(f[0].0),
            PrivatePkcs8KeyDer::from(f[0].1).into(),
            peer,
            Arc::new(Time(AtomicBool::new(false)))
        ),
        Err(Error::Time)
    ));
    let clock = Arc::new(Time(AtomicBool::new(true)));
    assert!(
        Pairing::new(
            CertificateDer::from(f[0].0),
            PrivatePkcs8KeyDer::from(f[1].1).into(),
            peer,
            clock.clone()
        )
        .is_err()
    );
    assert!(node_id(&CertificateDer::from(&b"not a certificate"[..])).is_err());
    let [small, large] = pairings(clock.clone());
    let mut buffers = Box::new(Buffers::new());
    assert!(matches!(
        small.server(&mut buffers, 0),
        Err(Error::Direction)
    ));
    assert!(matches!(
        large.client(&mut buffers, 0),
        Err(Error::Direction)
    ));
    let mut session = small.client(&mut buffers, 0).unwrap();
    clock.0.store(false, Ordering::Relaxed);
    assert!(matches!(session.pump(0), Err(Error::Time)));
    assert_eq!(session.authenticated_peer(), None);
}
#[test]
fn each_connection_uses_a_fresh_client_hello_key_share() {
    let [small, _] = pairings(Arc::new(Time(AtomicBool::new(true))));
    let mut a = Box::new(Buffers::new());
    let mut b = Box::new(Buffers::new());
    let mut first = small.client(&mut a, 0).unwrap();
    let mut second = small.client(&mut b, 0).unwrap();
    first.pump(0).unwrap();
    second.pump(0).unwrap();
    assert_ne!(
        key_share(first.pending_tls()),
        key_share(second.pending_tls())
    );
}

// Independently parse ClientHello extensions, checking the wire policy rather
// than only comparing random bytes in two messages.
fn key_share(record: &[u8]) -> Vec<u8> {
    assert_eq!(&record[..3], &[22, 3, 1]);
    assert_eq!(record[5], 1);
    let read16 = |at| u16::from_be_bytes([record[at], record[at + 1]]) as usize;
    let mut at = 9 + 2 + 32;
    at += 1 + record[at] as usize;
    let suites = read16(at);
    at += 2;
    assert_eq!(&record[at..at + suites], &[0x13, 1]);
    at += suites;
    at += 1 + record[at] as usize;
    let end = at + 2 + read16(at);
    at += 2;
    let mut key = None;
    while at < end {
        let kind = read16(at);
        let len = read16(at + 2);
        at += 4;
        match kind {
            51 => {
                assert_eq!(&record[at..at + 6], &[0, 36, 0, 29, 0, 32]);
                key = Some(record[at + 6..at + len].to_vec());
            }
            43 => assert_eq!(&record[at..at + len], &[2, 3, 4]),
            13 => assert_eq!(&record[at..at + len], &[0, 2, 8, 7]),
            35 | 41 | 42 => panic!("session resumption or early data offered"),
            _ => {}
        }
        at += len;
    }
    assert_eq!(at, end);
    let key = key.unwrap();
    assert_eq!(key.len(), 32);
    key
}

#[test]
fn oversized_fragmented_handshake_fails_instead_of_deadlocking() {
    let [_, large] = pairings(Arc::new(Time(AtomicBool::new(true))));
    let mut buffers = Box::new(Buffers::new());
    let mut session = large.server(&mut buffers, 0).unwrap();
    let mut bytes = vec![0; 32768];
    bytes[..5].copy_from_slice(&[22, 3, 3, 0x40, 0]);
    bytes[5..9].copy_from_slice(&[1, 0, 0x9c, 0x40]);
    bytes[16389..16394].copy_from_slice(&[22, 3, 3, 0x40, 0]);
    assert_eq!(session.receive_tls(&bytes).unwrap(), 32768);
    assert!(matches!(session.pump(0), Err(Error::Buffer)));
    assert!(matches!(session.receive_tls(&[0]), Err(Error::Closed)));
}

#[test]
fn transport_eof_revokes_authenticated_partial_record() {
    let [small, large] = pairings(Arc::new(Time(AtomicBool::new(true))));
    let mut ab = Box::new(Buffers::new());
    let mut bb = Box::new(Buffers::new());
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    handshake(&mut a, &mut b).unwrap();
    a.send_plaintext(b"incomplete").unwrap();
    a.pump(0).unwrap();
    let record = a.pending_tls();
    b.receive_tls(&record[..record.len() - 1]).unwrap();
    b.pump(0).unwrap();
    assert_eq!(b.authenticated_peer(), Some(small.local_node()));
    assert!(b.plaintext().is_empty());
    b.abort();
    assert_eq!(b.authenticated_peer(), None);
    assert!(b.plaintext().is_empty());
    assert!(matches!(b.pump(0), Err(Error::Closed)));
}

#[test]
fn handshake_deadline_and_clock_regression_close_the_session() {
    let [small, _] = pairings(Arc::new(Time(AtomicBool::new(true))));
    let mut ab = Box::new(Buffers::new());
    let mut bb = Box::new(Buffers::new());
    let mut a = small.client(&mut ab, 100).unwrap();
    a.pump(100).unwrap();
    // Applies even while the caller has not drained a pending ClientHello.
    a.pump(100 + HANDSHAKE_TIMEOUT_MS - 1).unwrap();
    assert!(matches!(
        a.pump(100 + HANDSHAKE_TIMEOUT_MS),
        Err(Error::Timeout)
    ));
    assert!(a.pending_tls().is_empty());
    let mut b = small.client(&mut bb, 100).unwrap();
    assert!(matches!(b.pump(99), Err(Error::Clock)));
}

#[test]
fn replayed_authenticated_record_revokes_the_session() {
    let [small, large] = pairings(Arc::new(Time(AtomicBool::new(true))));
    let mut ab = Box::new(Buffers::new());
    let mut bb = Box::new(Buffers::new());
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    handshake(&mut a, &mut b).unwrap();
    a.send_plaintext(b"one execution only").unwrap();
    a.pump(0).unwrap();
    let record = a.pending_tls().to_vec();
    b.receive_tls(&record).unwrap();
    b.pump(0).unwrap();
    assert_eq!(b.plaintext(), b"one execution only");
    b.consume_plaintext(18).unwrap();
    b.receive_tls(&record).unwrap();
    assert!(b.pump(0).is_err());
    assert_eq!(b.authenticated_peer(), None);
    assert!(b.plaintext().is_empty());
}
