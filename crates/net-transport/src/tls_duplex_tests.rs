//! Test identities and ephemeral secrets only; nothing is written or logged.
extern crate std;
use super::*;
use ring::{aead, hkdf};
use rustls::{KeyLog, pki_types::PrivatePkcs8KeyDer};
use std::sync::Mutex;

#[derive(Debug, Default)]
struct TestSecret(Mutex<Vec<u8>>);
impl KeyLog for TestSecret {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        if label == "CLIENT_TRAFFIC_SECRET_0" {
            *self.0.lock().unwrap() = secret.to_vec();
        }
    }
}
#[derive(Debug)]
struct Time;
impl TimeProvider for Time {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
            1_800_000_000,
        )))
    }
}
fn pairings(secret: Arc<TestSecret>) -> [Pairing; 2] {
    let mut fixtures = [
        (
            &include_bytes!("../tests/fixtures/a-test-cert.der")[..],
            &include_bytes!("../tests/fixtures/a-test-key.der")[..],
        ),
        (
            &include_bytes!("../tests/fixtures/b-test-cert.der")[..],
            &include_bytes!("../tests/fixtures/b-test-key.der")[..],
        ),
    ];
    fixtures.sort_by_key(|(cert, _)| node_id(&CertificateDer::from(*cert)).unwrap());
    core::array::from_fn(|i| {
        let mut p = Pairing::new(
            CertificateDer::from(fixtures[i].0),
            PrivatePkcs8KeyDer::from(fixtures[i].1).into(),
            node_id(&CertificateDer::from(fixtures[1 - i].0)).unwrap(),
            Arc::new(Time),
        )
        .unwrap();
        Arc::get_mut(&mut p.client).unwrap().key_log = secret.clone();
        p
    })
}
fn transfer(a: &mut Session<'_>, b: &mut Session<'_>) {
    let n = b.receive_tls(a.pending_tls()).unwrap();
    a.consume_tls(n).unwrap();
}
fn handshake(a: &mut Session<'_>, b: &mut Session<'_>) {
    for _ in 0..100 {
        a.pump(0).unwrap();
        b.pump(0).unwrap();
        transfer(a, b);
        transfer(b, a);
        if a.authenticated_peer().is_some()
            && b.authenticated_peer().is_some()
            && a.pending_tls().is_empty()
            && b.pending_tls().is_empty()
        {
            return;
        }
    }
    panic!("handshake did not complete");
}
struct Size(usize);
impl hkdf::KeyType for Size {
    fn len(&self) -> usize {
        self.0
    }
}
fn expand(secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let mut result = vec![0; len];
    prk.expand(&[&info], Size(len))
        .unwrap()
        .fill(&mut result)
        .unwrap();
    result
}
fn nonce(iv: &[u8], sequence: u64) -> aead::Nonce {
    let mut nonce: [u8; 12] = iv.try_into().unwrap();
    for (n, s) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *n ^= s;
    }
    aead::Nonce::assume_unique_for_key(nonce)
}
fn seal(key: &aead::LessSafeKey, iv: &[u8], seq: u64, handshake: &[u8]) -> Vec<u8> {
    let len = handshake.len() + 1 + 16;
    let mut header = vec![23, 3, 3, (len >> 8) as u8, len as u8];
    let mut plain = handshake.to_vec();
    plain.push(22);
    key.seal_in_place_append_tag(nonce(iv, seq), aead::Aad::from(&header), &mut plain)
        .unwrap();
    header.extend(plain);
    header
}

#[test]
fn fragmented_key_update_requests_input_before_owned_plaintext_can_encrypt() {
    let secret = Arc::new(TestSecret::default());
    let [small, large] = pairings(secret.clone());
    let mut ab = Buffers::new();
    let mut bb = Buffers::new();
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    handshake(&mut a, &mut b);
    let Connection::Client(client) = &mut a.connection else {
        unreachable!()
    };
    match client.process_tls_records(&mut []).state.unwrap() {
        ConnectionState::WriteTraffic(state) => state.refresh_traffic_keys().unwrap(),
        _ => panic!("fixture must be ready to update keys"),
    }
    a.pump(0).unwrap();
    let update = a.pending_tls().to_vec();
    a.consume_tls(update.len()).unwrap();
    let secret = secret.0.lock().unwrap();
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &expand(&secret, b"key", 16)).unwrap(),
    );
    let iv = expand(&secret, b"iv", 12);
    let mut payload = update[5..].to_vec();
    let plain = key
        .open_in_place(nonce(&iv, 0), aead::Aad::from(&update[..5]), &mut payload)
        .unwrap();
    assert_eq!(plain, &[24, 0, 0, 1, 1, 22]);
    // Fragment the authenticated HANDSHAKE message itself across two separately
    // authenticated records, not merely a ciphertext record across TCP reads.
    let first = seal(&key, &iv, 0, &plain[..2]);
    let second = seal(&key, &iv, 1, &plain[2..5]);
    b.send_plaintext(b"owned reply").unwrap();
    b.receive_tls(&first).unwrap();
    assert_eq!(b.receive_capacity(), 0);
    b.pump(0).unwrap();
    assert!(b.has_pending_plaintext());
    assert!(b.pending_tls().is_empty());
    assert!(
        b.receive_capacity() > 0,
        "real no-progress control state must admit continuation"
    );
    let capacity = b.receive_capacity();
    b.receive_tls(&[]).unwrap();
    assert_eq!(
        b.receive_capacity(),
        capacity,
        "Again/empty read must retain the witness"
    );
    b.receive_tls(&second[..1]).unwrap();
    assert_eq!(b.receive_capacity(), 0);
    b.pump(0).unwrap();
    assert!(b.has_pending_plaintext() && b.pending_tls().is_empty());
    assert!(b.receive_capacity() > 0);
    b.receive_tls(&second[1..]).unwrap();
    let mut reply = Vec::new();
    for now in 1..20 {
        b.pump(now).unwrap();
        a.pump(now).unwrap();
        transfer(&mut b, &mut a);
        transfer(&mut a, &mut b);
        reply.extend_from_slice(a.plaintext());
        a.consume_plaintext(a.plaintext().len()).unwrap();
    }
    assert_eq!(reply, b"owned reply");
    assert!(a.authenticated_peer().is_some() && b.authenticated_peer().is_some());
}

#[test]
fn full_admitted_backlog_drains_before_more_input_or_owned_transmit() {
    let [small, large] = pairings(Arc::new(TestSecret::default()));
    let mut ab = Buffers::new();
    let mut bb = Buffers::new();
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    handshake(&mut a, &mut b);
    let mut wire = Vec::new();
    for value in 1..=9 {
        a.send_plaintext(&vec![value; 4000]).unwrap();
        a.pump(0).unwrap();
        wire.extend_from_slice(a.pending_tls());
        a.consume_tls(a.pending_tls().len()).unwrap();
    }
    assert_eq!(
        b.receive_tls(&wire[..RECORD_BUFFER - 1]).unwrap(),
        RECORD_BUFFER - 1
    );
    assert_eq!(b.receive_capacity(), 1);
    assert_eq!(
        b.receive_tls(&wire[RECORD_BUFFER - 1..RECORD_BUFFER])
            .unwrap(),
        1
    );
    assert_eq!(b.receive_capacity(), 0);
    assert!(matches!(b.receive_tls(&[0]), Err(Error::WouldBlock)));
    b.send_plaintext(b"after backlog").unwrap();
    for value in 1..=8 {
        b.pump(0).unwrap();
        assert_eq!(b.plaintext(), vec![value; 4000]);
        assert_eq!(
            b.receive_capacity(),
            0,
            "productive input cannot replenish admitted backlog"
        );
        assert!(b.has_pending_plaintext() && b.pending_tls().is_empty());
        // Exposed receive backpressure is not a needs-input witness either.
        b.pump(0).unwrap();
        assert_eq!(b.receive_capacity(), 0);
        b.consume_plaintext(4000).unwrap();
    }
    b.pump(0).unwrap();
    assert!(b.receive_capacity() >= wire.len() - RECORD_BUFFER);
    b.receive_tls(&wire[RECORD_BUFFER..]).unwrap();
    b.pump(0).unwrap();
    assert_eq!(b.plaintext(), vec![9; 4000]);
    b.consume_plaintext(4000).unwrap();
    b.pump(0).unwrap();
    assert!(!b.has_pending_plaintext());
    transfer(&mut b, &mut a);
    a.pump(0).unwrap();
    assert_eq!(a.plaintext(), b"after backlog");
}

#[test]
fn admitted_corruption_fails_before_owned_plaintext_is_encrypted() {
    let [small, large] = pairings(Arc::new(TestSecret::default()));
    let mut ab = Buffers::new();
    let mut bb = Buffers::new();
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    handshake(&mut a, &mut b);
    a.send_plaintext(b"incoming").unwrap();
    a.pump(0).unwrap();
    let mut record = a.pending_tls().to_vec();
    *record.last_mut().unwrap() ^= 1;
    b.receive_tls(&record).unwrap();
    b.send_plaintext(b"must not pass corrupt input").unwrap();
    assert!(matches!(b.pump(0), Err(Error::Protocol(_))));
    assert!(b.pending_tls().is_empty() && b.plaintext().is_empty());
    assert!(!b.has_pending_plaintext());
    assert_eq!(b.receive_capacity(), 0);
    assert_eq!(b.authenticated_peer(), None);
}

#[test]
fn invalid_authenticated_key_update_revokes_owned_plaintext() {
    let secret = Arc::new(TestSecret::default());
    let [small, large] = pairings(secret.clone());
    let mut ab = Buffers::new();
    let mut bb = Buffers::new();
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    handshake(&mut a, &mut b);
    let secret = secret.0.lock().unwrap();
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &expand(&secret, b"key", 16)).unwrap(),
    );
    let iv = expand(&secret, b"iv", 12);
    // Authenticated TLS handshake syntax, invalid KeyUpdate request value 2.
    let record = seal(&key, &iv, 0, &[24, 0, 0, 1, 2]);
    b.receive_tls(&record).unwrap();
    b.send_plaintext(b"must not escape").unwrap();
    assert!(matches!(b.pump(0), Err(Error::Protocol(_))));
    assert!(!b.has_pending_plaintext());
    assert!(b.pending_tls().is_empty());
    assert_eq!(b.authenticated_peer(), None);
}

#[test]
fn authenticated_close_notify_precedes_owned_plaintext() {
    let [small, large] = pairings(Arc::new(TestSecret::default()));
    let mut ab = Buffers::new();
    let mut bb = Buffers::new();
    let mut a = small.client(&mut ab, 0).unwrap();
    let mut b = large.server(&mut bb, 0).unwrap();
    handshake(&mut a, &mut b);
    let Connection::Client(client) = &mut a.connection else {
        unreachable!()
    };
    let mut record = vec![0; RECORD_BUFFER];
    let count = match client.process_tls_records(&mut []).state.unwrap() {
        ConnectionState::WriteTraffic(mut state) => state.queue_close_notify(&mut record).unwrap(),
        _ => panic!("fixture must be ready to close"),
    };
    b.receive_tls(&record[..count]).unwrap();
    b.send_plaintext(b"must not escape").unwrap();
    assert!(matches!(b.pump(0), Err(Error::Closed)));
    assert!(!b.has_pending_plaintext());
    assert!(b.pending_tls().is_empty());
    assert_eq!(b.authenticated_peer(), None);
}

#[test]
fn local_echo_requires_pinned_handshake_and_distinct_alpn() {
    let mut fixtures = [
        (&include_bytes!("../tests/fixtures/a-test-cert.der")[..],
         &include_bytes!("../tests/fixtures/a-test-key.der")[..]),
        (&include_bytes!("../tests/fixtures/b-test-cert.der")[..],
         &include_bytes!("../tests/fixtures/b-test-key.der")[..]),
    ];
    fixtures.sort_by_key(|(cert, _)| node_id(&CertificateDer::from(*cert)).unwrap());
    let locals: [Pairing; 2] = core::array::from_fn(|i| {
        Pairing::new_local_echo(
            CertificateDer::from(fixtures[i].0),
            PrivatePkcs8KeyDer::from(fixtures[i].1).into(),
            node_id(&CertificateDer::from(fixtures[1-i].0)).unwrap(),
            Arc::new(Time),
        ).unwrap()
    });
    assert_eq!(locals[0].client.alpn_protocols, vec![LOCAL_ECHO_ALPN.to_vec()]);
    assert_eq!(locals[1].server.alpn_protocols, vec![LOCAL_ECHO_ALPN.to_vec()]);
    let mut raw=[0u8;20];
    raw[..2].copy_from_slice(&1u16.to_le_bytes());
    raw[2..4].copy_from_slice(&1u16.to_le_bytes());
    raw[4..8].copy_from_slice(&4u32.to_le_bytes());
    raw[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
    raw[16..20].copy_from_slice(&[1,2,3,4]);
    let mut a_buf=Buffers::new();
    let mut b_buf=Buffers::new();
    let mut a=locals[0].client(&mut a_buf,0).unwrap();
    let mut b=locals[1].server(&mut b_buf,0).unwrap();
    assert!(matches!(b.accept_local_echo(&raw),Err(Error::Handshake)));
    handshake(&mut a,&mut b);
    assert!(matches!(&b.connection, Connection::Server(server)
        if server.alpn_protocol() == Some(LOCAL_ECHO_ALPN)));
    let parsed=b.accept_local_echo(&raw).unwrap();
    assert_eq!(parsed.id(),0x1234);
    assert_eq!(parsed.payload(),&[1,2,3,4]);
    let mut bad=raw;
    bad[2]=19;
    assert!(matches!(b.accept_local_echo(&bad),Err(Error::Buffer)));
    let [legacy_small,legacy_large] = pairings(Arc::new(TestSecret::default()));
    let mut legacy_a_buf=Buffers::new();
    let mut legacy_b_buf=Buffers::new();
    let mut la=legacy_small.client(&mut legacy_a_buf,0).unwrap();
    let mut lb=legacy_large.server(&mut legacy_b_buf,0).unwrap();
    handshake(&mut la,&mut lb);
    assert!(matches!(lb.accept_local_echo(&raw),Err(Error::Direction)));
}

fn v019_local_pairings() -> [Pairing; 2] {
    let mut fixtures = [
        (&include_bytes!("../tests/fixtures/a-test-cert.der")[..],
         &include_bytes!("../tests/fixtures/a-test-key.der")[..]),
        (&include_bytes!("../tests/fixtures/b-test-cert.der")[..],
         &include_bytes!("../tests/fixtures/b-test-key.der")[..]),
    ];
    fixtures.sort_by_key(|(cert, _)| node_id(&CertificateDer::from(*cert)).unwrap());
    core::array::from_fn(|i| Pairing::new_local_echo(
        CertificateDer::from(fixtures[i].0),
        PrivatePkcs8KeyDer::from(fixtures[i].1).into(),
        node_id(&CertificateDer::from(fixtures[1-i].0)).unwrap(),
        Arc::new(Time),
    ).unwrap())
}
#[test]
fn v019_sec_n06_actual_tls_plaintext_requires_exact_generation_bound_active_ticket() {
    use crate::admission::{Admission, Error as AdmissionError};
    let locals=v019_local_pairings();
    let mut admission=Admission::new();
    let invalid=admission.begin(7,0,4).unwrap();
    let mut first_buffer=Buffers::new();
    let first=locals[1].server(&mut first_buffer,0).unwrap();
    assert_eq!(admission.authenticate(invalid,&first),Err(AdmissionError::Unauthenticated));
    assert_eq!(admission.pending_count(),0);
    drop(first);
    let ticket=admission.begin(7,0,4).unwrap();
    let mut client_buf=Buffers::new();
    let mut server_buf=Buffers::new();
    let mut a=locals[0].client(&mut client_buf,0).unwrap();
    let mut b=locals[1].server(&mut server_buf,0).unwrap();
    handshake(&mut a,&mut b);
    let active=admission.authenticate(ticket,&b).unwrap();
    assert_eq!(admission.active_count(),1);
    let duplicate=admission.begin(7,0,4).unwrap();
    assert_eq!(admission.authenticate(duplicate,&b),Err(AdmissionError::Duplicate));
    assert_eq!(admission.pending_count(),0);
    let mut frame=[0u8;20];
    frame[..2].copy_from_slice(&1u16.to_le_bytes());
    frame[2..4].copy_from_slice(&1u16.to_le_bytes());
    frame[4..8].copy_from_slice(&4u32.to_le_bytes());
    frame[8..16].copy_from_slice(&9u64.to_le_bytes());
    frame[16..20].copy_from_slice(&[1,2,3,4]);
    a.send_plaintext(&frame).unwrap();
    for now in 1..=16 {
        a.pump(now).unwrap();
        transfer(&mut a,&mut b);
        b.pump(now).unwrap();
        if b.plaintext()==frame.as_slice() { break; }
    }
    assert_eq!(b.plaintext(),frame.as_slice());
    let mut reply=[0u8;20];
    assert_eq!(admission.reply(active,&b,&mut reply),Ok(20));
    assert_eq!(reply,frame);
    let mut unrelated_buf=Buffers::new();
    let unrelated=locals[1].server(&mut unrelated_buf,0).unwrap();
    assert_eq!(admission.reply(active,&unrelated,&mut reply),Err(AdmissionError::Unauthenticated));
    assert_eq!(admission.finish_drain(active),Err(AdmissionError::Busy));
    b.consume_plaintext(20).unwrap();
    b.abort();
    assert_eq!(admission.reply(active,&b,&mut reply),Err(AdmissionError::Unauthenticated));
    assert_eq!(admission.active_count(),1); // abort never frees unknown DMA
    admission.begin_drain(active).unwrap();
    admission.finish_drain(active).unwrap(); // host witness; native must prove TX/DMA
    assert_eq!(admission.finish_drain(active),Err(AdmissionError::Stale));
}
#[test]
fn v019_sec_n03_16_authenticated_connections_do_not_steal_17th_active_credit() {
    use crate::admission::{Admission, Error as AdmissionError, ACTIVE};
    let locals=v019_local_pairings();
    let mut gate=Admission::new();
    let mut tickets=[None; ACTIVE];
    for (i, out) in tickets.iter_mut().enumerate() {
        let pending=gate.begin(i as u32+1,i as u64+1,32).unwrap();
        let mut client_buf=Buffers::new();
        let mut server_buf=Buffers::new();
        let mut client=locals[0].client(&mut client_buf,0).unwrap();
        let mut server=locals[1].server(&mut server_buf,0).unwrap();
        handshake(&mut client,&mut server);
        *out=Some(gate.authenticate(pending,&server).unwrap());
    }
    assert_eq!(gate.active_count(),ACTIVE);
    let pending=gate.begin(99,17,32).unwrap();
    let mut client_buf=Buffers::new();
    let mut server_buf=Buffers::new();
    let mut client=locals[0].client(&mut client_buf,0).unwrap();
    let mut server=locals[1].server(&mut server_buf,0).unwrap();
    handshake(&mut client,&mut server);
    assert_eq!(gate.authenticate(pending,&server),Err(AdmissionError::Capacity));
    assert_eq!(gate.active_count(),ACTIVE);
    assert_eq!(gate.pending_count(),0);
    gate.begin_restart();
    assert!(gate.restarting());
    assert_eq!(gate.finish_restart(),Err(AdmissionError::Busy));
    assert_eq!(gate.begin(100,18,32),Err(AdmissionError::Busy));
    for ticket in tickets.into_iter().flatten() {
        gate.finish_drain(ticket).unwrap();
    }
    assert_eq!(gate.active_count(),0);
    gate.finish_restart().unwrap();
    assert!(!gate.restarting());
    let fresh=gate.begin(100,18,32).unwrap();
    gate.reject(fresh).unwrap();
}

#[test]
fn v019_sec_n06_echo_dispatch_encrypts_authenticated_request_before_consuming() {
    use crate::admission::Admission;
    let pairs=v019_local_pairings();
    let mut gate=Admission::new();
    let ticket=gate.begin(7,0,16).unwrap();
    let mut a_buf=Buffers::new();
    let mut b_buf=Buffers::new();
    let mut client=pairs[0].client(&mut a_buf,0).unwrap();
    let mut server=pairs[1].server(&mut b_buf,0).unwrap();
    handshake(&mut client,&mut server);
    let key=gate.authenticate(ticket,&server).unwrap();

    let mut frame=[0u8;20];
    frame[..2].copy_from_slice(&1u16.to_le_bytes());
    frame[2..4].copy_from_slice(&1u16.to_le_bytes());
    frame[4..8].copy_from_slice(&4u32.to_le_bytes());
    frame[8..16].copy_from_slice(&123u64.to_le_bytes());
    frame[16..20].copy_from_slice(&[5,6,7,8]);

    client.send_plaintext(&frame).unwrap();
    for now in 1..=16 {
        client.pump(now).unwrap();
        transfer(&mut client,&mut server);
        server.pump(now).unwrap();
        if server.plaintext()==frame.as_slice() { break; }
    }
    assert_eq!(server.plaintext(),frame.as_slice());
    assert_eq!(gate.dispatch_echo(key,&mut server).unwrap(),frame.len());
    assert!(server.plaintext().is_empty());
    assert!(server.has_pending_plaintext());
    assert_eq!(gate.confirm_tls_output_drained(key,&server),
        Err(crate::admission::Error::Busy));
    assert_eq!(gate.dispatch_echo(key,&mut server),
        Err(crate::admission::Error::Busy));
    gate.begin_drain(key).unwrap();
    assert_eq!(gate.finish_drain(key),Err(crate::admission::Error::Busy));
    // Plaintext was accepted only into the real pinned TLS session; the
    // ciphertext must traverse the live TLS record output to reach the peer.
    for now in 17..=40 {
        server.pump(now).unwrap();
        transfer(&mut server,&mut client);
        client.pump(now).unwrap();
        if client.plaintext()==frame.as_slice() { break; }
    }
    assert_eq!(client.plaintext(),frame.as_slice());
    client.consume_plaintext(frame.len()).unwrap();
    assert!(!server.has_pending_plaintext());
    gate.confirm_tls_output_drained(key,&server).unwrap();
    assert_eq!(gate.confirm_tls_output_drained(key,&server),
        Err(crate::admission::Error::Stale));
    gate.finish_drain(key).unwrap(); // host only: native TX/DMA proof still required
}

#[test]
fn v019_sec_n06_echo_dispatch_rejects_mutating_opcode_without_queuing_response() {
    use crate::admission::{Admission,Error as AdmissionError};
    let pairs=v019_local_pairings();
    let mut gate=Admission::new();
    let ticket=gate.begin(7,0,16).unwrap();
    let mut a_buf=Buffers::new();
    let mut b_buf=Buffers::new();
    let mut client=pairs[0].client(&mut a_buf,0).unwrap();
    let mut server=pairs[1].server(&mut b_buf,0).unwrap();
    handshake(&mut client,&mut server);
    let active=gate.authenticate(ticket,&server).unwrap();
    let mut bad=[0u8;16];
    bad[..2].copy_from_slice(&1u16.to_le_bytes());
    bad[2..4].copy_from_slice(&19u16.to_le_bytes()); // removed remote-placement RPC
    bad[8..16].copy_from_slice(&31u64.to_le_bytes());
    client.send_plaintext(&bad).unwrap();
    for now in 1..=16 {
        client.pump(now).unwrap();
        transfer(&mut client,&mut server);
        server.pump(now).unwrap();
        if server.plaintext()==bad.as_slice() {break;}
    }
    assert_eq!(server.plaintext(),bad.as_slice());
    assert_eq!(gate.dispatch_echo(active,&mut server),Err(AdmissionError::Invalid));
    assert_eq!(server.plaintext(),bad.as_slice());
    assert!(!server.has_pending_plaintext());
}

#[test]
fn v019_sec_n05_fragmented_tls_records_preserve_echo_and_generation() {
    use crate::admission::{Admission,Error as AdmissionError};
    let pairs=v019_local_pairings();
    let mut a_buf=Buffers::new();
    let mut b_buf=Buffers::new();
    let mut client=pairs[0].client(&mut a_buf,0).unwrap();
    let mut server=pairs[1].server(&mut b_buf,0).unwrap();
    handshake(&mut client,&mut server);
    let mut gate=Admission::new();
    let pending=gate.begin(7,0,16).unwrap();
    let active=gate.authenticate(pending,&server).unwrap();
    let mut frame=[0u8;20];
    frame[..2].copy_from_slice(&1u16.to_le_bytes());
    frame[2..4].copy_from_slice(&1u16.to_le_bytes());
    frame[4..8].copy_from_slice(&4u32.to_le_bytes());
    frame[8..16].copy_from_slice(&77u64.to_le_bytes());
    frame[16..20].copy_from_slice(&[1,2,3,4]);

    client.send_plaintext(&frame[..8]).unwrap();
    for now in 1..=16 {
        client.pump(now).unwrap();
        transfer(&mut client,&mut server);
        server.pump(now).unwrap();
        if server.plaintext()==&frame[..8] {break;}
    }
    assert_eq!(server.plaintext(),&frame[..8]);
    assert_eq!(gate.dispatch_echo(active,&mut server),Err(AdmissionError::Busy));
    assert!(!server.has_pending_plaintext());
    client.send_plaintext(&frame[8..]).unwrap();
    for now in 17..=32 {
        client.pump(now).unwrap();
        transfer(&mut client,&mut server);
        server.pump(now).unwrap();
        if server.plaintext()==frame.as_slice() {break;}
    }
    assert_eq!(server.plaintext(),frame.as_slice());
    assert_eq!(gate.dispatch_echo(active,&mut server),Ok(20));
    assert!(server.plaintext().is_empty());
}
#[test]
fn v019_sec_n05_two_coalesced_echoes_are_consumed_one_at_a_time() {
    use crate::admission::{Admission,Error as AdmissionError};
    let pairs=v019_local_pairings();
    let mut a_buf=Buffers::new();
    let mut b_buf=Buffers::new();
    let mut client=pairs[0].client(&mut a_buf,0).unwrap();
    let mut server=pairs[1].server(&mut b_buf,0).unwrap();
    handshake(&mut client,&mut server);
    let mut gate=Admission::new();
    let pending=gate.begin(7,0,16).unwrap();
    let active=gate.authenticate(pending,&server).unwrap();
    let mut frames=[0u8;40];
    for i in 0..2 {
        let base=i*20;
        frames[base..base+2].copy_from_slice(&1u16.to_le_bytes());
        frames[base+2..base+4].copy_from_slice(&1u16.to_le_bytes());
        frames[base+4..base+8].copy_from_slice(&4u32.to_le_bytes());
        frames[base+8..base+16].copy_from_slice(&(i as u64+1).to_le_bytes());
        frames[base+16..base+20].copy_from_slice(&[1,2,3,4]);
    }
    client.send_plaintext(&frames).unwrap();
    for now in 1..=16 {
        client.pump(now).unwrap();
        transfer(&mut client,&mut server);
        server.pump(now).unwrap();
        if server.plaintext()==frames.as_slice() {break;}
    }
    assert_eq!(server.plaintext(),frames.as_slice());
    assert_eq!(gate.dispatch_echo(active,&mut server),Ok(20));
    assert_eq!(server.plaintext(),&frames[20..]);
    assert_eq!(gate.dispatch_echo(active,&mut server),Err(AdmissionError::Busy));
    for now in 17..=40 {
        server.pump(now).unwrap();
        transfer(&mut server,&mut client);
        client.pump(now).unwrap();
        if client.plaintext()==&frames[..20] {break;}
    }
    assert_eq!(client.plaintext(),&frames[..20]);
    client.consume_plaintext(20).unwrap();
    gate.confirm_tls_output_drained(active,&server).unwrap();
    assert_eq!(gate.dispatch_echo(active,&mut server),Ok(20));
    assert!(server.plaintext().is_empty());
}
#[test]
fn v019_sec_n_native_tcp_adapter_preserves_partial_socket_io_and_ciphertext() {
    use crate::admission::Admission;
    use crate::native_tcp::{self,NativeSocket,SocketError};
    struct NativeBytes {
        incoming: Vec<u8>,
        received: usize,
        emitted: Vec<u8>,
        chunk: usize,
    }
    impl NativeSocket for NativeBytes {
        fn poll_native(&mut self, _now_ms:u64)->Result<(),SocketError>{Ok(())}
        fn read_ciphertext(&mut self,out:&mut [u8])->Result<usize,SocketError>{
            if self.received==self.incoming.len(){return Err(SocketError::Again);}
            let count=out.len().min(self.chunk).min(self.incoming.len()-self.received);
            out[..count].copy_from_slice(&self.incoming[self.received..self.received+count]);
            self.received+=count;
            Ok(count)
        }
        fn queue_ciphertext(&mut self,bytes:&[u8])->Result<usize,SocketError>{
            let count=self.chunk.min(bytes.len());
            self.emitted.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
    }
    let pairs=v019_local_pairings();
    let mut c_buf=Buffers::new();
    let mut s_buf=Buffers::new();
    let mut client=pairs[0].client(&mut c_buf,0).unwrap();
    let mut server=pairs[1].server(&mut s_buf,0).unwrap();
    handshake(&mut client,&mut server);
    let mut gate=Admission::new();
    let p=gate.begin(7,0,16).unwrap();
    let active=gate.authenticate(p,&server).unwrap();
    let mut frame=[0u8;20];
    frame[..2].copy_from_slice(&1u16.to_le_bytes());
    frame[2..4].copy_from_slice(&1u16.to_le_bytes());
    frame[4..8].copy_from_slice(&4u32.to_le_bytes());
    frame[8..16].copy_from_slice(&13u64.to_le_bytes());
    frame[16..20].copy_from_slice(&[9,8,7,6]);
    client.send_plaintext(&frame).unwrap();
    client.pump(1).unwrap();
    let encrypted=client.pending_tls().to_vec();
    client.consume_tls(encrypted.len()).unwrap();
    let mut socket=NativeBytes{incoming:encrypted,received:0,emitted:Vec::new(),chunk:7};
    let mut scratch=[0u8;64];
    let mut echoes=0;
    for now in 1..=120 {
        let progress=native_tcp::turn(&mut socket,&mut gate,active,&mut server,&mut scratch,now).unwrap();
        echoes+=usize::from(progress.echo_queued!=0);
        if socket.received==socket.incoming.len()
            && !server.has_pending_plaintext() && server.pending_tls().is_empty()
            && echoes!=0 {break;}
    }
    assert_eq!(echoes,1,"partial records never generate two replies");
    assert_eq!(socket.received,socket.incoming.len());
    client.receive_tls(&socket.emitted).unwrap();
    client.pump(121).unwrap();
    assert_eq!(client.plaintext(),frame.as_slice());
    gate.begin_drain(active).unwrap();
    gate.finish_drain(active).unwrap(); // mock-only, no physical TX/DMA proof
}

#[test]
fn v019_sec_n_d_terminal_network_credit_requires_native_device_quiescence() {
    use crate::admission::{Admission,Error as AdmissionError};
    use crate::native_tcp::{self,NativeSocket,SocketError,Error as NativeError};
    struct EvidenceSocket { closed:bool, nic_done:bool }
    impl NativeSocket for EvidenceSocket {
        fn terminal_tx_quiescent(&self)->bool { self.closed && self.nic_done }
        fn poll_native(&mut self,_:u64)->Result<(),SocketError> {Ok(())}
        fn read_ciphertext(&mut self,_:&mut [u8])->Result<usize,SocketError>{
            Err(SocketError::Again)
        }
        fn queue_ciphertext(&mut self,_:&[u8])->Result<usize,SocketError>{
            Err(SocketError::Again)
        }
    }
    let pair=v019_local_pairings();
    let mut client_buf=Buffers::new();
    let mut server_buf=Buffers::new();
    let mut client=pair[0].client(&mut client_buf,0).unwrap();
    let mut server=pair[1].server(&mut server_buf,0).unwrap();
    handshake(&mut client,&mut server);
    let mut gate=Admission::new();
    let pending=gate.begin(7,0,16).unwrap();
    let active=gate.authenticate(pending,&server).unwrap();

    let mut socket=EvidenceSocket{closed:false,nic_done:false};
    assert_eq!(native_tcp::finish_session(&socket,&mut gate,active,&server),
        Err(NativeError::Admission(AdmissionError::Busy)));
    socket.closed=true;
    assert_eq!(native_tcp::finish_session(&socket,&mut gate,active,&server),
        Err(NativeError::Admission(AdmissionError::Busy)));
    socket.nic_done=true;
    let mut other_buf=Buffers::new();
    let other=pair[1].server(&mut other_buf,0).unwrap();
    assert_eq!(native_tcp::finish_session(&socket,&mut gate,active,&other),
        Err(NativeError::Admission(AdmissionError::Unauthenticated)));
    assert_eq!(gate.active_count(),1);
    native_tcp::finish_session(&socket,&mut gate,active,&server).unwrap();
    assert_eq!(gate.active_count(),0);
    assert_eq!(native_tcp::finish_session(&socket,&mut gate,active,&server),
        Err(NativeError::Admission(AdmissionError::Stale)));
}
#[test]
fn v019_sec_n_d_tls_pending_reply_prevents_even_quiescent_socket_retirement() {
    use crate::admission::{Admission,Error as AdmissionError};
    use crate::native_tcp::{self,NativeSocket,SocketError,Error as NativeError};
    struct Terminal;
    impl NativeSocket for Terminal {
        fn terminal_tx_quiescent(&self)->bool { true }
        fn poll_native(&mut self,_:u64)->Result<(),SocketError> {Ok(())}
        fn read_ciphertext(&mut self,_:&mut [u8])->Result<usize,SocketError>{
            Err(SocketError::Again)
        }
        fn queue_ciphertext(&mut self,_:&[u8])->Result<usize,SocketError>{
            Err(SocketError::Again)
        }
    }
    let pair=v019_local_pairings();
    let mut client_buf=Buffers::new();
    let mut server_buf=Buffers::new();
    let mut client=pair[0].client(&mut client_buf,0).unwrap();
    let mut server=pair[1].server(&mut server_buf,0).unwrap();
    handshake(&mut client,&mut server);
    let mut gate=Admission::new();
    let pending=gate.begin(7,0,16).unwrap();
    let key=gate.authenticate(pending,&server).unwrap();
    let mut frame=[0u8;16];
    frame[..2].copy_from_slice(&1u16.to_le_bytes());
    frame[2..4].copy_from_slice(&1u16.to_le_bytes());
    frame[8..16].copy_from_slice(&33u64.to_le_bytes());
    client.send_plaintext(&frame).unwrap();
    for now in 1..16 {
        client.pump(now).unwrap();
        transfer(&mut client,&mut server);
        server.pump(now).unwrap();
        if server.plaintext()==frame.as_slice() {break;}
    }
    assert_eq!(server.plaintext(),frame.as_slice());
    gate.dispatch_echo(key,&mut server).unwrap();
    assert_eq!(native_tcp::finish_session(&Terminal,&mut gate,key,&server),
        Err(NativeError::Admission(AdmissionError::Busy)));
    server.pump(16).unwrap();
    assert!(!server.pending_tls().is_empty());
    assert_eq!(native_tcp::finish_session(&Terminal,&mut gate,key,&server),
        Err(NativeError::Admission(AdmissionError::Busy)));
    server.consume_tls(server.pending_tls().len()).unwrap();
    // On real native TCP this consumed ciphertext is still separately
    // accounted; Terminal here simulates an independently verified device.
    native_tcp::finish_session(&Terminal,&mut gate,key,&server).unwrap();
    assert_eq!(gate.active_count(),0);
}
