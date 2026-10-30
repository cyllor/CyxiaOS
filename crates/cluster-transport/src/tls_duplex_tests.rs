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
