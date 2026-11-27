//! Fixed wire records between the native TLS verifier and its isolated signer.

pub const WIRE_BYTES: usize = 112;
pub const TRANSCRIPT_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;
pub const SIGN_TIMEOUT_NS: u64 = 250_000_000;
const REQUEST_MAGIC: u32 = 0x4359_5347;
const REPLY_MAGIC: u32 = 0x4359_5352;
const SERVER_CERT_VERIFY: u16 = 1;
const VERSION: u16 = 2;

const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\0";
const PREFIX_BYTES: usize = 64 + CONTEXT.len();
pub const MESSAGE_BYTES: usize = PREFIX_BYTES + TRANSCRIPT_BYTES;

pub fn certificate_verify_message(transcript: &[u8; TRANSCRIPT_BYTES]) -> [u8; MESSAGE_BYTES] {
    let mut result = [0x20; MESSAGE_BYTES];
    result[64..PREFIX_BYTES].copy_from_slice(CONTEXT);
    result[PREFIX_BYTES..].copy_from_slice(transcript);
    result
}

pub fn certificate_verify_hash(message: &[u8]) -> Option<[u8; TRANSCRIPT_BYTES]> {
    let message: &[u8; MESSAGE_BYTES] = message.try_into().ok()?;
    let hash: [u8; TRANSCRIPT_BYTES] = message[PREFIX_BYTES..].try_into().ok()?;
    (certificate_verify_message(&hash) == *message).then_some(hash)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub boot_epoch: u64,
    pub verifier_generation: u64,
    pub conn_id: u64,
    pub conn_generation: u64,
    pub key_generation: u64,
    pub nonce: u64,
    pub expires_ns: u64,
    pub transcript_hash: [u8; TRANSCRIPT_BYTES],
}

impl Request {
    pub fn encode(&self) -> [u8; WIRE_BYTES] {
        let mut wire = header(REQUEST_MAGIC);
        for (at, value) in [
            self.boot_epoch,
            self.verifier_generation,
            self.conn_id,
            self.conn_generation,
            self.key_generation,
            self.nonce,
            self.expires_ns,
        ]
        .into_iter()
        .enumerate()
        {
            wire[8 + at * 8..16 + at * 8].copy_from_slice(&value.to_le_bytes());
        }
        wire[64..96].copy_from_slice(&self.transcript_hash);
        wire[96..98].copy_from_slice(&SERVER_CERT_VERIFY.to_le_bytes());
        wire
    }

    pub fn decode(wire: &[u8; WIRE_BYTES]) -> Option<Self> {
        if wire[..8] != header(REQUEST_MAGIC)[..8]
            || wire[96..98] != SERVER_CERT_VERIFY.to_le_bytes()
            || wire[98..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let value = |start| u64::from_le_bytes(wire[start..start + 8].try_into().unwrap());
        let fields = [
            value(8),
            value(16),
            value(24),
            value(32),
            value(40),
            value(48),
            value(56),
        ];
        if fields.contains(&0) {
            return None;
        }
        Some(Self {
            boot_epoch: fields[0],
            verifier_generation: fields[1],
            conn_id: fields[2],
            conn_generation: fields[3],
            key_generation: fields[4],
            nonce: fields[5],
            expires_ns: fields[6],
            transcript_hash: wire[64..96].try_into().ok()?,
        })
    }

    pub fn encode_reply(&self, signature: &[u8; SIGNATURE_BYTES]) -> [u8; WIRE_BYTES] {
        let mut wire = header(REPLY_MAGIC);
        for (at, value) in [
            self.conn_id,
            self.conn_generation,
            self.key_generation,
            self.nonce,
        ]
        .into_iter()
        .enumerate()
        {
            wire[8 + at * 8..16 + at * 8].copy_from_slice(&value.to_le_bytes());
        }
        wire[48..].copy_from_slice(signature);
        wire
    }

    pub fn reply_signature(&self, wire: &[u8; WIRE_BYTES]) -> Option<[u8; SIGNATURE_BYTES]> {
        let signature = wire[48..].try_into().ok()?;
        (*wire == self.encode_reply(&signature)).then_some(signature)
    }
}

fn header(magic: u32) -> [u8; WIRE_BYTES] {
    let mut wire = [0; WIRE_BYTES];
    wire[..4].copy_from_slice(&magic.to_le_bytes());
    wire[4..6].copy_from_slice(&VERSION.to_le_bytes());
    wire[6..8].copy_from_slice(&(WIRE_BYTES as u16).to_le_bytes());
    wire
}
