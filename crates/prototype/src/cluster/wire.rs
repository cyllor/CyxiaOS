//! Canonical v1.3 wire values; no native structure layout is transmitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub trust_domain: [u8; 32],
    pub nodes: [[u8; 32]; 2],
    pub counters: [u64; 2],
    pub nonces: [[u8; 32]; 2],
    pub schema: [u8; 32],
    pub policy: [u8; 32],
    pub epoch: u64,
}
impl Config {
    pub fn encode(&self) -> [u8; 252] {
        let mut b = [0; 252];
        b[..2].copy_from_slice(&1u16.to_le_bytes());
        b[4..36].copy_from_slice(&self.trust_domain);
        for i in 0..2 {
            b[36 + i * 32..68 + i * 32].copy_from_slice(&self.nodes[i]);
            b[100 + i * 8..108 + i * 8].copy_from_slice(&self.counters[i].to_le_bytes());
            b[116 + i * 32..148 + i * 32].copy_from_slice(&self.nonces[i]);
        }
        b[180..212].copy_from_slice(&self.schema);
        b[212..244].copy_from_slice(&self.policy);
        b[244..252].copy_from_slice(&self.epoch.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 252 || b[..4] != [1, 0, 0, 0] {
            return Err(Error::Invalid);
        }
        let c = Self {
            trust_domain: b[4..36].try_into().unwrap(),
            nodes: [
                b[36..68].try_into().unwrap(),
                b[68..100].try_into().unwrap(),
            ],
            counters: [
                u64::from_le_bytes(b[100..108].try_into().unwrap()),
                u64::from_le_bytes(b[108..116].try_into().unwrap()),
            ],
            nonces: [
                b[116..148].try_into().unwrap(),
                b[148..180].try_into().unwrap(),
            ],
            schema: b[180..212].try_into().unwrap(),
            policy: b[212..244].try_into().unwrap(),
            epoch: u64::from_le_bytes(b[244..252].try_into().unwrap()),
        };
        if c.nodes[0] >= c.nodes[1] || c.counters.contains(&0) || c.epoch == 0 {
            return Err(Error::Invalid);
        }
        Ok(c)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u16,
    pub body_len: u32,
    pub sequence: u64,
    pub request: [u8; 16],
    pub cluster: [u8; 32],
    pub epoch: u64,
    pub sender_boot: u64,
    pub receiver_boot: u64,
}
impl Header {
    pub fn encode(&self) -> [u8; 96] {
        let mut b = [0; 96];
        b[..4].copy_from_slice(&0x43584331u32.to_le_bytes());
        b[4..6].copy_from_slice(&1u16.to_le_bytes());
        b[6..8].copy_from_slice(&self.kind.to_le_bytes());
        b[8..10].copy_from_slice(&96u16.to_le_bytes());
        b[12..16].copy_from_slice(&self.body_len.to_le_bytes());
        b[16..24].copy_from_slice(&self.sequence.to_le_bytes());
        b[24..40].copy_from_slice(&self.request);
        b[40..72].copy_from_slice(&self.cluster);
        b[72..80].copy_from_slice(&self.epoch.to_le_bytes());
        b[80..88].copy_from_slice(&self.sender_boot.to_le_bytes());
        b[88..96].copy_from_slice(&self.receiver_boot.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 96 || b[..6] != [0x31, 0x43, 0x58, 0x43, 1, 0] || b[8..12] != [96, 0, 0, 0] {
            return Err(Error::Invalid);
        }
        let h = Self {
            kind: u16::from_le_bytes(b[6..8].try_into().unwrap()),
            body_len: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            sequence: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            request: b[24..40].try_into().unwrap(),
            cluster: b[40..72].try_into().unwrap(),
            epoch: u64::from_le_bytes(b[72..80].try_into().unwrap()),
            sender_boot: u64::from_le_bytes(b[80..88].try_into().unwrap()),
            receiver_boot: u64::from_le_bytes(b[88..96].try_into().unwrap()),
        };
        if !matches!(h.kind&0x7fff,1..=6|16..=22|32..=33|48..=49|56)
            || h.body_len > 65536
            || h.sequence == 0
            || h.sender_boot == 0
            || (h.kind & 0x7fff != 1 && h.receiver_boot == 0)
        {
            return Err(Error::Invalid);
        }
        Ok(h)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub config: Config,
    pub formation: [u8; 32],
    pub signatures: [[u8; 64]; 2],
}
impl Proof {
    pub fn encode(&self) -> [u8; 412] {
        let mut b = [0; 412];
        b[..252].copy_from_slice(&self.config.encode());
        b[252..284].copy_from_slice(&self.formation);
        b[284..348].copy_from_slice(&self.signatures[0]);
        b[348..412].copy_from_slice(&self.signatures[1]);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 412 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            config: Config::decode(&b[..252])?,
            formation: b[252..284].try_into().unwrap(),
            signatures: [
                b[284..348].try_into().unwrap(),
                b[348..412].try_into().unwrap(),
            ],
        })
    }
}
