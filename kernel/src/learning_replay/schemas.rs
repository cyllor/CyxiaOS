//! Boot-immutable schema bindings, prepared in bounded paid service turns.
use cyxia_prototype::learning::{self, SchemaBinding, Schemas};
use sha2::{Digest, Sha256};

pub const SOURCE_CHUNK: usize = 512;
const FEATURE: &[u8] = include_bytes!("../../../crates/prototype/src/features.rs");
const ACTION: &[u8] = include_bytes!("../../../crates/prototype/src/policy_wire.rs");
const EMPTY: SchemaBinding = SchemaBinding {
    version: 13,
    hash: [0; 32],
};

pub struct Preparation {
    bindings: Schemas,
    digest: Option<Sha256>,
    offset: usize,
    stage: u8,
}
impl Preparation {
    pub const fn new() -> Self {
        Self {
            bindings: Schemas {
                feature: EMPTY,
                action: EMPTY,
                reward: EMPTY,
                learning: EMPTY,
            },
            digest: None,
            offset: 0,
            stage: 0,
        }
    }
    /// Partial digests are never exposed as a usable schema.
    pub fn ready(&self) -> Option<Schemas> {
        (self.stage == 4).then_some(self.bindings)
    }
    /// Hash at most one source chunk. Each short fixed semantic binding gets
    /// its own subsequent turn. Return only the number of source-file bytes
    /// consumed; zero also covers those fixed bindings and an already-ready
    /// cache. The caller retains its actual service-credit CPU accounting.
    pub fn step(&mut self) -> usize {
        if self.stage < 2 {
            let source = if self.stage == 0 { FEATURE } else { ACTION };
            let end = (self.offset + SOURCE_CHUNK).min(source.len());
            self.digest
                .get_or_insert_with(Sha256::new)
                .update(&source[self.offset..end]);
            let consumed = end - self.offset;
            self.offset = end;
            if end == source.len() {
                let binding = SchemaBinding {
                    version: 13,
                    hash: self
                        .digest
                        .take()
                        .expect("source digest initialized")
                        .finalize()
                        .into(),
                };
                if self.stage == 0 {
                    self.bindings.feature = binding;
                } else {
                    self.bindings.action = binding;
                }
                self.offset = 0;
                self.stage += 1;
            }
            return consumed;
        }
        if self.stage == 2 {
            self.bindings.reward = learning::reward_schema();
            self.stage = 3;
        } else if self.stage == 3 {
            self.bindings.learning = learning::learning_config();
            self.stage = 4;
        }
        0
    }
}
