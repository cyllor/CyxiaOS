//! Bounded model learning and validation mechanisms. Untrained fixtures and
//! incomplete native measurements never become accepted training labels.
pub mod capture;
pub mod data;
pub mod governance;
pub mod manifest;
pub mod reward;
pub mod softfloat;
pub mod train;
pub mod validate;

pub const FAMILIES: usize = 18;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Family {
    pub domain: u16,
    pub kind: u16,
}
impl Family {
    pub fn index(self) -> Result<usize, Error> {
        match (self.domain, self.kind) {
            (1, 1) => Ok(0),
            (1, 2) => Ok(1),
            (2..=15, 1) => Ok(usize::from(self.domain)),
            (16, 1) => Ok(16),
            (16, 2) => Ok(17),
            _ => Err(Error::Schema),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayGroup {
    pub seed: u64,
    pub workload: [u8; 32],
    pub initial_image: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaBinding {
    pub version: u32,
    pub hash: [u8; 32],
}
impl SchemaBinding {
    pub fn validate(self) -> Result<(), Error> {
        if self.version == 0 || self.hash == [0; 32] {
            Err(Error::Schema)
        } else {
            Ok(())
        }
    }
}

/// This version freezes all four semantic schemas; it is independent of the
/// outer IPC transport ABI and of the active model generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schemas {
    pub feature: SchemaBinding,
    pub action: SchemaBinding,
    pub reward: SchemaBinding,
    pub learning: SchemaBinding,
}
impl Schemas {
    pub fn validate(self) -> Result<(), Error> {
        self.feature.validate()?;
        self.action.validate()?;
        if self.reward != reward_schema() || self.learning != learning_config() {
            return Err(Error::Schema);
        }
        Ok(())
    }
}

fn binding(bytes: &[u8]) -> SchemaBinding {
    use sha2::{Digest, Sha256};
    SchemaBinding {
        version: 13,
        hash: Sha256::digest(bytes).into(),
    }
}

pub fn reward_schema() -> SchemaBinding {
    binding(b"full_cpu_v1.3\0paired_same_seed_workload_initial_image_frozen_other_domains_arrivals;W_ns=10000000000;requests_min=100;p99=nearest_rank;reject_timeout_pending_latency_ns=10000000000;dx=(X-X0)/max(X0,1/W);dl=(L-L0)/max(L0,0.000001);U=per_node_core_half_open_ns_union(P,E,O);priority=P,E,O;P=first_candidate_to_cleanup;E=action_lifetime_plus_observation_work;O=D13_observation_only;partner_protected_evidence_required;joint=equal_ns_remainder_ascending_action;Craw=absolute_candidate_U/W;C=clip(Craw,0,1);R=0.4*clip(dx,-1,1)-0.4*clip(dl,-1,1)-0.2*C;binary64_RNE_noFMA_written_order;warm_ns=1000000000;apply_limit_ns=5000000000;cleanup_limit_ns=5000000000;Unknown=no_label;renewal_same_value_new_keys_continuous;one_shot_once;DEFER_fallback_ns=4000000000")
}

pub fn learning_config() -> SchemaBinding {
    binding(b"last_layer_clip_project_v1.3\0shape=64,32,16,1;frozen=W1,W2,b1,b2;train_min_per_family=8;validation_min_per_family=4;families=18;group=seed,workload,initial_image;split=exclusive;ordered_one_pass;init=wq/64,bq/256;bq_seed=-32768..32767;h=integer_hidden2/256;prediction=leftfold_j0..15(w*h)+b;binary64_RNE_noFMA;error=prediction-R;finite_before_clip;gradient=clip(error*h,-1,1),clip(error,-1,1);simultaneous_update=theta-gradient/256;project_w=-2..127/64;project_b=-128..32767/256;quantize_once_half_away=w*64,b*256;preserve_other_bytes;validation=full_integer_MLP_output/256;MSE=fixed_order_leftfold_square_divide;overall_tolerance=0;family_tolerance=1/65536;workspace_max=1048576;extra_control_ns_per_100ms=9000000")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Numeric,
    Model,
    Manifest,
    Schema,
    Untrained,
    FrozenLayers,
    DataIncomplete,
    Evidence,
    GroupOverlap,
    Capacity,
    Order,
    Validation,
    Stale,
    Conflict,
    Budget,
    Deadline,
    Unknown,
    State,
    NoChange,
    Safety,
}
impl From<softfloat::FloatError> for Error {
    fn from(_: softfloat::FloatError) -> Self {
        Self::Numeric
    }
}
