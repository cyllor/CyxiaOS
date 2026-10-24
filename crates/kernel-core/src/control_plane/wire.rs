//! A new, versioned copy-in ABI. It does not reuse the existing action ABI.
//! Publisher identity and CPU are deliberately absent: only EL1 supplies them.
use super::{Epochs, Error, Identity, Plane, cores::ScaleProposal, policy::Proposal};
pub const WORDS: usize = 20;
pub const MAGIC: u64 = 0x4359_5849_4143_5031;
pub const VERSION: u64 = 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Policy(Proposal),
    Scale {
        epochs: Epochs,
        proposal: ScaleProposal,
    },
}
impl Request {
    pub const fn epochs(self) -> Epochs {
        match self {
            Self::Policy(p) => p.epochs,
            Self::Scale { epochs, .. } => epochs,
        }
    }
    pub fn encode(self) -> [u64; WORDS] {
        let e = self.epochs();
        let mut w = [0; WORDS];
        w[..8].copy_from_slice(&[
            MAGIC,
            VERSION,
            match self {
                Self::Policy(_) => 1,
                Self::Scale { .. } => 2,
            },
            e.boot,
            e.controller,
            e.model,
            e.resources,
            e.cores,
        ]);
        match self {
            Self::Policy(p) => {
                w[8] = p.subject.id;
                w[9] = p.subject.generation;
                w[10] = p.domain as u64;
                w[11] = p.sequence;
                w[12] = p.valid_from;
                w[13] = p.expires_at;
                w[14] = match p.plane {
                    Plane::Control => 0,
                    Plane::Business => 1,
                };
                w[15] = p.cpus;
                w[16] = p.units;
                w[17] = p.budget_ticks;
            }
            Self::Scale { proposal: p, .. } => {
                w[11] = p.sequence;
                w[13] = p.deadline;
                w[15] = p.desired_control;
            }
        }
        w
    }
    pub fn decode(w: [u64; WORDS]) -> Result<Self, Error> {
        if w[0] != MAGIC || w[1] != VERSION || w[18] != 0 || w[19] != 0 {
            return Err(Error::Invalid);
        }
        let e = Epochs {
            boot: w[3],
            controller: w[4],
            model: w[5],
            resources: w[6],
            cores: w[7],
        };
        if !e.valid() {
            return Err(Error::Invalid);
        }
        match w[2] {
            1 => Ok(Self::Policy(Proposal {
                epochs: e,
                subject: Identity {
                    id: w[8],
                    generation: w[9],
                },
                domain: usize::try_from(w[10]).map_err(|_| Error::Invalid)?,
                sequence: w[11],
                valid_from: w[12],
                expires_at: w[13],
                plane: match w[14] {
                    0 => Plane::Control,
                    1 => Plane::Business,
                    _ => return Err(Error::Invalid),
                },
                cpus: w[15],
                units: w[16],
                budget_ticks: w[17],
            })),
            2 => {
                if [8, 9, 10, 12, 14, 16, 17].iter().any(|&i| w[i] != 0) {
                    return Err(Error::Invalid);
                }
                Ok(Self::Scale {
                    epochs: e,
                    proposal: ScaleProposal {
                        generation: e.cores,
                        resource_epoch: e.resources,
                        sequence: w[11],
                        desired_control: w[15],
                        deadline: w[13],
                    },
                })
            }
            _ => Err(Error::Invalid),
        }
    }
}
