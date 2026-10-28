//! Pure, bounded coordinator choice logic. EL1 remains responsible for all
//! authorization, evidence validation, accounting, execution and atomic commit.
use cyxia_prototype::learning::{
    Error, FAMILIES, Family,
    coordinator_wire::{
        Command, CommandAction, CoordinatorSnapshot, ObservedExecutionState, ScoreMode,
    },
    governance::Stage,
};

const SHADOW_COMMANDS_PER_WINDOW: u64 = FAMILIES as u64 + 1;
const COMPLETE_FAMILY_MASK: u32 = (1u32 << FAMILIES) - 1;
const CANARY_FAMILY: Family = Family {
    domain: 15,
    kind: 1,
};

fn family_at(index: usize) -> Family {
    match index {
        0 => Family { domain: 1, kind: 1 },
        1 => Family { domain: 1, kind: 2 },
        2..=15 => Family {
            domain: index as u16,
            kind: 1,
        },
        16 => Family {
            domain: 16,
            kind: 1,
        },
        17 => Family {
            domain: 16,
            kind: 2,
        },
        _ => unreachable!(),
    }
}

fn shadow_action(snapshot: CoordinatorSnapshot) -> CommandAction {
    let slot = snapshot.last_command_sequence % SHADOW_COMMANDS_PER_WINDOW;
    if slot < FAMILIES as u64 {
        return CommandAction::Score {
            mode: ScoreMode::Shadow,
            family: family_at(slot as usize),
        };
    }
    CommandAction::CloseShadowWindow {
        window: u64::from(snapshot.closed_windows) + 1,
    }
}

fn ready_action(snapshot: CoordinatorSnapshot) -> CommandAction {
    let Some(permit) = snapshot.permit else {
        return CommandAction::Wait;
    };
    if snapshot.baseline_ready {
        CommandAction::BeginCanary {
            target: permit.target,
        }
    } else {
        CommandAction::PrepareBaseline {
            target: permit.target,
        }
    }
}

fn canary_action(snapshot: CoordinatorSnapshot) -> CommandAction {
    let Some(permit) = snapshot.permit else {
        return CommandAction::Wait;
    };
    if snapshot.now_ns >= permit.expires_ns || permit.used >= permit.quota {
        return CommandAction::Freeze {
            permit_id: permit.id,
        };
    }
    if let Some(pending) = snapshot.pending {
        match pending.state {
            ObservedExecutionState::Pending | ObservedExecutionState::Unknown => {
                return CommandAction::Wait;
            }
            ObservedExecutionState::Failed => {
                return CommandAction::Freeze {
                    permit_id: permit.id,
                };
            }
            ObservedExecutionState::Applied => {}
        }
    }
    if let Some(score) = snapshot.verified_score {
        return CommandAction::PublishCanary { score };
    }
    CommandAction::Score {
        mode: ScoreMode::Canary,
        family: CANARY_FAMILY,
    }
}

pub fn decide(snapshot: CoordinatorSnapshot) -> Result<Command, Error> {
    snapshot.shape()?;
    let sequence = snapshot
        .last_command_sequence
        .checked_add(1)
        .ok_or(Error::Numeric)?;
    let action = match snapshot.stage {
        Stage::Shadow => {
            if snapshot.closed_windows >= 10 && snapshot.shadow_coverage == COMPLETE_FAMILY_MASK {
                CommandAction::CloseShadowWindow {
                    window: u64::from(snapshot.closed_windows) + 1,
                }
            } else {
                shadow_action(snapshot)
            }
        }
        Stage::Ready => ready_action(snapshot),
        Stage::Canary => canary_action(snapshot),
        Stage::Frozen | Stage::Restoring | Stage::Active => CommandAction::Wait,
        Stage::Rejected => CommandAction::Release,
    };
    Ok(Command {
        binding: snapshot.binding,
        session: snapshot.session,
        revision: snapshot.revision,
        sequence,
        snapshot_digest: snapshot.digest()?,
        action,
    })
}

pub fn run(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let snapshot = CoordinatorSnapshot::decode(input)?;
    decide(snapshot)?.encode(output)
}
