use super::super::{Error, governance::Stage};
use crate::domains::ObjectKey;

pub(super) fn valid_object(object: ObjectKey) -> Result<(), Error> {
    if object.id == 0 || object.generation == 0 {
        Err(Error::Evidence)
    } else {
        Ok(())
    }
}

pub(super) fn stage_code(stage: Stage) -> u16 {
    match stage {
        Stage::Shadow => 1,
        Stage::Ready => 2,
        Stage::Canary => 3,
        Stage::Frozen => 4,
        Stage::Restoring => 5,
        Stage::Active => 6,
        Stage::Rejected => 7,
    }
}

pub(super) fn decode_stage(value: u16) -> Result<Stage, Error> {
    match value {
        1 => Ok(Stage::Shadow),
        2 => Ok(Stage::Ready),
        3 => Ok(Stage::Canary),
        4 => Ok(Stage::Frozen),
        5 => Ok(Stage::Restoring),
        6 => Ok(Stage::Active),
        7 => Ok(Stage::Rejected),
        _ => Err(Error::Schema),
    }
}
