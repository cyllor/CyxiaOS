use super::{
    ABI, RECEIPT_BYTES, RECEIPT_MAGIC,
    codec::valid_object,
    command::Command,
};
use crate::{
    domains::ObjectKey,
    learning::{
        Error,
        governance::EXTRA_NS,
        worker_wire::{array_at, put16, put32, put64, u16_at, u32_at, u64_at},
    },
    policy::ModelBinding,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ReceiptResult {
    Applied = 1,
    Rejected = 2,
    Deferred = 3,
    Conflict = 4,
    Stale = 5,
    Failed = 6,
    Unknown = 7,
}
impl ReceiptResult {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Applied),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Deferred),
            4 => Ok(Self::Conflict),
            5 => Ok(Self::Stale),
            6 => Ok(Self::Failed),
            7 => Ok(Self::Unknown),
            _ => Err(Error::Schema),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditEvidence {
    pub ledger_id: u64,
    pub serial: u64,
    pub window: u64,
    pub actual_ns: u64,
    pub core_generation: u64,
    pub cpu: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub result: ReceiptResult,
    pub boot_epoch: u64,
    pub role_context: ObjectKey,
    pub session: ObjectKey,
    pub revision: u64,
    pub command_sequence: u64,
    pub state_revision: u64,
    pub command_digest: [u8; 32],
    pub model: ModelBinding,
    pub effect_handle: u64,
    pub credit: CreditEvidence,
}
impl Receipt {
    pub fn shape(self) -> Result<(), Error> {
        valid_object(self.role_context)?;
        valid_object(self.session)?;
        if self.boot_epoch == 0
            || self.revision == 0
            || self.command_sequence == 0
            || self.state_revision < self.revision
            || self.command_digest == [0; 32]
            || self.model.generation == 0
            || self.model.model_hash == [0; 32]
            || self.model.schema_hash == [0; 32]
            || self.effect_handle == 0
            || self.credit.ledger_id == 0
            || self.credit.serial == 0
            || self.credit.actual_ns == 0
            || self.credit.actual_ns > EXTRA_NS
            || self.credit.core_generation == 0
            || self.credit.cpu >= 64
        {
            return Err(Error::Evidence);
        }
        Ok(())
    }

    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        self.shape()?;
        if output.len() < RECEIPT_BYTES {
            return Err(Error::Capacity);
        }
        let output = &mut output[..RECEIPT_BYTES];
        output.fill(0);
        output[..8].copy_from_slice(RECEIPT_MAGIC);
        put16(output, 8, ABI);
        put16(output, 10, self.result as u16);
        put32(output, 12, RECEIPT_BYTES as u32);
        put64(output, 16, self.boot_epoch);
        put64(output, 24, self.role_context.id);
        put64(output, 32, self.role_context.generation);
        put64(output, 40, self.session.id);
        put64(output, 48, self.session.generation);
        put64(output, 56, self.revision);
        put64(output, 64, self.command_sequence);
        put64(output, 72, self.state_revision);
        output[80..112].copy_from_slice(&self.command_digest);
        put64(output, 112, self.model.generation);
        output[120..152].copy_from_slice(&self.model.model_hash);
        output[152..184].copy_from_slice(&self.model.schema_hash);
        put64(output, 184, self.effect_handle);
        put64(output, 192, self.credit.ledger_id);
        put64(output, 200, self.credit.serial);
        put64(output, 208, self.credit.window);
        put64(output, 216, self.credit.actual_ns);
        put64(output, 224, self.credit.core_generation);
        put16(output, 232, self.credit.cpu);
        Ok(RECEIPT_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != RECEIPT_BYTES {
            return Err(Error::Capacity);
        }
        if &input[..8] != RECEIPT_MAGIC
            || u16_at(input, 8)? != ABI
            || u32_at(input, 12)? as usize != RECEIPT_BYTES
        {
            return Err(Error::Schema);
        }
        let receipt = Self {
            result: ReceiptResult::decode(u16_at(input, 10)?)?,
            boot_epoch: u64_at(input, 16)?,
            role_context: ObjectKey {
                id: u64_at(input, 24)?,
                generation: u64_at(input, 32)?,
            },
            session: ObjectKey {
                id: u64_at(input, 40)?,
                generation: u64_at(input, 48)?,
            },
            revision: u64_at(input, 56)?,
            command_sequence: u64_at(input, 64)?,
            state_revision: u64_at(input, 72)?,
            command_digest: array_at(input, 80)?,
            model: ModelBinding {
                generation: u64_at(input, 112)?,
                model_hash: array_at(input, 120)?,
                schema_hash: array_at(input, 152)?,
            },
            effect_handle: u64_at(input, 184)?,
            credit: CreditEvidence {
                ledger_id: u64_at(input, 192)?,
                serial: u64_at(input, 200)?,
                window: u64_at(input, 208)?,
                actual_ns: u64_at(input, 216)?,
                core_generation: u64_at(input, 224)?,
                cpu: u16_at(input, 232)?,
            },
        };
        receipt.shape()?;
        let mut canonical = [0; RECEIPT_BYTES];
        receipt.encode(&mut canonical)?;
        if canonical.as_slice() != input {
            return Err(Error::Evidence);
        }
        Ok(receipt)
    }

    pub fn validate_for_command(self, command: Command) -> Result<(), Error> {
        self.shape()?;
        command.shape()?;
        if self.boot_epoch != command.binding.boot_epoch
            || self.role_context != command.binding.role_context
            || self.session != command.session
            || self.revision != command.revision
            || self.command_sequence != command.sequence
            || self.credit.core_generation != command.binding.core_generation
        {
            return Err(Error::Stale);
        }
        if self.command_digest != command.digest()? {
            return Err(Error::Evidence);
        }
        Ok(())
    }
}
