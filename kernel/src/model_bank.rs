//! Four immutable model banks. The coordinator owns this value under the same
//! gate as Registry and CommitGate; execution pins outlive model replacement.
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    learning::{Schemas, manifest::Origin, validate::ValidatedCandidate},
    model::MODEL_BYTES,
    policy::ModelBinding,
};
use sha2::{Digest, Sha256};

const BANKS: usize = 4;
const OWNER_BASE: u64 = 0x434d_4f44_454c_0000;

/// A model occupies real control-pool memory. Implementations must reject a
/// write or unseal while any context can still access that allocation.
pub trait Memory {
    type Allocation: Copy;
    type Pin;
    fn allocate(&mut self, owner: ObjectKey) -> Result<Self::Allocation, Error>;
    fn unseal(&mut self, allocation: Self::Allocation) -> Result<(), Error>;
    fn write(
        &mut self,
        allocation: Self::Allocation,
        bytes: &[u8; MODEL_BYTES],
    ) -> Result<(), Error>;
    fn seal(&mut self, allocation: Self::Allocation) -> Result<(), Error>;
    fn hash(&mut self, allocation: Self::Allocation) -> Result<[u8; 32], Error>;
    fn pin(&mut self, allocation: Self::Allocation) -> Result<(Self::Pin, u64), Error>;
    fn release(&mut self, pin: &Self::Pin) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Mechanism bootstrapping is never evidence of a trained initial Active.
    Untrained,
    Validated {
        registration: [u8; 32],
        parent: [u8; 32],
    },
}
#[derive(Clone, Copy)]
struct Stored {
    binding: ModelBinding,
    provenance: Provenance,
}
pub struct ModelPin<P> {
    pin: P,
    physical: u64,
    binding: ModelBinding,
}
impl<P> ModelPin<P> {
    pub fn physical_address(&self) -> u64 {
        self.physical
    }
    pub fn binding(&self) -> ModelBinding {
        self.binding
    }
}
#[derive(Clone, Copy)]
pub enum ChangeKind {
    Promotion,
    Rollback,
}

pub struct ModelBank<M: Memory> {
    memory: M,
    allocations: [Option<M::Allocation>; BANKS],
    models: [Option<Stored>; BANKS],
    identity: Option<(u64, ModelBinding, Schemas)>,
    initialized: bool,
    active: usize,
    previous: Option<usize>,
}
impl<M: Memory> ModelBank<M> {
    pub const fn new(memory: M) -> Self {
        Self {
            memory,
            allocations: [None; BANKS],
            models: [None; BANKS],
            identity: None,
            initialized: false,
            active: 0,
            previous: None,
        }
    }
    /// Startup only. A Busy reply retains already allocated pages, and retry
    /// cannot change boot identity, schema or seed halfway through provisioning.
    pub fn initialize(
        &mut self,
        boot: u64,
        binding: ModelBinding,
        schemas: Schemas,
        seed: &[u8; MODEL_BYTES],
    ) -> Result<(), Error> {
        schemas.validate().map_err(|_| Error::Schema)?;
        if boot == 0
            || binding.generation == 0
            || binding.schema_hash != schemas.feature.hash
            || binding.model_hash != <[u8; 32]>::from(Sha256::digest(seed))
        {
            return Err(Error::Auth);
        }
        let identity = (boot, binding, schemas);
        if self.identity.is_some_and(|old| old != identity) {
            return Err(Error::Conflict);
        }
        if self.initialized {
            return Ok(());
        }
        self.identity = Some(identity);
        for i in 0..BANKS {
            if self.allocations[i].is_none() {
                self.allocations[i] = Some(self.memory.allocate(ObjectKey {
                    id: OWNER_BASE + i as u64,
                    generation: boot,
                })?);
            }
        }
        let allocation = self.allocations[0].ok_or(Error::NotReady)?;
        self.memory.write(allocation, seed)?;
        if self.memory.hash(allocation)? != binding.model_hash {
            return Err(Error::Conflict);
        }
        self.memory.seal(allocation)?;
        self.models[0] = Some(Stored {
            binding,
            provenance: Provenance::Untrained,
        });
        self.initialized = true;
        Ok(())
    }
    pub fn active(&self) -> Result<ModelBinding, Error> {
        self.models[self.active]
            .map(|model| model.binding)
            .ok_or(Error::NotReady)
    }
    pub fn active_provenance(&self) -> Result<Provenance, Error> {
        self.models[self.active]
            .map(|model| model.provenance)
            .ok_or(Error::NotReady)
    }
    pub fn provenance(&self, binding: ModelBinding) -> Result<Provenance, Error> {
        self.models.iter().flatten().find(|model| model.binding == binding)
            .map(|model| model.provenance).ok_or(Error::Stale)
    }
    pub fn schemas(&self) -> Result<Schemas, Error> {
        self.identity
            .map(|identity| identity.2)
            .ok_or(Error::NotReady)
    }
    /// Only the independently registered candidate type can enter a learned
    /// bank. Its borrowed bytes stay frozen until this bounded copy is sealed.
    pub fn stage(&mut self, candidate: &ValidatedCandidate<'_>) -> Result<ModelBinding, Error> {
        let active = self.active()?;
        let model = candidate.model();
        let manifest = model.manifest();
        let Origin::Learned(record) = manifest.origin else {
            return Err(Error::Auth);
        };
        if manifest.schemas != self.schemas()?
            || record.parent_hash != active.model_hash
            || candidate.parent_hash() != active.model_hash
            || candidate.registration_hash() == [0; 32]
            || manifest.parameters_hash == active.model_hash
        {
            return Err(Error::Stale);
        }
        let provenance = Provenance::Validated {
            registration: candidate.registration_hash(),
            parent: active.model_hash,
        };
        if let Some(old) = self
            .models
            .iter()
            .flatten()
            .find(|old| old.provenance == provenance)
        {
            return if old.binding.model_hash == manifest.parameters_hash
                && old.binding.generation == active.generation
            {
                Ok(old.binding)
            } else {
                Err(Error::Conflict)
            };
        }
        let binding = ModelBinding {
            generation: active.generation,
            model_hash: manifest.parameters_hash,
            schema_hash: active.schema_hash,
        };
        for i in 0..BANKS {
            if i == self.active || self.previous == Some(i) {
                continue;
            }
            let allocation = self.allocations[i].ok_or(Error::NotReady)?;
            match self.memory.unseal(allocation) {
                Err(Error::Busy) => continue,
                Err(error) => return Err(error),
                Ok(()) => {}
            }
            // A fallible copy can never leave an old advertised hash pointing
            // at partly replaced memory. Active and rollback banks are excluded.
            self.models[i] = None;
            self.memory.write(allocation, model.bytes())?;
            if self.memory.hash(allocation)? != binding.model_hash {
                return Err(Error::Conflict);
            }
            self.memory.seal(allocation)?;
            self.models[i] = Some(Stored {
                binding,
                provenance,
            });
            return Ok(binding);
        }
        Err(Error::Busy)
    }
    pub fn pin(&mut self, binding: ModelBinding) -> Result<ModelPin<M::Pin>, Error> {
        let i = self
            .models
            .iter()
            .position(|model| model.is_some_and(|m| m.binding == binding))
            .ok_or(Error::Stale)?;
        let allocation = self.allocations[i].ok_or(Error::NotReady)?;
        let (pin, physical) = self.memory.pin(allocation)?;
        Ok(ModelPin {
            pin,
            physical,
            binding,
        })
    }
    /// Call only after the exact EL0 context is stopped and its model PTE/TLB
    /// reference is revoked. Busy retains the original non-clonable pin.
    pub fn release(&mut self, pin: &ModelPin<M::Pin>) -> Result<(), Error> {
        self.memory.release(&pin.pin)
    }
    /// The returned mutable borrow prevents the bank changing between checking
    /// a switch and committing Registry under the coordinator's common gate.
    pub fn prepare_change(
        &mut self,
        next: ModelBinding,
        kind: ChangeKind,
    ) -> Result<PreparedChange<'_, M>, Error> {
        let active = self.active()?;
        if next.generation != active.generation.checked_add(1).ok_or(Error::Overflow)?
            || next.schema_hash != active.schema_hash
            || next.model_hash == active.model_hash
        {
            return Err(Error::Stale);
        }
        // Identical bytes can exist in an old pinned bank and a newly validated
        // candidate after A -> B -> A. Hash alone must not select that stale B.
        let same_model = |model: Stored| model.binding.model_hash == next.model_hash
            && model.binding.schema_hash == next.schema_hash;
        let i = match kind {
            ChangeKind::Promotion => self.models.iter().enumerate().find_map(|(i, model)| {
                let model = (*model)?;
                if same_model(model) && model.binding.generation == active.generation
                    && matches!(model.provenance, Provenance::Validated { parent, .. }
                        if parent == active.model_hash) {
                    Some(i)
                } else { None }
            }).ok_or(Error::Auth)?,
            ChangeKind::Rollback => self.previous.filter(|&i| {
                self.models[i].is_some_and(same_model)
            }).ok_or(Error::Stale)?,
        };
        if self
            .memory
            .hash(self.allocations[i].ok_or(Error::NotReady)?)?
            != next.model_hash
        {
            return Err(Error::Conflict);
        }
        Ok(PreparedChange {
            bank: self,
            index: i,
            next,
        })
    }
}
pub struct PreparedChange<'a, M: Memory> {
    bank: &'a mut ModelBank<M>,
    index: usize,
    next: ModelBinding,
}
impl<M: Memory> PreparedChange<'_, M> {
    /// No fallible allocation/copy or external callback remains after Registry
    /// accepts the same binding in the surrounding publication critical section.
    pub fn commit(self) -> ModelBinding {
        self.bank.previous = Some(self.bank.active);
        self.bank.active = self.index;
        self.bank.models[self.index]
            .as_mut()
            .expect("prepared immutable bank")
            .binding = self.next;
        self.next
    }
}

#[cfg(target_os = "none")]
pub struct NativeMemory;
#[cfg(target_os = "none")]
impl Memory for NativeMemory {
    type Allocation = crate::control_pool::Allocation;
    type Pin = crate::control_pool::Lease;
    fn allocate(&mut self, owner: ObjectKey) -> Result<Self::Allocation, Error> {
        crate::control_pool::allocate(owner, 1)
    }
    fn unseal(&mut self, allocation: Self::Allocation) -> Result<(), Error> {
        crate::control_pool::unseal(allocation)
    }
    fn write(
        &mut self,
        allocation: Self::Allocation,
        bytes: &[u8; MODEL_BYTES],
    ) -> Result<(), Error> {
        crate::control_pool::write(allocation, 0, bytes)?;
        crate::control_pool::zero_chunk(allocation, MODEL_BYTES, 4096 - MODEL_BYTES)
    }
    fn seal(&mut self, allocation: Self::Allocation) -> Result<(), Error> {
        crate::control_pool::seal(allocation)
    }
    fn hash(&mut self, allocation: Self::Allocation) -> Result<[u8; 32], Error> {
        crate::control_pool::inspect(allocation, 0, MODEL_BYTES, |bytes| {
            Sha256::digest(bytes).into()
        })
    }
    fn pin(&mut self, allocation: Self::Allocation) -> Result<(Self::Pin, u64), Error> {
        let (_, physical, _) = crate::control_pool::span(allocation)?;
        let pin = crate::control_pool::pin_readonly(allocation)?;
        Ok((pin, physical))
    }
    fn release(&mut self, pin: &Self::Pin) -> Result<(), Error> {
        crate::control_pool::unpin(pin)
    }
}
