//! Reattach to the surviving kernel slot after a service-only restart. Queries
//! restore custody for completion/cleanup, never transport or enqueue authority.
use super::*;

impl Driver {
    pub(super) fn custody_key(
        &self,
        contract: [u8; 16],
        hash: [u8; 32],
    ) -> [u8; TASK_CUSTODY_KEY_BYTES] {
        let mut key = [0; TASK_CUSTODY_KEY_BYTES];
        key[..8].copy_from_slice(&self.engine.boot.to_le_bytes());
        key[8..40].copy_from_slice(&self.engine.cluster());
        key[40..72].copy_from_slice(&self.engine.peer);
        key[72..88].copy_from_slice(&contract);
        key[88..].copy_from_slice(&hash);
        key
    }

    pub(super) fn recover_kernel_custody(&mut self) -> Result<(), ()> {
        if !self.custody_recovering {
            return Ok(());
        }
        let contracts: Vec<_> = self
            .engine
            .contracts
            .iter()
            .filter(|c| !c.remote && c.owner_boot == self.engine.boot)
            .cloned()
            .collect();
        for contract in contracts {
            let key = self.custody_key(contract.terms.id, contract.request_hash);
            let mut receipt = [0; 16];
            let token = match broker::request(
                OP_TASK,
                &key,
                &mut receipt,
                0,
                [TASK_LOOKUP_CUSTODY, 0, 0],
            ) {
                Ok((16, token)) if token != 0 => token,
                Err(NOT_FOUND) => continue,
                Err(AGAIN) => return Ok(()),
                _ => return Err(()),
            };
            let (state, admitted) = receipt_state(&receipt)?;
            self.kernel_token = Some(token);
            self.kernel_contract = Some(contract.terms.id);
            if let Some(task) = contract.task.filter(|task| {
                self.engine
                    .results
                    .iter()
                    .any(|r| r.key == *task && r.state == TaskState::Started && !r.received)
            }) {
                self.task_key = Some(task);
                if admitted {
                    self.engine
                        .reconcile_started(task, contract.owner_boot, contract.request_hash)
                        .map_err(|_| ())?;
                    self.activated = true;
                } else {
                    // Durable STARTED can precede the kernel's final admission.
                    // Only its explicit never-admitted proof permits cancellation.
                    if !matches!(state, 1 | 5) {
                        return Err(());
                    }
                    if !quiesce(token)? {
                        return Ok(());
                    }
                    let effect = self
                        .engine
                        .finish(task, TaskState::Cancelled, &[])
                        .map_err(|_| ())?;
                    persist(&mut self.engine, effect)?;
                }
            }
            self.custody_recovering = false;
            return Ok(());
        }

        // PREPARE has no journal record. CLOSE removes the live contract before
        // kernel release, so exact durable lookup alone cannot cover these cuts.
        let mut scope = self.engine.boot.to_le_bytes().to_vec();
        scope.extend_from_slice(&self.engine.peer);
        let mut receipt = [0; TASK_CUSTODY_KEY_BYTES + 16];
        let token = match broker::request(
            OP_TASK,
            &scope,
            &mut receipt,
            0,
            [TASK_CUSTODY_INVENTORY, 0, 0],
        ) {
            Ok((136, token)) if token != 0 => token,
            Err(NOT_FOUND) => {
                self.custody_recovering = false;
                return Ok(());
            }
            Err(AGAIN) => return Ok(()),
            _ => return Err(()),
        };
        let contract = receipt[72..88].try_into().unwrap();
        let hash = receipt[88..120].try_into().unwrap();
        if receipt[..120] != self.custody_key(contract, hash) {
            return Ok(());
        }
        let (state, admitted) = receipt_state(&receipt[120..])?;
        let closed = self.engine.closed_contract(contract, hash);
        let orphan_prepare = !admitted
            && matches!(state, 1 | 5)
            && !self
                .engine
                .contracts
                .iter()
                .any(|c| !c.remote && c.owner_boot == self.engine.boot)
            && !self.engine.contracts.iter().any(|c| c.terms.id == contract)
            && !self
                .engine
                .statuses()
                .iter()
                .any(|s| s.contract == contract)
            && !self
                .engine
                .results
                .iter()
                .any(|r| r.key.contract == contract);
        if closed || orphan_prepare {
            if !quiesce(token)? {
                return Ok(());
            }
            match broker::request(OP_TASK, &[], &mut [], 0, [4, token, 0]) {
                Ok(_) => self.custody_recovering = false,
                Err(AGAIN) => {}
                _ => return Err(()),
            }
        }
        // Unknown/mismatched custody stays unresolved. It is never restarted,
        // declared LOST within this boot, or released on an absence inference.
        Ok(())
    }
}

fn receipt_state(bytes: &[u8]) -> Result<(u64, bool), ()> {
    let state = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let admitted = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if !(1..=6).contains(&state) || admitted > 1 {
        return Err(());
    }
    Ok((state, admitted == 1))
}
fn quiesce(token: u64) -> Result<bool, ()> {
    broker::request(OP_TASK, &[], &mut [], 0, [5, token, 0]).map_err(|_| ())?;
    match broker::request(OP_TASK, &[], &mut [], 0, [8, token, 0]) {
        Ok(_) => Ok(true),
        Err(AGAIN) => Ok(false),
        _ => Err(()),
    }
}
