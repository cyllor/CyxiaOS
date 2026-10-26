//! Bounded protected A02 event stream. Counters are updated at boundaries,
//! independently of append(), so an exhausted or omitted trace cannot pass.
pub const TRACE_MAGIC: u64 = 0x4359584130325452;
pub const COUNTER_MAGIC: u64 = 0x4359584130324354;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Task {
    pub id: u64,
    pub generation: u64,
    pub role: u64,
    pub affinity: u64,
}
impl Task {
    const EMPTY: Self = Self {
        id: 0,
        generation: 0,
        role: 0,
        affinity: 0,
    };
}

#[repr(C)]
pub struct Capture<const N: usize, const T: usize> {
    pub header: [u64; 64],
    pub events: [[u64; 16]; N],
    pub counters: [u64; 64],
    tasks: [Task; T],
    active: [Task; 4],
    returned_origin: [u64; T],
    started: [u64; 4],
    masks: [u64; 6],
    core_generation: u64,
    control_seen: bool,
    business_seen: bool,
    denial_seen: bool,
    stopping: bool,
}
impl<const N: usize, const T: usize> Capture<N, T> {
    pub const fn new() -> Self {
        Self {
            header: [0; 64],
            events: [[0; 16]; N],
            counters: [0; 64],
            tasks: [Task::EMPTY; T],
            active: [Task::EMPTY; 4],
            returned_origin: [0; T],
            started: [0; 4],
            masks: [2, 13, 0, 0, 0, 0],
            core_generation: 1,
            control_seen: false,
            business_seen: false,
            denial_seen: false,
            stopping: false,
        }
    }
    pub fn begin(&mut self, tick: u64, frequency: u64, config: &[u64; 64]) {
        self.header[..20].copy_from_slice(&[
            TRACE_MAGIC,
            2,
            16,
            0,
            0,
            1,
            0,
            config[2],
            config[3],
            tick,
            0,
            frequency,
            1,
            2,
            13,
            0,
            0,
            0,
            0,
            4,
        ]);
        self.header[24..36].copy_from_slice(&config[4..16]);
        self.counters[..6].copy_from_slice(&[COUNTER_MAGIC, 2, 1, 0, config[2], config[3]]);
        self.counters[28..40].copy_from_slice(&config[4..16]);
    }
    pub fn boot(&mut self, epoch: u64) {
        if epoch == 0 || (self.header[6] != 0 && self.header[6] != epoch) {
            self.fail();
        } else {
            self.header[6] = epoch;
            self.counters[3] = epoch;
        }
    }
    fn fail(&mut self) {
        self.header[4] = self.header[4].saturating_add(1);
        self.counters[8] = self.counters[8].saturating_add(1);
        self.stopping = true;
    }
    fn append(&mut self, tick: u64, kind: u64, cpu: usize, task: Task, payload: &[u64]) {
        let index = self.header[3] as usize;
        if index >= N {
            self.fail();
            return;
        }
        let row = &mut self.events[index];
        row[..7].copy_from_slice(&[
            index as u64 + 1,
            tick,
            kind,
            cpu as u64,
            task.id,
            task.generation,
            self.core_generation,
        ]);
        row[7..7 + payload.len()].copy_from_slice(payload);
        self.header[3] += 1;
        self.counters[7] += 1;
    }
    fn find_registered(&mut self, id: u64, generation: u64) -> Result<(usize, Option<usize>), ()> {
        let Ok(used) = usize::try_from(self.counters[27]) else {
            self.fail();
            return Err(());
        };
        if used > T {
            self.fail();
            return Err(());
        }
        let mut found = None;
        let mut hole = false;
        for (index, task) in self.tasks[..used].iter().enumerate() {
            hole |= task.id == 0;
            if task.id == id && task.generation == generation {
                found = Some(index);
            }
        }
        if hole {
            self.fail();
            Err(())
        } else {
            Ok((used, found))
        }
    }
    fn register_task(&mut self, tick: u64, task: Task) -> Option<usize> {
        if self.stopping || self.sealed() {
            self.seal(tick);
            return None;
        }
        if task.id == 0 || task.generation == 0 || !(1..=2).contains(&task.role) {
            self.fail();
            return None;
        }
        let Ok((used, registered)) = self.find_registered(task.id, task.generation) else {
            return None;
        };
        if let Some(index) = registered {
            if self.tasks[index] != task {
                self.fail();
                None
            } else {
                Some(index)
            }
        } else if used < T && self.tasks[used].id == 0 {
            self.tasks[used] = task;
            self.counters[27] = (used + 1) as u64;
            self.append(tick, 1, 4, task, &[task.role, task.affinity]);
            Some(used)
        } else {
            self.fail();
            None
        }
    }
    pub fn prepare(&mut self, tick: u64, task: Task) -> bool {
        self.register_task(tick, task).is_some()
    }
    pub fn enter(&mut self, tick: u64, cpu: usize, task: Task) -> bool {
        if cpu >= 4
            || task.id == 0
            || task.generation == 0
            || !(1..=2).contains(&task.role)
            || self.active[cpu].id != 0
            || self
                .active
                .iter()
                .any(|t| t.id == task.id && t.generation == task.generation)
        {
            self.fail();
            return false;
        }
        let Some(task_index) = self.register_task(tick, task) else {
            return false;
        };
        self.active[cpu] = task;
        self.returned_origin[task_index] = 0;
        self.started[cpu] = tick;
        self.counters[16 + cpu] += 1;
        self.append(tick, 3, cpu, task, &[self.counters[16 + cpu]]);
        self.control_seen |= task.role == 2;
        self.business_seen |= task.role == 1;
        true
    }
    pub fn exit(&mut self, tick: u64, cpu: usize) {
        if cpu >= 4 || self.active[cpu].id == 0 {
            self.fail();
            return;
        }
        let task = self.active[cpu];
        self.counters[20 + cpu] += 1;
        self.counters[40 + cpu] += tick.saturating_sub(self.started[cpu]);
        self.append(tick, 4, cpu, task, &[self.counters[16 + cpu]]);
        self.active[cpu] = Task::EMPTY;
        let Ok((_, registered)) = self.find_registered(task.id, task.generation) else {
            return;
        };
        if let Some(index) = registered {
            self.returned_origin[index] = cpu as u64 + 1;
        } else {
            self.fail();
            return;
        }
        self.stopping |=
            self.denial_seen && self.control_seen && self.business_seen && self.header[6] != 0;
        self.seal(tick);
    }
    /// Invoked under the actual affinity admission lock, after the EL0 trap.
    pub fn bind(
        &mut self,
        tick: u64,
        cpu: usize,
        id: u64,
        generation: u64,
        mask: u64,
        result: u64,
    ) {
        if self.sealed() {
            return;
        }
        let Ok((_, registered)) = self.find_registered(id, generation) else {
            return;
        };
        let Some(index) = registered else {
            self.fail();
            return;
        };
        if cpu >= 4
            || self.returned_origin[index] != cpu as u64 + 1
            || self
                .active
                .iter()
                .any(|t| t.id == id && t.generation == generation)
        {
            self.fail();
            return;
        }
        let task = self.tasks[index];
        self.returned_origin[index] = 0;
        self.counters[24] += 1;
        let request = self.counters[24];
        self.append(tick, 5, cpu, task, &[request, mask]);
        if result == 1 {
            self.counters[25] += 1;
        } else if result == 0 {
            self.counters[26] += 1;
            self.tasks[index].affinity = mask;
        }
        self.append(tick, 6, cpu, task, &[request, result]);
        self.denial_seen |= task.role == 1 && mask & self.masks[0] != 0 && result == 1;
        self.stopping |=
            self.denial_seen && self.control_seen && self.business_seen && self.header[6] != 0;
        self.seal(tick);
    }
    pub fn owner(&mut self, tick: u64, generation: u64, masks: [u64; 6]) {
        if self.sealed() || (generation == self.core_generation && masks == self.masks) {
            return;
        }
        self.core_generation = generation;
        self.masks = masks;
        self.append(tick, 2, 4, Task::EMPTY, &masks);
    }
    fn seal(&mut self, tick: u64) {
        if !self.stopping || self.active.iter().any(|t| t.id != 0) || self.sealed() {
            return;
        }
        self.header[10] = tick;
        self.counters[6] = tick;
        self.counters[9] = self.core_generation;
        self.counters[10..16].copy_from_slice(&self.masks);
        self.counters[2] = 2;
        self.header[5] = 2;
    }
    pub fn sealed(&self) -> bool {
        self.header[5] == 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn task(id: u64, role: u64, affinity: u64) -> Task {
        Task {
            id,
            generation: 1,
            role,
            affinity,
        }
    }
    fn capture<const N: usize>() -> Capture<N, 8> {
        let mut c = Capture::new();
        let mut config = [0; 64];
        config[2] = 7;
        c.begin(100, 1000, &config);
        c.boot(4);
        c
    }
    #[test]
    fn counters_follow_boundaries_and_raw_denial_after_return() {
        let mut c = capture::<32>();
        assert!(c.enter(101, 1, task(20, 2, 2)));
        assert!(c.enter(102, 3, task(10, 1, 8)));
        c.exit(106, 3);
        c.bind(107, 3, 10, 1, 2, 1);
        assert!(!c.sealed());
        c.exit(110, 1);
        assert!(c.sealed());
        assert_eq!(&c.counters[16..24], &[0, 1, 0, 1, 0, 1, 0, 1]);
        assert_eq!(&c.counters[24..28], &[1, 1, 0, 2]);
        assert_eq!(&c.counters[40..44], &[0, 9, 0, 4]);
        assert_eq!(c.events[5][2], 5);
        assert_eq!(c.events[6][2], 6);
        assert!(!c.enter(111, 0, task(30, 1, 1)));
    }
    #[test]
    fn overflow_retains_counters_and_marks_loss_without_overwriting() {
        let mut c = capture::<2>();
        c.enter(101, 3, task(10, 1, 8));
        let first = c.events[0];
        c.exit(102, 3);
        assert_eq!(c.events[0], first);
        assert_eq!(c.header[3], 2);
        assert_eq!(c.counters[23], 1);
        assert!(c.header[4] > 0);
        assert!(c.sealed());
    }
    #[test]
    fn immutable_roles_cannot_be_changed_by_a_later_dispatch() {
        let mut c = capture::<16>();
        c.enter(101, 3, task(10, 1, 8));
        c.exit(102, 3);
        assert!(!c.enter(103, 1, task(10, 2, 2)));
        assert!(c.header[4] > 0);
    }
    #[test]
    fn admission_must_name_the_exact_returned_generation() {
        let mut c = capture::<16>();
        c.enter(101, 3, task(10, 1, 8));
        c.exit(102, 3);
        c.bind(103, 3, 10, 2, 2, 1);
        assert_eq!(c.counters[24], 0);
        assert!(c.header[4] > 0);
    }
    #[test]
    fn dynamic_tasks_register_before_their_own_first_entry() {
        let mut c = capture::<16>();
        c.enter(101, 3, task(10, 1, 8));
        c.exit(102, 3);
        c.enter(103, 0, task(30, 1, 1));
        assert_eq!(c.events[3][2], 1);
        assert_eq!(c.counters[27], 2);
    }
    #[test]
    fn prepared_task_registration_is_a_separate_event_before_entry() {
        let mut c = capture::<16>();
        let task = task(20, 2, 2);
        assert!(c.prepare(101, task));
        assert_eq!(c.events[0][2], 1);
        assert_eq!(c.counters[27], 1);
        assert!(c.enter(102, 1, task));
        assert_eq!(c.events[1][2], 3);
        assert_eq!(c.counters[27], 1);
        c.exit(103, 1);
        assert_eq!(c.events[2][2], 4);
        assert_eq!(c.returned_origin[0], 2);
    }
    #[test]
    fn dense_task_prefix_exhaustion_fails_without_reusing_a_registration() {
        let mut c: Capture<32, 2> = Capture::new();
        let mut config = [0; 64];
        config[2] = 7;
        c.begin(100, 1000, &config);
        c.boot(4);
        assert!(c.enter(101, 0, task(10, 1, 1)));
        c.exit(102, 0);
        assert!(c.enter(103, 1, task(20, 2, 2)));
        c.exit(104, 1);
        assert_eq!(c.counters[27], 2);
        assert!(!c.enter(105, 3, task(30, 1, 8)));
        assert_eq!(c.counters[27], 2);
        assert!(c.header[4] > 0);
    }
    #[test]
    fn owner_flags_are_recorded_even_without_a_core_generation_change() {
        let mut c = capture::<16>();
        c.owner(101, 1, [2, 13, 0, 0, 4, 0]);
        assert_eq!(c.events[0][6], 1);
        assert_eq!(c.events[0][11], 4);
        c.owner(102, 1, [2, 13, 0, 0, 4, 0]);
        assert_eq!(c.header[3], 1);
    }
    #[test]
    fn deferred_admission_retains_parked_caller_while_another_task_runs() {
        let mut c = capture::<32>();
        c.enter(101, 1, task(20, 2, 2));
        c.enter(102, 3, task(10, 1, 8));
        c.exit(103, 3);
        c.enter(104, 3, task(30, 1, 8));
        c.bind(105, 3, 10, 1, 2, 1);
        assert_eq!(c.header[4], 0);
        assert_eq!(c.counters[24], 1);
        assert!(!c.sealed());
        c.exit(106, 3);
        c.exit(107, 1);
        assert!(c.sealed());
    }
    #[test]
    fn reentry_revokes_the_old_returned_caller_before_a_new_trap() {
        let mut c = capture::<32>();
        c.enter(101, 3, task(10, 1, 8));
        c.exit(102, 3);
        c.enter(103, 3, task(10, 1, 8));
        c.bind(104, 3, 10, 1, 2, 1);
        assert_eq!(c.counters[24], 0);
        assert!(c.header[4] > 0);
    }
    #[test]
    fn no_host_epoch_can_replace_the_durable_boot_epoch() {
        let mut c = capture::<16>();
        c.boot(5);
        assert_eq!(c.header[6], 4);
        assert!(c.header[4] > 0);
    }
}
