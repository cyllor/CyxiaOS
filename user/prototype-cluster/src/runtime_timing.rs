//! Non-authoritative timing summary for the latest terminal session. It never
//! describes a current active session and is emitted only after teardown.
//! The shared clock refreshes on EL1/SVC reentry. A pure EL0 interval or host
//! deschedule can therefore be underestimated; zero never excludes either.
use crate::{broker, driver::{Driver, IngestTiming}};
use cyxia_prototype_cluster::abi::{OP_TRACE, RUNTIME_LOOP_WORDS, TRACE_RUNTIME_LOOP};

#[derive(Clone, Copy, Default)]
struct Segment([u64; 3]);
impl Segment {
    fn observe(&mut self, started: u64, finished: u64) {
        let duration = finished.saturating_sub(started);
        if duration > self.0[0] {
            self.0 = [duration, started, finished];
        }
    }
    fn merge(&mut self, value: [u64; 3]) {
        if value[0] > self.0[0] {
            self.0 = value;
        }
    }
}

pub(super) struct Tracker {
    session_started: u64,
    loops: u64,
    last_loop_started: u64,
    last_loop_finished: u64,
    gap: Segment,
    receive: Segment,
    ingest: Segment,
    handle: Segment,
    admission: Segment,
    tick: Segment,
    egress: Segment,
}
impl Tracker {
    pub(super) fn new(now: u64) -> Self {
        Self {
            session_started: now,
            loops: 0,
            last_loop_started: now,
            last_loop_finished: now,
            gap: Segment::default(),
            receive: Segment::default(),
            ingest: Segment::default(),
            handle: Segment::default(),
            admission: Segment::default(),
            tick: Segment::default(),
            egress: Segment::default(),
        }
    }
    pub(super) fn begin_loop(&mut self, now: u64) {
        if self.loops != 0 {
            self.gap.observe(self.last_loop_finished, now);
        }
        self.loops = self.loops.saturating_add(1);
        self.last_loop_started = now;
    }
    pub(super) fn finish_loop(&mut self, now: u64) {
        self.last_loop_finished = now.max(self.last_loop_started);
    }
    pub(super) fn receive(&mut self, started: u64, finished: u64) {
        self.receive.observe(started, finished);
    }
    pub(super) fn ingest(&mut self, started: u64, finished: u64, detail: IngestTiming) {
        self.ingest.observe(started, finished);
        self.handle.merge(detail.handle);
        self.admission.merge(detail.post_admission);
    }
    pub(super) fn tick(&mut self, started: u64, finished: u64) {
        self.tick.observe(started, finished);
    }
    pub(super) fn egress(&mut self, started: u64, finished: u64) {
        self.egress.observe(started, finished);
    }
    pub(super) fn report(
        &self,
        connection: u64,
        driver: &Driver,
        exit_ns: u64,
        reason: u64,
        result: u64,
    ) {
        let mut record = [0u64; RUNTIME_LOOP_WORDS];
        record[..9].copy_from_slice(&[
            1, connection, self.loops, self.session_started,
            self.last_loop_started, self.last_loop_finished,
            self.gap.0[0], self.gap.0[1], self.gap.0[2],
        ]);
        record[9..12].copy_from_slice(&self.receive.0);
        record[12..15].copy_from_slice(&self.ingest.0);
        record[15..18].copy_from_slice(&self.handle.0);
        record[18..21].copy_from_slice(&self.admission.0);
        record[21..24].copy_from_slice(&self.tick.0);
        record[24..27].copy_from_slice(&self.egress.0);
        record[27..31].copy_from_slice(&[
            driver.liveness_attempt_ns(), exit_ns, reason, result,
        ]);
        let mut bytes = [0u8; RUNTIME_LOOP_WORDS * 8];
        for (out, word) in bytes.chunks_exact_mut(8).zip(record) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        // The session has already selected its terminal result. Failure to
        // retain this summary cannot alter teardown, authority or retry state.
        let _ = broker::request(OP_TRACE, &bytes, &mut [], 0, [TRACE_RUNTIME_LOOP, 0, 0]);
    }
}
