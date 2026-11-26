//! Host-only paired timer polling benchmark. Not native timer IRQ evidence.
use cyxia_prototype::domains::platform::{
    TIMER_CAPACITY, TimerArm, TimerBackend, TimerClass, Timers,
};
use cyxia_prototype::domains::{Error, ObjectKey};
use std::{hint::black_box, time::Instant};

const ROUNDS: usize = 4096;
const SAMPLES: usize = 7;

#[derive(Default)]
struct Backend {
    attempts: usize,
}

impl TimerBackend for Backend {
    fn arm(&mut self, _: TimerArm) -> Result<(), Error> {
        Ok(())
    }

    fn cancel(&mut self, _: ObjectKey) -> Result<(), Error> {
        Ok(())
    }

    fn fire(&mut self, key: ObjectKey) -> Result<(), Error> {
        black_box(key);
        self.attempts += 1;
        Err(Error::Busy)
    }
}

fn main() {
    for count in [0, 1, 4, 16, 64, TIMER_CAPACITY] {
        for due in [false, true] {
            let mut timers = Timers::new();
            let mut backend = Backend::default();
            for i in 0..TIMER_CAPACITY {
                let key = ObjectKey {
                    id: i as u64 + 1,
                    generation: 1,
                };
                timers.register(key, TimerClass::HardDeadline, 0).unwrap();
                if count != 0 && i % (TIMER_CAPACITY / count) == 0 {
                    timers
                        .arm(key, if due { 1 } else { 2 }, 0, &mut backend)
                        .unwrap();
                }
            }
            for _ in 0..64 {
                assert_eq!(timers.poll(1, TIMER_CAPACITY, &mut backend), Ok(0));
            }
            backend.attempts = 0;
            let mut samples = [0u128; SAMPLES];
            for (index, sample) in samples.iter_mut().enumerate() {
                let start = Instant::now();
                for _ in 0..ROUNDS {
                    let result = black_box(&mut timers).poll(
                        black_box(1),
                        black_box(TIMER_CAPACITY),
                        black_box(&mut backend),
                    );
                    assert_eq!(black_box(result), Ok(0));
                }
                *sample = start.elapsed().as_nanos();
                println!("sample,{count},{due},{index},{sample}");
            }
            let expected = if due { count * ROUNDS * SAMPLES } else { 0 };
            assert_eq!(backend.attempts, expected);
            assert_eq!(timers.wakeups, 0);
            assert_eq!(timers.late_ns, 0);
            assert_eq!(timers.registered(), TIMER_CAPACITY);
            println!("check,{count},{due},{expected}");
        }
    }
}
