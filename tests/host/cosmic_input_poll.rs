#![allow(dead_code)]
mod desktop {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INPUT_LOGS: AtomicUsize = AtomicUsize::new(0);
    static HEX_WRITES: AtomicUsize = AtomicUsize::new(0);
    static LOSS_LOGS: AtomicUsize = AtomicUsize::new(0);
    static FAILURE_LOGS: AtomicUsize = AtomicUsize::new(0);

    fn log(bytes: &[u8]) {
        let counter = match bytes {
            b"GRAPHICS_INPUT_EVENT MECHANISM\n" => &INPUT_LOGS,
            b"GRAPHICS_INPUT_DROPPED MECHANISM\n" => &LOSS_LOGS,
            b"GRAPHICS_INPUT_STOPPED MECHANISM\n" => &FAILURE_LOGS,
            _ => panic!("unexpected input log {bytes:?}"),
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn hex(_: u64) {
        HEX_WRITES.fetch_add(1, Ordering::Relaxed);
    }
    mod graphics {
        use cyxia_driver_virtio::{Error, InputEvent, input_buffer::{InputBuffer, SYN_DROPPED, SYN_REPORT, KEY_BYTES}};
        use std::{collections::VecDeque, sync::atomic::{AtomicUsize, Ordering}};
        struct Board;
        static FAILURES: AtomicUsize = AtomicUsize::new(0);
        struct Transport;
        impl Transport { fn fail(&mut self) { FAILURES.fetch_add(1, Ordering::Relaxed); } }
        struct Queue { records: VecDeque<Result<InputEvent, Error>>, calls: usize }
        impl Queue {
            fn poll(&mut self, _: &mut Transport, _: &Board) -> Result<Option<InputEvent>, Error> {
                self.calls += 1;
                self.records.pop_front().transpose()
            }
        }
        struct Input { transport: Transport, queue: Queue }
        static mut INPUTS: [Option<Input>; 2] = [None, None];
        static mut EVENTS: InputBuffer = InputBuffer::new();

        // PRODUCTION_POLL

        fn device(records: impl IntoIterator<Item = Result<InputEvent, Error>>) -> Option<Input> {
            Some(Input { transport: Transport, queue: Queue { records: records.into_iter().collect(), calls: 0 } })
        }
        fn reset(inputs: [Option<Input>; 2]) {
            // These tests execute serially, exactly like the CPU0 owner.
            unsafe {
                *core::ptr::addr_of_mut!(INPUTS) = inputs;
                *core::ptr::addr_of_mut!(EVENTS) = InputBuffer::new();
            }
            FAILURES.store(0, Ordering::Relaxed);
            for counter in [&super::INPUT_LOGS, &super::HEX_WRITES,
                            &super::LOSS_LOGS, &super::FAILURE_LOGS] {
                counter.store(0, Ordering::Relaxed);
            }
        }
        fn event(kind: u16, code: u16, value: i32) -> InputEvent { InputEvent { kind, code, value } }
        fn drain() -> Vec<InputEvent> {
            let mut result = Vec::new();
            let mut out = [SYN_REPORT; 32];
            let buffer = unsafe { &mut *core::ptr::addr_of_mut!(EVENTS) };
            loop {
                match buffer.read(&mut out) {
                    Ok(count) => result.extend_from_slice(&out[..count]),
                    Err(Error::Busy) => break,
                    error => panic!("unexpected software input read {error:?}"),
                }
            }
            result
        }

        #[test]
        fn complete_packets_reach_reader_in_one_foreground_pass() {
            let motion = event(2, 0, -7);
            let key = event(1, 30, 1);
            reset([device([Ok(motion), Ok(SYN_REPORT)]), device([Ok(key), Ok(SYN_REPORT)])]);
            poll();
            assert_eq!(drain(), [motion, key, SYN_REPORT, SYN_REPORT],
                       "one foreground pass left complete input packets in DMA");
        }

        #[test]
        fn sustained_sources_are_fair_and_work_stops_after_32_rounds() {
            let a = event(2, 0, 1);
            let b = event(2, 1, -2);
            reset([device([Ok(a); 80]), device([Ok(b); 80])]);
            poll();
            let out = drain();
            assert_eq!(out.len(), 64, "hardware backlog was spread over too many foreground turns");
            for pair in out.chunks_exact(2) { assert_eq!(pair, [a, b]); }
            let inputs = unsafe { &*core::ptr::addr_of!(INPUTS) };
            for input in inputs.iter().flatten() {
                assert_eq!(input.queue.calls, 32, "poll exceeded its per-device work bound");
                assert_eq!(input.queue.records.len(), 48);
            }
        }

        #[test]
        fn event_logging_is_opt_in_and_loss_is_always_visible() {
            let motion = event(2, 0, 9);
            reset([device([Ok(motion), Ok(SYN_REPORT)]), None]);
            poll();
            assert_eq!(drain(), [motion, SYN_REPORT]);
            let trace = usize::from(cfg!(feature = "abi-trace"));
            assert_eq!(super::INPUT_LOGS.load(Ordering::Relaxed), trace);
            assert_eq!(super::HEX_WRITES.load(Ordering::Relaxed), trace);

            reset([device([Ok(SYN_DROPPED), Ok(SYN_REPORT)]), None]);
            poll();
            assert_eq!(drain(), [SYN_DROPPED, SYN_REPORT]);
            assert_eq!(super::LOSS_LOGS.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn device_failure_resynchronizes_without_releasing_the_other_devices_key() {
            let down = event(1, 30, 1);
            let motion = event(2, 0, -7);
            reset([
                device([Ok(down), Ok(SYN_REPORT), Err(Error::Queue)]),
                // The first report after loss closes the discarded packet;
                // only the following complete motion packet may be exposed.
                device([Ok(down), Ok(SYN_REPORT), Ok(SYN_REPORT), Ok(motion), Ok(SYN_REPORT)]),
            ]);
            for _ in 0..6 { poll(); }
            assert_eq!(drain(), [SYN_DROPPED, SYN_REPORT, motion, SYN_REPORT]);
            let mut keys = [0; KEY_BYTES];
            unsafe { &*core::ptr::addr_of!(EVENTS) }.key_state(&mut keys);
            assert_eq!(keys[30 / 8] & (1 << (30 % 8)), 1 << (30 % 8));
            assert_eq!(FAILURES.load(Ordering::Relaxed), 1);
            assert_eq!(super::FAILURE_LOGS.load(Ordering::Relaxed), 1);
            let inputs = unsafe { &*core::ptr::addr_of!(INPUTS) };
            assert!(inputs[0].is_none() && inputs[1].is_some());
        }
    }
}
