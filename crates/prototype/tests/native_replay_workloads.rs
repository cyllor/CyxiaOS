//! Production replay contracts with explicit host owner/receipt fixtures.
//! These checks create no native labels or substituted execution evidence.
use cyxia_prototype::domains::{Action, Error, ObjectKey};
use sha2::{Digest, Sha256};
#[path = "../../../kernel/src/learning_workload/background.rs"]
mod background;
#[path = "../../../kernel/src/domain_services/replay_core_image.rs"]
mod core_image;
#[path = "../../../kernel/src/domain_platform/replay_irq_image.rs"]
mod irq_image;

#[test]
fn original_coreset_is_bound_and_restored_without_assuming_mask_two() {
    let target = ObjectKey {
        id: 0x434f_5245,
        generation: 7,
    };
    let one = core_image::CoreImage::observed(target, 2, 13, 15, 0, false).unwrap();
    let two = core_image::CoreImage::observed(target, 6, 9, 15, 0, false).unwrap();
    assert_eq!(one.baseline(), Action::ControlSet(2));
    assert_eq!(two.baseline(), Action::ControlSet(6));
    assert_ne!(one.digest(), two.digest());
    assert_eq!(one.matches(two), Err(Error::Conflict));
    one.matches(core_image::CoreImage::observed(target, 2, 13, 15, 0, false).unwrap())
        .unwrap();
    // Independent canonical byte order binds actual ownership and health.
    let mut expected = b"CYXIA_ORIGINAL_CORESET_IMAGE_1.3\0".to_vec();
    for value in [0x434f_5245u64, 7, 6, 9, 15, 0] {
        expected.extend(value.to_le_bytes());
    }
    let digest: [u8; 32] = Sha256::digest(expected).into();
    assert_eq!(two.digest(), digest);
    let unhealthy_business = core_image::CoreImage::observed(target, 2, 13, 11, 0, false).unwrap();
    assert_ne!(one.digest(), unhealthy_business.digest());
    assert_eq!(one.matches(unhealthy_business), Err(Error::Conflict));
    assert_eq!(
        core_image::CoreImage::observed(target, 2, 13, 15, 4, false),
        Err(Error::Busy)
    );
    assert_eq!(
        core_image::CoreImage::observed(target, 2, 13, 15, 0, true),
        Err(Error::Busy)
    );
    assert_eq!(
        core_image::CoreImage::observed(target, 6, 13, 15, 0, false),
        Err(Error::NotReady)
    );
}

#[test]
fn irq_baseline_uses_the_actual_healthy_business_set_and_binds_original_route() {
    let target = ObjectKey {
        id: 41,
        generation: 1,
    };
    let image = irq_image::IrqImage::observed(target, 3, 15, 8, 0).unwrap();
    assert_eq!(image.baseline(), Action::IrqTarget(3));
    assert_eq!(
        irq_image::IrqImage::observed(target, 0, 15, 8, 0),
        Err(Error::NotReady)
    );
    let also_cpu0 = irq_image::IrqImage::observed(target, 3, 15, 9, 0).unwrap();
    assert_eq!(also_cpu0.baseline(), Action::IrqTarget(0));
    assert_eq!(also_cpu0.restored().current, 0);
    assert_ne!(also_cpu0.digest(), image.digest());
    assert_eq!(image.matches(also_cpu0), Err(Error::Conflict));
    let draining = irq_image::IrqImage::observed(target, 3, 15, 9, 1).unwrap();
    assert_eq!(draining.baseline(), Action::IrqTarget(3));
    assert_eq!(
        irq_image::IrqImage::observed(target, 3, 7, 8, 0),
        Err(Error::NotReady)
    );
    assert_eq!(
        irq_image::IrqImage::observed(target, 3, 15, 8, 8),
        Err(Error::NotReady)
    );
    let mut bytes = b"CYXIA_ORIGINAL_IRQ_IMAGE_1.3\0".to_vec();
    for value in [41u64, 1, 3, 15, 8, 0] {
        bytes.extend(value.to_le_bytes());
    }
    let expected: [u8; 32] = Sha256::digest(bytes).into();
    assert_eq!(image.digest(), expected);
    image.restored().matches(image).unwrap();
}

#[derive(Default)]
struct Echo {
    current: Option<(u64, u64)>,
    result: Option<Result<u64, Error>>,
    submitted: Vec<(u64, u64)>,
    submit_busy: bool,
    ack_busy: bool,
}
impl background::Echo for Echo {
    fn submit(&mut self, id: u64, value: u64) -> Result<(), Error> {
        if self.submit_busy {
            self.submit_busy = false;
            return Err(Error::Busy);
        }
        assert!(self.current.is_none());
        self.current = Some((id, value));
        self.submitted.push((id, value));
        Ok(())
    }
    fn result(&mut self, id: u64) -> Result<Option<Result<u64, Error>>, Error> {
        assert_eq!(self.current.map(|v| v.0), Some(id));
        Ok(self.result)
    }
    fn acknowledge(&mut self, id: u64) -> Result<(), Error> {
        assert_eq!(self.current.map(|v| v.0), Some(id));
        assert!(self.result.is_some());
        if self.ack_busy {
            self.ack_busy = false;
            return Err(Error::Busy);
        }
        self.current = None;
        self.result = None;
        Ok(())
    }
}
#[test]
fn optional_work_is_fixed_and_keeps_real_late_obligations_separate_from_foreground() {
    assert_eq!(
        background::FOREGROUND,
        ObjectKey {
            id: 12,
            generation: 1
        }
    );
    assert_eq!(
        background::OPTIONAL,
        ObjectKey {
            id: 16,
            generation: 1
        }
    );
    let seed = 17;
    let observation = 7_000_000_000;
    let mut q = background::Queue::new();
    let mut echo = Echo {
        submit_busy: true,
        ..Echo::default()
    };
    assert_eq!(
        q.poll(observation - 1_000_000_000, observation, seed, &mut echo),
        Err(Error::Busy)
    );
    assert!(!q.settled());
    assert!(echo.submitted.is_empty());
    q.poll(observation - 900_000_000, observation, seed, &mut echo)
        .unwrap();
    let warm = echo.current.unwrap();
    q.poll(observation, observation, seed, &mut echo).unwrap();
    assert_eq!(echo.current, Some(warm));
    assert_eq!(echo.submitted.len(), 1);
    // Advancing the wall clock cannot complete or replace unanswered work.
    assert_eq!(q.counts(), (0, 0));
    echo.result = Some(Ok(observation));
    q.poll(observation, observation, seed, &mut echo).unwrap();
    assert_eq!(q.counts(), (0, 0)); // Ordinary warmup is not a measured request.
    for i in 0..background::REQUESTS {
        let (id, offset, value) = background::Queue::frozen_request(seed, i).unwrap();
        q.poll(observation + offset, observation, seed, &mut echo)
            .unwrap();
        assert_eq!(echo.current, Some((id, value)));
        if i == 0 {
            echo.result = Some(Ok(observation + offset + 1_000_000));
            echo.ack_busy = true;
            assert_eq!(
                q.poll(
                    observation + offset + 1_000_000,
                    observation,
                    seed,
                    &mut echo
                ),
                Err(Error::Busy)
            );
            assert_eq!(q.counts(), (0, 0));
            assert_eq!(echo.current, Some((id, value)));
        }
        if i == background::REQUESTS - 1 {
            q.poll(observation + 12_000_000_000, observation, seed, &mut echo)
                .unwrap();
            assert!(!q.settled()); // Still a real outstanding optional request.
        }
        let at = if i == background::REQUESTS - 1 {
            observation + 12_000_000_001
        } else {
            observation + offset + 1_000_000
        };
        echo.result = Some(if i == 4 { Err(Error::Expired) } else { Ok(at) });
        q.poll(at, observation, seed, &mut echo).unwrap();
    }
    assert!(q.settled());
    assert_eq!(q.counts(), (99, 1));
    assert_eq!(echo.submitted.len(), 101);
    assert!(echo.current.is_none());
    let mut committed = Sha256::new();
    let mut independent = Sha256::new();
    for i in 0..100 {
        background::Queue::commit_request(&mut committed, seed, i).unwrap();
        for value in [
            16u64,
            1,
            0x1_0000 + i as u64,
            i as u64 * 100_000_000,
            seed ^ (0x1_0000 + i as u64),
        ] {
            independent.update(value.to_le_bytes());
        }
    }
    assert_eq!(committed.finalize(), independent.finalize());
}
