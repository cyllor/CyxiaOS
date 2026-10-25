//! Exercise the dependency resolver used by D10 on both control and owner CPUs.
#[path = "../../../kernel/src/domain_network/dependencies.rs"]
mod dependencies;
use cyxia_prototype::domains::{Error, ObjectKey};

#[test]
fn control_cpu_uses_published_endpoint_without_entering_cpu0_owner() {
    let target = ObjectKey {
        id: 43,
        generation: 9,
    };
    assert_eq!(
        dependencies::endpoint((7, target), false, |_| {
            panic!("a control reader must not enter the CPU0-only transport owner")
        }),
        Ok(target)
    );
}

#[test]
fn owner_cpu_rechecks_exact_epoch_and_endpoint_generation() {
    let target = ObjectKey {
        id: 43,
        generation: 9,
    };
    assert_eq!(
        dependencies::endpoint((7, target), true, |epoch| {
            assert_eq!(epoch, 7);
            Ok(target)
        }),
        Ok(target)
    );
    assert_eq!(
        dependencies::endpoint((7, target), true, |_| {
            Ok(ObjectKey {
                generation: 10,
                ..target
            })
        }),
        Err(Error::Stale)
    );
    assert_eq!(
        dependencies::endpoint((7, target), true, |_| Err(Error::NotReady)),
        Err(Error::NotReady)
    );
}
