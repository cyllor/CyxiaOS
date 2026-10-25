use cyxia_prototype::domains::{Action, Error, PolicyStamp};
use cyxia_prototype_cluster::{abi::PolicyWire, domain_ingress::accept_placement_policy};

fn placement() -> PolicyWire {
    PolicyWire {
        version: 9,
        snapshot_ns: 1_000_000_000,
        installed_until_ns: 0,
        value: 1,
        plan_seq: 21,
        controller_epoch: 3,
        action_index: 2,
    }
}

#[test]
fn only_zero_lease_placement_is_admitted_and_exact_retry_does_not_renew() {
    let p = placement();
    let first = accept_placement_policy(PolicyWire::default(), p, p.snapshot_ns).unwrap();
    assert_eq!(first.installed_until_ns, 0);
    assert_eq!(accept_placement_policy(p, p, u64::MAX), Ok(first));
    assert_eq!(
        accept_placement_policy(
            PolicyWire::default(),
            PolicyWire {
                installed_until_ns: p.snapshot_ns + 10_000_000_000,
                ..p
            },
            p.snapshot_ns,
        ),
        Err(Error::Format),
    );
    for action in [
        Action::TxBatch(4),
        Action::UnauthRate(4),
        Action::OfferCpu(100),
    ] {
        assert_eq!(
            PolicyStamp::default().accepts_action(action, first, p.snapshot_ns),
            Err(Error::Format)
        );
    }
}

#[test]
fn zero_lease_does_not_bypass_freshness_identity_or_version_conflicts() {
    let p = placement();
    assert_eq!(
        accept_placement_policy(PolicyWire::default(), p, p.snapshot_ns + 100_000_001),
        Err(Error::Expired)
    );
    assert_eq!(
        accept_placement_policy(p, PolicyWire { value: 2, ..p }, p.snapshot_ns),
        Err(Error::Conflict)
    );
    assert_eq!(
        accept_placement_policy(p, PolicyWire { plan_seq: 22, ..p }, p.snapshot_ns),
        Err(Error::Conflict)
    );
    assert_eq!(
        accept_placement_policy(
            PolicyWire::default(),
            PolicyWire { plan_seq: 0, ..p },
            p.snapshot_ns
        ),
        Err(Error::Format)
    );
    assert_eq!(
        accept_placement_policy(
            PolicyWire::default(),
            PolicyWire { value: 3, ..p },
            p.snapshot_ns
        ),
        Err(Error::Range)
    );
}
