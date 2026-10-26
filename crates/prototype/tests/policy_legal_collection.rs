use cyxia_prototype::{
    domains::{Action, Error},
    policy::collect_legal_actions,
};

fn options() -> [Option<Action>; 4] {
    [
        Some(Action::CpuWeight(1)),
        None,
        Some(Action::CpuWeight(2)),
        Some(Action::CpuWeight(4)),
    ]
}

#[test]
fn hard_rejections_filter_one_action_without_reordering_the_tier() {
    let mut output = [None; 4];
    let count = collect_legal_actions(&options(), &mut output, |action| {
        if action == Action::CpuWeight(2) {
            Err(Error::Budget)
        } else {
            Ok(())
        }
    })
    .unwrap();

    assert_eq!(count, 2);
    assert_eq!(
        &output[..count],
        &[Some(Action::CpuWeight(1)), Some(Action::CpuWeight(4))]
    );
}

#[test]
fn transient_owner_result_aborts_before_a_later_action_is_observed() {
    let mut output = [None; 4];
    let mut visited = Vec::new();
    let error = collect_legal_actions(&options(), &mut output, |action| {
        visited.push(action);
        if action == Action::CpuWeight(2) {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    })
    .unwrap_err();

    assert_eq!(error, Error::Busy);
    assert_eq!(visited, vec![Action::CpuWeight(1), Action::CpuWeight(2)]);
    assert_eq!(output[0], Some(Action::CpuWeight(1)));
    assert_eq!(output[1], None);
}

#[test]
fn undersized_output_fails_before_calling_the_owner() {
    let mut output = [None; 2];
    let mut called = false;
    let error = collect_legal_actions(&options(), &mut output, |_| {
        called = true;
        Ok(())
    })
    .unwrap_err();

    assert_eq!(error, Error::Capacity);
    assert!(!called);
}
