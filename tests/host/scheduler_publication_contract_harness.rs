#![allow(dead_code, unused_variables)]
use cyxia_prototype::domains::{Action, ApplyId, Error, ObjectKey, PolicyStamp};
use cyxia_prototype::features::{DomainObservation, TargetFeatures};
use cyxia_prototype::policy::ExecutionState;

mod domain_control {
    use super::*;
    pub use cyxia_prototype::policy::Prerequisite;
    // TARGET_SOURCE
    // FAMILY
    pub type Resolver = fn(ObjectKey) -> Result<[Option<Prerequisite>; 2], Error>;
    thread_local! {
        static FAMILIES: std::cell::RefCell<Vec<Family>> = const { std::cell::RefCell::new(Vec::new()) };
        static RESOLVERS: std::cell::RefCell<Vec<(u16, Resolver)>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    pub fn register(family: Family) -> Result<(), Error> {
        FAMILIES.with(|families| families.borrow_mut().push(family));
        Ok(())
    }
    pub fn register_dependencies(domain: u16, resolver: Resolver) -> Result<(), Error> {
        RESOLVERS.with(|resolvers| resolvers.borrow_mut().push((domain, resolver)));
        Ok(())
    }
    pub fn register_execution_observer(
        _: u16,
        _: fn(ObjectKey, u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        Ok(())
    }
    pub fn registered() -> (Family, Family, Option<Resolver>) {
        FAMILIES.with(|families| families.borrow_mut().clear());
        RESOLVERS.with(|resolvers| resolvers.borrow_mut().clear());
        super::register_control().unwrap();
        let (consumer, prerequisite) = FAMILIES.with(|families| {
            let families = families.borrow();
            (
                *families.iter().find(|f| f.domain == 1).unwrap(),
                *families.iter().find(|f| f.domain == 13).unwrap(),
            )
        });
        let resolver = RESOLVERS.with(|resolvers| {
            resolvers
                .borrow()
                .iter()
                .find(|(domain, _)| *domain == 1)
                .map(|(_, resolver)| *resolver)
        });
        (consumer, prerequisite, resolver)
    }
}

// The only boundary being replaced is callback implementation. Distinct panic
// payloads keep these identities distinct even when functions are optimized.
macro_rules! identity {
    ($name:ident($($argument:ident: $ty:ty),*) -> $result:ty) => {
        fn $name($($argument: $ty),*) -> $result { panic!(stringify!($name)) }
    };
}
identity!(control_target(domain:u16, kind:u16, ordinal:usize) -> Option<ObjectKey>);
identity!(foreign_target(domain:u16, kind:u16, ordinal:usize) -> Option<ObjectKey>);
identity!(control_current(domain:u16, kind:u16, target:ObjectKey) -> Result<Action,Error>);
identity!(foreign_current(domain:u16, kind:u16, target:ObjectKey) -> Result<Action,Error>);
identity!(validate_action(action:Action, target:ObjectKey, at:u64) -> Result<(),Error>);
identity!(foreign_legal(action:Action, target:ObjectKey, at:u64) -> Result<(),Error>);
identity!(legal_options(options:&[Option<Action>], target:ObjectKey, at:u64, output:&mut [Option<Action>]) -> Result<usize,Error>);
identity!(foreign_options(options:&[Option<Action>], target:ObjectKey, at:u64, output:&mut [Option<Action>]) -> Result<usize,Error>);
identity!(control_features(action:Action, target:ObjectKey) -> Result<TargetFeatures,Error>);
identity!(foreign_features(action:Action, target:ObjectKey) -> Result<TargetFeatures,Error>);
identity!(control_apply(action:Action, id:ApplyId, stamp:PolicyStamp, at:u64) -> Result<ExecutionState,Error>);
identity!(foreign_apply(action:Action, id:ApplyId, stamp:PolicyStamp, at:u64) -> Result<ExecutionState,Error>);
identity!(control_reconcile(action:Action, id:ApplyId, stamp:PolicyStamp, at:u64) -> Result<ExecutionState,Error>);
identity!(foreign_reconcile(action:Action, id:ApplyId, stamp:PolicyStamp, at:u64) -> Result<ExecutionState,Error>);
identity!(observation(domain:u16, target:ObjectKey) -> Result<[u64;4],Error>);
identity!(scheduling_dependencies(target:ObjectKey) -> Result<[Option<domain_control::Prerequisite>;2],Error>);
identity!(foreign_resolver(target:ObjectKey) -> Result<[Option<domain_control::Prerequisite>;2],Error>);
identity!(vector_dependencies(target:ObjectKey) -> Result<[Option<domain_control::Prerequisite>;2],Error>);
identity!(confirm_ipc_execution(target:ObjectKey, version:u64) -> Result<(),Error>);
// REGISTER
// MATCHER

#[test]
fn native_registration_is_recognized_without_invoking_any_callback() {
    let (consumer, prerequisite, resolver) = domain_control::registered();
    assert!(
        scheduler_publication_matches(&consumer, Some(&prerequisite), resolver, false),
        "native registrations must match"
    );
}

#[test]
fn every_named_callback_in_both_families_must_match() {
    let (consumer, prerequisite, resolver) = domain_control::registered();
    let replacements: [fn(&mut domain_control::Family); 7] = [
        |f| f.target = foreign_target,
        |f| f.current = foreign_current,
        |f| f.legal = foreign_legal,
        |f| f.legal_options = foreign_options,
        |f| f.target_features = foreign_features,
        |f| f.apply = foreign_apply,
        |f| f.reconcile = foreign_reconcile,
    ];
    for change in replacements {
        let mut changed = consumer;
        change(&mut changed);
        assert!(
            !scheduler_publication_matches(&changed, Some(&prerequisite), resolver, false),
            "callback identity must be exact for consumer"
        );
        let mut changed = prerequisite;
        change(&mut changed);
        assert!(
            !scheduler_publication_matches(&consumer, Some(&changed), resolver, false),
            "callback identity must be exact for prerequisite"
        );
    }
}

#[test]
fn family_domain_kind_and_target_source_must_match() {
    let (consumer, prerequisite, resolver) = domain_control::registered();
    for domain in [0, 2, 13, u16::MAX] {
        let mut changed = consumer;
        changed.domain = domain;
        assert!(
            !scheduler_publication_matches(&changed, Some(&prerequisite), resolver, false),
            "family metadata must be exact for consumer domain"
        );
    }
    for domain in [0, 1, 2, u16::MAX] {
        let mut changed = prerequisite;
        changed.domain = domain;
        assert!(
            !scheduler_publication_matches(&consumer, Some(&changed), resolver, false),
            "family metadata must be exact for prerequisite domain"
        );
    }
    let changes: [fn(&mut domain_control::Family); 2] = [
        |f| f.kind = 2,
        |f| f.target_source = domain_control::TargetSource::Services,
    ];
    for change in changes {
        let mut changed = consumer;
        change(&mut changed);
        assert!(
            !scheduler_publication_matches(&changed, Some(&prerequisite), resolver, false),
            "family metadata must be exact for consumer"
        );
        let mut changed = prerequisite;
        change(&mut changed);
        assert!(
            !scheduler_publication_matches(&consumer, Some(&changed), resolver, false),
            "family metadata must be exact for prerequisite"
        );
    }
}

#[test]
fn missing_prerequisite_falls_back() {
    let (consumer, _, resolver) = domain_control::registered();
    assert!(
        !scheduler_publication_matches(&consumer, None, resolver, false),
        "D13 registration is required"
    );
}

#[test]
fn resolver_must_be_present_and_native() {
    let (consumer, prerequisite, _) = domain_control::registered();
    for resolver in [None, Some(foreign_resolver as domain_control::Resolver)] {
        assert!(
            !scheduler_publication_matches(&consumer, Some(&prerequisite), resolver, false),
            "arbitrary resolver must retain the registered path"
        );
    }
}

#[test]
fn custom_binder_falls_back() {
    let (consumer, prerequisite, resolver) = domain_control::registered();
    assert!(
        !scheduler_publication_matches(&consumer, Some(&prerequisite), resolver, true),
        "custom binder must retain the registered path"
    );
}
