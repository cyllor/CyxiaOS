//! Actual task Gate/Guard, Scheduler/BackgroundBudgets and relevant production
//! locked branches. Other task families are explicit unsupported boundaries.
#![allow(dead_code,unused_imports)]
extern crate self as cyxia_arch_aarch64;
use std::sync::atomic::{AtomicBool,AtomicU64,AtomicUsize,Ordering};
use cyxia_prototype::{domains::{Action,Error,ObjectKey},domains::tasks::{Scheduler,CpuLayout},domains::maintenance::BackgroundBudgets,policy};
static CPU:AtomicUsize=AtomicUsize::new(1);static NOW:AtomicU64=AtomicU64::new(0);
mod cpu{pub fn slot()->usize{super::CPU.load(super::Ordering::Acquire)}}
mod timer{pub fn ticks()->u64{super::NOW.load(super::Ordering::Acquire)}pub fn frequency()->u64{1_000_000_000}}
fn now_ns()->u64{timer::ticks()}
fn key(id:u64)->ObjectKey{ObjectKey{id,generation:1}}
struct State{scheduler:Scheduler,background:BackgroundBudgets,layout:CpuLayout,draining:u64}
static mut STATE:State=State{scheduler:Scheduler::new(),background:BackgroundBudgets::new(),layout:CpuLayout{business_mask:9,healthy_mask:15,generation:4},draining:0};
mod domain_control{pub use cyxia_prototype::policy::Prerequisite;}
// OWNER_GATE_MODULE
// OWNER_GATE_BODY
// ACTUAL_LOCKED_BRANCHES
// SCHEDULER_PUBLICATION_BODY
fn fixture(){NOW.fetch_add(2_000_000_000,Ordering::AcqRel);CPU.store(1,Ordering::Release);unsafe{let s=&mut *core::ptr::addr_of_mut!(STATE);s.scheduler=Scheduler::new();s.background=BackgroundBudgets::new();s.layout=CpuLayout{business_mask:9,healthy_mask:15,generation:4};s.draining=0;for id in [12,15]{s.scheduler.register_group(key(id)).unwrap();s.background.register(key(id),400,100,now_ns()).unwrap();}}}
#[test]fn active_scheduler_single_live_borrow_reads_without_reentering_the_task_gate(){
 fixture();let guard=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().expect("Active CPU weight publication has no protected task borrow");
 assert_eq!(guard.validate(Action::CpuWeight(2),key(12),now_ns()),Ok(()),"legal query reentered its held Task gate");
 assert_eq!(guard.current(1,key(12)),Ok(Action::CpuWeight(1)),"current query reentered its held Task gate");
 let mut out=[None;4];let n=guard.legal_options(&[Some(Action::CpuWeight(1)),Some(Action::CpuWeight(2)),Some(Action::CpuWeight(4))],key(12),now_ns(),&mut out).unwrap();assert_eq!(n,3);assert_eq!(out[0],Some(Action::CpuWeight(1)));
 assert_eq!(guard.prerequisites(Action::CpuWeight(2),key(15)),Ok([Some(domain_control::Prerequisite{domain:13,target:key(15)}),None]));assert_eq!(guard.current(13,key(15)),Ok(Action::BackgroundBudget(400)));assert_eq!(guard.validate(Action::BackgroundBudget(50),key(15),now_ns()),Err(Error::Budget),"hard optional commitment was bypassed");
 assert_eq!(locked(|_|Ok(())),Err(Error::Busy));drop(guard);assert_eq!(locked(|_|Ok(())),Ok(()),"publication did not release Task gate");
}
#[test]fn active_scheduler_unavailable_owner_returns_busy_before_any_publication_borrow(){
 fixture();CPU.store(0,Ordering::Release);let held=acquire_guard().unwrap();CPU.store(1,Ordering::Release);assert!(matches!(reserve_scheduler_publication(Action::CpuWeight(2)),Err(Error::Busy)));CPU.store(0,Ordering::Release);drop(held);NOW.fetch_add(1_000_001,Ordering::AcqRel);CPU.store(1,Ordering::Release);let guard=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().expect("waiting C worker never acquired its publication borrow");assert_eq!(guard.current(1,key(12)),Ok(Action::CpuWeight(1)));drop(guard);
}
#[test]fn active_scheduler_business_draining_unhealthy_and_non_cpu_weight_are_not_authorized(){
 for mode in 0..4{fixture();unsafe{let s=&mut *core::ptr::addr_of_mut!(STATE);match mode{0=>CPU.store(0,Ordering::Release),1=>s.draining=2,2=>s.layout.healthy_mask&=!2,3=>s.layout.business_mask|=2,_=>()}}
  assert!(matches!(reserve_scheduler_publication(Action::CpuWeight(2)),Err(Error::Auth)),"invalid Active task publication role: {mode}");assert_eq!(locked(|_|Ok(())),Ok(()));}
 fixture();assert!(matches!(reserve_scheduler_publication(Action::SpawnTokens(1)),Ok(None)));assert_eq!(locked(|_|Ok(())),Ok(()));
}
#[test]fn active_scheduler_borrow_preserves_generations_ranges_and_actual_cpu_identity(){
 fixture();let guard=reserve_scheduler_publication(Action::CpuWeight(2)).unwrap().expect("Active CPU weight publication has no protected task borrow");let foreign=ObjectKey{id:12,generation:2};assert_eq!(guard.validate(Action::CpuWeight(2),foreign,now_ns()),Err(Error::Stale));assert_eq!(guard.current(1,foreign),Err(Error::Stale));assert!(guard.validate(Action::CpuWeight(0),key(12),now_ns()).is_err());CPU.store(2,Ordering::Release);assert_eq!(guard.current(1,key(12)),Err(Error::Auth),"borrow changed its control CPU identity");CPU.store(1,Ordering::Release);drop(guard);
}

mod learning_canary{pub fn blocks_active()->bool{false}}
mod domain_tasks{pub(crate) use super::{SchedulerPublication,SpawnPublication};}
