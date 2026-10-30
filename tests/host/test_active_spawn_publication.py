"""Actual D02 owner queries, ActiveScope/selection, Registry and accept accounting.

Hardware CPU/time and acquisition/release cost are controlled. Root permission,
history storage, evidence and delivery are explicit external kernel boundaries.
Executor, desired/ADMISSION writes, CommitGate, Registry and receipt are real.
"""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function
from test_active_accept_retry import program as accept_program


def program():
    control = (ROOT / 'kernel/src/domain_control.rs').read_text()
    tasks = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
    publication = (ROOT / 'kernel/src/domain_tasks/publication.rs').read_text()
    code = accept_program().split('fn setup(mode:')[0].replace('#![allow(dead_code,unused_imports)]', '#![allow(dead_code,unused_imports,unused_variables)]')
    code = code.replace('pub mod cpu{pub fn slot()->usize{1}}', 'pub mod cpu{pub fn slot()->usize{super::SLOT.load(super::Ordering::Acquire)}}')
    code = code.replace('#[derive(Clone,Copy)]struct Family{legal:fn(Action,ObjectKey,u64)->Result<(),Error>}', '#[derive(Clone,Copy)]' + function(control, 'pub struct Family'))
    code = code.replace('#[derive(Clone,Copy)]struct Context{core_generation:u64,ledger_generation:u64}', '#[derive(Clone,Copy,Default)]' + function(control, 'pub struct Context'))
    code = code.replace('#[derive(Clone,Copy)]struct Desired{state:ExecutionState,execution_observed:bool}', '#[derive(Clone,Copy)]' + function(control, 'struct Desired {'))
    code = code.replace(function(code, "impl<S: PublicationScope> policy::Executor for Executor<'_, S>"), function(control, "impl<S: PublicationScope> policy::Executor for Executor<'_, S>"))
    history = (ROOT / 'kernel/src/learning_history.rs').read_text()
    code += '\nmod learning_history{use super::*;\n' + function(history, "pub struct Publish<'") + '\npub fn record_publish(p:Publish<\'_>)->Result<bool,Error>{HISTORY.with(|h|*h.borrow_mut()=Some(History{apply:p.apply,version:p.plan_version,stamp:p.stamp,model:p.model,selected:p.selected,scores:p.scores.to_vec(),concurrent:p.concurrent.to_vec()}));Ok(true)}}\n' + function(control, 'fn execution_limit(')
    code = code.replace('families:[Option<Family>;1]', 'families:[Option<Family>;18],stability:[Option<StabilityGuard>;1],stability_high:usize')
    code = code.replace(function(code, 'fn require_control('), function(control, 'fn require_control('))
    for name in ['fn family_index(', 'fn locate(', 'fn bind_dependencies(', 'fn validate_selection(']:
        code = code.replace(function(code, name), function(control, name))
    code += '\n' + '\n'.join(function(control, name) for name in ['fn locate_family(', 'fn tiers(', 'fn categorical(', 'fn validate_selection_with(', 'fn bind_dependency_list(', 'pub fn admit_dependency('])
    code = code.replace(function(code, 'mod domain_tasks{'), '// TASKS')
    start = code.index('struct Gate;')
    end = code.index('pub mod core_replay', start)
    active = "struct ActiveScope<'a>(&'a CommitGate);\n" + function(control, 'impl PublicationScope for ActiveScope')
    active += '\n' + function(control, "struct ActivePublication<'") + '\n' + function(control, 'impl PublicationScope for ActivePublication')
    code = code[:start] + active + '\n' + code[end:]
    code = code.replace('model_gate:Option<Gate>', 'model_gate:Option<CommitGate>')
    code = code.replace('mod replay{pub fn reject_first_job', 'mod replay{pub fn published(plan:&super::Plan,boot:u64,stamp:Option<super::PolicyStamp>)->Result<(),super::Error>{assert_eq!(boot,11);assert_eq!(plan.iter().next().unwrap().action.domain(),2);assert_eq!(stamp.unwrap().version,1);super::EFFECTS.fetch_add(1,super::Ordering::AcqRel);Ok(())} pub fn allows_action(_:super::Action,_:super::ObjectKey)->bool{super::ROOT_ALLOWED.load(super::Ordering::Acquire)} pub fn reject_first_job')
    code = code.replace('mod domain_control{pub use super::{accept,abort,pending_job};pub use super::core_replay;}', '''mod domain_control{pub use super::{accept,abort,pending_job,Family,TargetSource};pub use super::core_replay;pub use cyxia_prototype::policy::Prerequisite;
pub fn register(f:Family)->Result<(),super::Error>{super::FAMILIES.with(|v|v.borrow_mut().push(f));Ok(())}
pub fn register_dependencies(_:u16,_:fn(super::ObjectKey)->Result<[Option<Prerequisite>;2],super::Error>)->Result<(),super::Error>{Ok(())}
pub fn register_execution_observer(_:u16,_:fn(super::ObjectKey,u64)->Result<(),super::Error>)->Result<(),super::Error>{Ok(())}}''')
    target = (ROOT / 'kernel/src/domain_control/target_batch.rs').read_text()
    code += '\n#[derive(Clone,Copy,PartialEq,Eq)]' + function(target, 'pub enum Source').replace('enum Source', 'enum TargetSource')
    bodies = [re.search(r'^static LOCK:.*;$', tasks, re.M)[0], function(tasks, 'struct Guard {')]
    bodies += [function(tasks, name) for name in ['impl Drop for Guard', 'fn acquire_guard()', 'fn locked<R>', 'fn locked_with_guard<R>', 'fn group_index(', 'pub fn validate_action(', 'pub fn current_action(', 'fn control_current(', 'pub fn register_control()']]
    bodies[2] = bodies[2].replace('self.permit.take().unwrap().release(timer::ticks());', 'self.permit.take().unwrap().release(timer::ticks());super::BORROWS.fetch_sub(1,Ordering::AcqRel);super::pay(super::RELEASE_CPU.load(Ordering::Acquire));super::WALL.fetch_add(super::RELEASE_WALL.load(Ordering::Acquire),Ordering::AcqRel);')
    bodies[3] = bodies[3].replace('let permit = LOCK', 'super::ACQUIRES.fetch_add(1,Ordering::AcqRel);super::pay(super::ACQUIRE_CPU.load(Ordering::Acquire));let permit = LOCK').replace('Ok(Guard {', 'super::BORROWS.fetch_add(1,Ordering::AcqRel);Ok(Guard {')
    validate = function(tasks, 'fn validate_locked(')
    bodies += ['fn validate_locked(s:&State,action:Action,target:ObjectKey,now:u64)->Result<(),Error>{action.validate()?;match action{' + function(validate, 'Action::CpuWeight(_) | Action::SpawnTokens(_) =>') + ',_=>Err(Error::Unsupported)}}']
    current = function(tasks, 'fn current_locked(')
    bodies += ['fn current_locked(s:&State,domain:u16,target:ObjectKey,now:u64)->Result<Action,Error>{match domain{' + current[current.index('        1 =>'):current.index('        3 if')] + '_=>Err(Error::Unsupported)}}']
    bodies = [body.replace('fn validate_locked(s:&State,action:Action,target:ObjectKey,now:u64)->Result<(),Error>{', 'fn validate_locked(s:&State,action:Action,target:ObjectKey,now:u64)->Result<(),Error>{VALIDATIONS.fetch_add(1,Ordering::AcqRel);').replace('fn current_locked(s:&State,domain:u16,target:ObjectKey,now:u64)->Result<Action,Error>{', 'fn current_locked(s:&State,domain:u16,target:ObjectKey,now:u64)->Result<Action,Error>{CURRENTS.fetch_add(1,Ordering::AcqRel);') for body in bodies]
    options = function(tasks, 'fn legal_options(')
    bodies += [options[:options.index('        let first =')] + options[options.rindex('        cyxia_prototype::policy::collect_legal_actions(options, output, |action| {'):]]
    install = function(tasks, 'pub fn install(')
    bodies += [install[:install.index('            Action::CpuWeight')] + function(install, 'Action::SpawnTokens(tokens) =>') + ',_=>Err(Error::Unsupported)}}) }']
    for name in ['pub(crate) struct SchedulerPublication', 'pub(crate) fn reserve_scheduler_publication(', 'impl SchedulerPublication', 'fn native_scheduler_family_matches(', 'pub(crate) fn scheduler_publication_matches(']:
        bodies.append(function(publication, name))
    if 'pub(crate) struct SpawnPublication' in publication:
        bodies += [function(publication, name) for name in ['pub(crate) struct SpawnPublication', 'pub(crate) fn reserve_spawn_publication(', 'impl SpawnPublication', 'pub(crate) fn spawn_publication_matches(']]
    bodies += ['fn scheduling_dependencies(_:ObjectKey)->Result<[Option<domain_control::Prerequisite>;2],Error>{panic!("unused D01 resolver")}', 'fn scheduling_dependencies_locked(_: &State,_:ObjectKey)->Result<[Option<domain_control::Prerequisite>;2],Error>{panic!("unused D01 owner")}', 'fn vector_dependencies(_:ObjectKey)->Result<[Option<domain_control::Prerequisite>;2],Error>{panic!("unused vector resolver")}', 'fn confirm_ipc_execution(_:ObjectKey,_:u64)->Result<(),Error>{panic!("unused IPC observer")}']
    task_fixture = (ROOT / 'tests/host/active_spawn_publication_harness.rs').read_text()
    admission = (ROOT / 'kernel/src/domain_control/dependencies.rs').read_text()
    admission += '\nimpl AdmissionView{pub fn snapshot(&self)->[u64;6]{let e=&self.entries[0];[e.domain.load(Ordering::Acquire),e.id.load(Ordering::Acquire),e.generation.load(Ordering::Acquire),e.version.load(Ordering::Acquire),e.until.load(Ordering::Acquire),e.state.load(Ordering::Acquire)]}}'
    task_fixture = task_fixture.replace('// OWNER_GATE_PATH', '#[path=' + json.dumps(str(ROOT / 'kernel/src/domain_tasks/owner_gate.rs')) + '] mod owner_gate;').replace('// ADMISSION_PATH', 'mod admission_view{\n' + admission + '\n}')
    code = code.replace('// TASKS', task_fixture.split('// TESTS')[0].replace('// TASK_BODIES', '\n'.join(bodies)))
    return code + '\n' + task_fixture.split('// TESTS')[1]


class ActiveSpawnPublication(unittest.TestCase):
    def test_actual_spawn_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'harness.rs').write_text(program())
            (directory / 'Cargo.toml').write_text('[package]\nname="active-spawn-publication"\nversion="0.1.0"\nedition="2024"\n[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path=' + json.dumps(str(ROOT / 'crates/prototype')) + '}\nsha2="=0.10.9"\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-active-spawn-publication' / directory.name), '--', '--test-threads=1', 'spawn_']
            run_env = env()
            run_env['RUST_MIN_STACK'] = '16777216'
            result = subprocess.run(command, cwd=ROOT, env=run_env, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('10 passed; 0 failed', result.stdout)
            original = program()
            spawn_impl = function(original, 'impl SpawnPublication')
            mutations = [
                (original.replace(spawn_impl, spawn_impl.replace('validate_locked(self.state, action, target, now_ns())', 'locked(|s|validate_locked(s,action,target,now_ns()))')), 'legal query reentered'),
                (original.replace(spawn_impl, spawn_impl.replace('current_locked(self.state, domain, target, now_ns())', 'locked(|s|current_locked(s,domain,target,now_ns()))')), 'current query reentered'),
                (original.replace(spawn_impl, spawn_impl.replace('cpu::slot() != self.cpu', 'false')), 'borrow changed control CPU identity'),
                (original.replace('!has_custom_binder && resolver.is_none() && native_scheduler_family_matches(consumer, 2)', 'native_scheduler_family_matches(consumer, 2)'), 'resolver must retain original path'),
                (original.replace('drop(spawn_publication);', 'core::mem::forget(spawn_publication);'), 'delivery retained Task guard'),
                (original.replace('self.owner.desired[slot] = Some(Desired {', 'let discarded_desired = Some(Desired {'), 'publication lost actual Desired intent'),
                (original.replace('ADMISSION.publish(', 'let ignored_admission = ('), 'publication lost actual ADMISSION intent'),
                (original.replace('let _ = crate::learning_history::record_publish(crate::learning_history::Publish {', 'let ignored_history = (crate::learning_history::Publish {'), 'publication omitted history metadata'),
                (original.replace('if crate::domain_tasks::spawn_publication_matches(', 'if false && crate::domain_tasks::spawn_publication_matches('), 'native Spawn publication reacquired its physical owner gate'),
            ]
            for changed, message in mutations:
                self.assertNotEqual(changed, original)
                (directory / 'harness.rs').write_text(changed)
                red = subprocess.run(command, cwd=ROOT, env=run_env, capture_output=True, text=True, timeout=120)
                output = red.stdout + red.stderr
                self.assertNotEqual(red.returncode, 0, output)
                self.assertNotIn('error[E', output)
                self.assertIn('test result: FAILED', output)
                self.assertIn(message, output)


if __name__ == '__main__':
    unittest.main()
