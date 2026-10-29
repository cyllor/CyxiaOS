"""Run the real matcher against the real native Family registration expression.

The host facade supplies callback identities, not task behavior. Callback
bodies panic if called; Clock, TaskGate, and TaskState do not exist here.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class SchedulerPublicationContract(unittest.TestCase):
    def test_only_the_native_registration_can_use_the_borrow(self):
        tasks = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        publication = (ROOT / 'kernel/src/domain_tasks/publication.rs').read_text()
        control = (ROOT / 'kernel/src/domain_control.rs').read_text()
        source = (ROOT / 'kernel/src/domain_control/target_batch.rs').read_text()
        try:
            matcher = function(publication, 'pub(crate) fn scheduler_publication_matches(')
        except ValueError:
            self.fail('native callback contract missing: arbitrary registered callbacks cannot safely use the borrow')
        helper = function(publication, 'fn native_scheduler_family_matches(')
        registration = function(tasks, 'pub fn register_control()')
        template = (ROOT / 'tests/host/scheduler_publication_contract_harness.rs').read_text()
        template = template.replace('// FAMILY', '#[derive(Clone, Copy)]\n' + function(control, 'pub struct Family'))
        template = template.replace('// TARGET_SOURCE', '#[derive(Clone, Copy, PartialEq, Eq)]\n'
                                    + function(source, 'pub enum Source').replace('enum Source', 'enum TargetSource'))

        def render(matching, registering):
            return template.replace('// MATCHER', matching).replace('// REGISTER', registering)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="scheduler-publication-contract"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                       str(directory / 'Cargo.toml'), '--target-dir',
                       str(ROOT / 'target/host-scheduler-publication-contract'), '--', '--test-threads=1']

            def run(matching, registering):
                (directory / 'harness.rs').write_text(render(matching, registering))
                return subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                      text=True, timeout=120)

            actual = matcher + '\n' + helper
            result = run(actual, registration)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('6 passed; 0 failed', result.stdout)

            # All mutations live in the temporary harness, never production.
            mutants = []
            for field in ['target', 'current', 'legal', 'legal_options', 'target_features', 'apply', 'reconcile']:
                lines = helper.splitlines()
                changed = '\n'.join(line for line in lines if f'family.{field},' not in line)
                self.assertNotEqual(changed, helper, field)
                mutants.append((matcher + '\n' + changed, registration, 'callback identity must be exact'))
            for check in ['family.domain == domain', 'family.kind == 1',
                          'family.target_source == crate::domain_control::TargetSource::Tasks']:
                self.assertEqual(helper.count(check), 1)
                mutants.append((matcher + '\n' + helper.replace(check, 'true'), registration,
                                'family metadata must be exact'))
            mutants.extend([
                (actual.replace('if has_custom_binder {', 'if false {'), registration,
                 'custom binder must retain the registered path'),
                (actual.replace('Some(prerequisite) => native_scheduler_family_matches(prerequisite, 13),',
                                'Some(_) => true,'), registration, 'family metadata must be exact'),
                (actual.replace('None => false,', 'None => true,', 1), registration,
                 'D13 registration is required'),
                (actual.replace('core::ptr::fn_addr_eq(resolver, scheduling_dependencies as',
                                'core::ptr::fn_addr_eq(resolver, foreign_resolver as'), registration,
                 'native registrations must match'),
                (actual, registration.replace('current: control_current,', 'current: foreign_current,'),
                 'native registrations must match'),
                (actual, registration.replace('register_dependencies(1, scheduling_dependencies)',
                                             'register_dependencies(1, foreign_resolver)'),
                 'native registrations must match'),
            ])
            for matching, registering, expected in mutants:
                red = run(matching, registering)
                output = red.stdout + red.stderr
                self.assertNotEqual(red.returncode, 0, output)
                self.assertIn(expected, output)
                self.assertNotIn('error[E', output)


if __name__ == '__main__':
    unittest.main()
