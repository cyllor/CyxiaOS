"""Production Executor precommit and NativeClock, with controlled owner callbacks.

The actual policy budget and wire types are used. Commit is a counted facade;
Registry tests separately check retained post-publication receipts.
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


class NativePublicationClock(unittest.TestCase):
    def test_native_final_gate_uses_original_cpu_origin_after_the_last_callback(self):
        source = (ROOT / 'kernel/src/domain_control.rs').read_text()
        body = function(source, 'fn publish(&mut self, plan: &Plan, version: u64, at: u64)')
        # Execute the full native precommit body. Mutating root/device/history
        # effects below this boundary are substituted with one counted commit.
        cutoff=body.index('self.scope.commit(');cutoff=body.rfind('\n',0,cutoff)+1
        marker=body.rfind('self.provenance.at(',0,cutoff)
        if marker>=0 and 'ScopeCommit' in body[marker:cutoff]:cutoff=body.rfind('\n',0,marker)+1
        suffix=body[body.rfind('\n        })();'):] if 'let result = (|| {' in body else '\n    }'
        body=body[:cutoff]+'self.published += 1; Ok(())'+suffix
        template = (ROOT / 'tests/host/native_publication_clock_harness.rs').read_text()
        template = template.replace('// NATIVE_CLOCK', function(source, 'impl policy::Clock for NativeClock'))
        template=template.replace('// SUBMISSION_TRACE_MODULE','#[path='+json.dumps(str(ROOT/'kernel/src/domain_control/submission.rs'))+'] mod submission;')
        template = template.replace('// NATIVE_PRECOMMIT', body)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'harness.rs').write_text(template)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="native-publication-clock"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-native-publication-clock'),
                '--', '--test-threads=1']
            result = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                    text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('4 passed; 0 failed', result.stdout)
            check = ('policy::PublicationBudget {\n'
                     '                started: self.publication_started,\n'
                     '                carried: self.publication_debit,\n'
                     '            }\n'
                     '            .check(commit)?;')
            self.assertEqual(template.count(check), 1, 'native publication CPU check changed')
            (directory / 'harness.rs').write_text(template.replace(check, ''))
            negative = subprocess.run(command + ['--exact', 'last_callback_cannot_hide_cpu_overrun'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            output = negative.stdout + negative.stderr
            self.assertNotEqual(negative.returncode, 0, output)
            self.assertNotIn('error[E', output)
            self.assertIn('test result: FAILED', output)
            self.assertIn('last callback CPU overrun reached commit', output)


if __name__ == '__main__':
    unittest.main()
