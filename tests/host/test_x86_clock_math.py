"""Check exact clock/timer arithmetic against independent wide-integer oracles."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class ClockArithmetic(unittest.TestCase):
    def test_production_rounding_saturation_and_overflow(self):
        runtime = (ROOT / 'kernel/src/arch/x86_64/runtime.rs').read_text()
        source = '\n'.join(function(runtime, name) for name in
                           ('fn counter_ns(', 'fn deadline_count('))
        source += r'''
#[test]
fn integral_nanosecond_periods_match_the_wide_oracle_and_keep_overflow_checks() {
    for period in (1..=100).map(|n| n * 1_000_000) {
        let last = u64::MAX / (period / 1_000_000);
        for counter in [0, 1, 12345, last] {
            assert_eq!(counter_ns(counter, period),
                u64::try_from(u128::from(counter) * u128::from(period) / 1_000_000).unwrap());
        }
        if last < u64::MAX {
            assert!(std::panic::catch_unwind(|| counter_ns(last + 1, period)).is_err());
        }
    }
}
#[test]
fn fractional_periods_are_not_rounded_to_whole_nanoseconds() {
    for period in [1, 999_999, 1_000_001, 10_000_003, 99_999_999] {
        for counter in [0, 1, 100_000, 1_234_567_890, u64::MAX] {
            let expected = u64::try_from(u128::from(counter) * u128::from(period) / 1_000_000);
            match expected {
                Ok(value) => assert_eq!(counter_ns(counter, period), value),
                Err(_) => assert!(std::panic::catch_unwind(|| counter_ns(counter, period)).is_err()),
            }
        }
    }
}
fn oracle(delta: u64, hz: u64) -> u32 {
    let product = u128::from(delta) * u128::from(hz);
    let ticks = product / 1_000_000_000 + u128::from(product % 1_000_000_000 != 0);
    ticks.max(1).min(u128::from(u32::MAX)) as u32
}
#[test]
fn deadlines_cover_zero_round_up_saturation_and_u64_product_overflow() {
    for delta in [0, 1, 999_999_999, 1_000_000_000, 1_000_000_001,
        u64::from(u32::MAX) * 1_000_000_000 - 1,
        u64::from(u32::MAX) * 1_000_000_000, u64::MAX] {
        for hz in [0, 1, 3, 62_500_000, 1_000_000_000, u64::MAX] {
            assert_eq!(deadline_count(delta, hz), oracle(delta, hz), "delta={delta} hz={hz}");
        }
    }
}
#[test]
fn deterministic_full_width_samples_match_the_oracle() {
    let mut state = 0x4a8f_702c_918e_3d61u64;
    for _ in 0..100_000 {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        let delta = state;
        state = state.rotate_left(31).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        assert_eq!(deadline_count(delta, state), oracle(delta, state));
        assert_eq!(deadline_count(delta % 1_000_000_000, state % 1_000_000_000),
            oracle(delta % 1_000_000_000, state % 1_000_000_000));
    }
}
'''
        with tempfile.TemporaryDirectory(prefix='cyxia-clock-math-') as directory:
            directory = Path(directory)
            rust = directory / 'clock.rs'; rust.write_text(source)
            binary = directory / 'clock'
            built = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                '-Dwarnings', str(rust), '-o', str(binary)], env=env(), capture_output=True,
                text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('4 passed; 0 failed', ran.stdout)


if __name__ == '__main__':
    unittest.main()
