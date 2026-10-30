"""D07 preparation shares one immutable platform view without weakening live checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def function(source: str, signature: str) -> str:
    """Extract a top-level Rust function through its unindented closing brace."""
    start = source.index(signature)
    end = source.index("\n}\n", start) + 2
    return source[start:end]


class TimerPreparationProjection(unittest.TestCase):
    def test_single_snapshot_projection_and_live_revalidation(self):
        platform = (ROOT / "kernel/src/domain_platform.rs").read_text()
        control = (ROOT / "kernel/src/domain_control.rs").read_text()

        start = platform.index("#[derive(Clone, Copy)]\npub(crate) struct TimerPreparation")
        end = platform.index("fn control_current(", start)
        projection = platform[start:end]

        self.assertEqual(
            projection.count("inspect_view("),
            1,
            "D07 preparation reacquired the platform owner view",
        )
        for required in [
            "view.soft_timers == 0",
            "view.measurement_core != CORE_GENERATION.load(Ordering::Acquire)",
            "DomainObservation::complete(view.timer.ok_or(Error::NotReady)?)",
            ".filter(|(_, stamp, _)| stamp.live(at))",
            "collect_legal_actions(options, output",
            "TargetFeatures::default()",
        ]:
            self.assertIn(required, projection)
        self.assertNotIn("control_legal(", projection)
        self.assertNotIn("now_ns()", projection)

        normal = function(control, "fn next_normal(")
        self.assertEqual(
            normal.count("crate::domain_platform::timer_preparation("),
            1,
            "normal preparation must create exactly one D07 projection",
        )
        for required in [
            "(f.domain, f.kind) == (7, 1)",
            "preparation.current()",
            "preparation.observation()",
            "preparation.legal_options(eligible, &mut legal)",
            "preparation.target_features(action)",
            "(f.legal_options)(eligible, target, wall_started, &mut legal)",
            "(f.target_features)(action, target)",
        ]:
            self.assertIn(required, normal)

        registration = function(platform, "pub fn register_control(")
        self.assertIn("legal: control_legal", registration)
        self.assertIn("control_legal(action, key, now_ns())?", registration)
        self.assertGreaterEqual(
            control.count("self.scope.legal(f, d.action, d.envelope.target, now)?;"),
            2,
            "CHECK/REVALIDATE no longer performs the live family legality check",
        )


if __name__ == "__main__":
    unittest.main()
