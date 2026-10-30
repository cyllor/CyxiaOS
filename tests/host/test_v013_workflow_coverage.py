"""V0.13 source changes must trigger both existing engineering/native workflows."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def push_branches(path: Path) -> list[str]:
    """Read this repository's explicit push branch list without a YAML dependency."""
    text = path.read_text()
    block = re.search(r"(?m)^on:\n  push:\n    branches:\n((?:      - [^\n]+\n)+)", text)
    if block is None:
        raise AssertionError(f"missing explicit push branch list in {path.name}")
    return [line.strip()[2:].strip("\"'") for line in block[1].splitlines()]


class V013WorkflowCoverage(unittest.TestCase):
    def test_v013_engineering_validation_is_automatically_triggered(self):
        branches = push_branches(ROOT / '.github/workflows/validate-prototype.yml')
        self.assertIn('CyxiaOS-V0.13', branches)
        self.assertIn('CyxiaOS-V0.12', branches)

    def test_v013_native_replay_is_automatically_triggered(self):
        branches = push_branches(ROOT / '.github/workflows/native-replay-current.yml')
        self.assertIn('CyxiaOS-V0.13', branches)
        self.assertIn('CyxiaOS-V0.12', branches)


if __name__ == '__main__':
    unittest.main()
