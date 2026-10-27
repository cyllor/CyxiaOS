"""Read the source-bound A10 wall-clock escape budget contract."""
from __future__ import annotations

from pathlib import Path
import re

from verify_smp import require


def _constant(source: str, name: str) -> int:
    match = re.search(rf'^pub const {name}: u64 = ([0-9_]+);$', source, re.MULTILINE)
    require(match is not None, 'missing A10 budget constant: ' + name)
    return int(match.group(1).replace('_', ''))


def scenario_budget(source_root: Path, mode: int) -> dict:
    require(type(mode) is int and mode in (1, 2, 3, 4), 'invalid A10 budget mode')
    path = Path(source_root) / 'crates/prototype/src/a10_budget.rs'
    source = path.read_text()
    standard = _constant(source, 'STANDARD_CLIENT_NS')
    cache = _constant(source, 'CACHE_CLIENT_NS')
    margin = _constant(source, 'CAPTURE_MARGIN_NS')
    max_polls = _constant(source, 'MAX_POLL_REQUESTS')
    client = cache if mode == 4 else standard
    require(client > 0 and margin > 0 and max_polls > 0 and client % max_polls == 0
            and (client + margin) % 1_000_000_000 == 0,
            'invalid A10 source budget')
    return dict(client_deadline_ns=client, client_poll_ns=client // max_polls,
                max_poll_requests=max_polls, capture_margin_ns=margin,
                capture_timeout_seconds=(client + margin) / 1_000_000_000)


def scenario_budgets(source_root: Path) -> dict:
    return {str(mode): scenario_budget(source_root, mode) for mode in range(1, 5)}
