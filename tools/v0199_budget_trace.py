"""Recompute fixed CPU0 accounting from stopped-guest counter intervals."""

import struct


CAPACITY = 4096
HEADER = struct.Struct("<6Q")
ROW = struct.Struct("<6Q")
TRACE_BYTES = ((HEADER.size + CAPACITY * ROW.size + 4095) // 4096) * 4096
MAGIC = 0x4359584255444731
WINDOW = 100_000_000
TOTAL_LIMIT = 70_000_000
CLASS_LIMITS = (30_000_000, 8_000_000, 7_500_000, 8_000_000, 8_000_000, 8_500_000)
COORDINATION, RECOVERY = 3, 4
KERNEL_COORDINATION_LIMIT = 2_000_000
ROLE_LIMITS = (30_000_000, 8_000_000, 4_000_000, 3_500_000, 4_000_000, 3_000_000, 4_500_000, 3_000_000)
ROLE_GRANTS = (
    (0, 1, 2_000_000), (1, 12, 2_000_000), (2, 1, 250_000), (2, 1, 250_000),
    (5, 0, 500_000), (3, 0, 500_000), (5, 0, 500_000), (3, 0, 500_000),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_trace(raw, summary, replacement_roles=None, recovery_slices=None):
    """Verify the original scalar accounting, including conservative gap carry."""
    require(len(raw) == TRACE_BYTES, "wrong stopped CPU0 trace size")
    magic, version, count, wall, counter, before = HEADER.unpack_from(raw)
    require((magic, version) == (MAGIC, 3) and 0 < count <= CAPACITY, "unsealed CPU0 trace")
    require(before < wall and before // WINDOW == wall // WINDOW, "CPU0 sample straddles a window")
    end_offset = HEADER.size + count * ROW.size
    require(not any(raw[end_offset:]), "unexpected unused CPU0 trace bytes")

    start_wall, start_counter = wall, counter
    lifetime = [0] * len(CLASS_LIMITS)
    window = None
    spending = []
    role_spending = []
    kernel_coordination = 0
    operations_seen = set()
    security_count = 0
    decision_spending = []
    crossing_gaps = 0
    peak = 0
    grants = 0
    role_generations = [0] * len(ROLE_LIMITS)
    reloaded_spending = [0] * len(ROLE_LIMITS)
    reloaded_turns = [0] * len(ROLE_LIMITS)
    recovery_count = 0
    largest_recovery = 0

    def enter(window_number):
        nonlocal window, spending, role_spending, kernel_coordination
        nonlocal operations_seen, security_count, decision_spending
        if window != window_number:
            window = window_number
            spending = [0] * len(CLASS_LIMITS)
            role_spending = [0] * len(ROLE_LIMITS)
            kernel_coordination = 0
            operations_seen = set()
            security_count = 0
            decision_spending = [0] * 16

    def check_credit(category, role, charge):
        require(sum(spending) + charge <= TOTAL_LIMIT
                and spending[category] + charge <= CLASS_LIMITS[category],
                "CPU0 class or total window limit exceeded")
        if role is not None:
            require(role_spending[role] + charge <= ROLE_LIMITS[role], "CPU0 role limit exceeded")
        elif category == COORDINATION:
            require(kernel_coordination + charge <= KERNEL_COORDINATION_LIMIT,
                    "EL1 coordination sublimit exceeded")

    for end, tick, quota, deadline, scope, lower in ROW.iter_unpack(raw[HEADER.size:end_offset]):
        require(end >= wall and tick >= counter, "regressed CPU0 counter or wall clock")
        require(before <= lower < end and lower // WINDOW == end // WINDOW,
                "CPU0 sample straddles a window")
        actual = tick - counter
        start_window = wall // WINDOW
        last_window = max(wall, end - 1) // WINDOW
        enter(start_window)
        role = None
        if scope == 0:
            require(quota == deadline == 0, "coordination gap contains a role grant")
            category = COORDINATION
            check_credit(category, role, actual)
            peak = max(peak, sum(spending) + actual)
            if last_window != start_window:
                # Persist the debit exactly once, while bounding both
                # touched windows by the independently sampled delta.
                crossing_gaps += 1
                enter(last_window)
                check_credit(category, role, actual)
        else:
            category = (scope & 0xff) - 1
            actor = (scope >> 8) & 0xff
            domain = (scope >> 16) & 0xffff
            generation = scope >> 32
            require(0 <= category < len(CLASS_LIMITS) and actor <= len(ROLE_LIMITS),
                    "unknown CPU0 grant scope")
            require(0 < quota <= (start_window + 1) * WINDOW - wall
                    and deadline == min((start_window + 1) * WINDOW, wall + 50_000_000)
                    and end <= deadline and last_window == start_window and actual <= quota,
                    "CPU0 grant expiry, window, or measured quota overrun")
            if actor == 0:
                require(category in (COORDINATION, RECOVERY) and generation == 0,
                        "invalid EL1 grant scope")
                expected = (2_000_000 if category == RECOVERY else
                            KERNEL_COORDINATION_LIMIT - kernel_coordination - 200_000)
                require(quota == expected, "incorrect EL1 prepayment")
                if category == RECOVERY:
                    recovery_count += 1
                    largest_recovery = max(largest_recovery, actual)
            else:
                role = actor - 1
                require((category, domain, quota) == ROLE_GRANTS[role],
                        "incorrect role grant class, domain, or quota")
                require(1 <= generation <= 2
                        and role_generations[role] <= generation <= role_generations[role] + 1,
                        "skipped or regressed role generation")
                role_generations[role] = generation
                if generation == 2:
                    reloaded_spending[role] += actual
                    reloaded_turns[role] += 1
            check_credit(category, role, quota)
            if category in (0, 1, 2):
                require(1 <= domain <= 15, "invalid control-domain grant")
            else:
                require(domain == 0, "unexpected domain on CPU0 grant")
            if category == 0:
                require(quota <= 2_000_000 and domain not in operations_seen,
                        "duplicate or oversize operations grant")
                operations_seen.add(domain)
            elif category == 1:
                require(quota <= 2_000_000 and security_count < 4, "excess security reviews")
                security_count += 1
            elif category == 2:
                require(decision_spending[domain] + quota <= 500_000,
                        "shared decision domain limit exceeded")
                decision_spending[domain] += actual
            grants += 1
        if role is not None:
            role_spending[role] += actual
        elif category == COORDINATION:
            kernel_coordination += actual
        spending[category] += actual
        lifetime[category] += actual
        peak = max(peak, sum(spending))
        wall, counter, before = end, tick, lower

    elapsed, accounted, upper, gaps, begin_ns, end_ns, *classes = summary
    require((begin_ns, end_ns) == (start_wall, wall), "trace wall endpoints differ from summary")
    require(0 < elapsed == accounted == counter - start_counter == sum(lifetime)
            and lifetime == classes and peak == upper and gaps == crossing_gaps,
            "trace does not conserve the reported CPU0 charges")
    if replacement_roles is not None:
        require(all(generation == 2 for generation in role_generations)
                and list(zip(reloaded_spending, reloaded_turns)) == replacement_roles,
                "trace replacement role charges differ from native evidence")
    if recovery_slices is not None:
        require((recovery_count, largest_recovery) == recovery_slices,
                "trace recovery slices differ from native evidence")
    return {"budget_intervals_replayed": count, "budget_grants_replayed": grants,
            "budget_max_window_upper_ns": peak, "budget_accounting_replayed": True}
