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
SIGNED_CAPACITY = 1024
SIGNED_EARLY_CAPACITY = 4096
SIGNED_HEADER = struct.Struct("<20Q")
SIGNED_FRAME_SPAN = struct.Struct("<2Q")
SIGNED_ROW = struct.Struct("<8Q")
SIGNED_TRACE_BYTES = ((SIGNED_HEADER.size + SIGNED_CAPACITY * SIGNED_ROW.size + 4095) // 4096) * 4096
SIGNED_EARLY_TRACE_BYTES = ((SIGNED_HEADER.size + SIGNED_EARLY_CAPACITY * SIGNED_ROW.size + 4095) // 4096) * 4096
SIGNED_MAGIC = 0x4359583253425544
SIGNED_ROLES = (6, 7, 2, 8, 9, 3, 10, 11)
SIGNED_ROLE_LIMIT = 2_000_000
SIGNED_CONSOLE_QUOTA = 1_000_000
SIGNED_RECOVERY_QUOTA = CLASS_LIMITS[RECOVERY]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_trace(raw, summary, replacement_roles=None, recovery_slices=None, *, boot_accounting=None):
    """Replay scalar accounting and bind the optional boot-entry prefix."""
    require(len(raw) == TRACE_BYTES, "wrong stopped CPU0 trace size")
    magic, version, count, wall, counter, before = HEADER.unpack_from(raw)
    require(magic == MAGIC and version in (3, 4) and 0 < count <= CAPACITY, "unsealed CPU0 trace")
    require((version == 4) == (boot_accounting is not None), "missing or unexpected early boot accounting")
    boot_intervals, boot_end, boot_cpu_ns = boot_accounting or (0, 0, 0)
    if version == 4:
        require(0 < boot_intervals < count and wall < boot_end and boot_cpu_ns > 0,
                "invalid early boot accounting")
    require(before < wall and before // WINDOW == wall // WINDOW, "CPU0 sample straddles a window")
    end_offset = HEADER.size + count * ROW.size
    require(not any(raw[end_offset:]), "unexpected unused CPU0 trace bytes")

    result = _replay_intervals(
        ROW.iter_unpack(raw[HEADER.size:end_offset]), (wall, counter, before), summary,
        replacement_roles, recovery_slices, boot_accounting=boot_accounting,
    )
    if version == 4:
        result.update(early_boot_coordination_intervals=boot_intervals,
                      early_boot_coordination_cpu_ns=boot_cpu_ns)
    return result


def _replay_intervals(intervals, origin, summary, replacement_roles=None, recovery_slices=None,
                      *, boot_accounting=None, signed_roles=None, opening_recovery=None):
    wall, counter, before = origin
    boot_intervals, boot_end, boot_cpu_ns = boot_accounting or (0, 0, 0)
    signed = signed_roles is not None
    opening_window, opening_cpu_ns = opening_recovery or (-1, 0)
    role_limits = [SIGNED_ROLE_LIMIT] * len(ROLE_GRANTS) if signed else ROLE_LIMITS
    start_wall, start_counter = wall, counter
    lifetime = [0] * len(CLASS_LIMITS)
    window = None
    spending = []
    role_spending = []
    role_returns = []
    all_role_debits = [0] * len(ROLE_GRANTS)
    all_role_returns = [0] * len(ROLE_GRANTS)
    windows = []
    window_upper = 0
    kernel_coordination = 0
    kernel_coordination_upper = 0
    operations_seen = set()
    security_count = 0
    decision_spending = []
    crossing_gaps = 0
    peak = opening_cpu_ns
    grants = 0
    role_generations = [0] * len(ROLE_LIMITS)
    reloaded_spending = [0] * len(ROLE_LIMITS)
    reloaded_turns = [0] * len(ROLE_LIMITS)
    recovery_count = 0
    largest_recovery = 0

    def finish_window():
        if signed and window is not None:
            windows.append({
                "window": window, "upper_ns": window_upper, "class_cpu_ns": spending,
                "role_cpu_ns": role_spending, "role_returns": role_returns,
                "kernel_coordination_cpu_ns": kernel_coordination,
                "kernel_coordination_upper_ns": kernel_coordination_upper,
            })

    def enter(window_number):
        nonlocal window, spending, role_spending, role_returns, window_upper
        nonlocal kernel_coordination, kernel_coordination_upper
        nonlocal operations_seen, security_count, decision_spending
        if window != window_number:
            finish_window()
            window = window_number
            spending = [0] * len(CLASS_LIMITS)
            spending[RECOVERY] = opening_cpu_ns if window == opening_window else 0
            window_upper = sum(spending)
            role_spending = [0] * len(role_limits)
            role_returns = [0] * len(role_limits)
            kernel_coordination = 0
            kernel_coordination_upper = 0
            operations_seen = set()
            security_count = 0
            decision_spending = [0] * 16

    def check_credit(category, role, charge):
        require(sum(spending) + charge <= TOTAL_LIMIT
                and spending[category] + charge <= CLASS_LIMITS[category],
                "CPU0 class or total window limit exceeded")
        if role is not None:
            require(role_spending[role] + charge <= role_limits[role], "CPU0 role limit exceeded")
        elif category == COORDINATION:
            require(kernel_coordination + charge <= KERNEL_COORDINATION_LIMIT,
                    "EL1 coordination sublimit exceeded")

    for index, row in enumerate(intervals, 1):
        end, tick, quota, deadline, scope, lower, *identity = row
        actor_id, generation = identity if signed else (0, scope >> 32)
        returned = scope >> 32 if signed else 0
        require(end >= wall and tick >= counter, "regressed CPU0 counter or wall clock")
        require(before <= lower < end and lower // WINDOW == end // WINDOW,
                "CPU0 sample straddles a window")
        actual = tick - counter
        # The counter reads occurred within their wall brackets. Charge can
        # never exceed the distance from the earliest possible start to the
        # latest possible end, even if the PMU samples were near the bounds.
        require(actual <= end - before, "CPU0 execution exceeds wall-clock bounds")
        if index <= boot_intervals:
            require(scope == 0, "role grant during early boot")
            if index == boot_intervals:
                require((end, tick - start_counter) == (boot_end, boot_cpu_ns),
                        "early boot debit differs from UART accounting")
        start_window = wall // WINDOW
        last_window = max(wall, end - 1) // WINDOW
        enter(start_window)
        role = None
        if scope == 0:
            require(quota == deadline == actor_id == generation == 0,
                    "coordination gap contains a role grant")
            category = COORDINATION
            check_credit(category, role, actual)
            window_upper = max(window_upper, sum(spending) + actual)
            kernel_coordination_upper = max(kernel_coordination_upper, kernel_coordination + actual)
            peak = max(peak, window_upper)
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
            require(0 <= category < len(CLASS_LIMITS) and actor <= len(role_limits),
                    "unknown CPU0 grant scope")
            require(0 < quota <= (start_window + 1) * WINDOW - wall
                    and deadline == min((start_window + 1) * WINDOW, wall + 50_000_000)
                    and end <= deadline and last_window == start_window and actual <= quota,
                    "CPU0 grant expiry, window, or measured quota overrun")
            if actor == 0:
                require(category in (COORDINATION, RECOVERY)
                        and generation == actor_id == returned == 0,
                        "invalid EL1 grant scope")
                expected = (2_000_000 if category == RECOVERY else
                            KERNEL_COORDINATION_LIMIT - kernel_coordination - 200_000)
                if signed:
                    expected = SIGNED_RECOVERY_QUOTA if category == RECOVERY else SIGNED_CONSOLE_QUOTA
                require(quota == expected, "incorrect EL1 prepayment")
                if category == RECOVERY:
                    recovery_count += 1
                    largest_recovery = max(largest_recovery, actual)
            else:
                role = actor - 1
                require((category, domain, quota) == ROLE_GRANTS[role],
                        "incorrect role grant class, domain, or quota")
                if signed:
                    require((role, actor_id, generation) == signed_roles[role],
                            "signed role identity differs from the durable role table")
                    require(returned <= (1 if category == 2 else 8)
                            and (returned == 0 or actual > 0),
                            "invalid native EL0 return count")
                else:
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
            role_returns[role] += returned
            all_role_debits[role] += actual
            all_role_returns[role] += returned
        elif category == COORDINATION:
            kernel_coordination += actual
            kernel_coordination_upper = max(kernel_coordination_upper, kernel_coordination)
        spending[category] += actual
        lifetime[category] += actual
        window_upper = max(window_upper, sum(spending))
        peak = max(peak, window_upper)
        wall, counter, before = end, tick, lower

    finish_window()
    elapsed, accounted, upper, gaps, begin_ns, end_ns, *classes = summary
    require((begin_ns, end_ns) == (start_wall, wall), "trace wall endpoints differ from summary")
    require(0 < elapsed == accounted == counter - start_counter == sum(lifetime)
            and lifetime == classes and peak == upper and (signed or gaps == crossing_gaps),
            "trace does not conserve the reported CPU0 charges")
    if replacement_roles is not None:
        require(all(generation == 2 for generation in role_generations)
                and list(zip(reloaded_spending, reloaded_turns)) == replacement_roles,
                "trace replacement role charges differ from native evidence")
    if recovery_slices is not None:
        require((recovery_count, largest_recovery) == recovery_slices,
                "trace recovery slices differ from native evidence")
    result = {"budget_intervals_replayed": index, "budget_grants_replayed": grants,
              "budget_max_window_upper_ns": peak, "budget_accounting_replayed": True}
    if signed:
        complete = [w["window"] for w in windows if start_wall // WINDOW < w["window"] < wall // WINDOW
                    and all(w["role_returns"])]
        require(any(right - left == 7 for left, right in zip(complete, complete[7:])),
                "fewer than eight consecutive complete windows with eight roles")
        result.update(budget_crossing_gaps=crossing_gaps, budget_role_returns=all_role_returns,
                      budget_role_cpu_ns=all_role_debits, budget_window_replay=windows,
                      budget_kernel_coordination_max_upper_ns=max(
                          w["kernel_coordination_upper_ns"] for w in windows),
                      budget_complete_eight_role_windows=complete)
    return result


def verify_signed_trace(raw, boot_epoch, roles, recovery, uart_budget, *,
                        media_budget=None, frame_budget=None):
    """Bind a sealed prefix to the durable role inventory and native UART."""
    trace_sizes = {1: (SIGNED_TRACE_BYTES, SIGNED_CAPACITY),
                   2: (SIGNED_EARLY_TRACE_BYTES, SIGNED_EARLY_CAPACITY),
                   3: (SIGNED_EARLY_TRACE_BYTES, SIGNED_EARLY_CAPACITY)}
    require(len(raw) in (SIGNED_TRACE_BYTES, SIGNED_EARLY_TRACE_BYTES),
            "wrong signed CPU0 trace size")
    (magic, version, count, wall, tick, before, epoch, phase_start, phase_end,
     end_wall, end_tick, charged, peak, idle, *classes) = SIGNED_HEADER.unpack_from(raw)
    size, capacity = trace_sizes.get(version, (0, 0))
    require(magic == SIGNED_MAGIC and len(raw) == size and 0 < count < capacity,
            "unsealed signed CPU0 trace")
    require(epoch == boot_epoch > 0, "signed CPU0 trace differs from the durable BootEpoch")
    require([(index, actor) for index, actor, _ in roles] == list(enumerate(SIGNED_ROLES))
            and all(generation > 0 for _, _, generation in roles), "missing signed CPU0 role inventory")
    require(before < wall and before // WINDOW == wall // WINDOW, "CPU0 sample straddles a window")
    elapsed = end_tick - tick
    require((elapsed, charged, idle) in uart_budget, "trace endpoint differs from the UART CPU0 ledger")
    require((version == 3) == (frame_budget is not None),
            "missing or unexpected FrameMeta Recovery settlement")
    rows_offset = SIGNED_HEADER.size
    frame_start = frame_end = 0
    if frame_budget is not None:
        frame_start, frame_end = SIGNED_FRAME_SPAN.unpack_from(raw, rows_offset)
        rows_offset += SIGNED_FRAME_SPAN.size
        require(frame_start == 1 and frame_start < frame_end < phase_start,
                "FrameMeta accounting does not precede policy and media")
    end_offset = rows_offset + count * SIGNED_ROW.size
    require(not any(raw[end_offset:]), "unexpected unused signed CPU0 trace bytes")
    intervals = list(SIGNED_ROW.iter_unpack(raw[rows_offset:end_offset]))
    replay = (elapsed, charged, peak, None, wall, end_wall, *classes)
    if version == 1:
        require(media_budget is None and len(recovery) == 2 and phase_start <= wall // WINDOW
                and 0 < phase_end == recovery[0] <= SIGNED_RECOVERY_QUOTA,
                "invalid opening signed Recovery debit")
        return _replay_intervals(intervals, (wall, tick, before), replay,
                                 recovery_slices=(1, recovery[1]), signed_roles=roles,
                                 opening_recovery=(phase_start, phase_end))

    require(media_budget is not None and len(recovery) == 3 and 0 < phase_start < phase_end < count,
            "missing signed media accounting span")
    media_rows = intervals[phase_start:phase_end]
    require(all(row[4] in (0, RECOVERY + 1) for row in intervals[:phase_end])
            and sum(row[4] == RECOVERY + 1 for row in intervals[:frame_start]) == int(version == 3)
            and sum(row[4] == RECOVERY + 1 for row in intervals[frame_end:phase_start])
            == (1 if version == 3 else 2)
            and media_rows[-1][4] == RECOVERY + 1, "invalid signed media scope")
    current = tick
    media_recovery = []
    frame_recovery = []
    startup_recovery = []
    for index, row in enumerate(intervals):
        if row[4] == RECOVERY + 1:
            debits = startup_recovery
            if frame_start <= index < frame_end:
                debits = frame_recovery
            elif phase_start <= index < phase_end:
                debits = media_recovery
            debits.append(row[1] - current)
        current = row[1]
    if frame_budget is not None:
        require(intervals[frame_end - 1][4] == RECOVERY + 1
                and all(0 <= used <= SIGNED_RECOVERY_QUOTA for used in frame_recovery)
                and frame_budget == (len(frame_recovery), sum(frame_recovery), SIGNED_RECOVERY_QUOTA)
                and sum(frame_recovery) > 0, "FrameMeta PMU debits differ from UART")
    require(startup_recovery == list(recovery) and all(used >= 0 for used in media_recovery)
            and media_budget == (len(media_recovery), sum(media_recovery), SIGNED_RECOVERY_QUOTA)
            and sum(media_recovery) > 0, "signed media PMU debits differ from UART")
    result = _replay_intervals(
        intervals, (wall, tick, before), replay, signed_roles=roles,
        recovery_slices=(len(frame_recovery) + len(media_recovery) + 3,
                         max(startup_recovery + frame_recovery + media_recovery)),
    )
    if frame_budget is not None:
        result.update(boot_frame_meta_recovery_batches=len(frame_recovery),
                      boot_frame_meta_recovery_cpu_ns=sum(frame_recovery),
                      boot_frame_meta_accounting_intervals=frame_end - frame_start)
    result.update(boot_media_recovery_batches=len(media_recovery),
                  boot_media_recovery_cpu_ns=sum(media_recovery),
                  boot_media_accounting_intervals=len(media_rows),
                  early_boot_recovery_cpu_ns=startup_recovery[0])
    return result


def verify_sustained(raw, windows):
    """Cross-check the workload markers against the already replayed trace."""
    _, _, count, _, _, _ = HEADER.unpack_from(raw)
    trace = list(ROW.iter_unpack(raw[HEADER.size:HEADER.size + count * ROW.size]))
    require(len(windows) == 8, "wrong sustained window count")
    first_window = windows[0][0]
    previous_end = 0
    totals = [0] * len(ROLE_LIMITS)
    work_cpu_ns = []
    role_calls = []
    all_roles = (1 << len(ROLE_LIMITS)) - 1
    decision_roles = sum(1 << i for i, (category, _, _) in enumerate(ROLE_GRANTS) if category == 2)
    per_window = all_roles ^ decision_roles
    serviced_in_run = 0
    for index, (window, begin, end, serviced, refused, security_reads) in enumerate(windows):
        require(window == first_window + index and max(1, previous_end) <= begin < end < count,
                "nonconsecutive or overlapping sustained accounting windows")
        preceding = trace[begin - 1]
        preceding_wall = preceding[0]
        grants = [0] * len(ROLE_LIMITS)
        require(serviced & per_window == per_window and serviced & ~all_roles == 0
                and (refused, security_reads) == (3, 4),
                "incomplete sustained syscall or slot refusal evidence")
        serviced_in_run |= serviced
        role_calls.append(serviced)
        for row in trace[begin:end]:
            end_wall, _, _, _, scope, _ = row
            require(preceding_wall // WINDOW == (end_wall - 1) // WINDOW == window,
                    "sustained work fell outside its aligned window")
            if scope:
                actor = (scope >> 8) & 0xff
                require(1 <= actor <= len(grants) and scope >> 32 == 2,
                        "unexpected kernel or stale role grant during sustained work")
                grants[actor - 1] += 1
            preceding_wall = end_wall
        require(grants[:2] == [1, 4] and all(grants), "missing sustained role grant")
        work_cpu_ns.append(trace[end - 1][1] - preceding[1])
        totals = [total + actual for total, actual in zip(totals, grants)]
        previous_end = end
    require(serviced_in_run == all_roles, "missing sustained decision or publisher syscall")
    require(trace[-1][0] >= (first_window + len(windows)) * WINDOW,
            "sustained trace ends before the final window closes")
    return {"sustained_windows": len(windows), "sustained_role_grants": totals,
            "sustained_slot_refusals": 2 * len(windows), "sustained_work_cpu_ns": work_cpu_ns,
            "sustained_role_calls_mask_by_window": role_calls}
