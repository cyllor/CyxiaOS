"""Recompute signed FILE_SERVICE and B3 peer settlement from paused QEMU."""

import json
import struct
import time

from check_elf import symbol
from verify_smp import require
from verify_v020_role_recovery import dump


CAPACITY = 128
HEADER = struct.Struct("<8Q")
ROW = struct.Struct("<9Q")
WINDOW_CAPACITY = 16
WINDOW_HEADER = struct.Struct("<16Q")
WINDOW_ROW = struct.Struct("<17Q")
WINDOW_NS = 100_000_000
CORE_CREDIT_NS = 90_000_000
MAX_CREDIT_NS = 2_000_000


def replay(raw, epoch, generation, owner_limit, windows=None, read_windows=0, custody=None):
    require(len(raw) == HEADER.size + CAPACITY * ROW.size, "wrong B3 budget witness size")
    boot, window_ns, core, granted, cpu, owner, count, omitted = HEADER.unpack_from(raw)
    require((boot, window_ns, core, granted, cpu, owner)
            == (epoch, WINDOW_NS, CORE_CREDIT_NS, owner_limit, 3, 12)
            and boot > 0 and MAX_CREDIT_NS <= granted <= core - MAX_CREDIT_NS
            and 0 < count <= CAPACITY and (omitted == 0 or count == CAPACITY),
            "B3 budget witness does not match the signed grant and accounting policy")
    charges, turns, peers = {}, [0, 0], set()
    prefix_turns, carries, peaks = {}, {}, {}
    spent = [0, 0]
    limits = (granted, core - granted)
    prior_seq, prior_finish = 0, 0
    first_window, last_window = None, None
    end = HEADER.size + count * ROW.size
    for seq, actor, gen, window, start, finish, reserved, cost, settled in ROW.iter_unpack(raw[HEADER.size:end]):
        require(seq > prior_seq and actor > 0 and gen > 0 and window == start // window_ns
                and finish >= start >= prior_finish and 0 < reserved <= MAX_CREDIT_NS
                and cost <= reserved and settled == 1,
                "unsuccessful or inconsistent B3 dispatch settlement")
        index = int(actor != owner)
        if index:
            peers.add((actor, gen))
        else:
            require(gen == generation, "role12 budget charge used a stale generation")
        amount = charges.setdefault(window, [0, 0])
        side_reservation = amount[index] + reserved
        core_reservation = sum(amount) + reserved
        require(side_reservation <= limits[index] and core_reservation <= core,
                "B3 dispatch was reserved beyond its available window credit")
        prefix_turns.setdefault(window, [0, 0])[index] += 1
        peak = peaks.setdefault(window, [0, 0, 0])
        peak[index] = max(peak[index], side_reservation)
        peak[2] = max(peak[2], core_reservation)
        amount[index] += cost
        if finish > (window + 1) * window_ns:
            carried = charges.setdefault(finish // window_ns, [0, 0])
            carried[index] += cost
            carries.setdefault(finish // window_ns, [0, 0])[index] += cost
            require(carried[index] <= limits[index] and sum(carried) <= core,
                    "B3 cross-window charge exceeded its credit")
        turns[index] += 1
        spent[index] += cost
        prior_seq, prior_finish = seq, finish
        if first_window is None:
            first_window = window
        last_window = window
    require(len(peers) == 1 and all(turns) and all(spent) and not any(raw[end:]),
            "missing owner/peer dispatches or invalid unwritten witness tail")
    report = {"status": "PASS", "boot_epoch": epoch, "cpu": cpu, "role_generation": generation,
            "window_ns": window_ns, "owner_limit_ns": granted, "core_limit_ns": core,
            "settled_turns": turns, "measured_cpu_ns": spent, "rows_omitted": omitted,
            "peak_owner_window_ns": max(row[0] for row in charges.values()),
            "peak_peer_window_ns": max(row[1] for row in charges.values()),
            "peak_core_window_ns": max(map(sum, charges.values())),
            "observed_window_count": len(charges),
            "interior_charged_windows": sum(first_window < key < last_window for key in charges)}
    require(windows is not None or read_windows == 0, "missing whole-window witness")
    if windows is not None:
        prefix = {
            index: (*prefix_turns.get(index, (0, 0)), *charge,
                    *carries.get(index, (0, 0)), *peaks.get(index, (0, 0, 0)))
            for index, charge in charges.items()
        }
        report["whole_windows"] = replay_windows(
            windows, epoch, generation, limits, count + omitted,
            prefix, (last_window, prior_seq), read_windows, custody,
        )
    return report


def replay_windows(raw, epoch, generation, limits, observed, prefix, end_prefix, read_windows, custody):
    require(len(raw) == WINDOW_HEADER.size + (WINDOW_CAPACITY + 1) * WINDOW_ROW.size,
            "wrong whole-window witness length")
    (revision, boot, gen, closed, omitted, errors, owner_turns, peer_turns, last_seq, last_finish,
     contexts, admissions, terminals, acks, open_present, reserved) = WINDOW_HEADER.unpack_from(raw)
    require((boot, gen) == (epoch, generation) and revision == 2 * observed and open_present == 1
            and reserved == 0 and 0 <= closed <= WINDOW_CAPACITY
            and (omitted == 0 or closed == WINDOW_CAPACITY),
            "unsealed B3 whole-window witness")
    require(errors == 0 and owner_turns + peer_turns == observed and last_seq >= observed,
            "B3 whole-window observation failed")
    captured = list(WINDOW_ROW.iter_unpack(raw[WINDOW_HEADER.size:]))
    require(not any(any(row) for row in captured[closed:WINDOW_CAPACITY]),
            "unwritten whole-window rows are not zero")
    windows = captured[:closed] + captured[-1:]
    require(all(left[0] < right[0] for left, right in zip(windows, windows[1:]))
            and windows[-1][0] * WINDOW_NS <= last_finish <= (windows[-1][0] + 1) * WINDOW_NS,
            "window indices or paused window disagree")
    if omitted:
        require(omitted <= windows[-1][0] - windows[-2][0] - 1,
                "whole-window omission count exceeds elapsed uncaptured intervals")
    core_limit = sum(limits)
    prior_seq = 0
    counts, read_counts, peaks = [0, 0], [0] * 4, [0] * 3
    read_coverage = []
    samples = []
    prefix_window, prefix_sequence = end_prefix
    for i, row in enumerate(windows):
        index, first, last, a, b, paid_a, paid_b, carry_a, carry_b, held_a, held_b, held_core, *rest = row
        work, straddled = rest[:4], rest[4]
        require((a + b > 0 and prior_seq < first <= last <= last_seq and a + b <= last - first + 1)
                or (a == b == first == last == 0),
                "inconsistent whole-window scheduler turns")
        if last:
            prior_seq = last
        require(0 <= carry_a <= paid_a <= limits[0] and 0 <= carry_b <= paid_b <= limits[1]
                and paid_a + paid_b <= core_limit,
                "B3 whole-window charge exceeds its limit")
        require(held_a <= limits[0] and held_b <= limits[1] and held_core <= core_limit
                and paid_a <= max(held_a, carry_a) and paid_b <= max(held_b, carry_b)
                and max(held_a, held_b) <= held_core
                and paid_a + paid_b <= max(held_core, carry_a + carry_b),
                "B3 whole-window reservation projection exceeds its limit")
        require(work[1] + work[2] <= a and work[0] + work[3] <= b and straddled <= sum(work),
                "whole-window file-operation count exceeds its role turns")
        if index in prefix:
            projection = row[3:12]
            exact = index < prefix_window or (index == prefix_window and last == prefix_sequence)
            require(projection == prefix[index] if exact
                    else all(full >= exact for full, exact in zip(projection, prefix[index])),
                    "whole-window sums disagree with exact per-turn prefix")
        counts = [x + y for x, y in zip(counts, (a, b))]
        read_counts = [x + y for x, y in zip(read_counts, work)]
        peaks = [max(x, y) for x, y in zip(peaks, (paid_a, paid_b, paid_a + paid_b))]
        if i < closed:
            samples.append({"window": index, "role_and_peer_turns": [a, b],
                            "role_and_peer_charged_ns": [paid_a, paid_b],
                            "role_and_peer_carried_ns": [carry_a, carry_b],
                            "protected_reads_completed": work[2], "client_read_acks": work[3],
                            "straddled_file_operations": straddled})
        # Exclude initial and open rows left at the capture boundary. Both
        # actors must have actual service, including a completed and ACKed
        # protected READ contained inside the same aligned grant window.
        if 0 < i < closed and a and b and work[2] and work[3] and straddled == 0:
            read_coverage.append(index)
    require(len(read_coverage) >= read_windows, "insufficient whole windows with authorized READ work")
    total_reads = [contexts, admissions, terminals, acks]
    if custody is not None:
        require(tuple(total_reads) == tuple(custody), "window records disagree with read custody")
    if omitted:
        require(all(x <= y for x, y in zip(counts + read_counts,
                                            [owner_turns, peer_turns] + total_reads)),
                "captured windows exceed lifetime observation")
    else:
        require(counts == [owner_turns, peer_turns] and read_counts == total_reads
                and prior_seq == last_seq, "whole-window witness lost a settlement")
    require(all(any(row[0] == key for row in windows)
                or omitted and windows[-2][0] < key < windows[-1][0] for key in prefix),
            "whole-window witness lost a per-turn prefix interval")
    return {"closed_window_count": closed, "closed_windows_omitted": omitted,
            "open_window": windows[-1][0], "authorized_read_windows": read_coverage,
            "closed_window_samples": samples,
            "lifetime_settled_turns": [owner_turns, peer_turns],
            "observed_file_operations": total_reads,
            "peak_observed_owner_ns": peaks[0], "peak_observed_peer_ns": peaks[1],
            "peak_observed_core_ns": peaks[2]}


def verify_file_owner_budget(qmp, elf, output, epoch, generation, catalog, read_windows=0, custody=None):
    grant = (catalog / "file-owner.bin").read_bytes()
    require(len(grant) == 24 and grant[:8] == b"CYXFSV01", "missing signed FILE_SERVICE budget input")
    owner_limit, = struct.unpack_from("<Q", grant, 16)
    witness = symbol(elf, "V020_G1_FILE_OWNER_BUDGET")
    try:
        totals = symbol(elf, "V020_G1_FILE_OWNER_WINDOWS")
    except ValueError as error:
        if read_windows or str(error) != "missing symbol V020_G1_FILE_OWNER_WINDOWS":
            raise
        windows = None
    else:
        for _ in range(4):
            windows = dump(qmp, output / "file-owner-windows.bin", totals["pa"], totals["size"])
            if struct.unpack_from("<Q", windows)[0] % 2 == 0:
                break
            # The guest was paused while B3 was publishing. Reacquire the
            # complete revision, then read the immutable prefix at that stop.
            qmp.execute("cont")
            time.sleep(0.002)
            qmp.execute("stop")
        else:
            raise ValueError("could not capture a settled whole-window revision")
    raw = dump(qmp, output / "file-owner-budget.bin", witness["pa"], witness["size"])
    report = replay(raw, epoch, generation, owner_limit, windows, read_windows, custody)
    (output / "file-owner-budget.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
