"""Real durable-fsync contention using QMP throttling of the actual data disk.

The throttle delays device completion, never acknowledges or replaces I/O.
Guest gates open only after the corresponding observable checkpoint/retry.
These checks require the normal source-bound os_smoke producer and a dedicated
data disk. Reboot persistence is separately checked by the probe's verify mode.
"""
import json
import re
import time

import x86_64 as pc


def checks(console, qmp, output):
    from os_smoke import boot_user_capacity, object_snapshot, reclaimed_probe, reclaimed_processes
    baseline = object_snapshot(console)
    pc.require(baseline['live'] == baseline['references'] == 0,
               'fsync contention starts with live descriptions')
    transcript = []

    def throttle(rate):
        arguments = dict(device='osdisk', bps=0, bps_rd=0, bps_wr=rate,
                         iops=0, iops_rd=0, iops_wr=0)
        response = qmp.execute('block_set_io_throttle', arguments)
        transcript.append(dict(command='block_set_io_throttle', arguments=arguments,
                               response=response, elapsed=time.monotonic() - started))
        (output / 'fsync-throttle.json').write_text(json.dumps(transcript, indent=2) + '\n')

    started = time.monotonic()

    # Run the killed instance first: it intentionally leaves the late file
    # empty. The later successful concurrent case rewrites and persists both
    # files, so reboot verification cannot be masked by this partial workload.
    try:
        throttle(1)
        kill_start = console.command('posix exec fsync-concurrent')
        killed_pid = console.until(rb'ELF pid=(\d+) started;', kill_start).group(1)
        console.until(rb'FSYNC_CONCURRENT_PROBE WAIT FIRST mode=concurrent ', kill_start)
        killed_generation = int(console.until(
            rb'STORAGE_CHECKPOINT_BEGIN generation=(\d+) ', kill_start).group(1))
        pending_pattern = rb'STORAGE_DURABLE generation=' + str(killed_generation).encode() + rb'\b'
        pc.require(re.search(pending_pattern, console.raw[kill_start:]) is None,
                   'killed fsync was already durable')
        console.command('posix kill ' + killed_pid.decode(),
                        [rb'pid=' + killed_pid + rb' killed; pages reclaimed'])
        killed_process, = reclaimed_processes(
            console, [killed_pid], state='Killed', code=137, **boot_user_capacity(console))
        pc.require(object_snapshot(console) == baseline, 'killed fsync retained descriptions')
        pc.require(re.search(pending_pattern, console.raw[kill_start:]) is None,
                   'commit finished before killed-caller reclamation was observed')
    finally:
        throttle(0)
    completed = console.until(
        rb'STORAGE_DURABLE generation=' + str(killed_generation).encode() +
        rb' [^\r\n]* flushes=(\d+)', kill_start, timeout=60)
    killed_flushes = int(completed.group(1))

    def durable_status():
        at = console.command('storage status')
        row = console.until(rb'STORAGE_STATUS state=Ready generation=(\d+) [^\r\n]*'
                            rb' writes=(\d+) flushes=(\d+)\b', at)
        return tuple(map(int, row.groups()))

    before_reuse = durable_status()
    resumed_at = console.program('posix exec fsync-root', b'FSYNC_PROBE ROOT_DURABLE PASS')
    resumed_pid = console.until(rb'ELF pid=(\d+) started;', resumed_at).group(1)
    resumed = reclaimed_probe(console, resumed_pid, baseline)
    resumed_generation, resumed_writes, resumed_flushes = durable_status()
    pc.require((resumed_generation, resumed_writes, resumed_flushes) == before_reuse
               and resumed_generation == killed_generation and resumed_flushes == killed_flushes,
               "unchanged root fsync did not reuse the killed caller's durable image")
    killed = dict(pid=int(killed_pid), process=killed_process,
                  generation=killed_generation, flushes=killed_flushes,
                  reclaimed_while_commit_pending=True, commit_survived_process_kill=True,
                  subsequent_fsync=resumed, subsequent_generation=resumed_generation,
                  subsequent_writes=resumed_writes, subsequent_flushes=resumed_flushes)

    results = []
    for mode in ('concurrent', 'interrupt', 'reuse', 'admitted-interrupt'):
        try:
            throttle(1)
            command = {'concurrent': 'fsync-concurrent', 'interrupt': 'fsync-interrupt',
                       'reuse': 'fsync-reuse',
                       'admitted-interrupt': 'fsync-admitted-interrupt'}[mode]
            start = console.command('posix exec ' + command)
            pid = console.until(rb'ELF pid=(\d+) started;', start).group(1)
            first = console.until(rb'FSYNC_CONCURRENT_PROBE WAIT FIRST mode=' +
                                  mode.encode() + rb' gate=([^\r\n]+)', start)
            begin = console.until(rb'STORAGE_CHECKPOINT_BEGIN generation=(\d+) ', start)
            generation = int(begin.group(1))

            def require_pending():
                pc.require(re.search(rb'STORAGE_DURABLE generation=' +
                                     str(generation).encode() + rb'\b',
                                     console.raw[start:]) is None,
                           'first fsync completed before contention gate')

            require_pending()
            console.command('touch ' + first.group(1).decode())
            late = console.until(rb'FSYNC_CONCURRENT_PROBE LATE_WRITE mode=' + mode.encode(), start)
            pc.require(begin.start() < late.start(), 'late write preceded the old snapshot')
            before = after = None
            if mode == 'admitted-interrupt':
                console.until(rb'FSYNC_CONCURRENT_PROBE ADMITTED_INTERRUPTED PASS', start)
                release = console.until(rb'FSYNC_CONCURRENT_PROBE READY RELEASE mode=' +
                                        mode.encode() + rb' gate=([^\r\n]+)', start)
            else:
                second = console.until(rb'FSYNC_CONCURRENT_PROBE WAIT SECOND mode=' +
                                       mode.encode() + rb' gate=([^\r\n]+)', start)

                def waits():
                    at = console.command('posix status')
                    row = console.until(rb'UserStatus \{ pid: ' + pid + rb',[^\r\n]+', at).group(0)
                    pc.require(b'state: Running' in row or b'state: Waiting' in row,
                               'fsync process ended before retry observation')
                    value = re.search(rb'\bwaits: (\d+)', row)
                    pc.require(value is not None, 'missing syscall wait counter')
                    return int(value.group(1))

                before = waits()
                deadline = time.monotonic() + 5
                while True:
                    after = waits()
                    if after > before:
                        break
                    pc.require(time.monotonic() < deadline, 'busy fsync never retried')
                    time.sleep(.01)
                require_pending()
                console.command('touch ' + second.group(1).decode())
                if mode == 'interrupt':
                    console.until(rb'FSYNC_CONCURRENT_PROBE INTERRUPTED PASS', start)
                elif mode == 'reuse':
                    console.until(rb'FSYNC_CONCURRENT_PROBE STALE_DESCRIPTOR PASS', start)
                console.until(rb'FSYNC_CONCURRENT_PROBE READY RELEASE mode=' + mode.encode(), start)
            require_pending()
        finally:
            throttle(0)
        if mode == 'admitted-interrupt':
            console.command('touch ' + release.group(1).decode())
        console.until(rb'FSYNC_CONCURRENT_PROBE PASS mode=' + mode.encode(), start, timeout=60)
        row = reclaimed_probe(console, pid, baseline)
        raw = bytes(console.raw[start:])
        begins = [int(value) for value in re.findall(rb'STORAGE_CHECKPOINT_BEGIN generation=(\d+) ', raw)]
        durable = [(int(value), int(flushes)) for value, flushes in re.findall(
            rb'STORAGE_DURABLE generation=(\d+) [^\r\n]* flushes=(\d+)', raw)]
        pc.require(len(begins) == 2 and begins[0] == generation and begins[1] > generation,
                   'second caller did not obtain its own fresh snapshot')
        pc.require([value for value, _ in durable] == begins and
                   durable[1][1] - durable[0][1] == 2,
                   'both generations did not complete real device FLUSH operations')
        row.update(mode=mode, waits_before=before, waits_after=after,
                   snapshot_generations=begins, durable_generations=durable,
                   late_write_after_first_snapshot=True)
        results.append(row)
    return dict(cases=results, killed_admitted_caller=killed, throttle_transcript=transcript,
                persistence_requires_separate_reboot=True)
