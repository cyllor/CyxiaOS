"""Real multi-process anonymous physical-pool pressure and reuse checks."""
import re
import x86_64 as pc
from verify_ported import parse_processes


def snapshot(console):
    start = console.command('ai system')
    console.until(rb'AI_SYSTEM_END\r?\n', start)
    match = console.until(rb'ANON_POOL capacity=(\d+) free=(\d+) used=(\d+) peak=(\d+) virtual_pages=(\d+)', start)
    row = dict(zip(('capacity', 'free', 'used', 'peak', 'virtual_pages'), map(int, match.groups())))
    pc.require(row['capacity'] == 65536 and row['virtual_pages'] == 16384 and
               row['free'] + row['used'] == row['capacity'], 'physical-pool accounting invalid')
    # Full-os attaches the actual PoolBridge. Require its receipt, not just
    # the legacy allocator counters. Quarantine is not synonymous with free.
    ledger = console.until(rb'ANON_POOL_LEDGER free=(\d+) reserved=(\d+) allocated=(\d+) quarantined=(\d+) permanent=(\d+) conservation=([A-Z]+)\r?\n', start)
    row['ledger'] = dict(zip(('free', 'reserved', 'allocated', 'quarantined', 'permanent'),
                             map(int, ledger.groups()[:5])))
    inv = row['ledger']
    pc.require(ledger.group(6) == b'OK' and
               inv['free'] + inv['reserved'] + inv['allocated'] + inv['quarantined'] == row['capacity'] and
               inv['permanent'] + row['capacity'] == 65536 and
               inv['allocated'] <= row['used'] <= inv['allocated'] + inv['quarantined'],
               'FrameMeta ledger conservation invalid')
    accounting = console.until(rb'AI_DOMAIN name=anonymous ([^\r\n]+)', start).group(1)
    row['anonymous'] = {key.decode(): int(value) for key, value in
                        re.findall(rb'(\w+)=(\d+)', accounting)}
    pc.require(row['anonymous']['grant_units'] - row['anonymous']['release_units'] == row['used'],
               'anonymous grants disagree with owned physical pages')
    return row


def checks(console):
    from os_smoke import object_snapshot, reclaimed_probe
    before = object_snapshot(console)
    pc.require(before['live'] == before['references'] == 0, 'pool probe begins with live objects')
    start = console.command('posix exec heap-pool-probe')
    pid = console.until(rb'ELF pid=(\d+) started;', start).group(1)
    console.until(rb'HEAP_POOL_PROBE PASS', start, timeout=60)
    single = reclaimed_probe(console, pid, before)
    pc.require(single['process']['heap_peak'] > 10240 and single['process']['thread_peak'] >= 4,
               '40 MiB and concurrent real stacks were not observed')
    initial = snapshot(console)
    pc.require(initial['used'] == 0 and initial['free'] == 65536, 'single-probe physical leak')
    holders = []

    def launch():
        start = console.command('posix exec heap-pool-hold')
        pid = int(console.until(rb'ELF pid=(\d+) started;', start).group(1))
        held = console.until(rb'HEAP_POOL_PROBE HELD pages=\d+ maps=\d+ pid=\d+ exhausted=[01] gate=/tmp/heap-pool-release-\d+\r?\n', start, timeout=60).group(0)
        fields = {k.decode(): int(v) for k, v in re.findall(rb'(pid|pages|maps|exhausted)=(\d+)', held)}
        pc.require(fields.get('pid') == pid and fields.get('pages', 0) > 0, 'holder missing real allocations')
        return fields

    def release(row, kill=False):
        pid = str(row['pid'])
        start = console.command('posix kill ' + pid if kill else 'touch /tmp/heap-pool-release-' + pid)
        if not kill:
            console.until(rb'HEAP_POOL_PROBE PASS mode=hold pid=' + pid.encode() + rb'\b', start, timeout=60)
        console.until(rb'pid=' + pid.encode() + (rb' killed; pages reclaimed' if kill else rb' Exited code=0\b'), start, timeout=60)
        at = console.command('posix list')
        process = parse_processes(bytes(console.raw[at:]))[row['pid']]
        pc.require(process['state'] == ('Killed' if kill else 'Exited') and
                   process['code'] == (137 if kill else 0), 'unexpected holder termination')
        pc.require(process['heap_pages'] == process['heap_allocations'] == process['thread_count'] == 0 and
                   process['heap_free'] == 16384 and process['image_free'] == 16384, 'holder not reclaimed')
        return process

    for _ in range(5): holders.append(launch())
    pc.require(all(row['pages'] == 15360 and row['exhausted'] == 0 for row in holders[:4]),
               'independent owners did not retain 60 MiB each')
    pc.require(holders[4]['pages'] == 4064 and holders[4]['exhausted'] == 1,
               'global capacity refusal was not measured')
    pressure = snapshot(console)
    pc.require(pressure['used'] == 65504 and pressure['free'] == 32, 'global reserve changed')
    exited = [release(holders[0])]
    replacement = launch()
    pc.require(replacement['pages'] == 15360, 'freed physical capacity was not reusable')
    reused = snapshot(console)
    pc.require(reused['used'] == 65504 and reused['free'] == 32, 'replacement accounting differs')
    # Keep the other owners alive: only 32 untouched pages remain. The next
    # 15,360-page holder must receive at least 15,328 of the killed owner's pages,
    # and its every-word zero checks therefore cover actual killed-owner reuse.
    killed = holders[1]
    exited.append(release(killed, kill=True))
    after_kill = snapshot(console)
    pc.require(after_kill['used'] == reused['used'] - killed['pages'], 'killed owner retained physical pages')
    after_kill_reuse = launch()
    pc.require(after_kill_reuse['pages'] == 15360, 'killed owner capacity not reusable')
    kill_reused = snapshot(console)
    pc.require(kill_reused['used'] == 65504 and kill_reused['free'] == 32,
               'killed-owner replacement accounting differs')
    minimum_killed_pages_reused = after_kill_reuse['pages'] - reused['free']
    pc.require(minimum_killed_pages_reused == 15328, 'killed-owner physical reuse not forced')
    for row in holders[2:] + [replacement, after_kill_reuse]: exited.append(release(row))
    final = snapshot(console)
    pc.require(final['free'] == 65536 and final['used'] == 0, 'global physical leak')
    pc.require(final['anonymous']['granted'] == final['anonymous']['released'], 'anonymous grant leak')
    pc.require(object_snapshot(console) == before, 'pool probe leaked open descriptions')
    return dict(single=single, holders=holders, replacement=replacement, exited=exited,
                initial=initial, pressure=pressure, reused=reused, killed=killed,
                after_kill=after_kill, after_kill_reuse=after_kill_reuse, kill_reused=kill_reused,
                minimum_killed_pages_reused=minimum_killed_pages_reused, final=final)
