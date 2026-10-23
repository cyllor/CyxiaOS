#!/usr/bin/env python3
"""Link a real GLib spawn/child-watch probe against the opt-in target sysroot."""
import fcntl
import json
from pathlib import Path
import shlex
import shutil
import subprocess
from build_sysroot import Builder, DEFAULT_OUTPUT, ROOT, digest, inspect_elf, toolchain


def main():
    out = DEFAULT_OUTPUT
    with (out / '.build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        foundation = json.loads((out / 'openbox-foundation-report.json').read_text())
        if not foundation.get('cyxia_spawn'):
            raise RuntimeError('Build foundation --only glib --cyxia-spawn first')
        builder = Builder(out, toolchain(), 8)
        builder.target_environment()
        flags = shlex.split(subprocess.check_output([builder.env['PKG_CONFIG'], '--static', '--cflags',
                            '--libs', 'glib-2.0'], env=builder.env, text=True))
        source = ROOT / 'user/ported/glib_spawn_probe.c'
        temporary = out / 'glib-spawn-probe.elf.tmp'
        builder.run([builder.env['CC'], '-Os', '-g', '-Wall', '-Wextra', '-Werror', '-Wl,--gc-sections',
                     str(source), *flags, '-o', str(temporary)], 'glib-spawn-probe-link.log')
        symbols = out / 'glib-spawn-probe.symbols.elf'
        builder.run([builder.tools['llvm-strip'], '--strip-debug', str(temporary)], 'glib-spawn-probe-strip.log')
        inspected = inspect_elf(temporary)
        shutil.copyfile(temporary, symbols)
        builder.run([builder.tools['llvm-strip'], '--strip-all', str(temporary)], 'glib-spawn-probe-compact.log')
        result = inspect_elf(temporary)
        temporary.replace(out / 'glib-spawn-probe.elf')
        result['file'] = str(out / 'glib-spawn-probe.elf')
        report = {'status': 'cross-built', 'guest_execution': 'not performed', 'executable': result,
                  'symbol_sha256': inspected['sha256'], 'source_sha256': digest(source),
                  'libglib_sha256': digest(out / 'sysroot/usr/lib/libglib-2.0.a'), 'commands': builder.commands}
        path = out / 'glib-spawn-probe-build-report.json'
        path.write_text(json.dumps(report, indent=2) + '\n')
        print(path)


if __name__ == '__main__':
    main()
