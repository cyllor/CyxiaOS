"""Launch the real CyxiaOS X11/Openbox integration session in QEMU.

This is the current porting/test desktop. LXDE and broad Linux binary
compatibility are not complete. No upstream download is performed here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
from doctor import ROOT, RUST_BIN, TARGET, env
from check_elf import inspect_elf
from shell import Guest
from verify_x11 import wait, pump
from desktop_session import embedded_programs, wait_window
from desktop_session import windows
from storage import create_disk


def build(profile, wm='openbox', app='x11'):
    directory = ROOT/'artifacts/sysroot/aarch64-musl'
    required = ['probe.elf', 'Xcyxia.elf', wm+'.elf', 'x11-probe.elf',
                'rootfs/usr/share/X11/xkb/cyxia-us.xkm']
    required += (['rootfs/etc/xdg/openbox/rc.xml', 'rootfs/etc/fonts/fonts.conf',
                  'rootfs/usr/share/themes/Cyxia/openbox-3/themerc',
                  'rootfs/usr/share/fonts/Roboto-Regular.ttf'] if wm == 'openbox'
                 else ['rootfs/etc/X11/twm/system.twmrc'])
    if wm == 'openbox': required.append('x11-inspect.elf')
    if app in ('gtk', 'files', 'desktop'):
        if wm != 'openbox':
            raise ValueError('The GTK/file manager profiles embed Openbox; use --wm openbox')
        required.append('gtk-probe.elf' if app == 'gtk' else 'pcmanfm.elf')
    if app == 'desktop':
        required += ['lxpanel.elf', 'cyxia-save.elf', 'cyxia-terminal.elf', 'cyxia-sh.elf',
                     'rootfs/etc/xdg/lxpanel/default/panels/panel']
    missing = [name for name in required if not (directory/name).is_file()]
    if missing:
        raise RuntimeError('Missing target artifacts: '+', '.join(missing)+'. See docs/implementation/x11-desktop-integration.md')
    features = 'graphics,openbox' if wm == 'openbox' else 'graphics,ported'
    if app == 'gtk': features = 'graphics,gtk'
    if app == 'files': features = 'graphics,pcmanfm,large-memory'
    if app == 'desktop': features = 'graphics,lxpanel,large-memory'
    command = [str(RUST_BIN/'cargo'),'build','-p','cyxia-kernel','--target',TARGET,'--features',features]
    if profile == 'release': command.append('--release')
    subprocess.run(command,cwd=ROOT,env=env(),check=True,timeout=180)
    elf = ROOT/'target'/TARGET/('release' if profile=='release' else 'debug')/'cyxia-kernel'
    inspect_elf(elf.read_bytes())
    return elf


def run(elf, output, display, wm='openbox', app='desktop', disk=None):
    application = {'x11': 'x11-demo', 'gtk': 'gtk-probe', 'files': 'pcmanfm',
                   'desktop': 'pcmanfm-desktop'}[app]
    programs = ['Xcyxia', wm, {'x11': 'x11-probe', 'gtk': 'gtk-probe'}.get(app, 'pcmanfm')]
    if app == 'desktop': programs += ['lxpanel', 'cyxia-save', 'cyxia-terminal', 'cyxia-sh']
    if wm == 'openbox': programs.append('x11-inspect')
    identities = embedded_programs(elf, programs)
    if app == 'desktop' and disk is None:
        disk = ROOT/'artifacts/cyxia-data.raw'
        if not disk.exists(): create_disk(disk)
    output.mkdir(parents=True, exist_ok=True)
    (output/'desktop-session.json').write_text(json.dumps(dict(
        kernel_sha256=hashlib.sha256(elf.read_bytes()).hexdigest(), programs=identities,
        disk=str(disk.resolve()) if disk else None), indent=2))
    with Guest(elf, output, graphics=True, rng=True, display=display, disk=disk) as guest:
        print(guest.until(b'cyxia:/> ').decode(errors='replace'), end='', flush=True)
        if app == 'desktop':
            guest.command('mkdir /Desktop')
            if b'NotFound' in guest.command('stat /Desktop/Welcome.txt'):
                guest.command('write /Desktop/Welcome.txt Welcome to CyxiaOS. Use the bottom-left menu to open Files or Terminal. Choose Save Files after editing to keep files across restarts.')
        start = len(guest.text)
        guest.command('posix exec xorg')
        wait(guest,start,b'CYXIA_XORG_READY 1024x768 input=keyboard,mouse')
        guest.command('posix exec '+wm)
        if wm == 'openbox': wait_window(guest)
        else: pump(guest, .8)
        start = len(guest.text)
        guest.command('posix exec '+application)
        if app in ('files', 'desktop'): wait_window(guest, 'Pcmanfm')
        else: wait(guest,start,b'GTK_PROBE WINDOW' if app == 'gtk' else b'X11_PROBE WINDOW', 30)
        if app == 'desktop':
            guest.command('posix exec lxpanel')
            wait_window(guest, 'lxpanel')
            guest.command('posix exec pcmanfm-home')
            deadline = time.monotonic()+30
            while time.monotonic() < deadline:
                clients = windows(guest) or []
                if any(w['class'] == 'Pcmanfm' and w['width'] < 1024 for w in clients): break
                pump(guest, .25)
            else: raise TimeoutError('PCManFM home window did not open')
            # Preserve the actual guest startup state for manual-session support.
            # The host only asks QEMU to capture its framebuffer.
            pump(guest, 1.5)
            guest.qmp.execute('screendump', {'filename': str(output/'desktop.ppm')})
            (output/'desktop-ready.json').write_text(json.dumps(dict(
                windows=clients, ready_at=time.time(),
                processes=guest.command('posix list').decode(errors='replace')), indent=2))
        print(f'\nCyxiaOS X11/{wm} is running. Drag the title bar; click inside and type.\n'
              'Alt+F4 closes the focused window.\n'
              'Use the bottom-left menu; Save Files commits current files to the data disk.\n'
              'Ctrl+C in this terminal stops this VM.',flush=True)
        while True:
            try:
                data = guest.poll()
            except RuntimeError as error:
                if str(error) not in ('UART disconnected', 'QEMU exited'):
                    raise
                # Cocoa window close disconnects UART just before process exit.
                # Treat only a confirmed clean QEMU exit as normal shutdown.
                try:
                    closed_cleanly = guest.proc.wait(timeout=.5) == 0
                except subprocess.TimeoutExpired:
                    raise error
                if not closed_cleanly:
                    raise
                print('CyxiaOS VM closed.', flush=True)
                break
            print(data.decode(errors='replace'),end='',flush=True)
            time.sleep(.01)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=['dev','release'],default='release')
    parser.add_argument('--display',choices=['cocoa','none'],default='cocoa')
    parser.add_argument('--wm',choices=['openbox','twm'],default='openbox')
    parser.add_argument('--app',choices=['x11','gtk','files','desktop'],default='desktop')
    parser.add_argument('--disk',type=Path,help='Existing dedicated CyxiaOS raw data disk')
    parser.add_argument('--elf',type=Path,help='Use an already built kernel')
    args=parser.parse_args()
    output=ROOT/'artifacts'/f'desktop-manual-{time.time_ns()}'
    try: run(args.elf.resolve() if args.elf else build(args.profile,args.wm,args.app), output,args.display,args.wm,args.app,args.disk)
    except KeyboardInterrupt: pass
