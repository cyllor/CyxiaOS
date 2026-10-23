"""Launch the VirtIO diagnostic and optional EL0 repaint test, not LXDE."""
import argparse
from pathlib import Path
import time
from doctor import ROOT
from shell import Guest
from verify_graphics import build

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--display', choices=['cocoa', 'none'], default='cocoa')
    parser.add_argument('--profile', choices=['dev', 'release'], default='dev')
    parser.add_argument('--paint', action='store_true', help='Run the real EL0 two-frame repaint test after boot')
    args = parser.parse_args()
    output = ROOT / 'artifacts' / f'graphics-manual-{time.time_ns()}'
    elf = build(args.profile)
    try:
        with Guest(elf, output, graphics=True, display=args.display) as guest:
            print('CyxiaOS D1 graphics diagnostic. Ctrl+C stops this VM. LXDE is not implemented.')
            if args.paint:
                print(guest.until(b'cyxia:/> ').decode('utf-8', errors='replace'), end='', flush=True)
                print(guest.command('posix spawn paint').decode('utf-8', errors='replace'), end='', flush=True)
            while True:
                print(guest.poll().decode('utf-8', errors='replace'), end='', flush=True)
                time.sleep(.01)
    except KeyboardInterrupt:
        pass
