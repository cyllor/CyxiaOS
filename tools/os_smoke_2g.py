"""Run the existing real OS smoke scenarios with the explicit 2 GiB launcher."""
import argparse
from pathlib import Path
import re

import os_smoke
import os_x86_2g as profile


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scenario', choices=('core', 'native'), default='native')
    args = parser.parse_args()
    os_smoke.os_x86 = profile
    result = os_smoke.capture(args.build, args.output, scenario=args.scenario)
    raw = (args.output / 'serial.raw').read_bytes()
    high = re.search(rb'X86_RAM_2G_OK high_page=([0-9a-f]{16})', raw)
    ram = re.search(rb'RAM_DISCOVERED bytes=(\d+)', raw)
    verified = bool(high and ram and 1 << 30 <= int(high[1], 16) < 2 << 30
                    and 1 << 30 < int(ram[1]) <= 2 << 30)
    result.update(runtime_ram_mib=2048, upper_gib_verified=verified,
                  detected_ram_bytes=int(ram[1]) if ram else None,
                  wrapper_producers=profile.producer_sources(__file__))
    if not verified:
        result.update(status='FAIL', error='Missing real upper-GiB boot verification')
    profile.pc.write_json(args.output / 'summary.json', result)
    print(result['status'], 'ram_mib=2048', 'upper_gib_verified=' + str(verified))
    return int(result['status'] == 'FAIL')


if __name__ == '__main__':
    raise SystemExit(main())
