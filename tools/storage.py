"""Create an empty dedicated CyxiaOS raw disk without overwriting existing data."""
import argparse
from pathlib import Path
from doctor import ROOT


def create_disk(path):
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.truncate(2*1024*1024)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('disk', nargs='?', type=Path, default=ROOT/'artifacts/cyxia-data.raw')
    args = parser.parse_args()
    print(create_disk(args.disk))
