"""Compile the actual production region snapshot helper, with geometry fixtures."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RegionForwarding(unittest.TestCase):
    def test_offsets_subtraction_order_and_default_vs_empty(self):
        helper = (ROOT / 'ports/cosmic/native-popup-input-v1/input-region.rs').read_text()
        prelude = '''
#[derive(Clone, Copy)] enum RectangleKind { Add, Subtract }
struct Point { x:i32, y:i32 } struct Size { w:i32, h:i32 }
struct Rectangle { loc:Point, size:Size }
pub struct RegionAttributes { rects:Vec<(RectangleKind, Rectangle)> }
'''
        checks = '''
fn rect(x:i32,y:i32,w:i32,h:i32)->Rectangle { Rectangle {loc:Point{x,y},size:Size{w,h}} }
fn main() {
 assert_eq!(input_region_snapshot(None), None);
 assert_eq!(input_region_snapshot(Some(&RegionAttributes{rects:vec![]})), Some(vec![]));
 let before=RegionAttributes {rects:vec![(RectangleKind::Add,rect(12,-8,1,1))]};
 let after=RegionAttributes {rects:vec![(RectangleKind::Add,rect(12,-8,360,384)),
    (RectangleKind::Subtract,rect(20,40,10,12)),(RectangleKind::Add,rect(-4,7,2,3))]};
 assert_eq!(input_region_snapshot(Some(&before)),Some(vec![(true,12,-8,1,1)]));
 assert_eq!(input_region_snapshot(Some(&after)),Some(vec![(true,12,-8,360,384),
    (false,20,40,10,12),(true,-4,7,2,3)]));
 assert_ne!(input_region_snapshot(Some(&before)),input_region_snapshot(Some(&after)));
}
'''
        with tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
            source = Path(directory)/'region.rs'; binary=Path(directory)/'region'
            source.write_text(prelude+helper+checks)
            subprocess.run(['rustc','--edition=2024',str(source),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)


if __name__ == '__main__': unittest.main()
