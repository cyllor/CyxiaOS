"""Independent payload codec reference, not a full G1 freeze or case verdict.

Widths and allowed parameter tuples are from V0.19.9 section 8.1-8.15.
This module never imports or calls the Rust action implementation.
"""
import struct
import unittest
from pathlib import Path

VECTORS = Path(__file__).with_name("v0199-action-payload-vectors.tsv")
FORMATS = {3:"<IH",4:"<HH",5:"<HB",8:"<B",10:"<B",11:"<B"}
VALUES = (
    (1,2,4,8),(1,2,4,8),((64,4),(256,16),(1024,32),(4096,64)),
    ((0,4),(2,8),(8,16),(16,32)),((8,1),(32,4),(64,8),(128,16)),
    (1,2,3),(0,50,200,1000),(1,2,4,8),(100,250,500,750),
    (1,4,8,16),(1,2,4,8),(4,8,16,32),(50,100,200,400),(0,1,2),(1,8,32,64),
)
def decode(domain,kind,raw):
    if type(domain) is not int or not 1<=domain<=15 or kind!=1:
        raise ValueError("domain or kind")
    fmt=FORMATS.get(domain,"<H")
    if len(raw)!=struct.calcsize(fmt):
        raise ValueError("width")
    v=struct.unpack(fmt,raw)
    value=v if len(v)>1 else v[0]
    if value not in VALUES[domain-1]:
        raise ValueError("tier")
    return v

class ActionVectors(unittest.TestCase):
    def test_complete_apply_wires_are_independent_little_endian_frames(self):
        rows=[]
        source=VECTORS.with_name("v0199-apply-wire-vectors.tsv")
        for line in source.read_text(encoding="ascii").splitlines():
            if line.startswith("#"):continue
            d,t,w,r=line.split("\t")
            domain,tier=int(d),int(t)
            value=VALUES[domain-1][tier]
            params=value if isinstance(value,tuple) else (value,)
            action=struct.pack(FORMATS.get(domain,"<H"),*params)
            work=struct.pack("<IHH3Q4H4Q2I",0x43594157,1,80,1,2,3,tier,domain,1,0,17,5,6,7,len(action),0)
            report=struct.pack("<3Q4H4QiIQ16s",1,2,3,tier,domain,1,0,17,5,6,7,0,len(action),1000,bytes(16))
            self.assertEqual((len(work),len(report)),(80,96))
            self.assertEqual(w,(work+action).hex())
            self.assertEqual(r,(report+action).hex())
            rows.append((domain,tier))
        self.assertEqual(rows,[(d,i) for d,v in enumerate(VALUES,1) for i in range(len(v))])
        self.assertEqual(len(rows),58)
    def test_literal_reference_and_rejections(self):
        rows=[]
        for line in VECTORS.read_text(encoding="ascii").splitlines():
            if line.startswith("#"):continue
            d,t,params,wire=line.split("\t")
            domain,tier=int(d),int(t)
            values=tuple(map(int,params.split(",")))
            raw=bytes.fromhex(wire)
            self.assertEqual(raw.hex(),wire)
            self.assertEqual(decode(domain,1,raw),values)
            expected=VALUES[domain-1][tier]
            self.assertEqual(values,expected if isinstance(expected,tuple) else (expected,))
            self.assertEqual(raw,struct.pack(FORMATS.get(domain,"<H"),*values))
            for kind,payload in ((2,raw),(1,raw[:-1]),(1,raw+b"\0")):
                with self.assertRaises(ValueError):decode(domain,kind,payload)
            rows.append((domain,tier))
        self.assertEqual(rows,[(d,i) for d,v in enumerate(VALUES,1) for i in range(len(v))])
        self.assertEqual(len(rows),58)
        for d,payload in ((3,bytes.fromhex("400000001000")),(4,bytes.fromhex("02001000")),(5,bytes.fromhex("200008")),(6,b"\0\0"),(16,b"\1\0")):
            with self.assertRaises(ValueError):decode(d,1,payload)

if __name__=="__main__":unittest.main()
