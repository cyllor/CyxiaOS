"""Negative raw contract fixtures are never native execution evidence."""
import copy
import struct
import unittest

from verify_v15_registers import (WORDS, MAGIC, CONFIG_MAGIC, ROW, EVENT, check,
                                  make_config, expected_seed, observe_platform_query,
                                  require_platform_queries, validate_platform_dtb)


def fixture():
    config = make_config(bytes(range(16)), bytes([1])*32, bytes([2])*32, bytes([3])*32)
    identity = struct.unpack('<16Q', config)
    w = [0]*WORDS
    w[:8] = [MAGIC, 1, 2, 15, 6, 0, 1000000000, 1]
    w[8:24] = identity
    for j in range(6):
        cpu, local = j//2+1, j%2
        b = 64+j*ROW
        seed = expected_seed(identity, j)
        w[b:b+12] = [cpu, local, seed, 0x41000000+j*4096, 4, 4, 1, 1, 30, 0, 8, 0]
        for k in range(8):
            e = b+32+k*EVENT
            c = [0]*104
            c[19:30] = [seed+r for r in range(19,30)]
            c[31:38] = [0x10100, 0, 0x31000, 0 if k<4 else (0x15<<26)|0x606, 0, 9 if k<4 else 8, seed]
            c[38:102] = [v for r in range(32) for v in (seed+128+r, seed+256+r)]
            c[102:104] = [(seed&3)<<22, (seed%31)+1]
            turn = 2*k+local+1
            w[e:e+8] = [turn, 100+turn*10, 105+turn*10, 1 if k<4 else 2, j, 1, turn-1, 1 if k<4 else 0]
            w[e+8:e+112] = c
    return w, config


class Contract(unittest.TestCase):
    def test_platform_queries_are_required_exactly_once(self):
        platform={'cpus':[{'cpu-index':i} for i in range(4)],'memory':{'base-memory':1024**3}}
        seen=set()
        with self.assertRaises(ValueError): require_platform_queries(seen)
        observe_platform_query('query-cpus-fast',platform['cpus'],{},platform,seen,'preboot')
        with self.assertRaises(ValueError): require_platform_queries(seen)
        with self.assertRaises(ValueError):
            observe_platform_query('query-cpus-fast',platform['cpus'],{},platform,seen,'preboot')
        observe_platform_query('query-memory-size-summary',platform['memory'],{},platform,seen,'preboot')
        require_platform_queries(seen)
        with self.assertRaises(ValueError):
            observe_platform_query('query-cpus-fast',platform['cpus'],{},platform,set(),'running')

    def test_header_only_dtb_is_not_a_four_cpu_platform(self):
        fake=struct.pack('>10I',0xd00dfeed,40,40,40,40,17,16,0,0,0)
        with self.assertRaises(ValueError): validate_platform_dtb(fake)

    def test_shape_is_not_native_pass(self):
        w,c = fixture()
        r = check(struct.pack('<%dQ'%WORDS,*w), c)
        self.assertEqual(r['native_acceptance_status'], 'NOT_RUN')
        self.assertEqual(r['status'], 'STRUCTURE_VALID')

    def test_each_register_and_pattern_half_is_required(self):
        w,c = fixture()
        for offset in list(range(19,30))+[37]+list(range(38,104)):
            x=copy.copy(w); x[64+32+8+offset]^=1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(struct.pack('<%dQ'%WORDS,*x),c)

    def test_no_zero_fresh_claim_or_fault_as_svc(self):
        w,c = fixture()
        for at,value in [(64+6,0),(64+4,0),(64+32+8+36,8),
                         (64+32+4*EVENT+8+34,0x24<<26), (64+32+6,999)]:
            x=copy.copy(w);x[at]=value
            with self.subTest(at=at), self.assertRaises(ValueError):
                check(struct.pack('<%dQ'%WORDS,*x),c)

    def test_identity_roots_and_reserved_are_strict(self):
        w,c=fixture()
        for at,value in [(8,0),(64+ROW+3,w[64+3]),(63,1),(64+31,1),(64+32+7,0)]:
            x=copy.copy(w);x[at]=value
            with self.subTest(at=at),self.assertRaises(ValueError):
                check(struct.pack('<%dQ'%WORDS,*x),c)


if __name__=='__main__': unittest.main()
