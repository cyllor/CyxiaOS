"""Bounded completed-WRITE EAGAIN records; synthetic oracle units, not native evidence."""
import hashlib
import importlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))

class WriteRetryOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier=importlib.import_module('verify_v13_a10')
        fixture=importlib.import_module('test_v13_a10').ProtectedFileReplies()
        fixture.setUp()
        cls.original,cls.terminal,cls.oracle,cls.binding=fixture.complete_cache_eviction()

    def stream(self,insertions=None,mutate=None):
        source=self.original
        rows=[bytearray(source[n:n+768]) for n in range(512,len(source),768)]
        result=[]
        for index,row in enumerate(rows):
            for _ in range((insertions or {}).get(index,0)):
                failed=bytearray(row)
                struct.pack_into('<Q',failed,80,0)
                failed[96:128]=hashlib.sha256(b'').digest()
                struct.pack_into('<q5Q',failed,208,-11,0,0,0,0,0)
                result.append(failed)
            result.append(row)
        for index,row in enumerate(result,1):
            struct.pack_into('<2Q',row,8,index,index*2_100_000_000)
            struct.pack_into('<Q',row,144,index)
        if mutate:mutate(result)
        head=bytearray(source[:512]);struct.pack_into('<Q',head,24,len(result))
        terminal=bytearray(self.terminal)
        struct.pack_into('<Q',terminal,288,(len(result)+1)*2_100_000_000)
        return bytes(head+b''.join(result)),bytes(terminal)

    def verify(self,stream):
        raw,terminal=stream
        return self.verifier.verify_filesystem(raw,self.binding,terminal,self.oracle,bytes(256))

    def test_no_retry_keeps_the_exact_existing_success_obligations(self):
        result=self.verify(self.stream())
        self.assertTrue(result['cache_eviction_verified'])
        self.assertEqual(result['completed_write_retries'],0)
        self.assertEqual(result['pressure_pages'],4096)
        self.assertFalse(result['A10_complete'])

    def test_one_completed_write_retry_preserves_same_chunk_then_success(self):
        result=self.verify(self.stream({7:1}))
        self.assertTrue(result['cache_eviction_verified'])
        self.assertEqual(result['completed_write_retries'],1)

    def test_retry_limit_is_global_across_both_files(self):
        self.assertEqual(self.verify(self.stream({7:45,139:45}))['completed_write_retries'],90)
        with self.assertRaises(ValueError):self.verify(self.stream({7:45,139:46}))

    def test_failed_reply_original_order_shape_and_zero_effect_guards(self):
        def u64(offset,value):return lambda rows:struct.pack_into('<Q',rows[7],offset,value)
        cases={
            'other_errno':lambda r:struct.pack_into('<q',r[7],208,-5),
            'wrong_operation':lambda r:struct.pack_into('<H',r[7],140,5),
            'wrong_owner':u64(32,999),
            'wrong_handle':u64(168,999),
            'wrong_offset':u64(184,65536),
            'zero_address':u64(192,0),
            'wrong_length':lambda r:struct.pack_into('<I',r[7],200,65535),
            'nonzero_count':u64(216,1),
            'claimed_object':u64(224,6),
            'claimed_write_seq':u64(240,1),
            'claimed_durable_seq':u64(248,1),
            'nonempty_hash':lambda r:r[7].__setitem__(slice(96,128),b'x'*32),
            'transferred_data':u64(80,1),
            'duplicate_request':lambda r:struct.pack_into('<Q',r[8],144,8),
            'changed_retry_address':lambda r:struct.pack_into('<Q',r[8],192,0x70000),
            'changed_retry_handle':lambda r:struct.pack_into('<Q',r[8],168,999),
            'changed_retry_offset':lambda r:struct.pack_into('<Q',r[8],184,65536),
            'too_fast_retry':lambda r:struct.pack_into('<Q',r[8],16,8*2_100_000_000+1),
        }
        for label,mutation in cases.items():
            with self.subTest(label=label),self.assertRaises(ValueError):
                self.verify(self.stream({7:1},mutation))
        for at in (0,6,135,136,270,271):
            with self.subTest(failed_at=at),self.assertRaises(ValueError):
                self.verify(self.stream({at:1}))

    def test_each_repeated_failure_remains_the_same_chunk_and_cadence(self):
        self.assertEqual(self.verify(self.stream({7:2}))['completed_write_retries'],2)
        for change in [lambda r:struct.pack_into('<Q',r[8],184,65536),
                       lambda r:struct.pack_into('<Q',r[8],16,8*2_100_000_000+1)]:
            with self.assertRaises(ValueError):self.verify(self.stream({7:2},change))

    def test_dangling_retry_never_certifies_a_completion(self):
        def truncate(rows):del rows[8:]
        with self.assertRaises(ValueError):self.verify(self.stream({7:1},truncate))

if __name__=='__main__':unittest.main()
