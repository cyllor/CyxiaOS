"""Optional DOMAIN_CONTROL record extension must not affect unrelated bank layouts."""
import struct
import unittest
from verify_domains import parse_control,active_control_records,CONTROL_MAGIC,CONTROL_WORDS


class DomainDigestCompatibility(unittest.TestCase):
    def test_nonzero_optional_full_output_hash_is_not_reserved_in_old_domain_reader(self):
        w=[0]*CONTROL_WORDS;w[:4]=[CONTROL_MAGIC,1,7,(1<<18)-1];w[12:14]=[64,640]
        b=512;w[b:b+8]=[1,1,1,1,1,1,1,7]
        w[b+14]=1;w[b+30]=1;w[b+639]=2
        pack=lambda:struct.pack('<%dQ'%len(w),*w)
        before=parse_control(pack());rows=active_control_records(pack())
        w[b+21:b+25]=[0x111,0x222,0x333,0x444]
        self.assertEqual(parse_control(pack()),before)
        self.assertEqual(active_control_records(pack()),rows)


if __name__=='__main__':unittest.main()
