"""Drive the real failure-capture callsite; no fixture can enrol native PASS."""
import unittest
from run_v13_boot_recovery import capture_failure
from transport import FrameDecoder


class FailureCapture(unittest.TestCase):
    def test_full_control_records_survive_failure_without_enlarging_small_debug_cap(self):
        class Qmp:
            def execute(self,command,args=None):
                if command=='query-status':return {'status':'paused','running':False}
                if command=='ringbuf-read':return ''
                return {}
        symbols={name:dict(pa=0x41000000+i*0x100000,size=size) for i,(name,size) in
                 enumerate([('boot',512),('control',331776),('runtime',8192),('unified',4096)])}
        saves=[]
        def save(name,pa,size):saves.append((name,pa,size));return bytes(size)
        result=capture_failure(Qmp(),save,symbols,bytes(512),FrameDecoder(),bytearray(),bytearray())
        self.assertIn(('failure-control.bin',symbols['control']['pa'],4096),saves)
        self.assertIn(('failure-control-full.bin',symbols['control']['pa'],331776),saves)
        self.assertNotIn('native_acceptance_status',result)


if __name__=='__main__':unittest.main()
