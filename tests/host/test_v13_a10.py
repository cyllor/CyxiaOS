import hashlib
import importlib
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))


class ProtectedFileReplies(unittest.TestCase):
    def setUp(self):
        try:self.verifier=importlib.import_module('verify_v13_a10')
        except ModuleNotFoundError as error:
            if error.name!='verify_v13_a10':raise
            self.fail('protected ordinary-file reply decoder is missing')
        self.binding=dict(nonce='08'*16,uuid='07'*16,image_sha256='04'*32,
                          input_sha256='05'*32,source_sha256='03'*32,boot_epoch=1,mode=1)

    def frame(self,operation,request,*,handle=(0,0),obj=(5,2),seq=0,data=b'',path='',offset=0):
        frame=bytearray(640)
        struct.pack_into('<QHHHHQQQQQQQIHHqQQQQQ',frame,0,
            0x435946494c453031,1,640,operation,3 if operation==2 else 0,
            request,11,9,*handle,offset,0x50000 if data else 0,len(data),len(path),0,
            0,len(data),*obj,seq,seq)
        frame[128:128+len(path)]=path.encode()
        return frame

    def capture(self):
        writer,reader=(100,9),(101,9)
        payload1=bytes([0x11])*4096;payload2=bytes([0x22])*4096
        fixtures=[
            (writer,self.frame(2,1,handle=(1,100),path='/a10/value'),b'',16),
            (writer,self.frame(4,2,handle=(1,100),data=payload1),payload1,16),
            (writer,self.frame(5,3,handle=(1,100),seq=1),b'',20),
            (writer,self.frame(4,4,handle=(1,100),data=payload2),payload2,20),
            (writer,self.frame(5,5,handle=(1,100),seq=2),b'',24),
            (reader,self.frame(2,1,handle=(1,200),path='/a10/value'),b'',24),
            (reader,self.frame(3,2,handle=(1,200),data=payload2),payload2,24),
        ]
        head=bytearray(512)
        struct.pack_into('<7Q',head,0,0x4359584131305452,1,768,len(fixtures),0,1,1)
        head[56:72]=bytes.fromhex(self.binding['nonce']);head[72:88]=bytes.fromhex(self.binding['uuid'])
        struct.pack_into('<4Q',head,88,*writer,*reader)
        for at,key in ((120,'image_sha256'),(152,'input_sha256'),(184,'source_sha256')):
            head[at:at+32]=bytes.fromhex(self.binding[key])
        rows=[]
        for index,(owner,frame,data,lsn) in enumerate(fixtures,1):
            row=bytearray(768)
            struct.pack_into('<12Q',row,0,0x4359584131304556,index,index*100,1,*owner,lsn,index*8,index*8,index,len(data),0)
            row[96:128]=hashlib.sha256(data).digest();row[128:]=frame;rows.append(row)
        return bytes(head+b''.join(rows)),payload2

    def test_acknowledged_sequence_is_read_through_an_independent_task_handle(self):
        raw,payload=self.capture()
        result=self.verifier.verify_visibility(raw,self.binding,'/a10/value',2,payload)
        self.assertEqual((result['object'],result['durable_write_seq'],result['commit_lsn']),((5,2),2,24))
        self.assertEqual(result['reader'],(101,9))
        self.assertFalse(result['A10_complete'])

    def test_missing_duplicate_stale_owner_and_nonmonotonic_commit_records_fail(self):
        raw,_=self.capture()
        for offset,value in ((512+768+8,1),(512+24,2),(512+32,999),(512+4*768+48,19)):
            changed=bytearray(raw);struct.pack_into('<Q',changed,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):self.verifier.decode(changed,self.binding)
        with self.assertRaises(ValueError):self.verifier.decode(raw[:-1],self.binding)

    def test_run_identity_and_overflow_cannot_be_changed(self):
        raw,_=self.capture()
        for at in (32,56,72,120,152,184,300):
            changed=bytearray(raw);changed[at]^=1
            with self.subTest(offset=at),self.assertRaises(ValueError):self.verifier.decode(changed,self.binding)

    def test_successful_fsync_with_lower_durable_sequence_is_rejected(self):
        raw,_=self.capture();changed=bytearray(raw)
        struct.pack_into('<Q',changed,512+4*768+128+120,1)
        with self.assertRaisesRegex(ValueError,'fsync receipt'):
            self.verifier.decode(changed,self.binding)

    def test_stale_payload_or_wrong_read_handle_cannot_prove_visibility(self):
        raw,payload=self.capture()
        stale=bytearray(raw);stale[512+6*768+96:512+6*768+128]=hashlib.sha256(bytes([0x11])*4096).digest()
        wrong=bytearray(raw);struct.pack_into('<Q',wrong,512+6*768+128+48,999)
        for changed in (stale,wrong):
            with self.assertRaises(ValueError):self.verifier.verify_visibility(changed,self.binding,'/a10/value',2,payload)

    def terminal(self):
        value=bytearray(512)
        for role,owner,consumed,observed,verified in ((1,(100,9),2,2,0),(2,(101,9),0,2,4096)):
            struct.pack_into('<18Q',value,(role-1)*256,0x4359584131305052,*owner,0,1000,
                16,0x4359584131305553,1,1,role,1,8,5,2,consumed,observed,verified,0)
        return value

    def test_terminal_consumption_requires_actual_exit_and_stable_role_binding(self):
        raw,_=self.capture();capture=self.verifier.decode(raw,self.binding)
        terminal=self.terminal()
        result=self.verifier.verify_terminal(terminal,self.binding,capture)
        self.assertEqual(result['writer']['consumed_sequence'],2)
        self.assertEqual(result['reader']['verified_bytes'],4096)
        for offset,value in ((0,0),(24,1),(40,15),(64,2),(72,2),(88,7),(136,99),(200,1),(256+8,100)):
            bad=bytearray(terminal);struct.pack_into('<Q',bad,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                self.verifier.verify_terminal(bad,self.binding,capture)

    def complete_prepare(self):
        first,_=self.capture()
        head=bytearray(first[:512]); rows=[]
        def add(owner,frame,data=b'',lsn=24):
            row=bytearray(768);index=len(rows)+1
            struct.pack_into('<12Q',row,0,0x4359584131304556,index,index*10,1,*owner,lsn,80,64,4,len(data),0)
            row[96:128]=hashlib.sha256(data).digest();row[128:]=frame;rows.append(row)
        writer,reader=(100,9),(101,9)
        value=self.verifier.payload(2)
        v1=self.verifier.payload(1)
        for operation,request,data,seq in ((2,1,b'',0),(4,2,v1,0),(5,3,b'',1),(4,4,value,0),(5,5,b'',2),(6,6,b'',0)):
            add(writer,self.frame(operation,request,handle=(1,100),seq=seq,data=data,path='/a10/value' if operation==2 else ''),data)
        for request in (1,5):
            stat=self.frame(10,request,seq=2,path='/a10/value');struct.pack_into('<H',stat,14,1);struct.pack_into('<Q',stat,88,4096)
            if request == 1:
                add(reader,stat)
                add(reader,self.frame(2,2,handle=(1,200),path='/a10/value'))
                add(reader,self.frame(3,3,handle=(1,200),data=value),value)
                add(reader,self.frame(6,4,handle=(1,200)))
            else:add(reader,stat)
        add(reader,self.frame(1,6,obj=(6,2),path='/a10/seen-0000000000000001'),lsn=29)
        struct.pack_into('<Q',head,24,len(rows))
        oracle=dict(uuid=self.binding['uuid'],boot_epoch=1,last_commit_lsn=29,files={
            '/a10/value':dict(inode=5,generation=2,size=4096,durable_write_seq=2,sha256=hashlib.sha256(value).hexdigest()),
            '/a10/seen-0000000000000001':dict(inode=6,generation=2,size=0,durable_write_seq=0,sha256=hashlib.sha256(b'').hexdigest())})
        return bytes(head+b''.join(rows)),self.terminal(),oracle

    def test_clean_prepare_binds_consumed_ack_read_and_disk_oracle(self):
        raw,terminal,oracle=self.complete_prepare()
        result=self.verifier.verify_filesystem(raw,self.binding,terminal,oracle)
        self.assertEqual(result['durable_write_seq'],2)
        self.assertFalse(result['A10_complete'])
        import copy
        for key,value in (('durable_write_seq',1),('generation',3),('sha256','00'*32)):
            bad=copy.deepcopy(oracle);bad['files']['/a10/value'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                self.verifier.verify_filesystem(raw,self.binding,terminal,bad)
        bad=copy.deepcopy(oracle);bad['last_commit_lsn']=28
        with self.assertRaises(ValueError):self.verifier.verify_filesystem(raw,self.binding,terminal,bad)

    def test_recovery_reader_requires_oracle_version_and_no_writer(self):
        import copy
        raw,terminal,oracle=self.complete_prepare()
        head=bytearray(raw[:512]);struct.pack_into('<Q',head,48,3);head[88:104]=bytes(16)
        rows=[bytearray(raw[at:at+768]) for at in range(512,len(raw),768)
              if struct.unpack_from('<Q',raw,at+32)[0] == 101
              and struct.unpack_from('<H',raw,at+128+12)[0] != 1]
        for index,row in enumerate(rows,1):struct.pack_into('<Q',row,8,index)
        struct.pack_into('<Q',head,24,len(rows))
        progress=bytearray(terminal);progress[:256]=bytes(256);struct.pack_into('<Q',progress,256+64,3)
        binding=dict(self.binding,mode=3)
        value=bytes(head+b''.join(rows))
        result=self.verifier.verify_filesystem(value,binding,progress,oracle)
        self.assertEqual(result['acknowledged_sequences'],[])
        bad=copy.deepcopy(oracle);bad['files']['/a10/value'].update(durable_write_seq=3,sha256=hashlib.sha256(self.verifier.payload(3)).hexdigest())
        with self.assertRaises(ValueError):self.verifier.verify_filesystem(value,binding,progress,bad)

    def test_overwrite_requires_current_reader_marker_before_version_three(self):
        raw,terminal,oracle=self.complete_prepare();head=bytearray(raw[:512]);struct.pack_into('<Q',head,48,2)
        reader=[bytearray(raw[at:at+768]) for at in range(512,len(raw),768)
                if struct.unpack_from('<Q',raw,at+32)[0] == 101]
        reader_count=len(reader); rows=list(reader)
        marker='/a10/seen-0000000000000001'
        value=self.verifier.payload(3)
        specs=[self.frame(2,1,handle=(1,100),path='/a10/value'),self.frame(10,2,obj=(6,2),path=marker),
               self.frame(4,3,handle=(1,100),data=value),self.frame(5,4,handle=(1,100),seq=3),
               self.frame(6,5,handle=(1,100))]
        for frame in specs:
            row=bytearray(768);row[128:]=frame
            is_write=struct.unpack_from('<H',frame,12)[0] == 4
            struct.pack_into('<12Q',row,0,0x4359584131304556,0,1,1,100,9,29,80,64,4,4096 if is_write else 0,0)
            row[96:128]=hashlib.sha256(value if is_write else b'').digest();rows.append(row)
        for index,row in enumerate(rows,1):
            struct.pack_into('<2Q',row,8,index,index*10);struct.pack_into('<Q',row,48,29)
        struct.pack_into('<Q',head,24,len(rows))
        progress=bytearray(terminal)
        for base in (0,256):struct.pack_into('<Q',progress,base+64,2)
        struct.pack_into('<2Q',progress,112,3,3)
        binding=dict(self.binding,mode=2)
        oracle['files']['/a10/value'].update(durable_write_seq=3,sha256=hashlib.sha256(value).hexdigest())
        result=self.verifier.verify_filesystem(bytes(head+b''.join(rows)),binding,progress,oracle)
        self.assertEqual(result['acknowledged_sequences'],[3])
        # A prior epoch marker cannot authorize this overwrite, even if its
        # inode happens to match the new reader marker.
        bad=bytearray(rows[reader_count+1]);frame=bytearray(bad[128:]);frame[128:128+len(marker)]=b'/a10/seen-0000000000000000';bad[128:]=frame
        changed=list(rows);changed[reader_count+1]=bad
        with self.assertRaises(ValueError):self.verifier.verify_filesystem(bytes(head+b''.join(changed)),binding,progress,oracle)

    def test_boot_recovery_counters_match_independent_prefix_including_first_boot(self):
        serial=b'STORAGE_V13_BOOT_DURABLE\nSMP_BOOT_OK a=4 b=15 c=0\n'+b''.join(f'SMP_CPU_ON a={cpu} b={cpu} c=0\n'.encode() for cpu in (1,2,3))
        for previous,lsn,replayed,tail in ((0,0,0,False),(2,29,6,True)):
            before=dict(uuid=self.binding['uuid'],boot_epoch=previous,last_commit_lsn=lsn,
                generation=previous+1,log_epoch=previous+1,replayed_blocks=replayed,
                committed_transactions=0 if previous == 0 else 5,discarded_tail=tail)
            page=bytearray(4096)
            struct.pack_into('<15Q',page,0,0x43595853544f3133,1,previous+1,
                *struct.unpack('<2Q',bytes.fromhex(before['uuid'])),before['committed_transactions'],
                replayed,int(tail),lsn+(6 if previous == 0 else 4),previous+2,previous+2,
                4121,replayed+(11 if previous == 0 else 7),4,1000)
            result=self.verifier.verify_boot(page,before,serial)
            self.assertEqual(result['replayed_blocks'],replayed)
            for at in (8,16,24,40,48,56,64,72,80,88,96,104,112,120):
                bad=bytearray(page);struct.pack_into('<Q',bad,at,999)
                # Read count and duration are nonzero lower bounds, not exact
                # timing or device-read totals.
                if at in (88,112):struct.pack_into('<Q',bad,at,0)
                with self.subTest(previous=previous,at=at),self.assertRaises(ValueError):
                    self.verifier.verify_boot(bad,before,serial)


if __name__=='__main__':unittest.main()
