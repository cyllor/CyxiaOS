#!/usr/bin/env python3
"""Independent read-only decoder of the reserved v1.3 boot volume and redo log."""
import hashlib
from contextlib import contextmanager
from pathlib import Path
import struct
from verify_smp import require

BLOCK = 4096
COUNT = 131072

def crc32c(data: bytes) -> int:
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8): value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff

def checksum(data: bytes, offset: int) -> None:
    require(crc32c(data[:offset]+bytes(4)+data[offset+4:]) == struct.unpack_from('<I',data,offset)[0], 'disk CRC32C mismatch')

def superblock(data: bytes) -> dict:
    require(len(data)==BLOCK, 'short superblock'); checksum(data,76)
    require(struct.unpack_from('<IHHII',data)==(0x43594653,1,80,BLOCK,COUNT), 'wrong disk format')
    require(struct.unpack_from('<5I',data,56)==(4098,4102,4118,256,0), 'wrong disk layout')
    require(not any(data[80:]), 'superblock reserved bytes')
    generation,checkpoint,epoch=struct.unpack_from('<3Q',data,32)
    require(generation>0 and epoch>0 and any(data[16:32]), 'zero disk identity/generation')
    return dict(uuid=data[16:32],generation=generation,checkpoint=checkpoint,epoch=epoch)

@contextmanager
def committed_volume(path: Path):
    """Read the highest valid committed prefix without modifying the image."""
    require(path.stat().st_size==BLOCK*COUNT, 'wrong boot volume size')
    with path.open('rb') as disk:
        def read(block):
            require(0<=block<COUNT,'disk block outside image')
            disk.seek(block*BLOCK); data=disk.read(BLOCK)
            require(len(data)==BLOCK,'short disk read'); return data
        copies=[]
        for index in (0,1):
            try: copies.append(superblock(read(index)))
            except ValueError: pass
        require(copies,'no valid superblock')
        copies.sort(key=lambda s:s['generation'])
        if len(copies)==2:
            old,new=copies
            require(old['uuid']==new['uuid'] and old['checkpoint']<=new['checkpoint'] and old['epoch']<=new['epoch'], 'conflicting superblocks')
            require(old['generation']!=new['generation'] or old==new,'equal generation disagreement')
            require(old['generation']==new['generation'] or old['epoch']<new['epoch'],'checkpoint epoch did not advance')
        sb=copies[-1]; cursor=2; lsn=sb['checkpoint']+1; txid=0; overlays={}; commits=0; discarded_tail=False
        def record(block):
            head=read(block); checksum(head[:64],56)
            magic,version,kind,length,payload_crc,r_txid,r_lsn,epoch,home,index,count=struct.unpack_from('<IHHIIQQQQII',head)
            require(magic==0x43594c47 and version==1 and kind in (1,2,3) and head[60:64]==bytes(4),'invalid log header')
            expected={1:16,2:4096,3:64}[kind]
            require(length==64+expected,'invalid log record length')
            data=head+(read(block+1) if kind==2 else b'')
            body=data[64:64+expected]
            require(crc32c(body)==payload_crc and not any(data[64+expected:]),'invalid redo body/padding')
            require(epoch==sb['epoch'] and r_txid>0 and r_lsn>0,'stale record identity')
            if kind==1:
                redos,reserved,total=struct.unpack('<IIQ',body)
                require(home==index==count==reserved==0 and 1<=redos<=128 and total==redos*BLOCK
                        and r_lsn+redos+1<2**64,'invalid BEGIN payload')
            elif kind==2:
                begin=r_lsn-index-1
                require(4098<=home<COUNT and 0<=index<count<=128 and begin>0
                        and begin+count+1<2**64,'invalid REDO fields')
            else:
                found,begin,last,redos,reserved=struct.unpack_from('<QQQII',body)
                require(home==index==count==reserved==0 and found==r_txid and 1<=redos<=128
                        and begin>0 and begin+redos==last and last+1==r_lsn,'invalid COMMIT fields')
            return kind,r_txid,r_lsn,home,index,count,body

        def transaction(cursor,lsn,txid):
            kind,found,seq,home,index,count,body=record(cursor)
            require(kind==1 and found>txid and seq==lsn and home==index==count==0,'invalid BEGIN chain')
            count=struct.unpack_from('<I',body)[0]
            require(1<=count<=128,'invalid BEGIN count')
            require(struct.unpack('<IIQ',body)==(count,0,count*BLOCK),'invalid BEGIN payload')
            pending={}; digest=hashlib.sha256(); begin=lsn
            for item in range(count):
                at=cursor+1+2*item
                require(at+1<4098,'REDO outside journal')
                k,t,s,h,i,n,image=record(at)
                require((k,t,s,i,n)==(2,found,begin+1+item,item,count) and 4098<=h<COUNT and h not in pending,'invalid REDO chain')
                pending[h]=image; digest.update(struct.pack('<Q',h));digest.update(image)
            at=cursor+1+2*count
            require(at<4098,'COMMIT outside journal')
            k,t,s,h,i,n,body=record(at)
            require((k,t,s,h,i,n)==(3,found,begin+count+1,0,0,0),'invalid COMMIT chain')
            require(struct.unpack_from('<QQQII',body)==(found,begin,begin+count,count,0) and body[32:]==digest.digest(),'COMMIT digest mismatch')
            return pending,at,s,found

        while cursor<4098:
            try:
                pending,at,s,found=transaction(cursor,lsn,txid)
            except ValueError as failure:
                # A torn/unflushed final transaction is not durable. Scan every
                # remaining aligned block before accepting the prior prefix:
                # even a COMMIT with a mismatched digest proves corruption if
                # its own record CRCs, counters and reserved fields are valid.
                for later in range(cursor,4098):
                    tail=read(later)
                    if tail[:8]!=struct.pack('<IHH',0x43594c47,1,3):
                        continue
                    try:
                        candidate=record(later)
                    except ValueError:
                        continue
                    require(candidate[2]<lsn, str(failure)+': valid current-epoch COMMIT after broken chain')
                first=read(cursor)
                discarded_tail=any(first) and struct.unpack_from('<Q',first,32)[0]==sb['epoch']
                break
            overlays.update(pending);commits+=1;cursor=at+1;lsn=s+1;txid=found
        def current(block): return overlays[block] if block in overlays else read(block)
        yield current, dict(uuid=sb['uuid'].hex(),generation=sb['generation'],checkpoint_lsn=sb['checkpoint'],
                            log_epoch=sb['epoch'],committed_transactions=commits,last_commit_lsn=lsn-1,
                            replayed_blocks=len(overlays),discarded_tail=discarded_tail)


def inspect(path: Path) -> dict:
    with committed_volume(path) as (current, metadata):
        table=b''.join(current(4102+i) for i in range(16))
        root_size,root_sequence=struct.unpack_from('<QQ',table,16)
        require(root_size in (128,256,384) and root_sequence==root_size//128,'invalid durable root size/sequence')
        files=root_size//128-1
        sizes=[]
        for inode in range(256):
            slot=table[inode*256:(inode+1)*256]; checksum(slot,252)
            require(struct.unpack_from('<I',slot)[0]==0x4359494e,'invalid inode magic')
            require(struct.unpack_from('<Q',slot,8)[0]==1,'reserved inode generation changed')
            live=inode<2+files
            expected=bytearray(256)
            struct.pack_into('<IH',expected,0,0x4359494e,2 if inode==0 else 1 if live else 0)
            struct.pack_into('<Q',expected,8,1)
            if live:
                seq=struct.unpack_from('<Q',slot,24)[0]
                size=struct.unpack_from('<Q',slot,16)[0]
                if inode==0:
                    require(size==root_size and seq==root_sequence,'invalid root inode')
                    start,blocks=4118,1
                elif inode==1:
                    require(size==64 and seq>0,'invalid boot inode')
                    start,blocks=4119,1
                else:
                    require(0<size<=8*1024*1024 and seq>0,'invalid cluster inode size/sequence')
                    start,blocks=4120+(inode-2)*2048,(size+BLOCK-1)//BLOCK
                    sizes.append((size,blocks,seq))
                struct.pack_into('<QQH',expected,16,size,seq,1)
                struct.pack_into('<Q',expected,40,1)
                struct.pack_into('<III',expected,48,0,start,blocks)
            require(slot[:252]==expected[:252],'unexpected allocated inode/layout')
        directory=current(4118)
        names=[b'.cyxia-boot',b'.cyxia-cluster-a',b'.cyxia-cluster-b']
        for index in range(files+1):
            entry=directory[index*128:(index+1)*128];checksum(entry,124)
            expected=bytearray(124);name=names[index]
            struct.pack_into('<IH',expected,0,index+1,len(name));struct.pack_into('<Q',expected,8,1);expected[16:16+len(name)]=name
            require(entry[:124]==expected,'invalid reserved directory entry')
        require(not any(directory[root_size:]),'directory unused suffix not zero')
        body=current(4119);epoch=struct.unpack_from('<Q',body,24)[0]
        require(body[:8]==b'CYXBOOT1' and body[8:24].hex()==metadata['uuid'] and epoch>0 and not any(body[36:]),'invalid boot body')
        require(struct.unpack_from('<I',body,32)[0]==crc32c(body[:32]),'boot CRC mismatch')
        require(struct.unpack_from('<Q',table,256+24)[0]==epoch,'inode and boot epoch disagree')
        bitmap=b''.join(current(4098+i) for i in range(4))
        expected=bytearray(16384)
        for block in range(4120):expected[block//8]|=1<<(block%8)
        cluster_records=[]
        for file in range(2):
            start=4120+file*2048
            stream=b''.join(current(start+i) for i in range(2048))
            size,blocks,seq=sizes[file] if file<files else (0,0,0)
            require(not any(stream[size:]),'cluster file unused suffix not zero')
            for block in range(start,start+blocks):expected[block//8]|=1<<(block%8)
            at,records=0,0
            while at<size:
                require(at+16<=size,'truncated cluster record header')
                header=stream[at:at+16]
                magic,length,body_crc,header_crc=struct.unpack('<4sIII',header)
                require(magic==b'CXV1' and 0<length<=33200 and crc32c(header[:12])==header_crc,'invalid cluster record header/CRC')
                at+=16
                require(at+length<=size,'truncated cluster record body')
                body=stream[at:at+length]
                require(crc32c(body)==body_crc,'cluster record body CRC mismatch')
                cluster_records.append(body.hex());at+=length;records+=1
            require(records==seq,'cluster inode durable sequence differs from record count')
        require(bitmap==bytes(expected),'boot/cluster volume allocation mismatch')
        return dict(metadata,boot_epoch=epoch,
                    cluster_files=files,cluster_file_sizes=[row[0] for row in sizes],cluster_records=cluster_records)
