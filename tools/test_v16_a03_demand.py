"""Exercise the real scene/QMP validators; fixtures confer no native verdict."""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

import v16_a03_demand as d


def scene():
    w = [0]*128
    w[:15] = [d.LAYOUT[0],1,128,1,2,6,20_000_000_000,1_000_000_000,11_000_000_000,
        12_000_000_000,16_000_000_000,19_000_000_000,*d.LAYOUT[4:],0]
    w[16:28] = [1,100,0,0,0,100,1,99,32_000,100,0x434f5245,1]
    recipe = b'CYXIA_A03_ORDINARY_DEMAND_V1\0'+struct.pack('<2Q',*d.LAYOUT[4:])+b'100-owned-arrivals;relative=((id-1)/10)*1000000000+((id-1)%10)*1000;deadline=5000000000;no-publication\0'
    w[32:36] = struct.unpack('<4Q',hashlib.sha256(recipe).digest()); w[36] = 1
    w[40:45] = [7,10,18_000_000_000,17_000_000_000,1]
    return struct.pack('<128Q',*w)


class SceneValidator(unittest.TestCase):
    def test_closed_scene_keeps_stimulus_separate_from_owner_acceptance(self):
        got = d.decode_scene(scene())
        self.assertEqual((got['released'],got['retired'],got['completed']), (100,100,1))
        self.assertFalse(got['applied_owner_verified'])

    def test_pending_owned_work_or_empty_stimulus_cannot_close_scene(self):
        for index,value in ((4,3),(5,5),(14,1),(17,99),(18,1),(19,1),(20,1),(21,99),(22,0),(24,0),(25,99),(26,99),(44,0),(127,1)):
            w = list(struct.unpack('<128Q',scene())); w[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError): d.decode_scene(struct.pack('<128Q',*w))

    def test_quiet_input_must_follow_real_drain_and_full_quiet_horizon(self):
        for index,value in ((11,17_000_000_000),(40,0),(41,0),(43,16_000_000_000),(43,19_000_000_000),(32,123)):
            w = list(struct.unpack('<128Q',scene())); w[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError): d.decode_scene(struct.pack('<128Q',*w))

    def test_publication_cap_includes_decode_and_rejects_overflow(self):
        s = d.decode_scene(scene()); q = [0]*640
        q[0:2] = [s['quiet_job']]*2; q[13:16] = [s['quiet_version'],1,0]
        q[19] = q[30] = 1; q[36] = s['quiet_input_ns']; q[639] = 2
        q[8:13] = [s['quiet_input_ns'],s['quiet_input_ns']+1_000_000,10_000,1_000,450_000]
        q[29] = 50_000
        self.assertEqual(d.decode_quiet_record(struct.pack('<640Q',*q),s)['publication_with_decode_ns'],500_000)
        q[29] += 1
        with self.assertRaisesRegex(ValueError,'decode/publication'): d.decode_quiet_record(struct.pack('<640Q',*q),s)
        q[12] = (1<<64)-1; q[29] = 1
        with self.assertRaisesRegex(ValueError,'decode/publication'): d.decode_quiet_record(struct.pack('<640Q',*q),s)


class QmpCustody(unittest.TestCase):
    def fixture(self, root):
        context = {'symbols':{key:{'pa':0x100000+i*0x100000} for i,key in enumerate(d.BANKS)}}
        platform = dict(cpus=[{'cpu-index':i} for i in range(4)],memory={'base-memory':1024**3})
        dtb = struct.pack('>2I',0xd00dfeed,40)+bytes(32)
        for name,raw in [('dtb-header.bin',dtb),('platform.dtb',dtb),('config-observed.bin',bytes(512)),('pending-demand.bin',scene())]:
            (root/name).write_bytes(raw)
        rows = [dict(direction='receive',message={'QMP':{'version':{},'capabilities':[]}})]
        def command(name,args=None,result=None):
            ident = 1+sum(r['direction'] == 'send' for r in rows)
            msg = dict(execute=name,id=ident)
            if args is not None: msg['arguments'] = args
            rows.append(dict(direction='send',message=msg))
            rows.append(dict(direction='receive',message=dict(id=ident,**{'return':{} if result is None else result})))
        command('qmp_capabilities'); command('query-cpus-fast',result=platform['cpus']); command('query-memory-size-summary',result=platform['memory'])
        def read(name,address,size): command('pmemsave',dict(filename=str(root/name),val=address,size=size))
        read('dtb-header.bin',0x40000000,40); read('platform.dtb',0x40000000,40)
        read('config-observed.bin',context['symbols']['config']['pa'],512)
        command('cont'); read('pending-demand.bin',context['symbols']['demand']['pa'],1024)
        command('stop'); command('query-status',result={'status':'paused'})
        for key,(_,size) in d.BANKS.items():
            if key == 'config': continue
            raw = scene() if key == 'demand' else bytes(size)
            (root/('probe-01-'+key+'.bin')).write_bytes(raw); (root/(key+'.bin')).write_bytes(raw)
            read('probe-01-'+key+'.bin',context['symbols'][key]['pa'],size)
        for key,(_,size) in d.BANKS.items():
            if key != 'config': read(key+'.bin',context['symbols'][key]['pa'],size)
        command('ringbuf-read',dict(device='cyxlog',size=1048576,format='base64'),result='')
        command('quit')
        rows.append(dict(direction='receive',message={'event':'SHUTDOWN','data':{'guest':False,'reason':'host-qmp-quit'}}))
        return context,rows,platform,dtb

    def test_confirmed_pause_exact_probe_and_final_bytes_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); context,rows,platform,dtb = self.fixture(root)
            self.assertEqual(d.verify_qmp(root,context,rows,platform,dtb),b'')
            bad = copy.deepcopy(rows)
            next(r for r in bad if r['direction'] == 'receive' and r['message'].get('return') == {'status':'paused'})['message']['return']['status'] = 'running'
            with self.assertRaises(ValueError): d.verify_qmp(root,context,bad,platform,dtb)
            bad = copy.deepcopy(rows)
            next(r for r in bad if r['direction'] == 'send' and r['message']['execute'] == 'pmemsave' and r['message']['arguments']['filename'].endswith('/demand.bin'))['message']['arguments']['val'] += 8
            with self.assertRaises(ValueError): d.verify_qmp(root,context,bad,platform,dtb)
            (root/'demand.bin').write_bytes(bytes(1024))
            with self.assertRaises(ValueError): d.verify_qmp(root,context,rows,platform,dtb)

    def test_unknown_command_external_read_and_false_shutdown_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); context,rows,platform,dtb = self.fixture(root)
            for mutation in ('command','path','shutdown'):
                bad = copy.deepcopy(rows)
                if mutation == 'command': next(r for r in bad if r['direction'] == 'send')['message']['execute'] = 'human-monitor-command'
                elif mutation == 'path':
                    next(r for r in bad if r['direction'] == 'send' and r['message']['execute'] == 'pmemsave')['message']['arguments']['filename'] = '/private/tmp/outside.bin'
                else: bad[-1]['message']['data']['guest'] = True
                with self.subTest(mutation=mutation), self.assertRaises(ValueError): d.verify_qmp(root,context,bad,platform,dtb)


if __name__ == '__main__': unittest.main()
