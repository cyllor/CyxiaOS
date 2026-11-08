"""Synthetic protocol/context tests; never native execution/acceptance evidence."""
import copy,hashlib,json,os,socket,sys,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(os.environ.get('CYXIA_TEST_ROOT',Path(__file__).resolve().parents[2]))
sys.path.insert(0,str(ROOT/'tools'))
sys.path.insert(0,os.environ.get('A10_CANDIDATE_TOOLS',str(ROOT/'tools')))
import verify_v13_a10_native_receipt as native
import v13_a10_native_capture as capture
sys.path.insert(0,str(ROOT/'tests/host'))
from test_v13_a10_native_receipt import fixture,SyntheticChild

def digest(message):
 return hashlib.sha256(json.dumps(message,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def block_error():
 return dict(event='BLOCK_IO_ERROR',timestamp=dict(seconds=1,microseconds=2),data=dict(
  device='disk0',nospace=False,**{'node-name':'cyxia-a10-disk','qom-path':'/machine/peripheral-anon/device[0]'},
  reason='Input/output error',operation='write',action='report'))
def insert_error(rows,witness,*,include_witness=True):
 ident=next(r['message']['id'] for r in rows if r['direction']=='send' and r['message']['execute']=='ringbuf-read')
 at=next(i for i,r in enumerate(rows) if r['direction']=='receive' and r['message'].get('id')==ident)
 rows.insert(at,dict(direction='receive',message=block_error()))
 cut=next(r for r in witness if r['event']=='backend-cut');witness.remove(cut)
 index=next(i for i,r in enumerate(witness) if r['event']=='qmp-response' and r['id']==ident)
 witness.insert(index,cut)
 if include_witness:witness.insert(index+1,dict(event='qmp-block-error',qmp_row=at+1,sha256=digest(rows[at]['message'])))
 for i,r in enumerate(witness):r.update(seq=i+1,monotonic_ns=(i+1)*100000)
 return at

class BlockIoContext(unittest.TestCase):
 def parser(self,rows,allow=False):
  events=[];candidates=[]
  result=list(native.transactions(rows,1000,events,**({'fault_events':candidates} if allow else {})))
  return result,events,candidates
 def setup_protocol(self,path,include_witness=True):
  context,layout,inputs,rows,witness=fixture(path,cut=True)
  at=insert_error(rows,witness,include_witness=include_witness)
  inputs.update(reverse_replies=False,unflushed='reverse-half')
  return context,layout,inputs,rows,witness,at
 def test_default_parser_still_denies_real_shape(self):
  with tempfile.TemporaryDirectory() as temp:
   case=self.setup_protocol(Path(temp))
   with self.assertRaisesRegex(ValueError,'unaccounted QMP asynchronous event'):self.parser(case[3])
 def test_fault_parser_collects_one_typed_event_without_native_verdict(self):
  with tempfile.TemporaryDirectory() as temp:
   _,_,_,rows,_,at=self.setup_protocol(Path(temp))
   _,events,candidates=self.parser(rows,True)
   self.assertEqual(events,['RESUME','STOP']);self.assertEqual(len(candidates),1)
   self.assertEqual(candidates[0]['qmp_row'],at+1);self.assertEqual(candidates[0]['sha256'],digest(block_error()))
 def test_typed_event_rejects_unknown_device_operation_schema_and_duplicate(self):
  edits=[('device','disk1'),('operation','read'),('action','stop'),('nospace',True),
         ('nospace',0),('node-name','#block999'),('qom-path','/elsewhere'),('reason','x'*257),('reason','\x00')]
  with tempfile.TemporaryDirectory() as temp:
   _,_,_,rows,_,at=self.setup_protocol(Path(temp))
   for key,value in edits:
    with self.subTest(key=key,value=value):
     changed=copy.deepcopy(rows);changed[at]['message']['data'][key]=value
     with self.assertRaises(ValueError):self.parser(changed,True)
   for change in ['extra','missing','duplicate','unknown','float-timestamp','bool-timestamp','before-resume','outside-request']:
    with self.subTest(change=change):
     changed=copy.deepcopy(rows)
     if change=='extra':changed[at]['message']['data']['extra']=0
     elif change=='missing':del changed[at]['message']['data']['nospace']
     elif change=='duplicate':changed.insert(at,copy.deepcopy(changed[at]))
     elif change=='unknown':changed[at]['message']['event']='DEVICE_TRAY_MOVED'
     elif change=='float-timestamp':changed[at]['message']['timestamp']['seconds']=1.0
     elif change=='bool-timestamp':changed[at]['message']['timestamp']['seconds']=True
     elif change=='before-resume':changed.insert(1,changed.pop(at))
     elif change=='outside-request':changed.insert(at+1,changed.pop(at))
     with self.assertRaises(ValueError):self.parser(changed,True)
 def test_protocol_requires_exact_source_bound_event_witness(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp);context,layout,inputs,rows,witness,at=self.setup_protocol(path)
   result=native.validate_protocol(path,context,layout,inputs,rows,witness)
   self.assertEqual(len(result['fault_io_events']),1)
   self.assertEqual(result['fault_io_events'][0]['witness']['sha256'],digest(block_error()))
   for change in ['missing','wrong-hash','wrong-row','extra-witness']:
    with self.subTest(change=change):
     altered=copy.deepcopy(witness);index=next(i for i,r in enumerate(altered) if r['event']=='qmp-block-error')
     if change=='missing':altered.pop(index)
     elif change=='wrong-hash':altered[index]['sha256']='00'*32
     elif change=='wrong-row':altered[index]['qmp_row']+=1
     elif change=='extra-witness':altered.insert(index,copy.deepcopy(altered[index]))
     for i,r in enumerate(altered):r['seq']=i+1
     with self.assertRaises(ValueError):native.validate_protocol(path,context,layout,inputs,rows,altered)
 def test_clean_protocol_never_collects_io_errors(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp);context,layout,inputs,rows,witness=fixture(path)
   ident=next(r['message']['id'] for r in rows if r['direction']=='send' and r['message']['execute']=='ringbuf-read')
   at=next(i for i,r in enumerate(rows) if r['direction']=='receive' and r['message'].get('id')==ident)
   rows.insert(at,dict(direction='receive',message=block_error()))
   with self.assertRaises(ValueError):native.validate_protocol(path,context,layout,inputs,rows,witness)
 def final_case(self,path):
  context,layout,inputs,rows,witness,_=self.setup_protocol(path)
  protocol=native.validate_protocol(path,context,layout,inputs,rows,witness)
  backend=protocol['lifecycle']['backend-cut'];ns=backend['monotonic_ns']
  cut=dict(event='cut',id=1,mutation=1,phase='before',monotonic_ns=ns-1,discarded_sectors=1,surviving_offsets=[],acks=0,flushes=0)
  raw=[dict(event='request',id=1,mutation=1,kind=3,monotonic_ns=ns-2),cut]
  replayed={'nbd_trace':dict(run_id=context['backend_run_id'],cut=cut)}
  scope=dict(post_resume_points=[1],resume_monotonic_ns=next(r['monotonic_ns'] for r in witness if r['event']=='qmp-request' and r['id']==8))
  (path/'nbd').mkdir();(path/'nbd/start.json').write_text(json.dumps(dict(run_id=context['backend_run_id'],cut=1,phase='before',reverse_replies=False,unflushed='reverse-half')))
  return context,inputs,protocol,replayed,scope,raw
 def test_final_custody_closes_actual_cut_interval_and_single_unacked_flush(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp);context,inputs,protocol,replayed,scope,raw=self.final_case(path)
   with patch('check_v13_fault_disk.read_events',return_value=raw):
    native.verify_fault_io_events(path,context,inputs,protocol,replayed,scope)
 def test_final_custody_rejects_incomplete_or_mismatched_actual_cut_proofs(self):
  mutations=['clean','wrong-run','wrong-cut-id','wrong-mutation','after-ack','write-not-flush','precut-event','after-stop-event',
   'pre-resume-cut','no-cut','extra-outstanding','acked-cut','reverse-replies','wrong-nbd-clock','missing-stop','missing-cut-witness']
  for mutation in mutations:
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temp:
    path=Path(temp);context,inputs,protocol,replayed,scope,raw=self.final_case(path)
    cut=protocol['lifecycle']['backend-cut'];io=protocol['fault_io_events'][0]['witness']
    if mutation=='clean':inputs['cut']=0
    elif mutation=='wrong-run':replayed['nbd_trace']['run_id']='cd'*16
    elif mutation=='wrong-cut-id':replayed['nbd_trace']['cut']['id']=9
    elif mutation=='wrong-mutation':replayed['nbd_trace']['cut']['mutation']=2
    elif mutation=='after-ack':inputs['phase']='after-ack'
    elif mutation=='write-not-flush':raw[0]['kind']=1
    elif mutation=='precut-event':io['monotonic_ns']=cut['monotonic_ns']-1
    elif mutation=='after-stop-event':io['monotonic_ns']=protocol['stop_request']['monotonic_ns']+1
    elif mutation=='pre-resume-cut':scope['resume_monotonic_ns']=raw[0]['monotonic_ns']+1
    elif mutation=='no-cut':raw.pop()
    elif mutation=='extra-outstanding':raw.insert(0,dict(event='request',id=2,kind=1,monotonic_ns=raw[0]['monotonic_ns']-1))
    elif mutation=='acked-cut':raw.insert(1,dict(event='ack',id=1,monotonic_ns=raw[0]['monotonic_ns']))
    elif mutation=='reverse-replies':inputs['reverse_replies']=True
    elif mutation=='wrong-nbd-clock':raw[-1]['monotonic_ns']=cut['monotonic_ns']+1
    elif mutation=='missing-stop':protocol['stop_request']=None
    elif mutation=='missing-cut-witness':del protocol['lifecycle']['backend-cut']
    with patch('check_v13_fault_disk.read_events',return_value=raw):
     patterns={'clean':'unsupported QMP block error fault context','wrong-run':'actual NBD run/cut policy mismatch','wrong-cut-id':'actual NBD run/cut policy mismatch','wrong-mutation':'actual NBD run/cut policy mismatch','after-ack':'unsupported QMP block error fault context','write-not-flush':'not a before-FLUSH cut','precut-event':'post-cut/pre-stop interval','after-stop-event':'post-cut/pre-stop interval','pre-resume-cut':'post-cut/pre-stop interval','no-cut':'lacks final actual raw cut','extra-outstanding':'ambiguous outstanding','acked-cut':'ambiguous outstanding','reverse-replies':'unsupported QMP block error fault context','wrong-nbd-clock':'post-cut/pre-stop interval','missing-stop':'lacks actual cut/stop proof','missing-cut-witness':'lacks actual cut/stop proof'}
     with self.assertRaisesRegex(ValueError,patterns[mutation]):native.verify_fault_io_events(path,context,inputs,protocol,replayed,scope)
 def test_journal_records_one_async_hash_at_parse_point_under_shared_lock(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);witness=capture.Witness(root/'witness.jsonl')
   journal=capture.TranscriptJournal(root/'qmp.jsonl',byte_limit=100000,command_limit=100,witness=witness)
   row=dict(direction='receive',message=block_error());journal.append(row);journal.close()
   rows=[json.loads(s) for s in (root/'witness.jsonl').read_text().splitlines()]
   self.assertEqual(len(rows),1);self.assertEqual(rows[0]['event'],'qmp-block-error')
   self.assertEqual(rows[0]['qmp_row'],1);self.assertEqual(rows[0]['sha256'],digest(block_error()))
 def test_real_qmp_receive_records_cut_event_and_reply_in_shared_clock_order(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);witness=capture.Witness(root/'witness');client,server=socket.socketpair()
   self.addCleanup(client.close);self.addCleanup(server.close)
   def peer():
    request=json.loads(server.recv(4096))
    witness.record('backend-cut',run_id='ab'*16,id=1,mutation=1,phase='before')
    server.sendall((json.dumps(block_error())+'\n'+json.dumps({'id':request['id'],'return':''})+'\n').encode())
   worker=threading.Thread(target=peer);worker.start()
   qmp=capture.NativeQmp(client,witness,journal_path=root/'qmp',byte_limit=100000,command_limit=2)
   try:self.assertEqual(qmp.execute('ringbuf-read',{'device':'cyxlog','size':1048576,'format':'base64'}),'')
   finally:qmp.close_journal();worker.join(2)
   self.assertFalse(worker.is_alive())
   rows=[json.loads(line) for line in (root/'witness').read_text().splitlines()]
   self.assertEqual([r['event'] for r in rows],['qmp-request','backend-cut','qmp-block-error','qmp-response'])
   self.assertEqual([r['seq'] for r in rows],[1,2,3,4])
   self.assertEqual(rows[2]['qmp_row'],2);self.assertEqual(rows[2]['sha256'],digest(block_error()))
   self.assertEqual(sorted(r['monotonic_ns'] for r in rows),[r['monotonic_ns'] for r in rows])
 def test_journal_cannot_record_a_second_io_event_as_valid_custody(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);witness=capture.Witness(root/'witness')
   journal=capture.TranscriptJournal(root/'qmp',byte_limit=100000,command_limit=10,witness=witness)
   try:
    journal.append(dict(direction='receive',message=block_error()))
    with self.assertRaisesRegex(ValueError,'block error bound'):journal.append(dict(direction='receive',message=block_error()))
   finally:journal.close()
   self.assertEqual(len((root/'witness').read_text().splitlines()),1)
 def test_complete_verifier_calls_final_io_check_after_raw_replay_and_never_skips_raw_failure(self):
  # These sparse disks intentionally have no filesystem. The existing synthetic
  # fixture mocks external attestation/raw oracle; the sentinel proves ordering
  # and mandatory invocation, never a native filesystem verdict.
  with tempfile.TemporaryDirectory() as temp:
   child=SyntheticChild(Path(temp),cut=True);order=[]
   def replay(*args):order.append('complete-raw-replay');return child.summary
   def finalize(*args):order.append('final-io-proof');raise ValueError('final-io-proof-sentinel')
   kwargs=dict(source_root=ROOT,build_manifest=child.build_root/'build-manifest.json',qemu_binary=child.root.parent/'trusted-qemu',qemu_source=child.root.parent/'synthetic-qemu-source')
   with patch.object(native,'qemu_identity',return_value=child.qemu),patch('verify_v13_a10_receipt.replay_child',side_effect=replay),patch.object(native,'verify_fault_io_events',side_effect=finalize):
    with self.assertRaisesRegex(ValueError,'final-io-proof-sentinel'):native.verify_native_child(child.root,**kwargs)
   self.assertEqual(order,['complete-raw-replay','final-io-proof'])
   with patch.object(native,'qemu_identity',return_value=child.qemu),patch('verify_v13_a10_receipt.replay_child',side_effect=ValueError('raw-disk-reconstruction-failed')),patch.object(native,'verify_fault_io_events') as final:
    with self.assertRaisesRegex(ValueError,'raw-disk-reconstruction-failed'):native.verify_native_child(child.root,**kwargs)
    final.assert_not_called()
 def test_original_cut_without_async_receive_witness_remains_rejected(self):
  with tempfile.TemporaryDirectory() as temp:
   path=Path(temp);context,layout,inputs,rows,witness,_=self.setup_protocol(path,False)
   with self.assertRaises(ValueError):native.validate_protocol(path,context,layout,inputs,rows,witness)

if __name__=='__main__':unittest.main(verbosity=2)
