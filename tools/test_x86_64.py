"""Host regressions for the x86 platform loader and evidence chain."""
import importlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib


def fixture_elf():
    raw=bytearray(0x2100)
    ident=b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH',raw,0,ident,2,62,1,0x100020,64,0,0,64,56,2,0,0,0)
    struct.pack_into('<IIQQQQQQ',raw,64,1,5,0x1000,0x100000,0x100000,0x100,0x100,0x1000)
    struct.pack_into('<IIQQQQQQ',raw,120,1,6,0x2000,0x101000,0x101000,0x100,0x2000,0x1000)
    flags=0x10003
    struct.pack_into('<8I',raw,0x1000,0x1badb002,flags,(-0x1badb002-flags)&0xffffffff,
        0x100000,0x100000,0x101100,0x103000,0x100020)
    raw[0x1020:0x1024]=b'\xfa\xf4\xeb\xfd'
    return bytes(raw)


def frame(payload,sequence):
    raw=struct.pack('<4sBBHQQ',b'CYX1',1,0,len(payload),1,sequence)+payload
    return raw+struct.pack('<I',zlib.crc32(raw))


class Loader(unittest.TestCase):
    def setUp(self):
        try:self.f=importlib.import_module('x86_64')
        except ModuleNotFoundError:self.fail('x86-64 build/run/check entry is absent')

    def test_flat_image_preserves_original_segments_and_zero_gaps(self):
        elf=fixture_elf();info=self.f.inspect_elf(elf);flat=self.f.boot_image(elf)
        self.assertEqual(info['entry'],0x100020)
        self.assertEqual(len(flat),0x1100)
        self.assertEqual(flat[:0x100],elf[0x1000:0x1100])
        self.assertEqual(flat[0x100:0x1000],bytes(0xf00))
        self.assertEqual(flat[0x1000:],elf[0x2000:])

    def test_arm_image_and_wrong_class_are_rejected(self):
        for offset,fmt,value in ((18,'H',183),(4,'B',1),(16,'H',3)):
            raw=bytearray(fixture_elf());struct.pack_into('<'+fmt,raw,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):self.f.boot_image(bytes(raw))

    def test_overlap_writable_code_and_outside_load_pool_are_rejected(self):
        for offset,value in ((64+4,7),(120+16,0x100000),(120+24,0x100000),(120+24,0xfffffffffffff000)):
            raw=bytearray(fixture_elf());struct.pack_into('<I' if offset==68 else '<Q',raw,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):self.f.boot_image(bytes(raw))

    def test_truncated_and_out_of_file_segments_are_rejected(self):
        for size in (0,63,120,0x2050):
            with self.subTest(size=size),self.assertRaises(ValueError):self.f.boot_image(fixture_elf()[:size])
        raw=bytearray(fixture_elf());struct.pack_into('<Q',raw,64+32,2**64-1)
        with self.assertRaises(ValueError):self.f.boot_image(bytes(raw))

    def test_multiboot_header_cannot_change_load_or_entry(self):
        for index,value in ((1,0x10007),(2,0),(3,0x100004),(4,0),(5,0x103000),(6,0x101100),(7,0x101000)):
            raw=bytearray(fixture_elf());struct.pack_into('<I',raw,0x1000+index*4,value)
            with self.subTest(index=index),self.assertRaises(ValueError):self.f.boot_image(bytes(raw))

    def test_duplicate_boot_headers_are_rejected(self):
        raw=bytearray(fixture_elf());raw[0x1040:0x1060]=raw[0x1000:0x1020]
        with self.assertRaises(ValueError):self.f.boot_image(bytes(raw))

    def test_finite_observation_bound(self):
        for value in (True,0,901,float('inf'),float('nan'),-1):
            with self.subTest(value=value),self.assertRaises(ValueError):self.f.validate_timeout(value)
        self.f.validate_timeout(30)


class Evidence(unittest.TestCase):
    def setUp(self):self.f=importlib.import_module('x86_64')

    def serial(self):
        return b''.join(frame(marker.encode(),i) for i,marker in enumerate(self.f.MARKERS,1))

    def test_complete_frames_and_guest_exit_are_both_required(self):
        result=self.f.validate_serial(self.serial(),33,forced=False,eof=True)
        self.assertEqual(result['markers'],list(self.f.MARKERS))
        for code,forced,eof in ((0,False,True),(35,False,True),(33,True,True),(33,False,False)):
            with self.subTest(code=code,forced=forced,eof=eof),self.assertRaises(ValueError):
                self.f.validate_serial(self.serial(),code,forced=forced,eof=eof)

    def test_forged_substrings_corruption_gaps_and_trailing_bytes_fail(self):
        cases=[self.serial()[:-1],self.serial()+b'x',b'X86_SELFTEST_OK\n',self.serial()+frame(b'FAIL bad',9)]
        corrupt=bytearray(self.serial());corrupt[25]^=1;cases.append(bytes(corrupt))
        cases.append(self.serial()+frame(b'continuing after success',9))
        cases.append(b''.join(frame((b'NOT_'+m.encode()) if i==1 else m.encode(),i) for i,m in enumerate(self.f.MARKERS,1)))
        cases.append(b''.join(frame(m.encode(),i+1) for i,m in enumerate(self.f.MARKERS,1)))
        for raw in cases:
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):self.f.validate_serial(raw,33,forced=False,eof=True)

    def test_kvm_requires_explicit_linux_x86_host(self):
        with patch.object(self.f.platform,'system',return_value='Darwin'),patch.object(self.f.platform,'machine',return_value='arm64'):
            with self.assertRaises(ValueError):self.f.accelerator('kvm')
            self.assertEqual(self.f.accelerator('tcg'),'tcg,thread=multi')
        with patch.object(self.f.platform,'system',return_value='Linux'),patch.object(self.f.platform,'machine',return_value='x86_64'):
            self.assertEqual(self.f.accelerator('kvm'),'kvm')

    def test_cleanup_timeout_only_signals_owned_process(self):
        class Proc:
            def __init__(self):self.calls=[];self.returncode=None
            def poll(self):return self.returncode
            def terminate(self):self.calls.append('terminate')
            def kill(self):self.calls.append('kill');self.returncode=-9
            def wait(self,timeout=None):
                self.calls.append('wait')
                if self.returncode is None:raise self_f.subprocess.TimeoutExpired('fixture',timeout)
                return self.returncode
        self_f=self.f;p=Proc()
        self.assertTrue(self.f.close_process(p))
        self.assertEqual(p.calls,['terminate','wait','kill','wait'])

    def test_reader_preserves_eof_and_rejects_timeout(self):
        import subprocess,sys
        p=subprocess.Popen([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"fixture")'],stdout=subprocess.PIPE)
        raw=bytearray()
        try:self.assertTrue(self.f.capture_stdout(p,raw,self.f.time.monotonic()+5))
        finally:self.f.close_process(p);p.stdout.close()
        self.assertEqual(bytes(raw),b'fixture')
        p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdout=subprocess.PIPE)
        try:
            with self.assertRaises(TimeoutError):self.f.capture_stdout(p,bytearray(),self.f.time.monotonic()+.02)
        finally:
            self.assertTrue(self.f.close_process(p));p.stdout.close()

    def test_strict_json_rejects_duplicate_and_nonfinite(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'manifest.json'
            for value in ('{"x":1,"x":2}','{"x":NaN}','{"x":1e999}'):
                p.write_text(value)
                with self.assertRaises(ValueError):self.f.read_json(p)

    def test_manifest_cannot_invoke_recorded_tool_path(self):
        f=self.f;sources={'kernel/src/main.rs':'source'};producer={'tools/x86_64.py':'tool'}
        cache={'base':'/private/tmp/fixture','effective':'/private/tmp/fixture/source'}
        manifest=dict(version=1,status='BUILT_NOT_RUN',target=f.TARGET,profile='dev',features=['selftest'],
            sources=sources,source_sha256=f.digest_map(sources),producer_sources=producer,
            source_root=str(f.ROOT.resolve()),native_acceptance_status='NOT_RUN',cache=cache,
            cargo={'path':'/untrusted/from-manifest','sha256':'binary'},
            rustc={'path':'/trusted/rustc','sha256':'binary'})
        with tempfile.TemporaryDirectory() as directory,patch.object(f,'read_json',return_value=manifest),\
                patch.object(f,'code_source_map',return_value=sources),patch.object(f,'tool_sources',return_value=producer),\
                patch.object(f,'build_cache_context',return_value=cache),patch.object(f,'build_environment'),\
                patch.object(f,'executable',side_effect=lambda name:'/trusted/'+name),\
                patch.object(f,'sha',return_value='binary'),patch.object(f,'compiler_tools') as compiler:
            with self.assertRaisesRegex(ValueError,'executable identity'):f.validate_build(directory)
            compiler.assert_not_called()

    def test_compiler_environment_override_is_rejected(self):
        with patch.object(self.f,'env',return_value={'RUSTC_WRAPPER':'untracked-wrapper'}):
            with self.assertRaisesRegex(ValueError,'ambient compiler'):self.f.build_environment({'effective':'cache'})

    def test_rustup_dispatcher_symlink_preserves_invocation_name(self):
        with tempfile.TemporaryDirectory() as directory:
            dispatcher=Path(directory)/'rustup';dispatcher.write_text('fixture');dispatcher.chmod(0o700)
            cargo=Path(directory)/'cargo';cargo.symlink_to(dispatcher)
            self.assertEqual(self.f.executable(str(cargo)),str(cargo))

    def test_fresh_checkout_creates_default_lock_parent_and_shares_existing_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();lock=root/'artifacts'/'v016-focus-a03-a10-20261109-r9'/'native-session.lock'
            with patch.object(self.f,'ROOT',root),patch.object(self.f,'DEFAULT_NATIVE_LOCK',lock):
                self.assertEqual(self.f.prepare_native_lock(lock),lock)
                self.assertTrue(lock.parent.is_dir())
                with self.f.native_lease(lock):
                    with self.assertRaises(BlockingIOError):
                        with self.f.native_lease(self.f.prepare_native_lock(lock)):
                            self.fail('same native lease was not mutually exclusive')

    def test_default_lock_rejects_linked_ancestor_and_custom_lock_parent_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();outside=root/'outside';outside.mkdir()
            (root/'artifacts').symlink_to(outside,target_is_directory=True)
            lock=root/'artifacts'/'campaign'/'native-session.lock'
            with patch.object(self.f,'ROOT',root),patch.object(self.f,'DEFAULT_NATIVE_LOCK',lock):
                with self.assertRaises(ValueError):self.f.prepare_native_lock(lock)
                self.assertFalse((outside/'campaign').exists())
                custom=root/'custom'/'session.lock'
                with self.assertRaises(ValueError):self.f.prepare_native_lock(custom)
                self.assertFalse(custom.parent.exists())

    def test_producer_has_no_arm_acceptance_import_dependency(self):
        sources=self.f.tool_sources()
        self.assertIn('tools/native_session.py',sources)
        self.assertIn('tools/build_sources.py',sources)
        self.assertNotIn('tools/build_unified.py',sources)
        self.assertFalse(any(name.startswith('tools/run_v') or name.startswith('tools/verify_') for name in sources))
        self.assertLessEqual(len(sources),6)

    def test_native_guard_and_lease_are_shared_across_platforms(self):
        common=importlib.import_module('native_session')
        a03=importlib.import_module('run_v16_a03_full_collection')
        a10=importlib.import_module('run_v16_a10_matrix_v4')
        for module in (self.f,a03,a10):
            self.assertIs(module.native_lease,common.native_lease)
            self.assertIs(module.idle_native_host,common.idle_native_host)
        for process in ('qemu-system-aarch64','qemu-system-x86_64','cargo','rustc','clang'):
            with patch.object(common.subprocess,'run') as run:
                run.return_value.stdout='42 /usr/bin/'+process+'\n'
                with self.subTest(process=process),self.assertRaises(ValueError):common.idle_native_host()

    def test_neutral_cache_namespaces_bind_sources_and_checkout(self):
        common=importlib.import_module('build_sources')
        builder=importlib.import_module('build_unified')
        self.assertIs(builder.build_cache_context,common.build_cache_context)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();a=root/'a';b=root/'b';a.mkdir();b.mkdir()
            first=common.build_cache_context(root/'cache',a,{'kernel':'first'})
            self.assertEqual(first,common.build_cache_context(root/'cache',a,{'kernel':'first'}))
            self.assertNotEqual(first['effective'],common.build_cache_context(root/'cache',a,{'kernel':'second'})['effective'])
            self.assertNotEqual(first['effective'],common.build_cache_context(root/'cache',b,{'kernel':'first'})['effective'])

    def test_neutral_source_snapshot_does_not_require_arm_files(self):
        common=importlib.import_module('build_sources');builder=importlib.import_module('build_unified')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.f.subprocess.run(['git','init','--quiet',str(root)],check=True)
            names=('Cargo.lock','Cargo.toml','kernel/src/main.rs','crates/arch-x86_64/src/lib.rs')
            for name in names:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture')
            self.assertEqual(set(common.code_source_map(root)),set(names))
            with self.assertRaisesRegex(ValueError,'incomplete native source'):builder.code_source_map(root)


if __name__=='__main__':unittest.main()
