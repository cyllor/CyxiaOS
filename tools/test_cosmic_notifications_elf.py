"""Adversarial static ELF fixtures; these never execute a compiler or guest."""
import copy
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from tools import cosmic_notifications_elf as subject
from tools.build_sysroot import BuildError, inspect_elf


PROFILE = dict(image_bytes=64 * 1024 * 1024, max_elf_bytes=64 * 1024 * 1024,
               stack_bytes=2 * 1024 * 1024, target_runtime_validated=False)
FIELDS = ('type', 'flags', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'align')


def ph(data, index, **changes):
    offset = 64 + index * 56
    old = dict(zip(FIELDS, struct.unpack_from('<IIQQQQQQ', data, offset)))
    old.update(changes)
    struct.pack_into('<IIQQQQQQ', data, offset, *(old[name] for name in FIELDS))


def fixture(*, high=0x02001000):
    """Three LOADs and every optional header understood by the real parser."""
    data = bytearray(0x4000)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0,
                     b'\x7fELF\x02\x01\x01' + bytes(9), 2, 62, 1,
                     high, 64, 0x3800, 0, 64, 56, 9, 64, 4, 0)
    headers = [
        (6, 4, 64, 0x01000040, 0x01000040, 9 * 56, 9 * 56, 8),
        (1, 4, 0, 0x01000000, 0x01000000, 4096, 4096, 4096),
        (1, 5, 4096, high, high, 256, 4096, 4096),
        (1, 6, 8192, high + 4096, high + 4096, 256, 4096, 4096),
        (7, 4, 8192, high + 4096, high + 4096, 16, 32, 8),
        (0x6474e552, 4, 8192, high + 4096, high + 4096, 256, 4096, 1),
        (0x6474e550, 4, 0x400, 0x01000400, 0x01000400, 16, 16, 4),
        (0x6474e551, 6, 0, 0, 0, 0, 0, 0),
        (4, 4, 0x500, 0x01000500, 0x01000500, 20, 20, 4),
    ]
    for index, values in enumerate(headers):
        struct.pack_into('<IIQQQQQQ', data, 64 + index * 56, *values)
    struct.pack_into('<III4s4s', data, 0x500, 4, 4, 3, b'GNU\0', b'id00')
    # Null, .text, .symtab, .strtab. One genuinely defined strong _start symbol.
    struct.pack_into('<IIQQQQIIQQ', data, 0x3800 + 64, 0, 1, 6, high, 4096, 256, 0, 0, 16, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 0x3800 + 128, 0, 2, 0, 0, 0x3000, 48, 3, 1, 8, 24)
    struct.pack_into('<IIQQQQIIQQ', data, 0x3800 + 192, 0, 3, 0, 0, 0x3100, 8, 0, 0, 1, 0)
    struct.pack_into('<IBBHQQ', data, 0x3000 + 24, 1, 0x12, 0, 1, high, 16)
    data[0x3100:0x3108] = b'\0_start\0'
    return data


class FullOsElf(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / 'notification.elf'

    def inspect(self, data=None, profile=None):
        self.path.write_bytes(fixture() if data is None else data)
        return subject.inspect_full_os_elf(self.path, PROFILE if profile is None else profile)

    def reject(self, data, message=None):
        with self.assertRaisesRegex(subject.FullOsElfError, message or '.'):
            self.inspect(data)

    def test_full_os_fixture_keeps_legacy_failure_and_complete_contract(self):
        result = self.inspect()
        self.assertEqual(result['profile'], 'full-os-v3')
        self.assertEqual(result['image_load_pages'], 3)
        self.assertEqual(result['required_pages'], 515)
        self.assertIs(result['legacy_window_exceeded'], True)
        self.assertEqual(result['executable']['file'], self.path.name)
        self.assertEqual(result['executable']['machine'], 62)
        self.assertEqual(len(result['executable']['program_headers']), 9)
        self.assertEqual(result['loader_contract'], subject.loader_contract())
        with self.assertRaisesRegex(BuildError, 'Invalid LOAD bounds'):
            inspect_elf(self.path, 'x86_64')

    def test_legacy_sized_file_matches_frozen_inspection_without_claiming_range_failure(self):
        result = self.inspect(fixture(high=0x01010000))
        legacy = inspect_elf(self.path, 'x86_64')
        legacy['file'] = self.path.name
        self.assertEqual(result['executable'], legacy)
        self.assertIs(result['legacy_window_exceeded'], False)

    def test_arbitrary_profiles_cannot_expand_or_change_the_contract(self):
        self.path.write_bytes(fixture())
        candidates = [None, 'full-os-v3', {}, dict(PROFILE, target_runtime_validated=0)]
        for key, value in [('image_bytes', 128 * 1024 * 1024), ('max_elf_bytes', True),
                           ('max_elf_bytes', float(PROFILE['max_elf_bytes'])),
                           ('stack_bytes', 4096), ('target_runtime_validated', True)]:
            candidates.append(dict(PROFILE, **{key: value}))
        for profile in candidates:
            with self.subTest(profile=profile), self.assertRaises(subject.FullOsElfError):
                subject.inspect_full_os_elf(self.path, profile)

    def test_reviewed_production_contract_rejects_drift(self):
        contracts = self.root / 'contracts'
        for name in subject.loader_contract():
            destination = contracts / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(subject.ROOT / name, destination)
        with mock.patch.object(subject, 'ROOT', contracts):
            self.inspect()
            path = contracts / 'crates/posix/src/executable.rs'
            path.write_bytes(path.read_bytes() + b'\n// unreviewed parser drift\n')
            with self.assertRaisesRegex(subject.FullOsElfError, 'Reviewed loader contract changed'):
                self.inspect()

    def test_only_bounded_regular_unlinked_inputs_are_read(self):
        self.path.write_bytes(fixture())
        link = self.root / 'link.elf'; link.symlink_to(self.path)
        directory_link = self.root / 'linked-directory'; directory_link.symlink_to(self.root, target_is_directory=True)
        fifo = self.root / 'fifo'
        import os
        os.mkfifo(fifo)
        oversized = self.root / 'oversized'
        with oversized.open('wb') as stream:
            stream.truncate(PROFILE['max_elf_bytes'] + 1)
        for path in (link, directory_link / self.path.name, fifo, oversized,
                     self.root, self.root / 'missing', self.root / '..' / self.path.name):
            with self.subTest(path=path), self.assertRaises(subject.FullOsElfError):
                subject.inspect_full_os_elf(path, PROFILE)

    def test_file_replacement_during_read_is_rejected(self):
        self.path.write_bytes(fixture())
        actual_fdopen = subject.os.fdopen

        class ReplaceAfterRead:
            def __init__(inner, stream): inner.stream = stream
            def __enter__(inner): return inner
            def __exit__(inner, *args): inner.stream.close()
            def read(inner, size):
                result = inner.stream.read(size)
                replacement = self.path.with_suffix('.replacement')
                replacement.write_bytes(result)
                replacement.replace(self.path)
                return result

        def open_stream(fd, *args, **kwargs):
            stream = actual_fdopen(fd, *args, **kwargs)
            # The four source-contract reads remain real and unchanged.
            return ReplaceAfterRead(stream) if subject.os.fstat(fd).st_size == 0x4000 else stream

        with mock.patch.object(subject.os, 'fdopen', side_effect=open_stream):
            with self.assertRaisesRegex(subject.FullOsElfError, 'changed during'):
                subject.inspect_full_os_elf(self.path, PROFILE)

    def test_wrong_isa_and_elf_identity_are_rejected(self):
        mutations = [('B', 7, 255), ('B', 8, 1), ('B', 9, 1), ('H', 16, 3),
                     ('H', 18, 183), ('I', 20, 2), ('I', 48, 1), ('H', 52, 63), ('H', 54, 55)]
        for fmt, offset, value in mutations:
            with self.subTest(offset=offset):
                data = fixture(); struct.pack_into('<' + fmt, data, offset, value)
                self.reject(data)
        self.reject(b'\x7fELF')

    def test_header_tables_cannot_be_truncated_misaligned_or_unbounded(self):
        for fmt, offset, value in [('H', 56, 0), ('H', 56, 33), ('Q', 32, 65),
                                   ('Q', 32, 0x3ff8), ('H', 58, 63), ('Q', 40, 0x3ff0)]:
            with self.subTest(offset=offset, value=value):
                data = fixture(); struct.pack_into('<' + fmt, data, offset, value)
                self.reject(data)

    def test_dynamic_interpreter_and_unknown_program_headers_are_rejected(self):
        for kind in (2, 3, 0x6474e553, 0x12345678):
            with self.subTest(kind=kind):
                data = fixture(); ph(data, 8, type=kind); self.reject(data, 'unsupported')

    def test_no_more_than_sixteen_loads_are_admitted(self):
        data = bytearray(0x14000)
        struct.pack_into('<16sHHIQQQIHHHHHH', data, 0,
                         b'\x7fELF\x02\x01\x01' + bytes(9), 2, 62, 1,
                         0x01001000, 64, 0, 0, 64, 56, 18, 64, 0, 0)
        struct.pack_into('<IIQQQQQQ', data, 64, 6, 4, 64, 0x01000040, 0x01000040, 1008, 1008, 8)
        for i in range(17):
            address = 0x01000000 + i * 4096
            struct.pack_into('<IIQQQQQQ', data, 64 + (i + 1) * 56,
                             1, 4 if i == 0 else 5, i * 4096, address, address, 4096, 4096, 4096)
        self.reject(data, 'Too many LOAD')

    def test_load_permissions_alignment_backing_and_bounds_are_preserved(self):
        mutations = [{'flags': v} for v in (0, 1, 2, 3, 7, 12)]
        mutations += [{'align': 2048}, {'align': 3}, {'offset': 4097}, {'memsz': 0},
                      {'filesz': 4097}, {'offset': 0x4000}, {'vaddr': 0x00fff000},
                      {'vaddr': 0x05000000}, {'memsz': (1 << 64) - 1}]
        for changes in mutations:
            with self.subTest(changes=changes):
                data = fixture(); ph(data, 2, **changes); self.reject(data)

    def test_load_page_overlap_is_rejected_even_with_matching_permissions(self):
        for flags in (5, 6):
            data = fixture(); ph(data, 3, flags=flags, vaddr=0x02001200, offset=0x2200)
            self.reject(data, 'Overlapping LOAD pages')

    def test_entry_cannot_use_bss_nonexecutables_or_unmapped_bytes(self):
        for entry in (0x02001100, 0x02002000, 0x03000000, (1 << 64) - 1):
            data = fixture(); struct.pack_into('<Q', data, 24, entry)
            self.reject(data, 'Entry point')

    def test_phdr_requires_exact_readable_file_mapping(self):
        for changes in ({'type': 0}, {'flags': 6}, {'offset': 72}, {'vaddr': 0x01000048},
                        {'filesz': 503}, {'memsz': 505}, {'align': 3}):
            with self.subTest(changes=changes):
                data = fixture(); ph(data, 0, **changes); self.reject(data)
        data = fixture(); ph(data, 1, filesz=64); self.reject(data, 'PHDR')

    def test_undefined_strong_symbols_are_rejected_but_weak_remain_static(self):
        data = fixture(); struct.pack_into('<H', data, 0x3000 + 24 + 6, 0)
        self.reject(data, 'Unresolved strong symbol')
        data[0x3000 + 24 + 4] = 0x22
        self.assertIs(self.inspect(data)['legacy_window_exceeded'], True)

    def test_symbol_table_shape_and_backing_cannot_be_bypassed(self):
        section = 0x3800 + 128
        for offset, value in ((56, 23), (32, 47), (24, 0x3ff0)):
            data = fixture(); struct.pack_into('<Q', data, section + offset, value)
            self.reject(data)

    def test_tls_template_requires_exact_file_offset_and_valid_extent(self):
        for changes in ({'flags': 5}, {'filesz': 33}, {'align': 3}, {'offset': 8200},
                        {'memsz': 0x04000001}, {'vaddr': 0x05000000}):
            with self.subTest(changes=changes):
                data = fixture(); ph(data, 4, **changes); self.reject(data, 'TLS')

    def test_pure_tbss_template_may_have_no_file_backed_load(self):
        data = fixture(); ph(data, 4, filesz=0, memsz=32, offset=len(data), vaddr=0x03000000)
        self.assertEqual(self.inspect(data)['image_load_pages'], 3)

    def test_gnu_property_and_truncated_notes_are_rejected(self):
        data = fixture(); struct.pack_into('<I', data, 0x508, 5)
        self.reject(data, 'GNU property')
        for offset in (0x500, 0x504):
            data = fixture(); struct.pack_into('<I', data, offset, 100)
            self.reject(data, 'Truncated ELF note')
        data = fixture(); ph(data, 8, filesz=4); self.reject(data, 'Truncated ELF note header')

    def test_relro_must_be_covered_by_writable_load_memory(self):
        for changes in ({'flags': 5}, {'memsz': 0}, {'memsz': 128}, {'memsz': 8192},
                        {'vaddr': 0x02001000}, {'offset': 0x4000}):
            with self.subTest(changes=changes):
                data = fixture(); ph(data, 5, **changes); self.reject(data)

    def test_unwind_header_must_describe_actual_readable_file_bytes(self):
        for changes in ({'flags': 6}, {'filesz': 0}, {'memsz': 17}, {'offset': 0x404},
                        {'vaddr': 0x03000000}, {'align': 3}):
            with self.subTest(changes=changes):
                data = fixture(); ph(data, 6, **changes); self.reject(data, 'unwind')

    def test_stack_is_nonexecutable_and_bounded_to_two_mib(self):
        for changes in ({'flags': 7}, {'filesz': 1}, {'align': 3}, {'memsz': 0x201000}):
            data = fixture(); ph(data, 7, **changes); self.reject(data, 'stack')

    def test_optional_headers_cannot_be_duplicated(self):
        for kind in (6, 7, 0x6474e550, 0x6474e551, 0x6474e552):
            data = fixture(); ph(data, 8, type=kind); self.reject(data, 'Duplicate')

    def test_image_page_budget_includes_the_fixed_stack(self):
        data = fixture(); struct.pack_into('<H', data, 56, 3)
        struct.pack_into('<Q', data, 24, 0x01001000)
        ph(data, 0, filesz=168, memsz=168)
        ph(data, 2, vaddr=0x01001000, memsz=64 * 1024 * 1024 - 4096)
        self.reject(data, 'LOAD pages and stack exceed')


if __name__ == '__main__':
    unittest.main()
