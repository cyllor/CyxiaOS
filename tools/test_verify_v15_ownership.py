"""Structural mutation vectors; synthetic host data never confers native PASS."""
import struct
import unittest

from verify_v15_ownership import MAGIC, WORDS, ROW_WORDS, validate_structure


def fixture():
    w = [0] * WORDS
    w[:12] = [MAGIC, 1, WORDS, 7, 2, 0, 0, 0, ROW_WORDS, 8, 2, 2]
    w[16:30] = list(range(1, 15))
    for i, (old, new) in enumerate(((2, 6), (6, 2))):
        at = 128 + i * ROW_WORDS
        r = [0] * ROW_WORDS
        r[:18] = [10, 31, 7, 1, 20 + i, 0, 50, 1, new, 100 + i * 2000,
                   120 + i * 2000, i + 1, i + 1, 0, 20 + i, 2, 32, 3 + i]
        r[18:20]=[1+i*2,9+i*3]
        for j, mask in enumerate((old, old, new, new)):
            r[32 + j * 16:48 + j * 16] = [120 + i * 2000 + j * 10, 15,
                mask, 15 ^ mask, 0, 0, 4 if j == 1 else 0, 0,
                1 + i * 2 + min(j,2), 9 + i * 3 + j, 1, 900, 300,
                63 if j >= 2 else 0, i + 1 if j else 0, i + 1 if j >= 2 else 0]
        h = r[128:160]
        h[:4] = [0x435958444f4d3031, 1, 7, (1 << 18) - 1]
        h[12:15] = [64, 640, 1]
        h[16:24] = [1] * 8
        r[128:160] = h
        record = [0] * 640
        record[:10] = [20 + i, 20 + i, 1, 2, 50, 1, 1, 7, 100 + i * 2000, 110 + i * 2000]
        record[13:18] = [i + 1, 2, 0, 2, i]
        record[19] = 1
        record[21:25] = [1] * 4
        record[28] = 160 + i * 2000
        record[30] = 1
        record[32:48] = [0x4359585254494e31, 3, 20 + i, 1, 100 + i * 2000,
                          1_000_000, 1 + i * 2, 9 + i * 3, 1, 2, 50, 1, i, 1, 7, 2]
        record[68:71] = [20 + i] * 3
        record[432:436] = [old, 15 ^ old, 15, 0]
        record[639] = 6
        r[192:832] = record
        w[at:at + ROW_WORDS] = r
    return w


def check(w):
    return validate_structure(struct.pack('<' + str(len(w)) + 'Q', *w))


class OwnershipStructure(unittest.TestCase):
    def test_complete_model_apply_handoff_owner_receipt_chain(self):
        self.assertEqual(check(fixture())['control_sets'], [2, 6, 2])

    def test_only_proposal_or_scripted_fixture_is_rejected(self):
        for offset, value in ((1, 3), (15, 0), (192 + 33, 1), (192 + 14, 1),
                              (192 + 30, 0), (192 + 2, 2), (128 + 3, 0)):
            w = fixture()
            w[128 + offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(w)

    def test_apply_decision_target_plan_and_boot_mismatch_are_rejected(self):
        for offset in (2, 3, 4, 5, 6, 7, 8, 11, 12, 14,18,19):
            w = fixture()
            w[128 + offset] += 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(w)

    def test_missing_stop_proof_double_owner_and_non_linear_publication_are_rejected(self):
        for offset, value in ((64 + 13, 31), (64 + 15, 0), (64 + 2, 2),
                              (64 + 3, 13), (64 + 4, 4), (64 + 6, 4),
                              (64 + 7, 4), (64 + 8, 1), (48 + 2, 6)):
            w = fixture()
            w[128 + offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(w)

    def test_capacity_spending_cannot_disappear_inside_one_window(self):
        for offset, value in ((64 + 11, 200), (64 + 12, 0)):
            w = fixture()
            w[128 + offset] = value
            with self.assertRaises(ValueError):
                check(w)

    def test_truncated_lost_unsealed_or_wrong_run_bank_is_rejected(self):
        for offset, value in ((0, 0), (4, 1), (5, 1), (6, 2), (16, 0), (128, 3)):
            w = fixture()
            w[offset] = value
            if offset == 16:
                w[17] = 0
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check(w)
        with self.assertRaises(ValueError):
            check(fixture()[:-1])


class OwnershipCaptureProvenance(unittest.TestCase):
    def calls(self):
        from test_verify_v13_boot_receipt import calls,ROOT
        rows=[]
        for entry in calls():
            rows.append(entry)
            if entry[0]=='pmemsave' and entry[1]['filename'].endswith(('/first.bin','/last.bin')):
                name='ownership-first.bin' if entry[1]['filename'].endswith('/first.bin') else 'ownership-last.bin'
                rows.append(('pmemsave',{'val':0x41700000,'size':WORDS*8,'filename':str(ROOT/name)},{}))
        return rows

    def replay(self,entries):
        from test_verify_v13_boot_receipt import SYMBOLS,PLATFORM,ROOT,transcript
        from verify_v13_boot_receipt import verify_qmp
        return verify_qmp(transcript(entries),ROOT,dict(SYMBOLS,ownership={'pa':0x41700000}),64,
                          PLATFORM,ownership=True)

    def test_both_exact_stopped_owner_captures_are_required(self):
        original=self.calls()
        self.assertEqual(self.replay(original),b'raw serial')
        for i,e in enumerate(original):
            if e[0]=='pmemsave' and '/ownership-' in e[1]['filename']:
                with self.assertRaises(ValueError):self.replay(original[:i]+original[i+1:])
                for field,value in (('val',0x41700008),('size',WORDS*8-8)):
                    changed=original.copy();changed[i]=(e[0],dict(e[1],**{field:value}),e[2])
                    with self.assertRaises(ValueError):self.replay(changed)

    def test_live_capture_or_correct_bytes_from_wrong_address_are_not_evidence(self):
        entries=self.calls()
        i=next(i for i,e in enumerate(entries) if e[0]=='pmemsave'
               and e[1]['filename'].endswith('/ownership-first.bin'))
        entry=entries.pop(i)
        stop=next(i for i,e in enumerate(entries) if e[0]=='stop')
        entries.insert(stop,entry)
        with self.assertRaises(ValueError):self.replay(entries)


if __name__ == '__main__':
    unittest.main()
