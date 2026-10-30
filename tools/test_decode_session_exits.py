import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest

from decode_session_exits import decode_session_exits


class SessionExitDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Compile and execute the actual kernel retention helper; this boundary
        # controls only boot/connection inputs and the stopped snapshot wrapper.
        root = pathlib.Path(__file__).resolve().parents[1]
        source = '''
#[path = "HELPER"] mod evidence;
use std::io::Write;
fn main() {
 let mut bank = [0u64; 80];
 let regressed = std::env::args().any(|arg| arg == "clock-regression");
 for (generation, connection, auth, now) in [(1,1,0,2000), (1,2,1,4000), (2,3,1,6000)] {
  let mut r = [0;24];
  r[..12].copy_from_slice(&[1,7,generation,connection,now,12,0x4001,5,2,auth,now-1500,4]);
  if regressed && connection == 3 {
   r[4]=3000; r[5]=6; r[6]=0x1004; r[7]=8; r[10]=4500;
  }
  assert!(evidence::retain(&mut bank,&r,7,generation,connection));
 }
 let mut words = [0u64;512];
 words[0]=0x435958554e493031; words[1]=7; words[6]=201; words[30]=2;
 words[432..].copy_from_slice(&bank);
 for word in words { std::io::stdout().write_all(&word.to_le_bytes()).unwrap(); }
}'''.replace('HELPER', str(root / 'kernel/src/unified_session_exit.rs'))
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)
            (path / 'fixture.rs').write_text(source)
            rustc = shutil.which('rustc') or str(pathlib.Path.home() / '.cargo/bin/rustc')
            subprocess.run([rustc, '--edition=2024', str(path / 'fixture.rs'), '-o', str(path / 'fixture')], check=True)
            cls.snapshot = subprocess.check_output([str(path / 'fixture')])
            cls.clock_regression_snapshot = subprocess.check_output([str(path / 'fixture'), 'clock-regression'])

    def decode(self, data=None, **kwargs):
        return decode_session_exits(self.snapshot if data is None else data,
                                   boot=kwargs.get('boot', 7), service_generation=kwargs.get('service_generation', 2))

    def test_actual_source_retains_original_and_latest_without_accepting_overflow(self):
        result = self.decode()
        self.assertEqual(result['counts'], {'unauthenticated': 1, 'authenticated': 2})
        self.assertEqual(result['first_authenticated']['service_generation'], 1)
        self.assertEqual(result['latest_authenticated']['service_generation'], 2)
        self.assertEqual(result['latest_authenticated']['reason'], 'driver_tick')
        self.assertEqual(result['latest_authenticated']['result'], 'driver_idle_timeout')
        self.assertFalse(result['ordinary_events_complete'])
        self.assertFalse(result['complete_session_history'])
        self.assertFalse(result['native_pass'])

    def test_malformed_and_cross_generation_evidence_rejected(self):
        for index, value in [(432, 5), (433, 0), (434, 2), (435, 0), (438, 3), (439, 1),
                             (440, 9), (441, 8), (442, 3), (445, 99), (446, 999), (447, 99),
                             (449, 99), (463, 1)]:
            words = list(struct.unpack('<512Q', self.snapshot))
            words[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.decode(struct.pack('<512Q', *words))
        for kwargs in [dict(boot=8), dict(service_generation=1), dict(service_generation=3)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.decode(**kwargs)
        with self.assertRaises(ValueError):
            self.decode(self.snapshot[:-1])
        with self.assertRaises(ValueError):
            self.decode(bytes(4096))

    def test_actual_producer_clock_regression_preserves_latest_exit(self):
        try:
            result = self.decode(self.clock_regression_snapshot)
        except ValueError as error:
            self.fail(f'producer-accepted clock regression must decode: {error}')
        self.assertEqual(result['counts'], {'unauthenticated': 1, 'authenticated': 2})
        self.assertEqual(result['first_authenticated']['ms'], 4000)
        latest = result['latest_authenticated']
        self.assertEqual((latest['ms'], latest['last_rx_ms']), (3000, 4500))
        self.assertEqual((latest['reason'], latest['result'], latest['origin']),
                         ('tls_pump', 'tls_clock', 'runtime'))
        self.assertEqual((latest['boot'], latest['service_generation'], latest['connection_epoch']), (7, 2, 3))
        self.assertFalse(result['ordinary_events_complete'])
        self.assertFalse(result['complete_session_history'])
        self.assertFalse(result['native_pass'])

        # Regressed last_rx remains invalid for a non-Clock result; accepting
        # this slot must not relax individual record validation.
        words = list(struct.unpack('<512Q', self.clock_regression_snapshot))
        words[432 + 56 + 6] = 0x4001
        with self.assertRaisesRegex(ValueError, 'malformed session-exit record'):
            self.decode(struct.pack('<512Q', *words))


if __name__ == '__main__':
    unittest.main()
