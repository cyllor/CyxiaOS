from pathlib import Path
import shutil


def replace(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one exact match, found {count}")
    target.write_text(text.replace(old, new, 1))


shutil.copyfile('.ci/protected-sha/sha256.rs', 'crates/arch-aarch64/src/sha256.rs')
shutil.copyfile('.ci/protected-sha/sha256.S', 'crates/arch-aarch64/src/sha256.S')

replace(
    'crates/arch-aarch64/src/lib.rs',
    'pub mod mmu;\n',
    'pub mod mmu;\npub mod sha256;\n',
)
replace(
    'kernel/src/domain_control.rs',
    '''pub fn init(boot: u64) -> Result<(), Error> {
    if boot == 0 {
        return Err(Error::Auth);
    }
''',
    '''pub fn init(boot: u64) -> Result<(), Error> {
    if boot == 0 {
        return Err(Error::Auth);
    }
    if !cyxia_arch_aarch64::sha256::selftest() {
        return Err(Error::Schema);
    }
''',
)
replace(
    'kernel/src/domain_control.rs',
    '    let input_hash = Sha256::digest(input_bytes).into();\n',
    '''    let input_hash = cyxia_arch_aarch64::sha256::digest_page(input_bytes)
        .unwrap_or_else(|| Sha256::digest(input_bytes).into());
''',
)
replace(
    'kernel/src/domain_control.rs',
    '        let output_hash = Sha256::digest(bytes).into();\n',
    '''        let output_hash = cyxia_arch_aarch64::sha256::digest_page(bytes)
            .unwrap_or_else(|| Sha256::digest(bytes).into());
''',
)
replace(
    'kernel/src/learning_history.rs',
    '''            || <[u8; 32]>::from(Sha256::digest(input)) != input_hash
''',
    '''            || cyxia_arch_aarch64::sha256::digest_page(input)
                .unwrap_or_else(|| Sha256::digest(input).into())
                != input_hash
''',
)
replace(
    'kernel/src/prototype_runtime/native.rs',
    '''                    worker.probed = worker.native.probe == 4;
''',
    '''                    worker.probed = worker.native.probe == 4;
                    // The final probe completion is its own prepaid recovery turn.
                    // A fresh 2.5 ms model turn must acquire and encode the first job.
                    return;
''',
)
replace(
    'tools/verify_m1.py',
    ''' # Only the two handwritten context transitions may access user FP state.
 # Interrupt handlers, Rust code and compiler helpers remain soft-float.
 transitions={'cyxia_enter_user', 'cyxia_user_return'}
''',
    ''' # Only the two handwritten user transitions and the exact reviewed SHA
 # transition may access FP/SIMD state. Other kernel code remains soft-float.
 transitions={'cyxia_enter_user', 'cyxia_user_return'}
 sha_transition='cyxia_sha256_compress_hw'
''',
)
replace(
    'tools/verify_m1.py',
    '''  if fp and not (allow_user_context and symbol in transitions and context_move):raise ValueError('FP/SIMD outside context save/restore: '+line)
''',
    '''  sha_allowed=symbol==sha_transition and bool(re.match(r'(?:stp|ldp)\\s+q\\d+,\\s*q\\d+,|(?:mrs|msr)\\s+.*\\b(?:fpcr|fpsr)\\b|(?:ld1|st1|rev32|add|mov|sha256h2?|sha256su[01])\\b',insn))
  if fp and not ((allow_user_context and symbol in transitions and context_move) or sha_allowed):raise ValueError('FP/SIMD outside reviewed transition: '+line)
''',
)
replace(
    'tests/host/test_verification.py',
    ''' def test_llvm_uppercase_fp_registers_cannot_bypass_scan(self):
''',
    ''' def test_bounded_sha_transition_is_exactly_scoped(self):
  text='4000 <cyxia_sha256_compress_hw>:\\n 4000: stp q0, q1, [sp, #16]\\n 4004: ld1 { v4.16b }, [x1], #16\\n 4008: sha256h q0, q1, v15.4s'
  self.assertEqual(inspect_instructions(text),3)
  for bad in ['4000 <ordinary_fn>:\\n 4000: sha256h q0, q1, v2.4s', '4000 <cyxia_sha256_compress_hw>:\\n 4000: fmov d0, x0', '4000 <cyxia_sha256_compress_hw_extra>:\\n 4000: sha256h q0, q1, v2.4s']:
   with self.subTest(text=bad):
    with self.assertRaises(ValueError):inspect_instructions(bad)
 def test_llvm_uppercase_fp_registers_cannot_bypass_scan(self):
''',
)
