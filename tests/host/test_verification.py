import unittest
from tools.check_dependencies import validate_graph
from tools.verify_m1 import inspect_instructions
class VerifyTests(unittest.TestCase):
 def test_forbidden_transitive_dependency(self):
  packages=[{'id':'core','name':'cyxia-kernel-core'},{'id':'x','name':'helper'},{'id':'arch','name':'cyxia-arch-aarch64'}]
  graph={'packages':packages,'resolve':{'nodes':[{'id':'core','dependencies':['x']},{'id':'x','dependencies':['arch']},{'id':'arch','dependencies':[]}]}}
  with self.assertRaises(ValueError):validate_graph(graph)
 def test_float_and_simd_rejected(self):
  for text in [' 4000: fmov d0, x0',' 4004: movi v0.16b, #0',' 4004: <unknown>']:
   with self.assertRaises(ValueError):inspect_instructions(text)
 def test_integer_instructions_allowed(self):self.assertEqual(inspect_instructions(' 4000: add x0, x1, #0x10\n 4004: ret'),2)
 def test_mapping_symbol_literal_pool_is_not_code(self):self.assertEqual(inspect_instructions('40200200: 00 d0 28 40  \t.word\t0x4028d000\n40200204: ret'),1)
 def test_fp_state_moves_only_in_explicit_transitions(self):
  text='4000 <cyxia_enter_user>:\n 4000: ldp q0, q1, [x0]\n 4004: msr fpcr, x1\n4010 <cyxia_user_return>:\n 4010: stp q0, q1, [x0]\n 4014: mrs x1, fpsr'
  self.assertEqual(inspect_instructions(text, allow_user_context=True),4)
  with self.assertRaises(ValueError):inspect_instructions(text)
 def test_transition_exception_does_not_allow_other_code(self):
  for text in ['4000 <cyxia_enter_user>:\n 4000: fmov d0, x0', '4000 <cyxia_user_return>:\n 4000: <unknown>', '4000 <irq_handler>:\n 4000: stp q0, q1, [x0]', '4000 <cyxia_enter_user_extra>:\n 4000: ldp q0, q1, [x0]', ' 4000: ldp q0, q1, [x0]', '4000 <cyxia_enter_user>:\n 4000: ret\n4010 <ordinary_fn>:\n 4010: mrs x0, fpcr']:
   with self.subTest(text=text):
    with self.assertRaises(ValueError):inspect_instructions(text, allow_user_context=True)
 def test_bounded_sha_transition_is_exactly_scoped(self):
  text='4000 <cyxia_sha256_compress_hw>:\n 4000: stp q0, q1, [sp, #16]\n 4004: ld1 { v4.16b }, [x1], #16\n 4008: sha256h q0, q1, v15.4s'
  self.assertEqual(inspect_instructions(text),3)
  for bad in ['4000 <ordinary_fn>:\n 4000: sha256h q0, q1, v2.4s', '4000 <cyxia_sha256_compress_hw>:\n 4000: fmov d0, x0', '4000 <cyxia_sha256_compress_hw_extra>:\n 4000: sha256h q0, q1, v2.4s']:
   with self.subTest(text=bad):
    with self.assertRaises(ValueError):inspect_instructions(bad)
 def test_llvm_uppercase_fp_registers_cannot_bypass_scan(self):
  for instruction in ['msr FPCR, x9', 'mrs x9, FPSR']:
   with self.assertRaises(ValueError):inspect_instructions('4000 <irq>:\n 4000: '+instruction, allow_user_context=True)
   self.assertEqual(inspect_instructions('4000 <cyxia_enter_user>:\n 4000: '+instruction, allow_user_context=True),1)
