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
