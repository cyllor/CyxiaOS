"""Regression cases for Rust declaration and use discovery in the G1 audit."""

import unittest

from .verify_v020_g1_parameter_use import DECLARATION, NUMBER, RUST_TEST, definition_span, locations, mask_rust


class RustSourceInventoryTests(unittest.TestCase):
    def test_comment_and_literal_text_cannot_satisfy_an_anchor(self):
        source = '''
/* ignored fake parameter and use
    /* nested comment */
    const BAD: u32 = 55;
    permit(BAD);
*/
let captured = r##"
    const ALSO_BAD: u32 = 99;
    permit(BAD); "# // literal text
    #[test]
    fn fake_test() {}
"##;
const GOOD: u32 = 16;
permit(GOOD);
unpermit(GOOD);
audit.update(b"CYX/RECOVERY/v2");
#[test]
fn real_test() {}
'''
        uncommented, code = mask_rust(source)
        self.assertEqual([match[1] for match in DECLARATION.finditer(code)], ["GOOD"])
        self.assertEqual([match[0] for match in NUMBER.finditer(code)], ["16"])
        self.assertEqual([match[1] for match in RUST_TEST.finditer(code)], ["real_test"])
        self.assertEqual(locations(code, uncommented, "permit(BAD)"), [])
        self.assertEqual(len(locations(code, uncommented, "permit(GOOD)")), 1)
        self.assertEqual(len(locations(code, uncommented, 'audit.update(b"CYX/RECOVERY/v2")')), 1)

    def test_const_initializer_skips_array_types_strings_and_nested_semicolons(self):
        source = '''
pub const LIMITS: [usize; 3] = [
    1, { let n = "a;b".len(); n + 1 }, 3,
];
pub const MARKER: u8 = b';';
'''
        uncommented, code = mask_rust(source)
        expressions = [uncommented[slice(*definition_span(code, decl))].strip()
                       for decl in DECLARATION.finditer(code)]
        self.assertEqual(expressions, ['[\n    1, { let n = "a;b".len(); n + 1 }, 3,\n]', "b';'"])


if __name__ == "__main__":
    unittest.main()
