"""Exercise the linked vector oracle with isolated instruction mismatches."""

import unittest

from tools import check_v0199_el1_vectors as checker


class VectorChecks(unittest.TestCase):
    def layout(self):
        table = 0x8000
        symbols = {
            **dict.fromkeys(checker.STACK_GATE_LABELS, 0),
            "__exception_scratch": 0x48000,
            "__exception_stacks": 0x50000,
            "__stack_base": 0x20000,
            "__stack_top": 0x60000,
            "SMP_STACK_TOPS": 0x1D000,
            "EXCEPTION_ADMISSION_CLOSED": 0x44000,
            "exception_dispatch": 0x16000,
            "exception_quiescent_stop": 0x16100,
            "high_entry": 0x17000,
            "secondary_high": 0x17100,
            "secondary_high_halt": 0x17150,
        }
        route_words = len(checker.vector_route(0, 0, symbols))
        frames = [table + checker.TABLE_BYTES + kind * route_words * 4 for kind in range(checker.VECTOR_COUNT)]
        start = frames[-1] + route_words * 4
        for name, ops in checker.stack_gate_sequences(symbols).items():
            symbols[name] = start
            start += 4 * len(ops)

        instructions = {symbols["exception_dispatch"]: "ret", symbols["exception_quiescent_stop"]: "wfe"}
        literals = {}

        def write(pc, ops):
            for op in ops:
                if isinstance(op, tuple):
                    reg, value = op
                    literal = 0x19000 + 8 * len(literals)
                    literals[literal] = value
                    op = f"ldr {reg},{literal:#x}"
                instructions[pc] = op
                pc += 4

        for kind, frame in enumerate(frames):
            slot = table + kind * checker.VECTOR_STRIDE
            write(slot, [f"b {frame:#x}"] + ["nop"] * 31)
            write(frame, checker.vector_route(kind, frame, symbols))
        for name, ops in checker.stack_gate_sequences(symbols).items():
            write(symbols[name], ops)
        write(symbols["high_entry"], [
            "mov x0,#0x0", ("x1", symbols["__stack_base"]), ("x2", symbols["__stack_top"]),
        ])
        write(symbols["secondary_high"], [
            ("x0", symbols["SMP_STACK_TOPS"]), "ldr x2,[x0,x19,lsl #3]",
            f"cbz x2,{symbols['secondary_high_halt']:#x}", "mov sp,x2", "mov x0,x19",
            "sub x1,x2,#0x10,lsl #12",
        ])
        register = symbols["exception_register_stack"]
        for name, offset in checker.WRITER_OFFSETS.items():
            write(symbols[name] + offset - 8, [
                f"bl {register:#x}", ("x0", table), checker.VBAR_STORE, "isb",
            ])
        return instructions, table, frames, symbols, literals.__getitem__

    def test_complete_slots_and_frame_sequences(self):
        instructions, table, _, symbols, read_literal = layout = self.layout()
        routes = checker.check_vectors(*layout)
        self.assertEqual([entry["kind"] for entry in routes], list(range(16)))
        self.assertEqual([entry["slot_va"] for entry in routes[12:]],
                         ["0x8600", "0x8680", "0x8700", "0x8780"])
        checker.check_stack_gate(instructions, symbols, read_literal)
        self.assertEqual(len(checker.check_writers(instructions, table, symbols, read_literal)), 2)

    def test_vector_alias_and_wrong_kind_are_reported(self):
        instructions, table, frames, _, _ = layout = self.layout()
        slot = table + 12 * checker.VECTOR_STRIDE
        instructions[slot] = f"b {frames[8]:#x}"
        with self.assertRaisesRegex(ValueError, "vector slot 12"):
            checker.check_vectors(*layout)
        instructions[slot] = f"b {frames[12]:#x}"
        instructions[frames[12] + 0x68] = "mov x1,#0x8"
        with self.assertRaisesRegex(ValueError, "vector route 12"):
            checker.check_vectors(*layout)

    def test_stack_frame_requires_full_precheck(self):
        instructions, _, _, symbols, read_literal = self.layout()
        headroom_check = symbols["exception_check_sp"] + 16
        instructions[headroom_check] = "add x6,x4,#0x120"
        with self.assertRaisesRegex(ValueError, "exception_check_sp"):
            checker.check_stack_gate(instructions, symbols, read_literal)

    def test_restore_requires_all_integer_registers(self):
        instructions, _, _, symbols, read_literal = self.layout()
        address = next(pc for pc, op in instructions.items() if op == "ldp x28,x29,[x30,#0xe0]")
        del instructions[address]
        with self.assertRaisesRegex(ValueError, r"expected 'ldp x28,x29"):
            checker.check_stack_gate(instructions, symbols, read_literal)

    def test_emergency_stack_switch_and_second_entry_stop_are_required(self):
        instructions, _, _, symbols, read_literal = self.layout()
        instructions[symbols["exception_emergency"] + 48] = "nop"
        with self.assertRaisesRegex(ValueError, "expected 'mov sp,x4'"):
            checker.check_stack_gate(instructions, symbols, read_literal)
        instructions[symbols["exception_emergency"] + 48] = "mov sp,x4"
        instructions[symbols["exception_busy"] + 16] = f"b {symbols['exception_entry']:#x}"
        with self.assertRaisesRegex(ValueError, "exception_busy"):
            checker.check_stack_gate(instructions, symbols, read_literal)

    def test_only_boot_writes_vbar_and_cookie(self):
        instructions, table, _, symbols, read_literal = self.layout()
        instructions[symbols["high_entry"] + 24] = "nop"
        with self.assertRaisesRegex(ValueError, "expected 'isb'"):
            checker.check_writers(instructions, table, symbols, read_literal)
        instructions[symbols["high_entry"] + 24] = "isb"
        instructions[0x17200] = "msr contextidr_el1,x9"
        with self.assertRaisesRegex(ValueError, "entry CPU slot has an unexpected writer"):
            checker.check_writers(instructions, table, symbols, read_literal)
        instructions[0x17200] = "msr vbar_el1,x9"
        with self.assertRaisesRegex(ValueError, "writer set differs"):
            checker.check_writers(instructions, table, symbols, read_literal)


if __name__ == "__main__":
    unittest.main()
