"""Regression checks for the stopped-guest DMA FrameMeta readback."""
import unittest
from unittest.mock import Mock, patch

from v020_frame_meta import FRAME_ROW, PAGE, PERMANENT_ROW, RAM_BASE, queue_dma_rows


class QueueDmaRows(unittest.TestCase):
    def setUp(self):
        self.rows = [PERMANENT_ROW] * 19
        self.row = (0x80003e00, 4, 1, 1, 0, 1, 1, 0)
        self.qmp = Mock()
        self.qmp.execute.return_value = "000000000a003e08: 0x00000002\r\n"
        patcher = patch("v020_frame_meta.symbol", side_effect=self.symbol)
        patcher.start()
        self.addCleanup(patcher.stop)

    def symbol(self, image, name):
        if name in ("__sec_n_dma_start", "V020_DMA_BLOCK_QUEUE"):
            return {"pa": RAM_BASE, "size": 19 * PAGE}
        if name == "__sec_n_dma_end":
            return {"pa": RAM_BASE + 19 * PAGE, "size": 0}
        raise ValueError(f"missing symbol {name}")

    def inspect(self, required):
        raw = b"".join(FRAME_ROW.pack(*row) for row in self.rows)
        return queue_dma_rows(self.qmp, b"elf", raw, required)

    def test_ownership_requires_all_pages_and_actual_device_id(self):
        self.rows[:] = [self.row] * len(self.rows)
        rows, owners = self.inspect({"block"})
        self.assertEqual(rows, dict.fromkeys(range(19), self.row))
        self.assertEqual(owners["block"]["transport_pa"], "0xa003e00")
        self.qmp.execute.assert_called_once_with("human-monitor-command",
                                                {"command-line": "xp/1wx 0xa003e08"})
        self.qmp.execute.return_value = "000000000a003e08: 0x00000004\r\n"
        with self.assertRaisesRegex(ValueError, "does not identify"):
            self.inspect({"block"})

    def test_partial_or_unexpected_assignment_fails_closed(self):
        self.rows[0] = self.row
        with self.assertRaisesRegex(ValueError, "incomplete block DMA"):
            self.inspect({"block"})
        with self.assertRaisesRegex(ValueError, "inactive block DMA"):
            self.inspect(set())


if __name__ == "__main__":
    unittest.main()
