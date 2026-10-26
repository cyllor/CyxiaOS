#!/usr/bin/env python3
"""Static contract checks for the locked CyxiaOS QEMU PMU patch."""
from __future__ import annotations

import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATCH = ROOT / "tools" / "qemu" / "cyxia-per-vcpu-pmu.patch"


class QemuPmuPatchContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = PATCH.read_text(encoding="utf-8")

    def test_patch_is_well_formed(self) -> None:
        subprocess.run(
            ["git", "apply", "--stat", str(PATCH)],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_times_only_translated_guest_execution(self) -> None:
        self.assertIn("qemu_thread_jit_execute();\n+    cyxia_cpu_exec_start(cpu);", self.text)
        self.assertIn("tcg_qemu_tb_exec(cpu_env(cpu), tb_ptr);\n+    cyxia_cpu_exec_stop(cpu);", self.text)
        self.assertNotIn("return (uint64_t)ts.tv_sec * ARM_CPU_FREQ", self.text)

    def test_longjmp_closes_active_interval(self) -> None:
        self.assertIn("static void cpu_exec_longjmp_cleanup", self.text)
        self.assertIn("g_assert(cpu == current_cpu);\n+    cyxia_cpu_exec_stop(cpu);", self.text)

    def test_guest_read_includes_current_active_interval(self) -> None:
        self.assertIn("now - cpu->cyxia_exec_started_ns", self.text)
        self.assertIn("cyxia_cpu_exec_time_ns(env_cpu(env), &exec_ns)", self.text)

    def test_upstream_fallback_remains(self) -> None:
        self.assertIn("qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)", self.text)
        self.assertIn("#ifndef CONFIG_USER_ONLY", self.text)

    def test_patch_does_not_change_guest_budgets_or_verifier(self) -> None:
        forbidden = (
            "reserved_ns",
            "native task credit overrun",
            "tools/verify_domains.py",
            "kernel/src/domain_tasks",
        )
        for marker in forbidden:
            self.assertNotIn(marker, self.text)


if __name__ == "__main__":
    unittest.main()
