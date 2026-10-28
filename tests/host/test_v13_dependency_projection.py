import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class DependencyProjectionTests(unittest.TestCase):
    def test_d04_control_projection_does_not_replace_executor_resolver(self):
        control = (ROOT / "kernel/src/domain_control.rs").read_text()
        storage = (ROOT / "kernel/src/domain_storage.rs").read_text()
        self.assertIn("register_dependencies(4, dependencies)", storage)
        self.assertIn("register_dependency_binder(4, control_dependencies)", storage)
        self.assertIn("owner.dependency_binders[dependency_slot]", control)
        self.assertIn("DEPENDENCY_RESOLVERS", control)
        self.assertIn("admit_dependencies(consumer: u16", control)

    def test_collapsed_projection_revalidates_both_real_owners(self):
        storage = (ROOT / "kernel/src/domain_storage.rs").read_text()
        tasks = (ROOT / "kernel/src/domain_tasks.rs").read_text()
        device = (ROOT / "kernel/src/prototype_storage.rs").read_text()
        self.assertIn("control_cache_dependency(at)", storage)
        self.assertIn("control_io_dependency(at)", storage)
        self.assertEqual(storage.count("admit_dependency(memory, 4, at)"), 1)
        self.assertEqual(storage.count("admit_dependency(disk, 4, at)"), 1)
        self.assertIn("cache_dependency_view(at)", tasks)
        self.assertIn("cache_authorized_pages(at)", tasks)
        self.assertIn("io_dependency_view(at)", storage)
        self.assertIn("view.io, view.facts[2], view.facts[31]", device)


if __name__ == "__main__":
    unittest.main()
