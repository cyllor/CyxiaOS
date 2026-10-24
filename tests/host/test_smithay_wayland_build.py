from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import build_smithay_wayland as builder
import build_smithay_xdg as xdg_builder


class SmithayWaylandBuildTests(unittest.TestCase):
    def test_trusted_workspace_preflight_resolves_its_own_locked_offline_closure(self):
        upstream = {"CARGO_HOME": "/fresh/server/cargo-home",
                    "CARGO_TARGET_DIR": "/fresh/server/target",
                    "CARGO_NET_OFFLINE": "true", "PATH": "/trusted/bin"}
        trusted = builder.workspace_preflight_environment(upstream, Path("/trusted/cargo"))
        self.assertEqual(trusted["CARGO_HOME"], "/trusted/cargo")
        self.assertEqual(trusted["CARGO_TARGET_DIR"], "/fresh/server/target")
        self.assertEqual(trusted["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(trusted["PATH"], "/trusted/bin")
        self.assertEqual(upstream["CARGO_HOME"], "/fresh/server/cargo-home")
        trusted["PATH"] = "/changed"
        self.assertEqual(upstream["PATH"], "/trusted/bin")


    def test_modules_cannot_overwrite_main_or_each_other(self):
        for modules in ((Path("nested/main.rs"),),
                        (Path("one/native.rs"), Path("two/native.rs")),
                        (Path("one/native.rs"), Path("two/Native.rs"))):
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                builder.BuildProfile(modules=modules)

    def test_profile_is_immutable_and_cannot_write_outside_output(self):
        from dataclasses import FrozenInstanceError
        for name in ("", "../server", "/tmp/server", "server.elf", "nested/server"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                builder.BuildProfile(binary_stem=name)
        profile = builder.BuildProfile()
        with self.assertRaises(FrozenInstanceError):
            profile.binary_stem = "changed"
        self.assertEqual(profile.source, builder.PROBE)
        self.assertNotEqual(profile.source, xdg_builder.PROFILE.source)
        self.assertEqual(xdg_builder.PROFILE.entrypoint, Path(xdg_builder.__file__).resolve())

    SOURCE = '''
[package]
name="smithay"
version="0.7.0"
edition="2024"
[dependencies]
libc="0.2"
wayland-server={version="0.31",optional=true}
unused={version="1",optional=true}
[build-dependencies]
[features]
default=["backend_unused"]
wayland_frontend=["wayland-server"]
backend_unused=["unused"]
'''

    def packages(self):
        return [
            {"name": "smithay", "dependencies": ["libc", "wayland-server"]},
            {"name": "libc", "version": "0.2.182"},
            {"name": "wayland-server", "version": "0.31.13"},
        ]

    def test_image_admission_counts_unaligned_load_boundary_and_stack(self):
        # One full aligned page plus a segment occupying two partial pages.
        # The old ceil(memsz / 4096) sum incorrectly admitted only two pages.
        headers = [
            {"type": 1, "vaddr": 0x1000000, "memsz": 4096},
            {"type": 1, "vaddr": 0x1002ff0, "memsz": 32},
            {"type": 7, "vaddr": 0x1002ff0, "memsz": 8192},
        ]
        self.assertEqual(builder.image_page_count(headers), 3)
        self.assertEqual(builder.image_page_count(headers) + 64, 67)
        headers[1]["memsz"] = 16
        self.assertEqual(builder.image_page_count(headers), 2)

    def test_projected_frontend_retains_exact_dependency_and_disables_other_backends(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text(self.SOURCE)
            builder.project_manifest(path, {
                "projected_dependencies": ["libc", "wayland-server"],
                "projected_features": ["wayland_frontend"],
            }, self.packages())
            data = tomllib.loads(path.read_text())
            self.assertEqual(data["features"], {
                "default": [], "wayland_frontend": ["wayland-server"],
            })
            self.assertNotIn("unused", data["dependencies"])
            self.assertEqual(data["dependencies"]["wayland-server"], {
                "version": "=0.31.13", "optional": True,
            })
            self.assertIn("backend_unused", data["lints"]["rust"]["unexpected_cfgs"]["check-cfg"][0])

    def test_missing_mandatory_dependency_or_ambiguous_pin_leaves_manifest_untouched(self):
        for dependencies, packages in [
            ([], self.packages()),
            (["libc"], self.packages() + [{"name": "libc", "version": "0.2.181"}]),
        ]:
            with self.subTest(dependencies=dependencies), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "Cargo.toml"
                path.write_text(self.SOURCE)
                before = path.read_bytes()
                with self.assertRaises(ValueError):
                    builder.project_manifest(path, {
                        "projected_dependencies": dependencies, "projected_features": [],
                    }, packages)
                self.assertEqual(path.read_bytes(), before)

    def test_unknown_projected_feature_cannot_silently_compile_without_frontend(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text(self.SOURCE)
            before = path.read_bytes()
            with self.assertRaises(KeyError):
                builder.project_manifest(path, {
                    "projected_dependencies": ["libc", "wayland-server"],
                    "projected_features": ["not_a_real_upstream_feature"],
                }, self.packages())
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
