"""Pure host profile gates; no compiler, Meson, native tool or guest execution."""
import copy
import hashlib
import json
from pathlib import Path
import shlex
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

try:
    from tools import build_mesa_production_v1 as subject
except ImportError:
    import build_mesa_production_v1 as subject


class ProductionFixture:
    def __init__(self, root):
        self.work = root / "mesa-production"
        self.prefix = root / "sdk"
        self.directory = self.work / "build"
        self.options_path = self.directory / "meson-info/intro-buildoptions.json"
        self.commands_path = self.directory / "compile_commands.json"
        self.options_path.parent.mkdir(parents=True)
        self.cc = self.prefix / "bin/target-cc"
        self.cxx = self.work / "bin/mesa-target-cxx"
        self.args = ["-ffunction-sections", "-fdata-sections", "-isystem", str(self.work / "uapi-include")]
        # Explicit host metadata fixture uses the actual Meson JSON types.
        self.values = {
            "prefix": "/usr", "libdir": "lib", "wrap_mode": "nofallback",
            "buildtype": "minsize", "debug": False, "default_library": "static",
            "b_staticpic": False, "platforms": [], "gallium-drivers": ["softpipe"],
            "vulkan-drivers": [], "llvm": "disabled", "draw-use-llvm": False,
            "glx": "disabled", "egl": "enabled", "gles1": "disabled", "gles2": "enabled",
            "gbm": "disabled", "glvnd": "disabled", "video-codecs": [], "gallium-va": "disabled",
            "build-tests": False, "shared-glapi": "disabled", "opengl": False,
            "cyxia-static-softpipe": True, "shader-cache": "disabled", "allow-kcmp": "disabled",
            "cyxia-demand-texture-cache": True, "cyxia-compute-oom": True,
            "cyxia-nir-small-slabs": True, "b_ndebug": "true", "egl-native-platform": "surfaceless",
            "optimization": "s", "c_args": self.args, "cpp_args": self.args,
            "cpp_link_args": [str(self.work / "cxx-runtime/libcyxia-mesa-cxx.a"), "-Wl,--error-limit=0"],
            "cyxia-probe-source": str(subject.ROOT / "user/ported/egl_probe.c"),
        }
        self.records = [self.record("nir_search.c", "nir_search.o", self.cc),
                        self.record("glsl.cpp", "glsl.o", self.cxx),
                        self.record("entry.S", "entry.o", self.cc)]
        self.builder = SimpleNamespace(output=self.work, sdk_prefix=self.prefix,
                                       target=SimpleNamespace(cc=lambda prefix: self.cc),
                                       mesa_profile="native-surfaceless", jobs=2)
        self.save()

    def record(self, source, output, compiler):
        argv = [str(compiler), "-Oz", "-DMESA_DEBUG=0", "-DNDEBUG", "-o", output, "-c", source]
        return {"directory": str(self.directory), "file": source, "output": output,
                "command": shlex.join(argv)}

    def save(self):
        self.options_path.write_text(json.dumps([{"name": k, "value": v} for k, v in self.values.items()]))
        self.commands_path.write_text(json.dumps(self.records))

    def validate(self):
        return subject.validate_production_configuration(self.builder, self.directory,
                                                          subject.options_for("native-surfaceless"), self.args)


class ProductionConfiguration(unittest.TestCase):
    def test_actual_typed_metadata_and_commands_bind_identity_without_executing(self):
        with tempfile.TemporaryDirectory() as directory:
            f = ProductionFixture(Path(directory))
            result = f.validate()
            self.assertEqual(result["command_counts"], {"c": 1, "cpp": 1, "assembly": 1})
            self.assertEqual(result["command_count"], 3)
            self.assertEqual(result["compile_commands"]["sha256"], hashlib.sha256(f.commands_path.read_bytes()).hexdigest())
            self.assertEqual(result["metadata"]["sha256"], hashlib.sha256(f.options_path.read_bytes()).hexdigest())
            self.assertEqual(result["optimization"], "-Oz")
            self.assertTrue(result["ndebug"])
            self.assertEqual(f.validate(), result)

    def test_old_if_release_and_profile_or_feature_drift_are_rejected(self):
        changes = [{"b_ndebug": "if-release"}, {"b_ndebug": True}, {"debug": True},
                   {"buildtype": "release"}, {"optimization": "3"}, {"gallium-drivers": []},
                   {"cyxia-compute-oom": False}, {"shader-cache": "enabled"}, {"egl-native-platform": "x11"}]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory)); f.values.update(change); f.save()
                with self.assertRaises(subject.BuildError): f.validate()
        with tempfile.TemporaryDirectory() as directory:
            f = ProductionFixture(Path(directory)); del f.values["gles2"]; f.save()
            with self.assertRaises(subject.BuildError): f.validate()
        with tempfile.TemporaryDirectory() as directory:
            f = ProductionFixture(Path(directory))
            data = json.loads(f.options_path.read_text()); data.append(copy.deepcopy(data[0]))
            f.options_path.write_text(json.dumps(data))
            with self.assertRaises(subject.BuildError): f.validate()

    def test_macro_optimizer_and_hidden_command_overrides_are_rejected(self):
        for extra in (["-UNDEBUG"], ["-U", "NDEBUG"], ["-DNDEBUG=0"], ["-Wp,-UNDEBUG"],
                      ["-O2"], ["@hidden.rsp"], ["-include", "override.h"], ["-imacros", "override.h"],
                      ["--config=override.cfg"], ["-Xclang", "-undef"], ["-DMESA_DEBUG=1"], [";", "true"]):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory)); f.records[0]["command"] += " " + shlex.join(extra); f.save()
                with self.assertRaises(subject.BuildError): f.validate()
        for missing in ("-DNDEBUG", "-Oz", "-DMESA_DEBUG=0"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory))
                argv = shlex.split(f.records[0]["command"]); argv.remove(missing)
                f.records[0]["command"] = shlex.join(argv); f.save()
                with self.assertRaises(subject.BuildError): f.validate()

    def test_incomplete_relocated_or_misidentified_commands_are_rejected(self):
        for mode in ("empty", "missing_cpp", "wrong_compiler", "wrong_directory", "wrong_source", "wrong_output", "duplicate_output"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory))
                if mode == "empty": f.records = []
                elif mode == "missing_cpp": f.records = [f.records[0]]
                elif mode == "wrong_compiler": f.records[0]["command"] = f.records[0]["command"].replace(str(f.cc), "/wrong/cc", 1)
                elif mode == "wrong_directory": f.records[0]["directory"] = str(f.work)
                elif mode == "wrong_source": f.records[0]["file"] = "different.c"
                elif mode == "wrong_output": f.records[0]["output"] = "different.o"
                elif mode == "duplicate_output": f.records.append(copy.deepcopy(f.records[0]))
                f.save()
                with self.assertRaises(subject.BuildError): f.validate()

    def test_missing_bad_oversized_or_symlink_metadata_is_rejected(self):
        for mode in ("missing", "bad_json", "oversized", "symlink"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory))
                if mode == "missing": f.options_path.unlink()
                elif mode == "bad_json": f.options_path.write_bytes(b"not JSON")
                elif mode == "oversized":
                    with f.options_path.open("wb") as stream: stream.truncate(subject.MAX_CONFIGURATION_BYTES + 1)
                elif mode == "symlink":
                    saved = f.work / "options.json"; f.options_path.replace(saved); f.options_path.symlink_to(saved)
                with self.assertRaises(subject.BuildError): f.validate()

    def test_real_build_path_checks_before_compile_and_rechecks_after_compile(self):
        for mode in ("old_profile", "valid_until_compile", "drift_during_compile"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory)); calls = []
                if mode == "old_profile": f.values["b_ndebug"] = "if-release"; f.save()
                sentinel = RuntimeError("STOP BEFORE ANY NATIVE COMPILER")
                def run(argv, log):
                    calls.append((argv, log))
                    if log == "compile.log":
                        if mode == "valid_until_compile": raise sentinel
                        f.values["b_ndebug"] = "if-release"; f.save()
                f.builder.run = run
                with patch.object(subject, "environment", return_value=(f.work / "cross.ini", f.work / "native.ini", f.args)):
                    if mode == "valid_until_compile":
                        with self.assertRaises(RuntimeError) as caught:
                            subject.build_libraries(f.builder, f.work / "source", False)
                        self.assertIs(caught.exception, sentinel)
                    else:
                        with self.assertRaises(subject.BuildError):
                            subject.build_libraries(f.builder, f.work / "source", False)
                self.assertEqual([log for _, log in calls], ["setup.log"] if mode == "old_profile" else ["setup.log", "compile.log"])
                self.assertEqual(hasattr(f.builder, "mesa_production_configuration"), mode != "old_profile")


if __name__ == "__main__":
    unittest.main()
