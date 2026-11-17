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
    from tools import build_mesa_production_v2 as subject
except ImportError:
    import build_mesa_production_v2 as subject


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
            "optimization": "s", "c_args": self.args, "cpp_args": [*self.args, subject.LIBCPP_FAST_ARGUMENT],
            "cpp_link_args": [str(self.work / "cxx-runtime/libcyxia-mesa-cxx.a"), "-Wl,--error-limit=0"],
            "cyxia-probe-source": str(subject.ROOT / "user/ported/egl_probe.c"),
        }
        self.records = [self.record("nir_search.c", "nir_search.o", self.cc)]
        self.records.extend(self.record(f"glsl_{index}.cpp", f"glsl_{index}.o", self.cxx)
                            for index in range(subject.PINNED_NATIVE_X86_CPP_COMMANDS))
        self.records.append(self.record("entry.S", "entry.o", self.cc))
        self.builder = SimpleNamespace(output=self.work, sdk_prefix=self.prefix,
                                       target=SimpleNamespace(cc=lambda prefix: self.cc, architecture="x86_64"),
                                       mesa_profile="native-surfaceless", jobs=2)
        self.save()

    def record(self, source, output, compiler):
        argv = [str(compiler), "-Oz", "-DMESA_DEBUG=0", "-DNDEBUG",
                *subject.NDEBUG_WARNING_SUPPRESSIONS]
        if compiler == self.cxx:
            argv.append(subject.LIBCPP_FAST_ARGUMENT)
        argv.extend(["-o", output, "-c", source])
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
            self.assertEqual(result["command_counts"], {"c": 1, "cpp": 64, "assembly": 1})
            self.assertEqual(result["command_count"], 66)
            self.assertEqual(result["libcpp_hardening"], {"definition": subject.LIBCPP_FAST_ARGUMENT,
                                                        "mode": "FAST", "cpp_command_count": 64,
                                                        "c_and_assembly_override_count": 0})
            self.assertEqual(result["ndebug_warning_suppression_counts"],
                             {flag: 66 for flag in subject.NDEBUG_WARNING_SUPPRESSIONS})
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
        for mode in ("old_profile", "old_v1_cpp_args", "old_v1_cpp_command", "valid_until_compile", "drift_during_compile"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory)); calls = []
                if mode == "old_profile": f.values["b_ndebug"] = "if-release"; f.save()
                elif mode == "old_v1_cpp_args": f.values["cpp_args"] = f.args; f.save()
                elif mode == "old_v1_cpp_command":
                    argv = shlex.split(f.records[-2]["command"]); argv.remove(subject.LIBCPP_FAST_ARGUMENT)
                    f.records[-2]["command"] = shlex.join(argv); f.save()
                sentinel = RuntimeError("STOP BEFORE ANY NATIVE COMPILER")
                def run(argv, log):
                    calls.append((argv, log))
                    if log == "compile.log":
                        if mode == "valid_until_compile": raise sentinel
                        argv = shlex.split(f.records[-2]["command"])
                        argv[argv.index(subject.LIBCPP_FAST_ARGUMENT)] = "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE"
                        f.records[-2]["command"] = shlex.join(argv); f.save()
                f.builder.run = run
                with patch.object(subject, "environment", return_value=(f.work / "cross.ini", f.work / "native.ini", f.args)):
                    if mode == "valid_until_compile":
                        with self.assertRaises(RuntimeError) as caught:
                            subject.build_libraries(f.builder, f.work / "source", False)
                        self.assertIs(caught.exception, sentinel)
                    else:
                        with self.assertRaises(subject.BuildError):
                            subject.build_libraries(f.builder, f.work / "source", False)
                preflight_failure = mode in ("old_profile", "old_v1_cpp_args", "old_v1_cpp_command")
                self.assertEqual([log for _, log in calls], ["setup.log"] if preflight_failure else ["setup.log", "compile.log"])
                self.assertEqual(hasattr(f.builder, "mesa_production_configuration"), not preflight_failure)
                self.assertIn("-Dc_args=" + repr(f.args), calls[0][0])
                self.assertIn("-Dcpp_args=" + repr([*f.args, subject.LIBCPP_FAST_ARGUMENT]), calls[0][0])


    def test_each_cpp_command_requires_fast_without_cancellation_or_redefinition(self):
        replacements = [[], ["-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE"],
                        [subject.LIBCPP_FAST_ARGUMENT, subject.LIBCPP_FAST_ARGUMENT],
                        [subject.LIBCPP_FAST_ARGUMENT, "-U_LIBCPP_HARDENING_MODE"],
                        [subject.LIBCPP_FAST_ARGUMENT, "-U", "_LIBCPP_HARDENING_MODE"],
                        [subject.LIBCPP_FAST_ARGUMENT, "-D_LIBCPP_HARDENING_MODE=4"],
                        [subject.LIBCPP_FAST_ARGUMENT, "-D", "_LIBCPP_HARDENING_MODE=2"],
                        [subject.LIBCPP_FAST_ARGUMENT, "-D_LIBCPP_HARDENING_MODE_FAST=2"],
                        [subject.LIBCPP_FAST_ARGUMENT, "-D_LIBCPP_HARDENING_MODE_DEFAULT=2"],
                        [subject.LIBCPP_FAST_ARGUMENT, "-Wp,-U_LIBCPP_HARDENING_MODE"],
                        [subject.LIBCPP_FAST_ARGUMENT, "-D_LIBCPP_ENABLE_ASSERTIONS=0"],
                        [subject.LIBCPP_FAST_ARGUMENT, "-D_LIBCPP_DEBUG=0"]]
        for index in (1, 64):
            for replacement in replacements:
                with self.subTest(index=index, replacement=replacement), tempfile.TemporaryDirectory() as directory:
                    f = ProductionFixture(Path(directory)); argv = shlex.split(f.records[index]["command"])
                    position = argv.index(subject.LIBCPP_FAST_ARGUMENT)
                    argv[position:position + 1] = replacement
                    f.records[index]["command"] = shlex.join(argv); f.save()
                    with self.assertRaises(subject.BuildError): f.validate()

    def test_actual_cpp_options_must_preserve_fast_without_changing_c_options(self):
        for mode in ("cpp_missing", "cpp_none", "cpp_duplicate", "c_fast"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory))
                if mode == "cpp_missing": f.values["cpp_args"] = f.args
                elif mode == "cpp_none":
                    f.values["cpp_args"] = [*f.args, "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE"]
                elif mode == "cpp_duplicate":
                    f.values["cpp_args"] = [*f.args, subject.LIBCPP_FAST_ARGUMENT, subject.LIBCPP_FAST_ARGUMENT]
                elif mode == "c_fast": f.values["c_args"] = [*f.args, subject.LIBCPP_FAST_ARGUMENT]
                f.save()
                with self.assertRaises(subject.BuildError): f.validate()

    def test_c_and_assembly_do_not_receive_cpp_hardening_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            f = ProductionFixture(Path(directory)); f.validate()
            self.assertNotIn(subject.LIBCPP_FAST_ARGUMENT, shlex.split(f.records[0]["command"]))
            self.assertNotIn(subject.LIBCPP_FAST_ARGUMENT, shlex.split(f.records[-1]["command"]))
        for index in (0, -1):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory)); f.records[index]["command"] += " " + subject.LIBCPP_FAST_ARGUMENT; f.save()
                with self.assertRaises(subject.BuildError): f.validate()

    def test_fixed_native_cpp_command_count_cannot_drop_or_add_translation_units(self):
        for change in ("missing", "extra"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                f = ProductionFixture(Path(directory))
                if change == "missing": del f.records[1]
                else: f.records.append(f.record("extra.cpp", "extra.o", f.cxx))
                f.save()
                with self.assertRaises(subject.BuildError): f.validate()

    def test_upstream_ndebug_warning_flags_are_allowed_and_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            f = ProductionFixture(Path(directory)); result = f.validate()
            self.assertEqual(result["ndebug_warning_suppression_counts"],
                             {flag: 66 for flag in subject.NDEBUG_WARNING_SUPPRESSIONS})
            argv = shlex.split(f.records[0]["command"])
            argv = [arg for arg in argv if arg not in subject.NDEBUG_WARNING_SUPPRESSIONS]
            f.records[0]["command"] = shlex.join(argv); f.save()
            self.assertEqual(f.validate()["ndebug_warning_suppression_counts"],
                             {flag: 65 for flag in subject.NDEBUG_WARNING_SUPPRESSIONS})


if __name__ == "__main__":
    unittest.main()
