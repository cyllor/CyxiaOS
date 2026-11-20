# Mesa Wayland software buffer allocation failures

Retains the complete original Mesa 26.2.3 `platform_wayland.c` translation unit,
including its upstream MIT notice. `source-policy.json` binds its original hash
to the actual unchanged SDK used by the panel and clock.

The normal guest reached the real 16-object metadata boundary. Its panel's
`memfd_create` returned ENOMEM, but Mesa left `back` pointing to the failed
allocation, ignored an update failure during swap, and copied to NULL in
`dri2_wl_swrast_put_image2`.

The versioned patch rolls back that published pointer, tolerates a late loader
callback with no valid backing, returns failure from damage swap, and propagates
that result from ordinary swap. It does not grant an allocation, change a quota,
replace the renderer, or declare the complete desktop usable.

Seven host regressions extract the real retained Mesa functions and inject an
allocation refusal at their boundary. Original code fails six checks, including
the actual invalid copy. The patched functions pass all seven, covering repeated
refusal, no invalid submission, genuine byte copying and recovery.

```sh
python3 -m unittest discover -s tests/host -p test_mesa_wayland_allocation.py -v
python3 tools/build_mesa_wayland_oom_v1.py --output artifacts/<new-native-repair>
python3 tools/relink_cosmic_mesa_wayland_v1.py \
  --parent-build artifacts/v017-panel-allocation-build-v5 \
  --repair artifacts/<new-native-repair> --output artifacts/<new-panel-build>
python3 tools/assemble_cosmic_mesa_wayland_v1.py \
  --build artifacts/<new-panel-build> --base-build artifacts/v017-os-time-applet-v3 \
  --output artifacts/<new-normal-catalog>
```

The native builder reuses the exact original compilation flags and binds every
actual include dependency. The target is an x86_64 relocatable object with the
same public symbol set. It also creates a full EGL archive with exactly one
changed member; all SDK inputs remain unchanged.

Rust's Smithay archive contains the old C object. The GUI builder therefore
recompiles only the genuine root with a linker that prepends the new C object.
The real link map must show the repaired object and no selected old Wayland
member. Rust source, full locked graph, features and dependency archives are
retained and independently revalidated by the catalog consumer. This is a
normal compilation and static link, with no executable patching.

Guest EGL failure/recovery and the original calendar scenario are separate
acceptance steps. Build and host-test success do not certify those steps.
