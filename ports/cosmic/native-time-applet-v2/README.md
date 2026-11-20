# Genuine Epoch 1.10.0 clock, static Wayland XKB

Upstream: `pop-os/cosmic-applets` commit
`406d1b7d627138fdf4078f654268d3d8774e50f1`.
All 19 workspace members, default members, GUI features, translations and clock/
calendar code are retained. Only native dependency selection changes.

The original ELF reached the real winit keyboard initialization and aborted with
`XKBNotFound`: `xkbcommon-dl` tried dynamic loading on the static target. A small
native regression using the actual clock's selected Cargo rlib reproduced the
missing library before this patch, without needing a compositor.

`xkbcommon-dl` 0.4.2 is retained in full from its checksum-pinned registry archive.
The `static-wayland` feature supplies every original core and Compose function
table entry using the same real target `libxkbcommon.a`. Missing symbols are
link errors. X11 retains its original dynamic loader and features; this port
does not certify an X11 session. Genuine static Wayland client/EGL bindings and
the prior backend FD ownership fix are retained from the verified panel source.

The SDK, native archive pins, process grants, two build jobs, 3 GiB build budget
and 3,600 second deadline are unchanged. Build and installation independently
validate the complete original Git tree, native bindings, archive contents,
retained source, full Cargo resolution and target ELF. Exact producer snapshots
are retained with each build for subsequent historical validation.

```sh
python3 tools/build_cosmic_time_applet_v2.py \
  --output artifacts/<new-clock-build> \
  --cache-from artifacts/v017-time-applet-build-v1
python3 tools/assemble_cosmic_time_applet_v2.py \
  --build artifacts/<new-clock-build> \
  --base-build artifacts/v017-os-panel-allocation-v2 \
  --output artifacts/<new-clock-catalog>
```

The formal image selects `cosmic-time-applet-v1`, a separate ROM inventory
profile requiring the five genuine core programs, genuine clock and desktop
entry. Build success alone does not establish clock rendering or full COSMIC.
