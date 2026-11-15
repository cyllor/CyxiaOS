# Pinned COSMIC built-in theme export

This is an explicit generation tool, not a replacement settings daemon. It calls
the real `cosmic_theme::Theme::{light,dark}_default()` and
`cosmic_config::CosmicConfigEntry::write_entry` from libcosmic commit
`5a8bd9482a35ae94c1e54edf77b331c6b970f170`. The daemon remains unchanged.

The generator accepts exactly `light` or `dark`. Run each mode in a separate fresh
CyxiaOS guest with the full-os filesystem profile. It refuses a nonempty selected
theme configuration directory, writes the upstream version-2 theme, checks all 39
regular key files, reads it through `Theme::get_entry`, then writes and compares
every canonical key byte again. Upstream `ColorRepr` quantizes floating-point
colors into 8-bit hex during serialization; byte-stable serialization and matching
mode/name are checked instead of equality with the original unquantized floats.
It checks atomic-write cleanup and syncs the directory before emitting output.

Successful output is a `THEME_DEFAULTS BEGIN` record binding mode, upstream ID,
version, key count and source commit, sorted `THEME_DEFAULTS KEY` records with
byte lengths and lowercase hex payloads, and a final `THEME_DEFAULTS PASS` record.
Any failure exits nonzero; incomplete output is not an asset set. Each key is
bounded to 8192 bytes and the total to 256 KiB. Generation does not install assets.

The separate installer must verify complete successful captures and preserve the
exact generated RON bytes under these system-default directories:

- `/usr/share/cosmic/com.system76.CosmicTheme.Light/v2/`
- `/usr/share/cosmic/com.system76.CosmicTheme.Dark/v2/`

`Config::new` looks these up through XDG data directories, while user keys retain
priority. Installing immutable system assets therefore does not overwrite user
configuration. The pinned upstream root `LICENSE` is MPL-2.0; installation should
retain that license and provenance for the source, generator, build and captures.

The builder reuses only the actual target libraries from
`artifacts/v017-cosmic-settings-20261115-r1/build-native-04`, after the existing
`cosmic_session_inputs.validate_inputs(..., component='cosmic-settings-daemon')`
validates the source, dependency, compiler and SDK provenance. It inventories all
library search roots, Rust runtime libraries, SDK files and producer/tool bytes
before and after linking. The caller holds the shared native lease; the builder
does not acquire a nested lease. It permits one compiler process, a 120-second
link deadline, at least 1 GiB free disk and at most 256 MiB output.

From the repository root, while holding that lease:

```sh
python3 tools/build_cosmic_theme_defaults.py build \
  --settings-prefix artifacts/v017-cosmic-settings-20261115-r1/sysroot-settings-01 \
  --output artifacts/v017-cosmic-settings-20261115-r1/theme-defaults-build-01 \
  --prefix artifacts/v017-cosmic-settings-20261115-r1/theme-defaults-prefix-01
```

Both destinations must be fresh and disjoint from inputs. Successful static ELF
admission and unchanged inputs precede publication into the explicit prefix.
`validate --prefix <prefix>` rechecks the receipt and original inputs without
compiling or running a guest.

Build success means cross-built only. Guest execution, generated assets and a
working COSMIC session remain unverified in the build receipt; separate actual
guest captures and installation evidence are required for those claims.
