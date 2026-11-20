# Notifications: local SDK v2 binding

This recipe keeps the static-v1 upstream commit, source policy, effective lock,
patches, GUI/a11y/X11 features and resource profile unchanged. Only the twelve
native input hashes and the SDK assembly receipt change. The frozen static-v1
producer and installer consume this separate recipe; their old inputs remain.

SDK inputs are real x86_64 musl/X.Org builds, independently verified
xkbcommon-X11 output, and exact retained Wayland/FFI archives. See
`tools/prepare_cosmic_notifications_sdk_v2.py` for the assembly and origin checks.
Compilation and installation do not establish notification or session readiness.
