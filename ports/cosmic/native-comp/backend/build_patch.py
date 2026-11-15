"""Regenerate the native backend patch against the two-patch source export.

This only copies and edits source; it never invokes Cargo or modifies upstream.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[4]
SUPPORT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def build(base, work):
    if work.exists():
        raise FileExistsError(work)
    if work.is_relative_to(base):
        raise ValueError("work directory must not be inside the source export")
    previous = json.loads((SUPPORT.parent / "offscreen-patch.json").read_text())
    if sha(base / "Cargo.lock") != previous["source_lock_sha256"]:
        raise ValueError("base export has the wrong Cargo.lock")
    for name, expected in previous["after"].items():
        if sha(base / name) != expected:
            raise ValueError(f"base export is not the offscreen patch postimage: {name}")
    shutil.copytree(base, work)
    changed = set()

    def edit(name, old, new):
        path = work / name
        text = path.read_text()
        if text.count(old) != 1:
            raise ValueError(f"ambiguous preimage: {name}: {old[:80]!r}")
        path.write_text(text.replace(old, new))
        changed.add(name)

    edit("Cargo.toml", 'backend-winit = [', 'backend-cyxia = []\nbackend-winit = [')
    edit("src/lib.rs", '    feature = "backend-x11"\n)))]', '    feature = "backend-x11",\n    feature = "backend-cyxia"\n)))]')
    edit("src/backend/mod.rs", 'pub mod offscreen;', '#[cfg(feature = "backend-cyxia")]\npub mod cyxia;\npub mod offscreen;')
    edit("src/backend/mod.rs", '        res = match backend {', '        res = match backend {\n            #[cfg(feature = "backend-cyxia")]\n            selection::Backend::Cyxia => cyxia::init_backend(dh, event_loop, state),')
    edit("src/backend/selection.rs", 'pub(super) enum Backend {', 'pub(super) enum Backend {\n    #[cfg(feature = "backend-cyxia")]\n    Cyxia,')
    edit("src/backend/selection.rs", '        return match requested {', '        return match requested {\n            #[cfg(feature = "backend-cyxia")]\n            "cyxia" => Ok(&[Backend::Cyxia]),')
    edit("src/backend/selection.rs", '            "x11" | "winit" | "kms" => Err(', '            #[cfg(not(feature = "backend-cyxia"))]\n            "cyxia" => Err("Requested COSMIC backend is disabled at build time"),\n            "x11" | "winit" | "kms" => Err(')
    edit("src/backend/selection.rs", '    if nested {', '''    // A native-only build does not inherit an unrelated parent DISPLAY.
    #[cfg(feature = "backend-cyxia")]
    if !cfg!(any(feature = "backend-kms", feature = "backend-winit", feature = "backend-x11")) {
        return Ok(&[Backend::Cyxia]);
    }
    if nested {''')
    edit("src/backend/selection.rs", '    #[cfg(not(feature = "backend-kms"))]\n    {\n        Err(', '    #[cfg(all(not(feature = "backend-kms"), feature = "backend-cyxia"))]\n    { Ok(&[Backend::Cyxia]) }\n    #[cfg(not(any(feature = "backend-kms", feature = "backend-cyxia")))]\n    {\n        Err(')
    edit("src/state.rs", '// SPDX-License-Identifier: GPL-3.0-only', '// SPDX-License-Identifier: GPL-3.0-only\n\n#[cfg(feature = "backend-cyxia")]\nuse crate::backend::cyxia::CyxiaState;')
    edit("src/state.rs", 'pub enum BackendData {', 'pub enum BackendData {\n    #[cfg(feature = "backend-cyxia")]\n    Cyxia(CyxiaState),')
    edit("src/state.rs", "pub enum LockedBackend<'a> {", "pub enum LockedBackend<'a> {\n    #[cfg(feature = \"backend-cyxia\")]\n    Cyxia(&'a mut CyxiaState),")
    edit("src/state.rs", 'impl BackendData {', '''impl BackendData {
    #[cfg(feature = "backend-cyxia")]
    pub fn cyxia(&mut self) -> &mut CyxiaState {
        match self {
            BackendData::Cyxia(state) => state,
            _ => unreachable!("Called cyxia in another backend"),
        }
    }
''')
    edit("src/state.rs", '    pub fn schedule_render(&mut self, output: &Output) {\n        match self {', '    pub fn schedule_render(&mut self, output: &Output) {\n        match self {\n            #[cfg(feature = "backend-cyxia")]\n            BackendData::Cyxia(state) => state.schedule_render(output),')
    edit("src/state.rs", '    ) -> Result<Option<DrmNode>, anyhow::Error> {\n        match self {', '    ) -> Result<Option<DrmNode>, anyhow::Error> {\n        match self {\n            #[cfg(feature = "backend-cyxia")]\n            BackendData::Cyxia(_) => anyhow::bail!("Cyxia ABI v1 does not expose DMA-BUF import"),')
    edit("src/state.rs", "    ) -> Result<RendererRef<'_>, GlMultiError> {\n        match self {", "    ) -> Result<RendererRef<'_>, GlMultiError> {\n        match self {\n            #[cfg(feature = \"backend-cyxia\")]\n            BackendData::Cyxia(state) => Ok(RendererRef::Glow(&mut state.renderer)),")
    edit("src/state.rs", '    pub fn update_screen_filter(&mut self, screen_filter: &ScreenFilter) -> anyhow::Result<()> {\n        match self {', '    pub fn update_screen_filter(&mut self, screen_filter: &ScreenFilter) -> anyhow::Result<()> {\n        match self {\n            #[cfg(feature = "backend-cyxia")]\n            BackendData::Cyxia(state) => state.update_screen_filter(screen_filter),')
    edit("src/state.rs", "    pub fn lock(&mut self) -> LockedBackend<'_> {\n        match self {", "    pub fn lock(&mut self) -> LockedBackend<'_> {\n        match self {\n            #[cfg(feature = \"backend-cyxia\")]\n            BackendData::Cyxia(state) => LockedBackend::Cyxia(state),")
    edit("src/state.rs", '    pub fn all_outputs(&self) -> Vec<Output> {\n        match self {', '    pub fn all_outputs(&self) -> Vec<Output> {\n        match self {\n            #[cfg(feature = "backend-cyxia")]\n            LockedBackend::Cyxia(state) => state.all_outputs(),')
    edit("src/state.rs", '        let all_outputs = self.all_outputs();\n\n        // update outputs', '        #[cfg(feature = "backend-cyxia")]\n        if let LockedBackend::Cyxia(state) = self {\n            state.validate_config()?;\n            if test_only { return Ok(()); }\n        }\n        let all_outputs = self.all_outputs();\n\n        // update outputs')
    edit("src/state.rs", '            LockedBackend::Winit(state) => state.apply_config_for_outputs(test_only),', '            LockedBackend::Winit(state) => state.apply_config_for_outputs(test_only),\n            #[cfg(feature = "backend-cyxia")]\n            LockedBackend::Cyxia(state) => {\n                state.update_screen_filter(screen_filter)?;\n                state.apply_config_for_outputs(test_only)\n            },')
    edit("src/state.rs", '                LockedBackend::Kms(state) => state.schedule_render(&output),', '                LockedBackend::Kms(state) => state.schedule_render(&output),\n                #[cfg(feature = "backend-cyxia")]\n                LockedBackend::Cyxia(state) => state.schedule_render(&output),')
    edit("src/lib.rs", '    event_loop.run(None, &mut state, |state| {', '    let loop_result = event_loop.run(None, &mut state, |state| {')
    edit("src/lib.rs", '    })?;\n\n    // kill kiosk child', '    });\n\n    #[cfg(feature = "backend-cyxia")]\n    let native_shutdown_result = backend::cyxia::shutdown(&mut state);\n\n    // kill kiosk child')
    edit("src/lib.rs", '    std::mem::drop(state);\n\n    if let Some(code)', '    std::mem::drop(state);\n\n    loop_result?;\n    #[cfg(feature = "backend-cyxia")]\n    native_shutdown_result?;\n\n    if let Some(code)')
    session_path = "src/wayland/handlers/session_lock.rs"
    session_text = (work / session_path).read_text()
    lock_start = session_text.index("    fn lock(&mut self, locker: SessionLocker) {")
    lock_end = session_text.index("\n    fn unlock(&mut self)", lock_start)
    original_lock = session_text[lock_start:lock_end]
    handler_lock = '''    fn lock(&mut self, locker: SessionLocker) {
        #[cfg(feature = "backend-cyxia")]
        if matches!(self.backend, crate::state::BackendData::Cyxia(_)) {
            self.begin_cyxia_lock(locker);
            return;
        }
        self.accept_session_lock(locker);
    }
'''
    edit(session_path, original_lock, handler_lock)
    accepted_lock = original_lock.replace("    fn lock(", "    pub(crate) fn accept_session_lock(")
    accepted_lock = accepted_lock.replace(
        "        let mut shell = self.common.shell.write();",
        "        if !locker.ext_session_lock().is_alive() { return; }\n        let mut shell = self.common.shell.write();",
    )
    accepted_lock = accepted_lock.replace(
        "if let Some(session_lock) = shell.session_lock.as_ref()\n            && self",
        "if let Some(session_lock) = shell.session_lock.as_ref()\n            && session_lock.ext_session_lock != *locker.ext_session_lock()\n            && session_lock.ext_session_lock.is_alive()\n            && self",
    )
    accepted_lock = accepted_lock.replace(
        "        shell.session_lock = Some(SessionLock {\n            ext_session_lock,\n            surfaces: HashMap::new(),\n        });",
        '''        // Native blanking already installed an internal barrier and may
        // have configured lock surfaces before the public locked event.
        if shell.session_lock.as_ref().is_none_or(|lock| lock.ext_session_lock != ext_session_lock) {
            shell.session_lock = Some(SessionLock {
                ext_session_lock,
                surfaces: HashMap::new(),
            });
        }''',
    )
    path = work / session_path
    path.write_text(path.read_text() + "\nimpl State {\n" + accepted_lock + "}\n")
    edit(session_path, "        if let Some(session_lock) = &mut shell.session_lock\n            && let Some(output)",
         "        if let Some(session_lock) = &mut shell.session_lock\n            && session_lock.ext_session_lock.is_alive()\n            && session_lock.ext_session_lock == *lock_surface.ext_session_lock()\n            && let Some(output)")
    edit("src/input/mod.rs", "        // An input device going away is not user activity,", '''        #[cfg(feature = "backend-cyxia")]
        if let crate::state::BackendData::Cyxia(backend) = &self.backend {
            use crate::backend::cyxia::{PendingInput, input_allowed};
            let kind = match &event {
                InputEvent::DeviceAdded { .. } | InputEvent::DeviceRemoved { .. } => PendingInput::DeviceLifecycle,
                InputEvent::Keyboard { event } if smithay::backend::input::KeyboardKeyEvent::state(event) == KeyState::Released => PendingInput::Release,
                InputEvent::PointerButton { event } if smithay::backend::input::PointerButtonEvent::state(event) == smithay::backend::input::ButtonState::Released => PendingInput::Release,
                _ => PendingInput::Other,
            };
            // Focus is already isolated by the provisional Shell session lock.
            // Allow releases to reconcile libei/pre-lock holds, never new input.
            if !input_allowed(backend.input_suspended(), kind) { return; }
        }
        // An input device going away is not user activity,''')
    focus_path = "src/shell/focus/mod.rs"
    edit(focus_path, "        let focus_target = match target {", '''        #[cfg(feature = "backend-cyxia")]
        if !cyxia_lock_allows_focus(state, target) { return; }
        let focus_target = match target {''')
    edit(focus_path, ") {\n    // update keyboard focus", ''') {
    #[cfg(feature = "backend-cyxia")]
    if !cyxia_lock_allows_focus(state, target) { return; }
    // update keyboard focus''')
    focus_guard = '''// Native blanking installs a provisional Shell barrier before protocol ACK.
// Enforce it at every common focus write and before installing popup grabs;
// periodic refresh alone cannot protect events within one Wayland dispatch.
#[cfg(feature = "backend-cyxia")]
pub(crate) fn cyxia_lock_allows_focus(state: &State, target: Option<&KeyboardFocusTarget>) -> bool {
    use crate::backend::cyxia::{LockFocusTarget, lock_focus_allowed};
    if !matches!(&state.backend, crate::state::BackendData::Cyxia(_)) { return true; }
    let shell = state.common.shell.read();
    let session_lock = shell.session_lock.as_ref();
    let kind = match target {
        None => LockFocusTarget::Clear,
        Some(KeyboardFocusTarget::LockSurface(surface)) => LockFocusTarget::LockSurface {
            alive: surface.alive() && surface.ext_session_lock().is_alive(),
            current_owner: session_lock.is_some_and(|lock| &lock.ext_session_lock == surface.ext_session_lock()),
            registered: session_lock.is_some_and(|lock| lock.surfaces.values().any(|registered| registered == surface)),
        },
        Some(KeyboardFocusTarget::LayerSurface(layer)) => LockFocusTarget::Layer {
            show_on_lock: layer_show_on_lock(layer.wl_surface()),
        },
        Some(KeyboardFocusTarget::Popup(popup)) => LockFocusTarget::Popup {
            root_show_on_lock: find_popup_root_surface(popup).is_ok_and(|root| layer_show_on_lock(&root)),
        },
        _ => LockFocusTarget::Other,
    };
    lock_focus_allowed(session_lock.is_some(), kind)
}

'''
    focus_header = "/// Internal, used to ensure that ActiveFocus, KeyboardFocusTarget, and FocusedOutput are all in sync\n#[profiling::function]\nfn update_focus_state("
    edit(focus_path, focus_header, focus_guard + focus_header)
    edit("src/wayland/handlers/xdg_shell/mod.rs", "        if let Some(root) = maybe_root {\n            let target = root;", '''        if let Some(root) = maybe_root {
            #[cfg(feature = "backend-cyxia")]
            if !crate::shell::focus::cyxia_lock_allows_focus(self, Some(&root)) {
                return;
            }
            let target = root;''')
    for source in [*SUPPORT.glob("*.rs"), *(SUPPORT / "native").glob("*.rs")]:
        name = f"src/backend/cyxia/{source.relative_to(SUPPORT)}"
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, work / name)
        changed.add(name)
    patch = ROOT / "ports/cosmic/patches/cosmic-comp-native-backend.patch"
    chunks = []
    for name in sorted(changed):
        before = (base / name).read_text().splitlines(keepends=True) if (base / name).exists() else []
        after = (work / name).read_text().splitlines(keepends=True)
        chunks.extend(difflib.unified_diff(before, after, fromfile=f"a/{name}" if before else "/dev/null", tofile=f"b/{name}"))
    patch.write_text("".join(chunks))
    manifest = {key: previous[key] for key in ("schema_version", "component", "repository", "commit", "source_lock_sha256")}
    manifest.update({
        "base_patch_sha256": previous["patch_sha256"],
        "patch_sha256": sha(patch),
        "before": {name: sha(base / name) for name in sorted(changed)},
        "after": {name: sha(work / name) for name in sorted(changed)},
        "status": "PATCHED_NOT_LINKED_OR_GUEST_VERIFIED",
    })
    (SUPPORT.parent / "backend-patch.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    build(args.base.resolve(), args.work.resolve())
