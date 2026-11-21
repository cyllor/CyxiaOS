"""Complete-source panel popup input forwarding, layered over the 128-FD host."""
import difflib
import json
from pathlib import Path
import subprocess
import tempfile
import cosmic_applet_hosts_v1 as hosts

base, require = hosts.base, hosts.require
PORT = base.ROOT / 'ports/cosmic/native-popup-input-v1'
FILES = ('cosmic-panel-bin/src/xdg_shell_wrapper/space/popup.rs',
         'cosmic-panel-bin/src/space/wrapper_space.rs',
         'cosmic-panel-bin/src/space/overflow.rs')


def changed_source(name, text):
    def replace(old, new):
        nonlocal text
        require(text.count(old) == 1, 'Popup input preimage changed: ' + name + ': ' + old[:60])
        text = text.replace(old, new)
    if name == FILES[0]:
        replace('use sctk::compositor::Region;', 'use sctk::compositor::{CompositorState, Region};')
        replace('use smithay::desktop::PopupManager;', 'use smithay::desktop::PopupManager;\nuse smithay::wayland::compositor::{with_states, RegionAttributes, RectangleKind, SurfaceAttributes};')
        replace('    pub input_region: Option<Region>,', '    pub input_region: Option<Region>,\n    pub input_compositor: CompositorState,\n    pub input_snapshot: Option<InputRegionSnapshot>,')
        helper = (PORT / 'input-region.rs').read_text()
        replace('impl PanelPopup {', helper + '''
impl PanelPopup {
    /// Forward effective committed input before mapping, and after later changes.
    /// Reuse an unchanged snapshot; do not create a new wl_region every frame.
    pub fn sync_input_region(&mut self, surface: &PopupSurface) -> bool {
        let snapshot = with_states(surface.wl_surface(), |states| {
            let mut attributes = states.cached_state.get::<SurfaceAttributes>();
            input_region_snapshot(attributes.current().input_region.as_ref())
        });
        if self.input_snapshot.as_ref() == Some(&snapshot) { return false; }
        let region = snapshot.as_ref().map(|rectangles| {
            // This is the same bound compositor used to create this popup.
            let region = Region::new(&self.input_compositor).expect("bound popup compositor");
            for &(add, x, y, width, height) in rectangles {
                if add { region.add(x, y, width, height); }
                else { region.subtract(x, y, width, height); }
            }
            region
        });
        self.c_popup.wl_surface().set_input_region(region.as_ref().map(Region::wl_region));
        self.input_region = region;
        self.input_snapshot = Some(snapshot);
        true
    }
''')
    elif name == FILES[1]:
        replace('        let input_region = Region::new(compositor_state)?;\n\n        if let Some(s_window_geometry)', '        if let Some(s_window_geometry)')
        start = text.index('        if let Some(input_regions) = with_states(s_surface.wl_surface(), |states| {')
        end = text.index('        let fractional_scale =', start)
        text = text[:start] + text[end:]
        replace('                input_region: Some(input_region),', '                input_region: None,\n                input_compositor: compositor_state.clone(),\n                input_snapshot: None,')
        replace('            p.popup.map();', '''            let input_changed = p.popup.sync_input_region(&p.s_surface);
            if input_changed && !p.popup.pending_initial_commit {
                p.popup.c_popup.wl_surface().commit();
            }
            p.popup.map();''')
    else:
        replace('                input_region: None,', '                input_region: None,\n                input_compositor: compositor_state.clone(),\n                input_snapshot: None,')
    return text


def contract():
    policy = base.load_json(PORT / 'source-policy.json')
    require(policy['kind'] == 'cosmic-panel-popup-input-v1'
            and policy['parent_source_policy_sha256'] == base.digest(hosts.PORT / 'source-policy.json')
            and policy['before_tree_sha256'] == hosts.contract('panel')[0]['after_tree_sha256']
            and policy['patch_sha256'] == base.digest(PORT / 'native.patch')
            and policy['helper_sha256'] == base.digest(PORT / 'input-region.rs')
            and set(policy['changed_files']) == set(FILES), 'Popup input source contract changed')
    return policy


def verify_export(source):
    policy = contract(); tree = base.tree_identity(source)
    require(tree['sha256'] == policy['after_tree_sha256']
            and hosts.canonical(hosts.modes(source)) == policy['mode_sha256'], 'Complete popup input source changed')
    for name, record in policy['changed_files'].items():
        require(base.digest(source / name) == record['after'], 'Popup input source file changed: ' + name)
    return tree


def apply(source):
    policy = contract()
    require(hosts.verify_export('panel', source)['sha256'] == policy['before_tree_sha256'], 'Popup parent changed')
    for flags in (['--check'], []):
        subprocess.run(['/usr/bin/git', 'apply', *flags, str(PORT / 'native.patch')], cwd=source,
            env=base.clean_environment('/usr/bin:/bin'), capture_output=True, check=True)
    return verify_export(source)


def prepare():
    require(not (PORT / 'source-policy.json').exists(), 'Preserving popup policy')
    with tempfile.TemporaryDirectory(prefix='cyxia-popup-policy-', dir='/private/tmp') as temporary:
        source = Path(temporary) / 'source'; _, before = hosts.export('panel', source)
        original_modes = hosts.canonical(hosts.modes(source)); patch = ''; changed = {}
        for name in FILES:
            path = source / name; old = path.read_text(); before_sha = base.digest(path)
            new = changed_source(name, old); path.write_text(new)
            changed[name] = dict(before=before_sha, after=base.digest(path))
            patch += ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile='a/' + name, tofile='b/' + name))
        (PORT / 'native.patch').write_text(patch)
        require(hosts.canonical(hosts.modes(source)) == original_modes, 'Popup patch changed modes')
        policy = dict(kind='cosmic-panel-popup-input-v1', parent_source_policy_sha256=base.digest(hosts.PORT / 'source-policy.json'),
            before_tree_sha256=before['sha256'], after_tree_sha256=base.tree_identity(source)['sha256'], mode_sha256=original_modes,
            changed_files=changed, patch_sha256=base.digest(PORT / 'native.patch'), helper_sha256=base.digest(PORT / 'input-region.rs'))
        (PORT / 'source-policy.json').write_text(json.dumps(policy, indent=2) + '\n')
        verify_export(source)
    print('POPUP_INPUT_POLICY_PREPARED')


if __name__ == '__main__':
    from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
    with native_lease(DEFAULT_NATIVE_LOCK): idle_native_host(); prepare()
