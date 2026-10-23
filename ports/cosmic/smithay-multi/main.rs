//! Real concurrent xdg-shell windows, independent scene mechanisms and native scanout.
mod native;
mod scene;

use native::{InputAction, InputDecoder, InputEvent, NativeDisplay};
use scene::{Rect, Scene, Window};
use smithay::{
    backend::{
        allocator::Fourcc,
        egl::{EGLContext, EGLDisplay, ffi::egl, native::EGLSurfacelessDisplay},
        input::{ButtonState, InputTime, KeyState},
        renderer::{
            Bind, Color32F, ExportMem, Frame, Offscreen, Renderer, TextureMapping,
            element::{
                Kind,
                surface::{WaylandSurfaceRenderElement, render_elements_from_surface_tree},
            },
            gles::{GlesRenderbuffer, GlesRenderer},
            utils::{draw_render_elements, on_commit_buffer_handler, with_renderer_surface_state},
        },
    },
    input::{
        Seat, SeatHandler, SeatState,
        keyboard::{FilterResult, XkbConfig},
        pointer::{ButtonEvent, CursorImageStatus, MotionEvent},
    },
    reexports::wayland_protocols::xdg::shell::server::xdg_toplevel,
    reexports::wayland_server::{
        Client, Display, Resource,
        backend::{ClientData, ClientId, DisconnectReason},
        protocol::{wl_buffer::WlBuffer, wl_seat::WlSeat, wl_surface::WlSurface},
    },
    utils::{Rectangle, Serial, Transform},
    wayland::{
        buffer::BufferHandler,
        compositor::{
            CompositorClientState, CompositorHandler, CompositorState, SurfaceAttributes,
            with_states,
        },
        pointer_constraints::PointerConstraintsHandler,
        shell::xdg::{
            Configure, PopupSurface, PositionerState, ToplevelSurface, XdgShellHandler,
            XdgShellState,
        },
        shm::{ShmHandler, ShmState},
    },
};
use std::{
    error::Error,
    ffi::{CStr, CString},
    io,
    os::{
        fd::{AsFd, AsRawFd},
        unix::net::UnixStream,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
const WIDTH: i32 = 128;
const HEIGHT: i32 = 96;

fn emit(line: &str) -> Result {
    require(
        line.len() <= 64 && line.ends_with('\n'),
        "telemetry exceeds atomic write bound",
    )?;
    loop {
        // SAFETY: The complete line remains readable for its exact byte length.
        // CyxiaOS accepts at most 64 bytes per console write. One syscall keeps
        // concurrently scheduled processes from interleaving logical records.
        let written = unsafe { libc::write(libc::STDOUT_FILENO, line.as_ptr().cast(), line.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        require(
            written as usize == line.len(),
            "short atomic telemetry write",
        )?;
        return Ok(());
    }
}

fn require(ok: bool, reason: &str) -> Result {
    if ok {
        Ok(())
    } else {
        Err(reason.to_owned().into())
    }
}

#[repr(C)]
struct Mapping {
    source: i32,
    target: i32,
}
#[repr(C)]
struct SpawnRequest {
    size: u32,
    flags: u32,
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    cwd: *const libc::c_char,
    mappings: *const Mapping,
    mapping_count: u32,
    reserved: u32,
    reserved2: u64,
}
const _: () = assert!(std::mem::size_of::<SpawnRequest>() == 64);

fn spawn_client(fd: i32, round: u32) -> Result<libc::pid_t> {
    let path = c"/bin/smithay-multi-client";
    let round = CString::new(round.to_string())?;
    let argv = [path.as_ptr(), round.as_ptr(), std::ptr::null()];
    let env = [std::ptr::null()];
    let mappings = [
        Mapping {
            source: -2,
            target: 0,
        },
        Mapping {
            source: 1,
            target: 1,
        },
        Mapping {
            source: 2,
            target: 2,
        },
        Mapping {
            source: fd,
            target: 3,
        },
    ];
    let request = SpawnRequest {
        size: 64,
        flags: 0,
        path: path.as_ptr(),
        argv: argv.as_ptr(),
        envp: env.as_ptr(),
        cwd: std::ptr::null(),
        mappings: mappings.as_ptr(),
        mapping_count: 4,
        reserved: 0,
        reserved2: 0,
    };
    // SAFETY: Every pointer refers to a live, correctly sized ABI-v1 object.
    // The synchronous kernel call copies strings and mappings before returning.
    let pid = unsafe { libc::syscall(0x43595810, &request as *const SpawnRequest) };
    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }
    require(pid > 0, "spawn returned invalid pid")?;
    Ok(pid as libc::pid_t)
}

struct ClientState {
    id: u32,
    compositor: CompositorClientState,
    disconnected: AtomicBool,
    protocol_error: AtomicBool,
}
impl ClientData for ClientState {
    fn initialized(&self, _: ClientId) {}
    fn disconnected(&self, _: ClientId, reason: DisconnectReason) {
        self.protocol_error.store(
            matches!(reason, DisconnectReason::ProtocolError(_)),
            Ordering::Release,
        );
        self.disconnected.store(true, Ordering::Release);
    }
}
#[derive(Default)]
struct ManagedWindow {
    toplevel: Option<ToplevelSurface>,
    awaiting: Option<(Serial, bool)>,
    activated: bool,
    configures: u32,
    acks: u32,
    commits: u32,
    mapped: bool,
    callback_pending: bool,
    closing: bool,
    detaches: u32,
    destroyed: u32,
}
struct App {
    compositor: CompositorState,
    shm: ShmState,
    xdg: XdgShellState,
    windows: [ManagedWindow; 2],
    scene: Scene<8>,
    seats: SeatState<Self>,
    seat: Seat<Self>,
    keyboard_focus: Option<u32>,
    pointer: (f64, f64),
    next_scene: usize,
    input_complete: bool,
    pressed: bool,
    moved: bool,
    serial: u32,
    error: Option<String>,
    live_surfaces: usize,
    destroyed_buffers: usize,
}
fn index(id: u32) -> Result<usize> {
    match id {
        1 => Ok(0),
        2 => Ok(1),
        _ => Err("unknown client identity".into()),
    }
}
fn surface_id(surface: &WlSurface) -> Result<u32> {
    let client = surface.client().ok_or("surface client disconnected")?;
    Ok(client
        .get_data::<ClientState>()
        .ok_or("unowned surface")?
        .id)
}
fn placement(id: u32) -> Rect {
    let (x, y) = if id == 1 { (8, 8) } else { (40, 24) };
    Rect {
        x,
        y,
        width: 64,
        height: 48,
    }
}
fn seed(id: u32, frame: u32) -> Result<u32> {
    let seeds: &[u32] = if id == 1 {
        &[0, 272, 48, 273, 32]
    } else {
        &[0, 30, 272, 46]
    };
    seeds
        .get(frame as usize)
        .copied()
        .ok_or_else(|| "unexpected buffer commit".into())
}
fn label(id: Option<u32>) -> &'static str {
    match id {
        Some(1) => "A",
        Some(2) => "B",
        _ => "none",
    }
}
impl CompositorHandler for App {
    fn compositor_state(&mut self) -> &mut CompositorState {
        &mut self.compositor
    }
    fn client_compositor_state<'a>(&self, client: &'a Client) -> &'a CompositorClientState {
        &client
            .get_data::<ClientState>()
            .expect("owned client data")
            .compositor
    }
    fn new_surface(&mut self, _: &WlSurface) {
        self.live_surfaces += 1;
    }
    fn destroyed(&mut self, _: &WlSurface) {
        self.live_surfaces -= 1;
    }
    fn commit(&mut self, surface: &WlSurface) {
        if let Err(error) = self.commit_surface(surface) {
            self.error = Some(error.to_string());
        }
    }
}
impl BufferHandler for App {
    fn buffer_destroyed(&mut self, _: &WlBuffer) {
        self.destroyed_buffers += 1;
    }
}
impl ShmHandler for App {
    fn shm_state(&self) -> &ShmState {
        &self.shm
    }
}
impl PointerConstraintsHandler for App {}
impl XdgShellHandler for App {
    fn xdg_shell_state(&mut self) -> &mut XdgShellState {
        &mut self.xdg
    }
    fn new_toplevel(&mut self, surface: ToplevelSurface) {
        let result = (|| -> Result {
            let i = index(surface_id(surface.wl_surface())?)?;
            require(
                self.windows[i].toplevel.is_none(),
                "one toplevel per client required",
            )?;
            self.windows[i].toplevel = Some(surface);
            Ok(())
        })();
        if let Err(error) = result {
            self.error = Some(error.to_string());
        }
    }
    fn new_popup(&mut self, surface: PopupSurface, _: PositionerState) {
        surface.send_popup_done();
        self.error = Some("popup outside bounded window profile".into());
    }
    fn grab(&mut self, _: PopupSurface, _: WlSeat, _: Serial) {
        self.error = Some("popup grab outside bounded window profile".into());
    }
    fn reposition_request(&mut self, _: PopupSurface, _: PositionerState, _: u32) {
        self.error = Some("popup reposition outside bounded window profile".into());
    }
    fn toplevel_destroyed(&mut self, surface: ToplevelSurface) {
        if let Some(window) = self
            .windows
            .iter_mut()
            .find(|window| window.toplevel.as_ref() == Some(&surface))
        {
            if window.mapped || !window.closing {
                self.error = Some("toplevel destroyed before close/unmap".into());
            }
            window.toplevel = None;
            window.destroyed += 1;
        } else {
            self.error = Some("unknown toplevel destruction".into());
        }
    }
    fn ack_configure(&mut self, surface: WlSurface, configure: Configure) {
        if let Err(error) = self.ack(surface, configure) {
            self.error = Some(error.to_string());
        }
    }
}
impl SeatHandler for App {
    type KeyboardFocus = WlSurface;
    type PointerFocus = WlSurface;
    type TouchFocus = WlSurface;
    fn seat_state(&mut self) -> &mut SeatState<Self> {
        &mut self.seats
    }
    fn focus_changed(&mut self, _: &Seat<Self>, _: Option<&WlSurface>) {}
    fn cursor_image(&mut self, _: &Seat<Self>, _: CursorImageStatus) {}
}
smithay::delegate_dispatch2!(App);

impl App {
    fn serial(&mut self) -> Serial {
        self.serial += 1;
        self.serial.into()
    }
    fn surface(&self, id: u32) -> Result<WlSurface> {
        Ok(self.windows[index(id)?]
            .toplevel
            .as_ref()
            .ok_or("missing toplevel")?
            .wl_surface()
            .clone())
    }
    fn configure(&mut self, id: u32, activated: bool) -> Result {
        let window = &mut self.windows[index(id)?];
        require(window.awaiting.is_none(), "configuration already pending")?;
        let surface = window
            .toplevel
            .as_ref()
            .ok_or("configure without toplevel")?;
        surface.with_pending_state(|state| {
            state.size = Some((64, 48).into());
            if activated {
                state.states.set(xdg_toplevel::State::Activated);
            } else {
                state.states.unset(xdg_toplevel::State::Activated);
            }
        });
        let serial = surface.send_configure();
        window.awaiting = Some((serial, activated));
        window.activated = activated;
        let sequence = window.configures;
        window.configures += 1;
        emit(&format!(
            "SMITHAY_MULTI CONFIG id={id} n={sequence} serial={} w=64 h=48 a={}\n",
            u32::from(serial),
            u8::from(activated)
        ))
    }
    fn ack(&mut self, surface: WlSurface, configure: Configure) -> Result {
        let id = surface_id(&surface)?;
        let window = &mut self.windows[index(id)?];
        let Configure::Toplevel(configure) = configure else {
            return Err("unexpected popup ACK".into());
        };
        let (serial, activated) = window.awaiting.ok_or("unsolicited configure ACK")?;
        require(
            window.toplevel.as_ref().map(ToplevelSurface::wl_surface) == Some(&surface)
                && configure.serial == serial
                && configure.state.size == Some((64, 48).into())
                && configure
                    .state
                    .states
                    .contains(xdg_toplevel::State::Activated)
                    == activated,
            "configure ACK identity or state mismatch",
        )?;
        let sequence = window.acks;
        window.acks += 1;
        window.awaiting = None;
        emit(&format!(
            "SMITHAY_MULTI ACK id={id} n={sequence} serial={}\n",
            u32::from(serial)
        ))
    }
    fn commit_surface(&mut self, surface: &WlSurface) -> Result {
        let id = surface_id(surface)?;
        let i = index(id)?;
        on_commit_buffer_handler::<Self>(surface);
        let attached =
            with_renderer_surface_state(surface, |state| state.buffer().is_some()).unwrap_or(false);
        if attached {
            let window = &mut self.windows[i];
            require(
                !window.closing && window.awaiting.is_none() && !window.callback_pending,
                "commit before ACK or preceding frame completion",
            )?;
            let frame = window.commits;
            let seed = seed(id, frame)?;
            let size = with_renderer_surface_state(surface, |state| state.buffer_size())
                .flatten()
                .ok_or("missing buffer size")?;
            require(size.w == 64 && size.h == 48, "unexpected committed size")?;
            if !window.mapped {
                self.scene
                    .insert(Window {
                        id,
                        rect: placement(id),
                    })
                    .map_err(|_| "scene insertion failed")?;
                window.mapped = true;
            }
            window.commits += 1;
            window.callback_pending = true;
            emit(&format!(
                "SMITHAY_MULTI COMMIT id={id} frame={frame} seed={seed}\n"
            ))?;
        } else if self.windows[i].configures == 0 {
            self.configure(id, id == 2)?;
        } else {
            require(
                self.windows[i].mapped
                    && self.windows[i].closing
                    && !self.windows[i].callback_pending,
                "unexpected unmap or empty commit",
            )?;
            self.windows[i].mapped = false;
            self.windows[i].detaches += 1;
            self.scene.remove(id).map_err(|_| "scene removal failed")?;
            self.apply_focus("unmap")?;
            self.pointer_motion()?;
            emit(&format!("SMITHAY_MULTI UNMAP id={id}\n"))?;
        }
        Ok(())
    }
    fn apply_focus(&mut self, reason: &str) -> Result {
        let new = self.scene.focus();
        if self.keyboard_focus == new {
            return Ok(());
        }
        let old = self.keyboard_focus;
        for id in 1..=2 {
            let window = &self.windows[index(id)?];
            let activated = new == Some(id);
            if window.mapped && window.activated != activated {
                self.configure(id, activated)?;
            }
        }
        let surface = new.map(|id| self.surface(id)).transpose()?;
        let keyboard = self.seat.get_keyboard().ok_or("missing keyboard")?;
        let serial = self.serial();
        keyboard.set_focus(self, surface, serial);
        self.keyboard_focus = new;
        emit(&format!(
            "SMITHAY_MULTI FOCUS previous={} current={} reason={reason}\n",
            old.unwrap_or(0),
            new.unwrap_or(0)
        ))
    }
    fn pointer_motion(&mut self) -> Result {
        let focus = self
            .scene
            .hit_test(self.pointer.0, self.pointer.1)
            .map(|window| {
                self.surface(window.id).map(|surface| {
                    (
                        surface,
                        (f64::from(window.rect.x), f64::from(window.rect.y)).into(),
                    )
                })
            })
            .transpose()?;
        let pointer = self.seat.get_pointer().ok_or("missing pointer")?;
        let serial = self.serial();
        pointer.motion(
            self,
            focus,
            &MotionEvent {
                location: self.pointer.into(),
                serial,
                time: InputTime::now(),
            },
        );
        pointer.frame(self);
        Ok(())
    }
    fn input(&mut self, action: InputAction) -> Result {
        require(
            self.next_scene > 0 && self.next_scene < 10 && !self.input_complete,
            "input outside captured scene barrier",
        )?;
        let scene = self.next_scene - 1;
        let time = InputTime::now();
        let serial = self.serial();
        match action {
            InputAction::Key { code, pressed } => {
                let expected = match scene {
                    0 => 30,
                    2 => 48,
                    5 => 46,
                    6 | 8 => 16,
                    7 => 32,
                    _ => 0,
                };
                require(
                    expected != 0 && code == expected,
                    "unexpected keyboard phase or code",
                )?;
                let id = self.keyboard_focus.ok_or("key without focus")?;
                let keyboard = self.seat.get_keyboard().ok_or("missing keyboard")?;
                require(self.pressed != pressed, "unbalanced key event")?;
                keyboard.input::<(), _>(
                    self,
                    (u32::from(code) + 8).into(),
                    if pressed {
                        KeyState::Pressed
                    } else {
                        KeyState::Released
                    },
                    serial,
                    time,
                    |_, _, _| FilterResult::Forward,
                );
                self.pressed = pressed;
                if !pressed {
                    self.input_complete = true;
                    emit(&format!(
                        "SMITHAY_MULTI INPUT scene={scene} target={id} kind=key code={code}\n"
                    ))?;
                    if code == 16 {
                        let window = &mut self.windows[index(id)?];
                        require(!window.closing, "duplicate close")?;
                        window.closing = true;
                        window
                            .toplevel
                            .as_ref()
                            .ok_or("close without toplevel")?
                            .send_close();
                        emit(&format!("SMITHAY_MULTI CLOSE id={id}\n"))?;
                    }
                }
            }
            InputAction::Motion { dx, dy } => {
                let expected = match scene {
                    1 => (-32, -16),
                    3 | 4 => (40, 24),
                    _ => (0, 0),
                };
                require(
                    (dx, dy) == expected && expected != (0, 0) && !self.moved && !self.pressed,
                    "unexpected pointer motion",
                )?;
                self.pointer.0 = (self.pointer.0 + f64::from(dx)).clamp(0.0, 127.0);
                self.pointer.1 = (self.pointer.1 + f64::from(dy)).clamp(0.0, 95.0);
                self.pointer_motion()?;
                self.moved = true;
            }
            InputAction::Button { code, pressed } => {
                require(
                    self.moved
                        && (scene == 1 || scene == 3 || scene == 4)
                        && code == if scene == 3 { 273 } else { 272 }
                        && self.pressed != pressed,
                    "unexpected button phase, code or ordering",
                )?;
                let target = self
                    .scene
                    .hit_test(self.pointer.0, self.pointer.1)
                    .ok_or("button outside windows")?
                    .id;
                if pressed {
                    self.scene
                        .focus_raise(target)
                        .map_err(|_| "focus/raise failed")?;
                    self.apply_focus("click")?;
                }
                let pointer = self.seat.get_pointer().ok_or("missing pointer")?;
                pointer.button(
                    self,
                    &ButtonEvent {
                        serial,
                        time,
                        button: u32::from(code),
                        state: if pressed {
                            ButtonState::Pressed
                        } else {
                            ButtonState::Released
                        },
                    },
                );
                pointer.frame(self);
                self.pressed = pressed;
                if !pressed {
                    self.input_complete = true;
                    emit(&format!(
                        "SMITHAY_MULTI INPUT scene={scene} target={target} kind=button code={code}\n"
                    ))?;
                }
            }
            InputAction::Resync => {
                return Err("native input loss requires resynchronization".into());
            }
        }
        Ok(())
    }
    fn ready(&self, exited: &[bool; 2]) -> bool {
        if self.next_scene >= 10 || self.windows.iter().any(|w| w.awaiting.is_some()) {
            return false;
        }
        let expected = [
            (1, 1),
            (1, 2),
            (2, 2),
            (3, 2),
            (4, 2),
            (4, 3),
            (4, 4),
            (4, 4),
            (5, 4),
            (5, 4),
        ][self.next_scene];
        if (self.windows[0].commits, self.windows[1].commits) != expected {
            return false;
        }
        if self.next_scene > 0 && !self.input_complete {
            return false;
        }
        match self.next_scene {
            0..=6 => self.scene.len() == 2,
            7 | 8 => self.scene.len() == 1 && exited[1],
            9 => self.scene.len() == 0 && exited[0] && exited[1],
            _ => false,
        }
    }
}

fn expected_pixel(id: u32, frame: u32, x: u32, y: u32) -> Result<[u8; 4]> {
    let seed = seed(id, frame)?;
    Ok([
        (3 * x + y + 29 * id + 47 * frame + seed) as u8,
        (x + 5 * y + 11 * id + 31 * frame + 3 * seed) as u8,
        (7 * (x ^ y) + 13 * id + 19 * frame + 5 * seed) as u8,
        255,
    ])
}
fn render(
    app: &mut App,
    renderer: &mut GlesRenderer,
    buffer: &mut GlesRenderbuffer,
    native: &mut NativeDisplay,
) -> Result {
    if app.next_scene == 0 {
        app.scene
            .focus_raise(2)
            .map_err(|_| "initial focus failed")?;
        app.apply_focus("initial")?;
        app.pointer_motion()?;
    }
    let mut elements: Vec<WaylandSurfaceRenderElement<GlesRenderer>> = Vec::new();
    for window in app.scene.top_to_bottom() {
        let surface = app.surface(window.id)?;
        let imported = render_elements_from_surface_tree(
            renderer,
            &surface,
            (window.rect.x, window.rect.y),
            1.0,
            1.0,
            Kind::Unspecified,
        );
        require(
            imported.len() == 1,
            "one real surface element per window required",
        )?;
        elements.extend(imported);
    }
    let mut target = renderer.bind(buffer)?;
    let full = Rectangle::from_size((WIDTH, HEIGHT).into());
    let mut frame = renderer.render(&mut target, (WIDTH, HEIGHT).into(), Transform::Flipped180)?;
    frame.clear(Color32F::new(0.0, 0.0, 0.0, 1.0), &[full])?;
    draw_render_elements(&mut frame, 1.0, &elements, &[full])?;
    frame.finish()?.wait()?;
    let mapping = renderer.copy_framebuffer(
        &target,
        Rectangle::from_size((WIDTH, HEIGHT).into()),
        Fourcc::Abgr8888,
    )?;
    let flipped = mapping.flipped();
    let bytes = renderer.map_texture(&mapping)?;
    require(
        bytes.len() == (WIDTH * HEIGHT * 4) as usize,
        "readback size mismatch",
    )?;
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let row = if flipped { HEIGHT - 1 - y } else { y };
            let start = ((row * WIDTH + x) * 4) as usize;
            let expected = match app.scene.hit_test(f64::from(x), f64::from(y)) {
                Some(window) => expected_pixel(
                    window.id,
                    app.windows[index(window.id)?].commits - 1,
                    (x - window.rect.x) as u32,
                    (y - window.rect.y) as u32,
                )?,
                None => [0, 0, 0, 255],
            };
            if bytes[start..start + 4] != expected {
                return Err(format!(
                    "scene {} pixel mismatch x={x} y={y} actual={:?} expected={expected:?}",
                    app.next_scene,
                    &bytes[start..start + 4]
                )
                .into());
            }
        }
    }
    native.present_rgba(32, 48, WIDTH as u32, HEIGHT as u32, bytes, flipped)?;
    drop(mapping);
    drop(target);
    // Exactly one real callback belongs to each newly committed buffer. A
    // stationary other window has no fabricated callback or commit.
    for id in 1..=2 {
        let i = index(id)?;
        if !app.windows[i].callback_pending {
            continue;
        }
        let surface = app.surface(id)?;
        let callbacks = with_states(&surface, |states| {
            states
                .cached_state
                .get::<SurfaceAttributes>()
                .current()
                .frame_callbacks
                .drain(..)
                .collect::<Vec<_>>()
        });
        require(
            callbacks.len() == 1,
            "one frame callback per committed buffer required",
        )?;
        for callback in callbacks {
            callback.done(app.next_scene as u32);
        }
        app.windows[i].callback_pending = false;
    }
    emit(&format!(
        "SMITHAY_MULTI SCENE n={} top={} focus={} windows={}\n",
        app.next_scene,
        label(app.scene.top_to_bottom().next().map(|w| w.id)),
        label(app.scene.focus()),
        app.scene.len()
    ))?;
    app.next_scene += 1;
    app.input_complete = false;
    app.moved = false;
    Ok(())
}

fn run() -> Result {
    // SAFETY: Process initialization precedes all libraries; this synchronous
    // profile does not start background SHM cleanup or renderer threads.
    unsafe {
        std::env::set_var("LIBGL_ALWAYS_SOFTWARE", "true");
        std::env::set_var("GALLIUM_DRIVER", "softpipe");
        std::env::set_var("MESA_SHADER_CACHE_DISABLE", "true");
    }
    let mut native = NativeDisplay::connect()?;
    let mut display: Display<App> = Display::new()?;
    let mut dh = display.handle();
    let mut seats = SeatState::new();
    let mut seat = seats.new_wl_seat(&dh, "cyxia-native");
    seat.add_keyboard(
        XkbConfig {
            keymap_text: Some(include_str!("us.xkb")),
            ..XkbConfig::default()
        },
        200,
        25,
    )?;
    seat.add_pointer();
    let mut app = App {
        compositor: CompositorState::new::<App>(&dh),
        shm: ShmState::new::<App>(&dh, vec![]),
        xdg: XdgShellState::new_with_capabilities::<App>(&dh, []),
        windows: Default::default(),
        scene: Scene::new(),
        seats,
        seat,
        keyboard_focus: None,
        pointer: (48.0, 32.0),
        next_scene: 0,
        input_complete: false,
        pressed: false,
        moved: false,
        serial: 0,
        error: None,
        live_surfaces: 0,
        destroyed_buffers: 0,
    };
    // SAFETY: This process exclusively owns EGL on this thread.
    let egl = unsafe { EGLDisplay::new(EGLSurfacelessDisplay)? };
    let context = EGLContext::new(&egl)?;
    // SAFETY: The context is exclusively owned and confined to this thread.
    let mut renderer = unsafe { GlesRenderer::new(context)? };
    let softpipe = renderer.with_context(|gl| {
        // SAFETY: A current context owns the terminated GL renderer string.
        unsafe {
            let name = gl.GetString(0x1F01);
            !name.is_null() && CStr::from_ptr(name.cast()).to_bytes() == b"softpipe"
        }
    })?;
    require(softpipe, "real Mesa softpipe required")?;
    let mut buffer: GlesRenderbuffer =
        renderer.create_buffer(Fourcc::Abgr8888, (WIDTH, HEIGHT).into())?;
    emit("SMITHAY_MULTI READY wayland=1 gles=1 native=1 xdg=1 windows=2\n")?;
    emit("SMITHAY_MULTI CANVAS x=32 y=48 width=128 height=96\n")?;
    let mut clients = Vec::new();
    for id in 1..=2 {
        let (server, socket) = UnixStream::pair()?;
        let data = Arc::new(ClientState {
            id,
            compositor: Default::default(),
            disconnected: AtomicBool::new(false),
            protocol_error: AtomicBool::new(false),
        });
        let client = dh.insert_client(server, data.clone())?;
        let child = spawn_client(socket.as_raw_fd(), id)?;
        drop(socket);
        emit(&format!("SMITHAY_MULTI SPAWN id={id} child={child}\n"))?;
        clients.push((child, data, client));
    }
    let mut exited = [false; 2];
    let mut decoder = InputDecoder::new();
    let deadline = Instant::now() + Duration::from_secs(180);
    while app.next_scene < 10 {
        require(Instant::now() < deadline, "window/input deadline exceeded")?;
        display.dispatch_clients(&mut app)?;
        if let Some(error) = app.error.take() {
            return Err(error.into());
        }
        for (i, (child, data, _)) in clients.iter().enumerate() {
            require(
                !data.protocol_error.load(Ordering::Acquire),
                "client protocol error",
            )?;
            if exited[i] || !data.disconnected.load(Ordering::Acquire) {
                continue;
            }
            let mut status = 0;
            // SAFETY: Each child PID belongs to this process; status is writable.
            let waited = unsafe { libc::waitpid(*child, &mut status, libc::WNOHANG) };
            require(waited >= 0, "waitpid failed")?;
            if waited == 0 {
                continue;
            }
            require(
                waited == *child
                    && status == 0
                    && app.windows[i].detaches == 1
                    && app.windows[i].destroyed == 1,
                "client exit/unmap lifecycle failed",
            )?;
            exited[i] = true;
            emit(&format!(
                "SMITHAY_MULTI EXIT id={} child={child} status=0\n",
                i + 1
            ))?;
        }
        if app.ready(&exited) {
            render(&mut app, &mut renderer, &mut buffer, &mut native)?;
        }
        if app.next_scene < 10 {
            let mut events = [InputEvent::default(); 32];
            let count = native::read_input(&mut events)?;
            for event in &events[..count] {
                if let Some(actions) = decoder.push(*event)? {
                    for action in actions {
                        app.input(action)?;
                    }
                }
            }
        }
        display.flush_clients()?;
        let mut fd = libc::pollfd {
            fd: display.as_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one valid descriptor record.
        if unsafe { libc::poll(&mut fd, 1, 5) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    require(
        exited == [true, true]
            && app.live_surfaces == 0
            && app.destroyed_buffers == 9
            && app.scene.len() == 0
            && app.scene.focus().is_none()
            && app.keyboard_focus.is_none()
            && app.xdg.toplevel_surfaces().is_empty()
            && app.xdg.popup_surfaces().is_empty()
            && app.windows.iter().all(|w| {
                !w.mapped && !w.callback_pending && w.awaiting.is_none() && w.toplevel.is_none()
            })
            && app.windows[0].configures == 4
            && app.windows[0].acks == 4
            && app.windows[1].configures == 3
            && app.windows[1].acks == 3,
        "multiwindow cleanup or configuration incomplete",
    )?;
    drop(buffer);
    // SAFETY: with_context makes the owned context current.
    let error = renderer.with_context(|gl| unsafe { gl.GetError() })?;
    require(error == 0, "GL error after window rendering")?;
    renderer.egl_context().unbind()?;
    drop(renderer);
    drop(egl);
    drop(clients);
    drop(app);
    drop(display);
    drop(dh);
    // SAFETY: All renderer/display objects were destroyed on this thread.
    require(
        unsafe {
            egl::GetCurrentContext() == egl::NO_CONTEXT && egl::ReleaseThread() != egl::FALSE
        },
        "EGL cleanup failed",
    )?;
    emit("SMITHAY_MULTI TOTAL clients=2 cfg=7 acks=7 closes=2 cosmic=0\n")?;
    emit("SMITHAY_MULTI RESULT PASS scenes=10 commits=9 pixels=122880\n")
}
fn main() {
    if let Err(error) = run() {
        let _ = emit("SMITHAY_MULTI FAIL\n");
        let prefix = "SMITHAY_MULTI ERROR ";
        let mut line = prefix.to_owned();
        for character in error.to_string().chars() {
            let character = if character == '\r' || character == '\n' {
                ' '
            } else {
                character
            };
            if line.len() + character.len_utf8() + 1 > 64 {
                line.push('\n');
                let _ = emit(&line);
                line.truncate(prefix.len());
            }
            line.push(character);
        }
        line.push('\n');
        let _ = emit(&line);
        std::process::exit(1);
    }
}
