//! Bounded real Smithay compositor integration on CyxiaOS.
mod native;

use native::{InputAction, InputDecoder, InputEvent, NativeDisplay};
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
    reexports::wayland_server::{
        Client, Display,
        backend::{ClientData, ClientId, DisconnectReason},
        protocol::{wl_buffer::WlBuffer, wl_surface::WlSurface},
    },
    utils::{Rectangle, Transform},
    wayland::{
        buffer::BufferHandler,
        compositor::{
            CompositorClientState, CompositorHandler, CompositorState, SurfaceAttributes,
            with_states,
        },
        pointer_constraints::PointerConstraintsHandler,
        shm::{ShmHandler, ShmState},
    },
};
use std::{
    error::Error,
    ffi::{CStr, CString},
    io::{self, Write},
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
    std::io::stdout().lock().write_all(line.as_bytes())?;
    Ok(())
}

fn require(ok: bool, reason: &str) -> Result {
    if ok {
        Ok(())
    } else {
        Err(reason.to_owned().into())
    }
}

#[derive(Default)]
struct ClientState {
    compositor: CompositorClientState,
    disconnected: AtomicBool,
}
impl ClientData for ClientState {
    fn initialized(&self, _: ClientId) {}
    fn disconnected(&self, _: ClientId, _: DisconnectReason) {
        self.disconnected.store(true, Ordering::Release);
    }
}

struct Barrier {
    surface: WlSurface,
    pressed: bool,
    motion: bool,
}

struct App {
    compositor: CompositorState,
    shm: ShmState,
    seats: SeatState<Self>,
    seat: Seat<Self>,
    pending: Option<WlSurface>,
    focused: Option<WlSurface>,
    barrier: Option<Barrier>,
    error: Option<String>,
    live_surfaces: usize,
    destroyed_buffers: usize,
    detaches: usize,
    round: u32,
    frame: u32,
    serial: u32,
    pointer: (f64, f64),
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
        // The upstream handler owns/takes the committed buffer. The renderer's
        // surface-element path is the only importer; never take it a second time.
        on_commit_buffer_handler::<Self>(surface);
        let attached =
            with_renderer_surface_state(surface, |state| state.buffer().is_some()).unwrap_or(false);
        if attached {
            if self.pending.is_some() || self.barrier.is_some() || self.frame >= 3 {
                self.error = Some("unexpected overlapping surface commit".into());
            } else {
                self.pending = Some(surface.clone());
            }
        } else {
            self.detaches += 1;
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
    fn serial(&mut self) -> smithay::utils::Serial {
        self.serial += 1;
        self.serial.into()
    }
    fn focus(&mut self, surface: &WlSurface) {
        if self.focused.as_ref() == Some(surface) {
            return;
        }
        let keyboard = self.seat.get_keyboard().expect("created keyboard");
        let pointer = self.seat.get_pointer().expect("created pointer");
        let serial = self.serial();
        keyboard.set_focus(self, Some(surface.clone()), serial);
        self.pointer = (16.0, 16.0);
        let serial = self.serial();
        pointer.motion(
            self,
            Some((surface.clone(), (0.0, 0.0).into())),
            &MotionEvent {
                location: self.pointer.into(),
                serial,
                time: InputTime::now(),
            },
        );
        pointer.frame(self);
        self.focused = Some(surface.clone());
    }
    fn input(&mut self, action: InputAction) -> Result {
        let surface = self
            .focused
            .clone()
            .ok_or("native input before surface focus")?;
        let serial = self.serial();
        let time = InputTime::now();
        let complete = match action {
            InputAction::Key { code, pressed } => {
                let keyboard = self.seat.get_keyboard().ok_or("missing keyboard")?;
                // Smithay takes XKB codes; its Wayland serializer subtracts 8.
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
                let expected = match self.frame {
                    0 => 30,
                    2 => 16,
                    _ => 0,
                };
                require(code == expected, "unexpected native keyboard phase/code")?;
                let barrier = self.barrier.as_mut().ok_or("key without frame barrier")?;
                if pressed {
                    require(!barrier.pressed, "duplicate key press")?;
                    barrier.pressed = true;
                    false
                } else {
                    require(barrier.pressed, "key release without press")?;
                    true
                }
            }
            InputAction::Motion { dx, dy } => {
                require(
                    self.frame == 1 && dx == 4 && dy == 3,
                    "unexpected native motion",
                )?;
                self.pointer.0 = (self.pointer.0 + f64::from(dx)).clamp(0.0, 127.0);
                self.pointer.1 = (self.pointer.1 + f64::from(dy)).clamp(0.0, 95.0);
                let pointer = self.seat.get_pointer().ok_or("missing pointer")?;
                pointer.motion(
                    self,
                    Some((surface.clone(), (0.0, 0.0).into())),
                    &MotionEvent {
                        location: self.pointer.into(),
                        serial,
                        time,
                    },
                );
                pointer.frame(self);
                self.barrier
                    .as_mut()
                    .ok_or("motion without frame barrier")?
                    .motion = true;
                false
            }
            InputAction::Button { code, pressed } => {
                require(
                    self.frame == 1 && code == 272,
                    "unexpected native pointer button",
                )?;
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
                let barrier = self
                    .barrier
                    .as_mut()
                    .ok_or("button without frame barrier")?;
                require(barrier.motion, "button before physical motion")?;
                if pressed {
                    require(!barrier.pressed, "duplicate button press")?;
                    barrier.pressed = true;
                    false
                } else {
                    require(barrier.pressed, "button release without press")?;
                    true
                }
            }
            InputAction::Resync => {
                return Err("input loss requires resynchronization; fixture stopped".into());
            }
        };
        if complete {
            let barrier = self.barrier.take().ok_or("missing completion barrier")?;
            let callbacks = with_states(&barrier.surface, |states| {
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
                "exactly one real frame callback required",
            )?;
            for callback in callbacks {
                callback.done(self.round * 100 + self.frame);
            }
            emit(&format!(
                "SMITHAY_WAYLAND INPUT_FORWARDED round={} frame={}\n",
                self.round, self.frame
            ))?;
            self.frame += 1;
        }
        Ok(())
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
    let path = c"/bin/smithay-wayland-client";
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

fn expected_pixel(round: u32, frame: u32, x: u32, y: u32) -> [u8; 4] {
    let seed = [0, 30, 272][frame as usize];
    [
        (3 * x + y + 29 * round + 47 * frame + seed) as u8,
        (x + 5 * y + 11 * round + 31 * frame + 3 * seed) as u8,
        (7 * (x ^ y) + 13 * round + 19 * frame + 5 * seed) as u8,
        255,
    ]
}

fn render(
    app: &mut App,
    renderer: &mut GlesRenderer,
    buffer: &mut GlesRenderbuffer,
    native: &mut NativeDisplay,
    surface: WlSurface,
) -> Result {
    let (width, height) = if app.frame == 2 { (96, 64) } else { (64, 48) };
    let size = with_renderer_surface_state(&surface, |state| state.buffer_size())
        .flatten()
        .ok_or("missing committed surface size")?;
    require(
        size.w == width && size.h == height,
        "unexpected committed buffer dimensions",
    )?;
    let elements: Vec<WaylandSurfaceRenderElement<GlesRenderer>> =
        render_elements_from_surface_tree(renderer, &surface, (0, 0), 1.0, 1.0, Kind::Unspecified);
    require(
        elements.len() == 1,
        "one imported upstream surface element required",
    )?;
    let mut target = renderer.bind(buffer)?;
    let full = Rectangle::from_size((WIDTH, HEIGHT).into());
    // Match Smithay's displayed-surface example: this output transform places
    // logical y=0 at the framebuffer top. ExportMem then reports its actual
    // bottom-up mapping, which the oracle and native scanout both normalize.
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
            let expected = if x < width && y < height {
                expected_pixel(app.round, app.frame, x as u32, y as u32)
            } else {
                [0, 0, 0, 255]
            };
            if bytes[start..start + 4] != expected {
                return Err(format!("pixel mismatch x={x} y={y} flipped={flipped} actual={:?} expected={expected:?}", &bytes[start..start+4]).into());
            }
        }
    }
    native.present_rgba(32, 48, WIDTH as u32, HEIGHT as u32, bytes, flipped)?;
    drop(mapping);
    drop(target);
    app.focus(&surface);
    app.barrier = Some(Barrier {
        surface,
        pressed: false,
        motion: false,
    });
    emit(&format!(
        "SMITHAY_WAYLAND FRAME_READY round={} frame={} x=32 y=48 width=128 height=96 surface_width={} surface_height={} seed={}\n",
        app.round,
        app.frame,
        width,
        height,
        [0, 30, 272][app.frame as usize]
    ))
}

fn run() -> Result {
    // SAFETY: Environment setup precedes all library initialization; the
    // selected synchronous SHM-drop profile does not create worker threads.
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
        seats,
        seat,
        pending: None,
        focused: None,
        barrier: None,
        error: None,
        live_surfaces: 0,
        destroyed_buffers: 0,
        detaches: 0,
        round: 0,
        frame: 0,
        serial: 0,
        pointer: (16.0, 16.0),
    };
    // SAFETY: This process exclusively owns EGL and confines it to this thread.
    let egl = unsafe { EGLDisplay::new(EGLSurfacelessDisplay)? };
    let context = EGLContext::new(&egl)?;
    // SAFETY: The new context is exclusively owned and confined to this thread.
    let mut renderer = unsafe { GlesRenderer::new(context)? };
    let softpipe = renderer.with_context(|gl| {
        // SAFETY: with_context makes the owned context current; GL owns its
        // terminated renderer string. A missing string fails the check.
        unsafe {
            let name = gl.GetString(0x1F01);
            !name.is_null() && CStr::from_ptr(name.cast()).to_bytes() == b"softpipe"
        }
    })?;
    require(softpipe, "actual Mesa softpipe renderer required")?;
    let mut buffer: GlesRenderbuffer =
        renderer.create_buffer(Fourcc::Abgr8888, (WIDTH, HEIGHT).into())?;
    emit("SMITHAY_WAYLAND READY frontend=upstream renderer=upstream native=1\n")?;
    for round in 1..=2 {
        app.round = round;
        app.frame = 0;
        let (server, client_socket) = UnixStream::pair()?;
        let data = Arc::new(ClientState::default());
        let _client = dh.insert_client(server, data.clone())?;
        let child = spawn_client(client_socket.as_raw_fd(), round)?;
        drop(client_socket);
        emit(&format!(
            "SMITHAY_WAYLAND SPAWN round={round} child={child}\n"
        ))?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut decoder = InputDecoder::new();
        while !data.disconnected.load(Ordering::Acquire) {
            require(Instant::now() < deadline, "client/input deadline exceeded")?;
            display.dispatch_clients(&mut app)?;
            if let Some(error) = app.error.take() {
                return Err(error.into());
            }
            if let Some(surface) = app.pending.take() {
                render(&mut app, &mut renderer, &mut buffer, &mut native, surface)?;
            }
            let mut events = [InputEvent::default(); 32];
            let count = native::read_input(&mut events)?;
            for event in &events[..count] {
                if let Some(actions) = decoder.push(*event)? {
                    for action in actions {
                        app.input(action)?;
                    }
                }
            }
            display.flush_clients()?;
            let mut fd = libc::pollfd {
                fd: display.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll receives one valid live descriptor record.
            let status = unsafe { libc::poll(&mut fd, 1, 5) };
            if status < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error().into());
            }
        }
        let mut status = 0;
        // SAFETY: The returned child is owned by this process; status is writable.
        require(
            unsafe { libc::waitpid(child, &mut status, 0) } == child && status == 0,
            "client did not exit successfully",
        )?;
        require(
            app.frame == 3 && app.barrier.is_none() && app.pending.is_none(),
            "incomplete frame/input sequence",
        )?;
        require(
            app.live_surfaces == 0
                && app.destroyed_buffers == round as usize * 3
                && app.detaches == round as usize * 3,
            "upstream object lifecycle incomplete",
        )?;
        let keyboard = app.seat.get_keyboard().ok_or("missing keyboard")?;
        let serial = app.serial();
        keyboard.set_focus(&mut app, None, serial);
        app.focused = None;
        emit(&format!(
            "SMITHAY_WAYLAND ROUND_PASS round={round} frames=3 surfaces=0\n"
        ))?;
    }
    drop(buffer);
    let error = renderer.with_context(|gl| unsafe { gl.GetError() })?;
    require(error == 0, "GL error after surface rendering")?;
    renderer.egl_context().unbind()?;
    drop(renderer);
    drop(egl);
    drop(app);
    drop(display);
    drop(dh);
    // SAFETY: All renderer/display objects have been destroyed on this thread.
    require(
        unsafe {
            egl::GetCurrentContext() == egl::NO_CONTEXT && egl::ReleaseThread() != egl::FALSE
        },
        "EGL thread cleanup failed",
    )?;
    emit("SMITHAY_WAYLAND RESULT PASS rounds=2 frames=6 pixels=73728 native=1 input=1 cosmic=0\n")
}

fn main() {
    if let Err(error) = run() {
        let _ = emit(&format!("SMITHAY_WAYLAND FAIL {error}\n"));
        std::process::exit(1);
    }
}
