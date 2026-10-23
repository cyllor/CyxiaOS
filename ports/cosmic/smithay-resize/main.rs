//! Real concurrent xdg-shell windows, independent scene mechanisms and native scanout.
mod geometry;
mod native;
use geometry::{Authority, CommitGeometry, Interaction, Kind as DragKind, Limits};
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
        pointer::{
            AxisFrame, ButtonEvent, CursorImageStatus, Focus, GestureHoldBeginEvent,
            GestureHoldEndEvent, GesturePinchBeginEvent, GesturePinchEndEvent,
            GesturePinchUpdateEvent, GestureSwipeBeginEvent, GestureSwipeEndEvent,
            GestureSwipeUpdateEvent, GrabStartData, MotionEvent, PointerGrab, PointerInnerHandle,
            RelativeMotionEvent,
        },
    },
    reexports::wayland_protocols::xdg::shell::server::xdg_toplevel,
    reexports::wayland_server::{
        Client, Display, Resource,
        backend::{ClientData, ClientId, DisconnectReason},
        protocol::{wl_buffer::WlBuffer, wl_seat::WlSeat, wl_surface::WlSurface},
    },
    utils::{Logical, Point, Rectangle, SERIAL_COUNTER, Serial, Transform},
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
    let path = c"/bin/smithay-resize-client";
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
#[derive(Clone, Copy)]
struct Pending {
    serial: Serial,
    rect: Rect,
    activated: bool,
    resizing: bool,
}
#[derive(Default)]
struct ManagedWindow {
    toplevel: Option<ToplevelSurface>,
    awaiting: Option<Pending>,
    geometry: CommitGeometry,
    activated: bool,
    resizing: bool,
    configures: u32,
    acks: u32,
    commits: u32,
    requests: u32,
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
    interaction: Interaction,
    seats: SeatState<Self>,
    seat: Seat<Self>,
    keyboard_focus: Option<u32>,
    pointer: (f64, f64),
    next_scene: usize,
    step_done: bool,
    pressed: bool,
    key_down: bool,
    resize_updates: u32,
    resize_finished: bool,
    cancellations: u32,
    quarantine: bool,
    pointer_sample: Option<usize>,
    rejected: u32,
    accepted: u32,
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
    let (x, y) = if id == 1 { (24, 16) } else { (40, 24) };
    Rect {
        x,
        y,
        width: 64,
        height: 48,
    }
}
fn seed(id: u32, frame: u32) -> Result<u32> {
    let seeds: &[u32] = if id == 1 {
        &[0, 272, 272, 272, 272, 32, 273, 273]
    } else {
        &[0, 32]
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
    fn move_request(&mut self, surface: ToplevelSurface, seat: WlSeat, serial: Serial) {
        if let Err(error) = self.request(surface, seat, serial, DragKind::Move, 0) {
            self.error = Some(error.to_string());
        }
    }
    fn resize_request(
        &mut self,
        surface: ToplevelSurface,
        seat: WlSeat,
        serial: Serial,
        edges: xdg_toplevel::ResizeEdge,
    ) {
        if let Err(error) = self.request(surface, seat, serial, DragKind::Resize, edges as u32) {
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
        // Share the upstream sequence used by xdg configure events. Separate
        // counters can accidentally make an old configure look like a current
        // input serial even though pointer-grab ownership is still checked.
        SERIAL_COUNTER.next_serial()
    }
    fn surface(&self, id: u32) -> Result<WlSurface> {
        Ok(self.windows[index(id)?]
            .toplevel
            .as_ref()
            .ok_or("missing toplevel")?
            .wl_surface()
            .clone())
    }
    fn geometry(&self, id: u32) -> Rect {
        self.scene
            .get(id)
            .map(|w| w.rect)
            .unwrap_or_else(|| placement(id))
    }
    fn configure(
        &mut self,
        id: u32,
        activated: bool,
        resizing: bool,
        rect: Rect,
        anchored: bool,
    ) -> Result {
        let window = &mut self.windows[index(id)?];
        require(window.awaiting.is_none(), "configuration already pending")?;
        let surface = window
            .toplevel
            .as_ref()
            .ok_or("configure without toplevel")?;
        surface.with_pending_state(|state| {
            state.size = Some((rect.width, rect.height).into());
            if activated {
                state.states.set(xdg_toplevel::State::Activated);
            } else {
                state.states.unset(xdg_toplevel::State::Activated);
            }
            if resizing {
                state.states.set(xdg_toplevel::State::Resizing);
            } else {
                state.states.unset(xdg_toplevel::State::Resizing);
            }
        });
        let serial = surface.send_configure();
        window
            .geometry
            .offer(u32::from(serial), rect, anchored)
            .map_err(|_| "configure geometry transaction unavailable")?;
        window.awaiting = Some(Pending {
            serial,
            rect,
            activated,
            resizing,
        });
        window.activated = activated;
        window.resizing = resizing;
        let sequence = window.configures;
        window.configures += 1;
        emit(&format!(
            "SMITHAY_RS CONFIG id={id} n={sequence} s={} w={} h={} a={} r={}\n",
            u32::from(serial),
            rect.width,
            rect.height,
            u8::from(activated),
            u8::from(resizing)
        ))
    }
    fn ack(&mut self, surface: WlSurface, configure: Configure) -> Result {
        let id = surface_id(&surface)?;
        let window = &mut self.windows[index(id)?];
        let Configure::Toplevel(configure) = configure else {
            return Err("unexpected popup ACK".into());
        };
        let pending = window.awaiting.ok_or("unsolicited configure ACK")?;
        require(
            window.toplevel.as_ref().map(ToplevelSurface::wl_surface) == Some(&surface)
                && configure.serial == pending.serial
                && configure.state.size == Some((pending.rect.width, pending.rect.height).into())
                && configure
                    .state
                    .states
                    .contains(xdg_toplevel::State::Activated)
                    == pending.activated
                && configure
                    .state
                    .states
                    .contains(xdg_toplevel::State::Resizing)
                    == pending.resizing,
            "configure ACK state mismatch",
        )?;
        let sequence = window.acks;
        window.acks += 1;
        window.awaiting = None;
        window
            .geometry
            .ack(u32::from(pending.serial))
            .map_err(|_| "configure geometry ACK mismatch")?;
        emit(&format!(
            "SMITHAY_RS ACK id={id} n={sequence} s={}\n",
            u32::from(pending.serial)
        ))
    }
    fn commit_surface(&mut self, surface: &WlSurface) -> Result {
        let id = surface_id(surface)?;
        let i = index(id)?;
        on_commit_buffer_handler::<Self>(surface);
        let attached =
            with_renderer_surface_state(surface, |state| state.buffer().is_some()).unwrap_or(false);
        if attached {
            let current = self.geometry(id);
            let window = &mut self.windows[i];
            require(
                !window.closing && window.awaiting.is_none() && !window.callback_pending,
                "commit before ACK or previous frame",
            )?;
            let frame = window.commits;
            let seed = seed(id, frame)?;
            let size = with_renderer_surface_state(surface, |state| state.buffer_size())
                .flatten()
                .ok_or("missing buffer size")?;
            let applied = window
                .geometry
                .commit(current, (size.w, size.h))
                .map_err(|_| "buffer differs from ACKed geometry transaction")?;
            let rect = applied.rect;
            emit(&format!(
                "SMITHAY_RS APPLY id={id} s={} anchor={} x={} y={}\n",
                applied.serial.unwrap_or(0),
                u8::from(applied.anchored),
                rect.x,
                rect.y
            ))?;
            if window.mapped {
                self.scene
                    .set_geometry(id, rect)
                    .map_err(|_| "geometry update failed")?;
            } else {
                self.scene
                    .insert(Window { id, rect })
                    .map_err(|_| "scene insertion failed")?;
                window.mapped = true;
            }
            window.commits += 1;
            window.callback_pending = true;
            emit(&format!(
                "SMITHAY_RS COMMIT id={id} frame={frame} seed={seed}\n"
            ))?;
        } else if self.windows[i].configures == 0 {
            self.configure(id, id == 2, false, placement(id), false)?;
        } else {
            require(
                self.windows[i].mapped
                    && self.windows[i].closing
                    && !self.windows[i].callback_pending,
                "unexpected unmap",
            )?;
            self.windows[i].mapped = false;
            self.windows[i].detaches += 1;
            self.windows[i].geometry.clear();
            self.scene.remove(id).map_err(|_| "scene removal failed")?;
            let cancelled = self.interaction.cancel(id).is_some();
            // Recompute pending focus only after removal. WindowGrab::motion
            // replaces a cancelled owner with a focusless release quarantine.
            self.pointer_motion()?;
            if cancelled {
                require(
                    self.quarantine,
                    "owner grab did not enter release quarantine",
                )?;
                self.cancellations += 1;
                emit(&format!("SMITHAY_RS CANCEL id={id} reason=unmap\n"))?;
                self.pointer_receipt(self.next_scene)?;
            }
            self.apply_focus("unmap")?;
            emit(&format!("SMITHAY_RS UNMAP id={id}\n"))?;
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
            let w = &self.windows[index(id)?];
            let active = new == Some(id);
            if w.mapped && w.activated != active {
                self.configure(id, active, false, self.geometry(id), false)?;
            }
        }
        let surface = new.map(|id| self.surface(id)).transpose()?;
        let keyboard = self.seat.get_keyboard().ok_or("missing keyboard")?;
        let serial = self.serial();
        keyboard.set_focus(self, surface, serial);
        self.keyboard_focus = new;
        emit(&format!(
            "SMITHAY_RS FOCUS previous={} current={} reason={reason}\n",
            old.unwrap_or(0),
            new.unwrap_or(0)
        ))
    }
    fn pointer_target(&self) -> Result<Option<(WlSurface, Point<f64, Logical>)>> {
        self.scene
            .hit_test(self.pointer.0, self.pointer.1)
            .map(|w| {
                self.surface(w.id)
                    .map(|s| (s, (f64::from(w.rect.x), f64::from(w.rect.y)).into()))
            })
            .transpose()
    }
    fn pointer_motion(&mut self) -> Result {
        let focus = self.pointer_target()?;
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
    fn pointer_receipt(&mut self, scene: usize) -> Result {
        // The sample is captured inside the real grab callback, after Smithay
        // updates its physical pressed-button vector. Query focus/grab only
        // after returning from that callback to avoid locking it recursively.
        let held = self
            .pointer_sample
            .take()
            .ok_or("missing pointer state sample")?;
        let pointer = self.seat.get_pointer().ok_or("missing pointer")?;
        let focus = pointer
            .current_focus()
            .map(|surface| surface_id(&surface))
            .transpose()?
            .unwrap_or(0);
        emit(&format!(
            "SMITHAY_RS POINTER n={scene} grabbed={} held={held} focus={focus}\n",
            u8::from(pointer.is_grabbed())
        ))
    }
    fn request(
        &mut self,
        surface: ToplevelSurface,
        seat: WlSeat,
        serial: Serial,
        kind: DragKind,
        edge: u32,
    ) -> Result {
        let id = surface_id(surface.wl_surface())?;
        let i = index(id)?;
        let n = self.windows[i].requests;
        self.windows[i].requests += 1;
        emit(&format!(
            "SMITHAY_RS REQUEST id={id} n={n} kind={} s={} edge={edge}\n",
            kind.name(),
            u32::from(serial)
        ))?;
        let pointer = self.seat.get_pointer().ok_or("missing pointer")?;
        let held = pointer.with_grab(|s, _| u32::from(s));
        let start = pointer.grab_start_data();
        let owner = start
            .as_ref()
            .and_then(|g| g.focus.as_ref())
            .and_then(|(surface, _)| surface_id(surface).ok());
        emit(&format!(
            "SMITHAY_RS AUTH id={id} n={n} s={} held={} owner={}\n",
            u32::from(serial),
            held.unwrap_or(0),
            owner.unwrap_or(0)
        ))?;
        require(
            self.windows[i].mapped && self.windows[i].toplevel.as_ref() == Some(&surface),
            "request on unmapped/unknown toplevel",
        )?;
        let authority = Authority {
            same_seat: Seat::<Self>::from_resource(&seat).as_ref() == Some(&self.seat),
            requested: u32::from(serial),
            held,
            requester: id,
            owner,
        };
        let rect = self.geometry(id);
        let accepted = self.interaction.begin(
            authority,
            kind,
            edge,
            rect,
            (self.pointer.0 as i32, self.pointer.1 as i32),
            Limits {
                min_width: 32,
                min_height: 24,
                max_width: 96,
                max_height: 80,
            },
        );
        if let Err(reason) = accepted {
            self.rejected += 1;
            return emit(&format!(
                "SMITHAY_RS REJECT id={id} n={n} why={}\n",
                reason.name()
            ));
        }
        let start = start.ok_or("accepted authority missing click grab")?;
        self.accepted += 1;
        pointer.set_grab(self, WindowGrab { id, start }, serial, Focus::Clear);
        if kind == DragKind::Resize {
            self.configure(id, true, true, rect, true)?;
        }
        emit(&format!(
            "SMITHAY_RS GRAB id={id} kind={} s={}\n",
            kind.name(),
            u32::from(serial)
        ))
    }
    fn drag_motion(&mut self) -> Result {
        let drag = self
            .interaction
            .motion((self.pointer.0 as i32, self.pointer.1 as i32))
            .map_err(|_| "invalid drag geometry")?;
        match drag.kind {
            DragKind::Move => {
                self.scene
                    .set_geometry(drag.id, drag.latest)
                    .map_err(|_| "move geometry failed")?;
            }
            DragKind::Resize => {
                self.configure(drag.id, true, true, drag.latest, true)?;
                self.resize_updates += 1;
            }
        }
        emit(&format!(
            "SMITHAY_RS DRAG id={} kind={} n={} x={} y={} w={} h={}\n",
            drag.id,
            drag.kind.name(),
            self.next_scene - 1,
            drag.latest.x,
            drag.latest.y,
            drag.latest.width,
            drag.latest.height
        ))
    }
    fn end_drag(&mut self, serial: Serial) -> Result {
        let drag = self
            .interaction
            .finish()
            .ok_or("release without interactive grab")?;
        match drag.kind {
            DragKind::Move => {}
            DragKind::Resize => {
                self.resize_finished = true;
                self.configure(drag.id, true, false, drag.latest, true)?;
            }
        }
        emit(&format!(
            "SMITHAY_RS END id={} kind={} s={}\n",
            drag.id,
            drag.kind.name(),
            u32::from(serial)
        ))
    }
    fn input(&mut self, action: InputAction) -> Result {
        require(
            self.next_scene > 0 && self.next_scene < 12 && !self.step_done,
            "input outside captured scene",
        )?;
        let n = self.next_scene - 1;
        let time = InputTime::now();
        let serial = self.serial();
        match action {
            InputAction::Key { code, pressed } => {
                require(
                    (n == 7 || n == 10) && code == 16 || (n == 4 || n == 9) && code == 32,
                    "unexpected key phase",
                )?;
                require(self.key_down != pressed, "unbalanced key")?;
                let id = self.keyboard_focus.ok_or("key without focus")?;
                emit(&format!(
                    "SMITHAY_RS KEY n={n} id={id} code={code} state={} s={}\n",
                    u8::from(pressed),
                    u32::from(serial)
                ))?;
                let keyboard = self.seat.get_keyboard().ok_or("missing keyboard")?;
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
                self.key_down = pressed;
                if !pressed {
                    self.step_done = true;
                    emit(&format!("SMITHAY_RS INPUT n={n} kind=key code={code}\n"))?;
                    if code == 16 {
                        let w = &mut self.windows[index(id)?];
                        require(!w.closing, "duplicate close")?;
                        w.closing = true;
                        w.toplevel
                            .as_ref()
                            .ok_or("missing close toplevel")?
                            .send_close();
                        emit(&format!("SMITHAY_RS CLOSE id={id}\n"))?;
                    }
                }
            }
            InputAction::Motion { dx, dy } => {
                let expected = match n {
                    1 => (-8, -4),
                    2 => (12, 8),
                    6 => (-16, 0),
                    _ => (0, 0),
                };
                require(
                    expected != (0, 0) && (dx, dy) == expected && self.pressed,
                    "unexpected drag motion",
                )?;
                emit(&format!("SMITHAY_RS MOTION n={n} dx={dx} dy={dy}\n"))?;
                self.pointer.0 = (self.pointer.0 + f64::from(dx)).clamp(0.0, 127.0);
                self.pointer.1 = (self.pointer.1 + f64::from(dy)).clamp(0.0, 95.0);
                self.pointer_motion()?;
                self.step_done = true;
                emit(&format!(
                    "SMITHAY_RS INPUT n={n} kind=motion dx={dx} dy={dy}\n"
                ))?;
            }
            InputAction::Button { code, pressed } => {
                require(
                    matches!(n, 0 | 3 | 5 | 8)
                        && code == if n <= 3 { 272 } else { 273 }
                        && pressed == matches!(n, 0 | 5)
                        && self.pressed != pressed,
                    "unexpected button phase",
                )?;
                let id = self
                    .scene
                    .hit_test(self.pointer.0, self.pointer.1)
                    .map(|window| window.id)
                    .unwrap_or(0);
                if pressed {
                    require(id != 0, "button press outside windows")?;
                    self.scene
                        .focus_raise(id)
                        .map_err(|_| "focus/raise failed")?;
                    self.apply_focus("click")?;
                }
                emit(&format!(
                    "SMITHAY_RS BUTTON n={n} id={id} code={code} state={} s={}\n",
                    u8::from(pressed),
                    u32::from(serial)
                ))?;
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
                if n == 8 {
                    self.pointer_receipt(9)?;
                }
                self.step_done = true;
                emit(&format!(
                    "SMITHAY_RS INPUT n={n} kind=button code={code} state={}\n",
                    u8::from(pressed)
                ))?;
            }
            InputAction::Resync => return Err("input loss requires cancellation/resync".into()),
        }
        if let Some(error) = self.error.take() {
            return Err(error.into());
        }
        Ok(())
    }
    fn ready(&self, exited: &[bool; 2]) -> bool {
        if self.next_scene >= 12 || self.windows.iter().any(|w| w.awaiting.is_some()) {
            return false;
        }
        if self.next_scene > 0 && !self.step_done {
            return false;
        }
        let expected = [
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 1),
            (5, 1),
            (6, 1),
            (7, 1),
            (8, 1),
            (8, 1),
            (8, 1),
            (8, 2),
            (8, 2),
        ][self.next_scene];
        if (self.windows[0].commits, self.windows[1].commits) != expected {
            return false;
        }
        match self.next_scene {
            0 => self.scene.len() == 2,
            1 => self.accepted == 1 && self.interaction.active().is_some(),
            2 => self.resize_updates == 1,
            3 => self.resize_updates == 2,
            4 | 5 => self.resize_finished && self.interaction.active().is_none(),
            6 => self.accepted == 2 && self.interaction.active().is_some(),
            7 => self.resize_updates == 3,
            8 => self.scene.len() == 1 && exited[0] && self.cancellations == 1 && self.quarantine,
            9 | 10 => self.scene.len() == 1 && exited[0] && !self.quarantine,
            11 => self.scene.len() == 0 && exited[0] && exited[1],
            _ => false,
        }
    }
}

struct WindowGrab {
    id: u32,
    start: GrabStartData<App>,
}
macro_rules! forward_grab_event {
    ($name:ident,$event:ty) => {
        fn $name(
            &mut self,
            data: &mut App,
            handle: &mut PointerInnerHandle<'_, App>,
            event: &$event,
        ) {
            handle.$name(data, event);
        }
    };
}
impl PointerGrab<App> for WindowGrab {
    fn motion(
        &mut self,
        data: &mut App,
        handle: &mut PointerInnerHandle<'_, App>,
        _focus: Option<(WlSurface, Point<f64, Logical>)>,
        event: &MotionEvent,
    ) {
        if data.scene.get(self.id).is_none() {
            data.pointer_sample = Some(handle.current_pressed().len());
            // The owner was removed before this focus update. Keep consuming
            // physical buttons until the held set drains; none may be delivered
            // as an orphan release to another window. No dead surface is kept
            // in the quarantine's start data or restored as pending focus.
            let mut start = self.start.clone();
            start.focus = None;
            handle.set_grab(
                self,
                data,
                event.serial,
                Focus::Clear,
                ReleaseGrab { start },
            );
            data.quarantine = true;
            return;
        }
        handle.motion(data, None, event);
        if let Err(error) = data.drag_motion() {
            data.error = Some(error.to_string());
        }
    }
    fn relative_motion(
        &mut self,
        data: &mut App,
        handle: &mut PointerInnerHandle<'_, App>,
        focus: Option<(WlSurface, Point<f64, Logical>)>,
        event: &RelativeMotionEvent,
    ) {
        handle.relative_motion(data, focus, event);
    }
    fn button(
        &mut self,
        data: &mut App,
        handle: &mut PointerInnerHandle<'_, App>,
        event: &ButtonEvent,
    ) {
        handle.button(data, event);
        if handle.current_pressed().is_empty() {
            if let Err(error) = data.end_drag(event.serial) {
                data.error = Some(error.to_string());
                return;
            }
            // The pending focus origin was sampled before the last drag motion.
            // Restore from the current committed scene, without recursively
            // locking PointerHandle from inside this pointer-grab callback.
            handle.unset_grab(self, data, event.serial, event.time, false);
            match data.pointer_target() {
                Ok(focus) => handle.motion(
                    data,
                    focus,
                    &MotionEvent {
                        location: data.pointer.into(),
                        serial: event.serial,
                        time: event.time,
                    },
                ),
                Err(error) => data.error = Some(error.to_string()),
            }
        }
    }
    fn axis(
        &mut self,
        data: &mut App,
        handle: &mut PointerInnerHandle<'_, App>,
        details: AxisFrame,
    ) {
        handle.axis(data, details);
    }
    fn frame(&mut self, data: &mut App, handle: &mut PointerInnerHandle<'_, App>) {
        handle.frame(data);
    }
    forward_grab_event!(gesture_swipe_begin, GestureSwipeBeginEvent);
    forward_grab_event!(gesture_swipe_update, GestureSwipeUpdateEvent);
    forward_grab_event!(gesture_swipe_end, GestureSwipeEndEvent);
    forward_grab_event!(gesture_pinch_begin, GesturePinchBeginEvent);
    forward_grab_event!(gesture_pinch_update, GesturePinchUpdateEvent);
    forward_grab_event!(gesture_pinch_end, GesturePinchEndEvent);
    forward_grab_event!(gesture_hold_begin, GestureHoldBeginEvent);
    forward_grab_event!(gesture_hold_end, GestureHoldEndEvent);
    fn start_data(&self) -> &GrabStartData<App> {
        &self.start
    }
    fn unset(&mut self, data: &mut App) {
        // Removing a grab must not restore an old rectangle under a new-size
        // buffer. Owner removal discards the geometry transaction instead.
        data.interaction.cancel(self.id);
    }
}

/// Focusless cancellation state, with no retained surface reference. It uses
/// Smithay's actual physical button set and ends only on its last release.
struct ReleaseGrab {
    start: GrabStartData<App>,
}
impl PointerGrab<App> for ReleaseGrab {
    fn motion(
        &mut self,
        data: &mut App,
        handle: &mut PointerInnerHandle<'_, App>,
        _: Option<(WlSurface, Point<f64, Logical>)>,
        event: &MotionEvent,
    ) {
        handle.motion(data, None, event);
    }
    fn relative_motion(
        &mut self,
        _: &mut App,
        _: &mut PointerInnerHandle<'_, App>,
        _: Option<(WlSurface, Point<f64, Logical>)>,
        _: &RelativeMotionEvent,
    ) {
    }
    fn button(
        &mut self,
        data: &mut App,
        handle: &mut PointerInnerHandle<'_, App>,
        event: &ButtonEvent,
    ) {
        if handle.current_pressed().is_empty() {
            data.pointer_sample = Some(handle.current_pressed().len());
            handle.unset_grab(self, data, event.serial, event.time, false);
            match data.pointer_target() {
                Ok(focus) => handle.motion(
                    data,
                    focus,
                    &MotionEvent {
                        location: data.pointer.into(),
                        serial: event.serial,
                        time: event.time,
                    },
                ),
                Err(error) => data.error = Some(error.to_string()),
            }
        }
    }
    fn axis(&mut self, _: &mut App, _: &mut PointerInnerHandle<'_, App>, _: AxisFrame) {}
    fn frame(&mut self, data: &mut App, handle: &mut PointerInnerHandle<'_, App>) {
        handle.frame(data);
    }
    forward_grab_event!(gesture_swipe_begin, GestureSwipeBeginEvent);
    forward_grab_event!(gesture_swipe_update, GestureSwipeUpdateEvent);
    forward_grab_event!(gesture_swipe_end, GestureSwipeEndEvent);
    forward_grab_event!(gesture_pinch_begin, GesturePinchBeginEvent);
    forward_grab_event!(gesture_pinch_update, GesturePinchUpdateEvent);
    forward_grab_event!(gesture_pinch_end, GesturePinchEndEvent);
    forward_grab_event!(gesture_hold_begin, GestureHoldBeginEvent);
    forward_grab_event!(gesture_hold_end, GestureHoldEndEvent);
    fn start_data(&self) -> &GrabStartData<App> {
        &self.start
    }
    fn unset(&mut self, data: &mut App) {
        data.quarantine = false;
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
    for window in app.scene.top_to_bottom() {
        emit(&format!(
            "SMITHAY_RS GEOM n={} id={} x={} y={} w={} h={}\n",
            app.next_scene,
            window.id,
            window.rect.x,
            window.rect.y,
            window.rect.width,
            window.rect.height
        ))?;
    }
    emit(&format!(
        "SMITHAY_RS SCENE n={} top={} focus={} win={} grab={}\n",
        app.next_scene,
        label(app.scene.top_to_bottom().next().map(|w| w.id)),
        label(app.scene.focus()),
        app.scene.len(),
        app.interaction
            .active()
            .map(|g| g.kind.name())
            .unwrap_or("none")
    ))?;
    app.next_scene += 1;
    app.step_done = false;
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
        interaction: Interaction::default(),
        seats,
        seat,
        keyboard_focus: None,
        pointer: (32.0, 24.0),
        next_scene: 0,
        step_done: false,
        pressed: false,
        key_down: false,
        resize_updates: 0,
        resize_finished: false,
        cancellations: 0,
        quarantine: false,
        pointer_sample: None,
        rejected: 0,
        accepted: 0,
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
    emit("SMITHAY_RS READY wayland=1 gles=1 native=1 xdg=1 windows=2\n")?;
    emit("SMITHAY_RS CANVAS x=32 y=48 width=128 height=96\n")?;
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
        emit(&format!("SMITHAY_RS SPAWN id={id} child={child}\n"))?;
        clients.push((child, data, client));
    }
    let mut exited = [false; 2];
    let mut decoder = InputDecoder::new();
    let deadline = Instant::now() + Duration::from_secs(180);
    while app.next_scene < 12 {
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
                "SMITHAY_RS EXIT id={} child={child} status=0\n",
                i + 1
            ))?;
        }
        if app.ready(&exited) {
            render(&mut app, &mut renderer, &mut buffer, &mut native)?;
        }
        if app.next_scene < 12 {
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
            && app.destroyed_buffers == 10
            && app.scene.len() == 0
            && app.scene.focus().is_none()
            && app.keyboard_focus.is_none()
            && app.xdg.toplevel_surfaces().is_empty()
            && app.xdg.popup_surfaces().is_empty()
            && app.windows.iter().all(|w| {
                !w.mapped && !w.callback_pending && w.awaiting.is_none() && w.toplevel.is_none()
            })
            && app.windows[0].configures == 8
            && app.windows[0].acks == 8
            && app.windows[1].configures == 3
            && app.windows[1].acks == 3
            && app.windows[0].requests == 2
            && app.windows[1].requests == 0
            && app.rejected == 0
            && app.accepted == 2
            && app.resize_updates == 3
            && app.interaction.active().is_none()
            && app.cancellations == 1
            && !app.quarantine
            && app.pointer_sample.is_none()
            && app.windows.iter().all(|window| window.geometry.is_empty())
            && !app.pressed
            && !app.key_down
            && !app
                .seat
                .get_pointer()
                .ok_or("missing pointer")?
                .is_grabbed(),
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
    emit("SMITHAY_RS TOTAL clients=2 cfg=11 acks=11 closes=2 rejected=0\n")?;
    emit("SMITHAY_RS RESULT PASS scenes=12 commits=10 pixels=147456\n")
}
fn main() {
    if let Err(error) = run() {
        let _ = emit("SMITHAY_RS FAIL\n");
        let prefix = "SMITHAY_RS ERROR ";
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
