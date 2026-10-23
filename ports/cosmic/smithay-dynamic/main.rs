//! Named Wayland admission, independent client lifetimes and real native scanout.
mod clients;
mod native;
use clients::{Key, Peer, Registry};
mod scene;

use native::{InputAction, InputDecoder, InputEvent, NativeDisplay};
use scene::{Rect, Scene, Window};
use smithay::{
    backend::{
        allocator::Fourcc,
        egl::{EGLContext, EGLDisplay, ffi::egl, native::EGLSurfacelessDisplay},
        input::{InputTime, KeyState},
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
        pointer::CursorImageStatus,
    },
    reexports::wayland_protocols::xdg::shell::server::xdg_toplevel,
    reexports::wayland_server::{
        Client, Display, Resource,
        backend::{ClientData, ClientId, DisconnectReason},
        protocol::{wl_buffer::WlBuffer, wl_seat::WlSeat, wl_surface::WlSurface},
    },
    utils::{Rectangle, SERIAL_COUNTER, Serial, Transform},
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
    ffi::CStr,
    io,
    os::{
        fd::{AsFd, AsRawFd},
        unix::net::{UnixListener, UnixStream},
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

const SOCKET_PATH: &str = "/tmp/cyxia-wayland-0";
struct ClientState {
    key: Key,
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
#[derive(Clone, Copy, Default)]
struct Counts {
    configures: u32,
    acks: u32,
    commits: u32,
    detaches: u32,
    destroyed: u32,
}
#[derive(Default)]
struct ManagedWindow {
    toplevel: Option<ToplevelSurface>,
    surface: Option<WlSurface>,
    surface_destroyed: bool,
    awaiting: Option<(Serial, bool)>,
    activated: bool,
    mapped: bool,
    callback_pending: bool,
    closing: bool,
    counts: Counts,
}
struct Connection {
    key: Key,
    client: Client,
    data: Arc<ClientState>,
    window: ManagedWindow,
}
struct App {
    compositor: CompositorState,
    shm: ShmState,
    xdg: XdgShellState,
    registry: Registry<ClientId, 2>,
    connections: [Option<Connection>; 2],
    history: [Option<Counts>; 3],
    retired_key: Option<(Key, ClientId)>,
    rejections: u32,
    admissions: u32,
    stale_checks: u32,
    scene: Scene<8>,
    seats: SeatState<Self>,
    seat: Seat<Self>,
    keyboard_focus: Option<u32>,
    next_scene: usize,
    step_done: bool,
    key_down: bool,
    error: Option<String>,
    live_surfaces: usize,
    destroyed_buffers: usize,
}
fn placement(id: u32) -> Rect {
    let (x, y) = match id {
        1 => (8, 8),
        2 => (40, 24),
        _ => (48, 16),
    };
    Rect {
        x,
        y,
        width: 64,
        height: 48,
    }
}
fn label(id: Option<u32>) -> &'static str {
    match id {
        Some(1) => "A",
        Some(2) => "B",
        Some(3) => "C",
        _ => "none",
    }
}
fn seed(id: u32, frame: u32) -> Result<u32> {
    require(
        (id == 1 && frame < 4) || ((id == 2 || id == 3) && frame < 2),
        "unexpected buffer commit",
    )?;
    Ok(if frame == 0 { 0 } else { 32 })
}
fn peer_credentials(socket: &UnixStream) -> Result<Peer> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: Both writable output objects have the exact advertised sizes;
    // the descriptor is owned by the accepted UnixStream for this whole call.
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error().into());
    }
    require(
        length as usize == std::mem::size_of::<libc::ucred>() && credentials.pid > 0,
        "invalid peer credentials",
    )?;
    Ok(Peer {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}
impl CompositorHandler for App {
    fn compositor_state(&mut self) -> &mut CompositorState {
        &mut self.compositor
    }
    fn client_compositor_state<'a>(&self, client: &'a Client) -> &'a CompositorClientState {
        &client
            .get_data::<ClientState>()
            .expect("registered client data")
            .compositor
    }
    fn new_surface(&mut self, _: &WlSurface) {
        self.live_surfaces += 1;
    }
    fn destroyed(&mut self, surface: &WlSurface) {
        self.live_surfaces -= 1;
        if let Some(connection) = self
            .connections
            .iter_mut()
            .flatten()
            .find(|connection| connection.window.surface.as_ref() == Some(surface))
        {
            connection.window.surface_destroyed = true;
        }
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
            let slot = self.owned_slot(surface.wl_surface())?;
            let connection = self.connections[slot]
                .as_mut()
                .ok_or("missing connection")?;
            require(
                connection.window.toplevel.is_none(),
                "one toplevel per connection required",
            )?;
            connection.window.surface = Some(surface.wl_surface().clone());
            connection.window.toplevel = Some(surface);
            Ok(())
        })();
        if let Err(error) = result {
            self.error = Some(error.to_string());
        }
    }
    fn new_popup(&mut self, surface: PopupSurface, _: PositionerState) {
        surface.send_popup_done();
        self.error = Some("popup outside dynamic fixture".into());
    }
    fn grab(&mut self, _: PopupSurface, _: WlSeat, _: Serial) {
        self.error = Some("popup grab outside dynamic fixture".into());
    }
    fn reposition_request(&mut self, _: PopupSurface, _: PositionerState, _: u32) {
        self.error = Some("popup reposition outside dynamic fixture".into());
    }
    fn toplevel_destroyed(&mut self, surface: ToplevelSurface) {
        if let Some(connection) = self
            .connections
            .iter_mut()
            .flatten()
            .find(|connection| connection.window.toplevel.as_ref() == Some(&surface))
        {
            connection.window.toplevel = None;
            connection.window.counts.destroyed += 1;
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
    fn owned_slot(&self, surface: &WlSurface) -> Result<usize> {
        let client = surface.client().ok_or("resource client disconnected")?;
        let key = client
            .get_data::<ClientState>()
            .ok_or("unregistered resource client")?
            .key;
        self.registry
            .get(key, &client.id())
            .map_err(|_| "stale resource or foreign owner")?;
        Ok(key.slot)
    }
    fn window(&self, id: u32) -> Result<&ManagedWindow> {
        self.connections
            .iter()
            .flatten()
            .find(|connection| connection.key.id == id)
            .map(|connection| &connection.window)
            .ok_or_else(|| "unknown window".into())
    }
    fn window_mut(&mut self, id: u32) -> Result<&mut ManagedWindow> {
        self.connections
            .iter_mut()
            .flatten()
            .find(|connection| connection.key.id == id)
            .map(|connection| &mut connection.window)
            .ok_or_else(|| "unknown window".into())
    }
    fn surface(&self, id: u32) -> Result<WlSurface> {
        self.window(id)?
            .surface
            .clone()
            .ok_or_else(|| "missing surface".into())
    }
    fn counts(&self, id: u32) -> Counts {
        self.window(id)
            .map(|window| window.counts)
            .unwrap_or_else(|_| self.history[(id - 1) as usize].unwrap_or_default())
    }
    fn accept(
        &mut self,
        listener: &UnixListener,
        dh: &mut smithay::reexports::wayland_server::DisplayHandle,
    ) -> Result {
        loop {
            let (socket, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            let peer = peer_credentials(&socket)?;
            let key = match self.registry.reserve(peer) {
                Ok(key) => key,
                Err(clients::Error::Full) => {
                    self.rejections += 1;
                    emit(&format!(
                        "SMITHAY_DYN REJECT why=full pid={} uid={} gid={}\n",
                        peer.pid, peer.uid, peer.gid
                    ))?;
                    drop(socket);
                    continue;
                }
                Err(_) => return Err("connection registry admission failed".into()),
            };
            let data = Arc::new(ClientState {
                key,
                compositor: Default::default(),
                disconnected: AtomicBool::new(false),
                protocol_error: AtomicBool::new(false),
            });
            let client = match dh.insert_client(socket, data.clone()) {
                Ok(client) => client,
                Err(error) => {
                    self.registry
                        .rollback(key)
                        .map_err(|_| "registration rollback failed")?;
                    return Err(error.into());
                }
            };
            let protocol_peer = client.get_credentials(dh)?;
            self.registry
                .bind(key, client.id())
                .map_err(|_| "connection owner binding failed")?;
            let registered_peer = self
                .registry
                .get(key, &client.id())
                .map_err(|_| "registered connection ownership mismatch")?
                .peer;
            require(
                protocol_peer.pid == registered_peer.pid
                    && protocol_peer.uid == registered_peer.uid
                    && protocol_peer.gid == registered_peer.gid,
                "Wayland credentials differ from accepted socket",
            )?;
            self.admissions += 1;
            emit(&format!(
                "SMITHAY_DYN ACCEPT id={} slot={} gen={} pid={}\n",
                key.id, key.slot, key.generation, peer.pid
            ))?;
            emit(&format!(
                "SMITHAY_DYN PEER id={} uid={} gid={}\n",
                key.id, peer.uid, peer.gid
            ))?;
            if let Some((old, owner)) = self
                .retired_key
                .as_ref()
                .filter(|(old, _)| old.slot == key.slot)
            {
                require(
                    matches!(self.registry.get(*old, owner), Err(clients::Error::Stale)),
                    "old connection key survived reuse",
                )?;
                emit(&format!(
                    "SMITHAY_DYN STALE old={} slot={} gen={} rejected=1\n",
                    old.id, old.slot, old.generation
                ))?;
                self.stale_checks += 1;
            }
            require(
                self.connections[key.slot].is_none(),
                "occupied connection slot",
            )?;
            self.connections[key.slot] = Some(Connection {
                key,
                client,
                data,
                window: ManagedWindow::default(),
            });
        }
        Ok(())
    }
    fn configure(&mut self, id: u32, activated: bool) -> Result {
        let window = self.window_mut(id)?;
        require(window.awaiting.is_none(), "configure already pending")?;
        let surface = window
            .toplevel
            .as_ref()
            .ok_or("configure missing toplevel")?;
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
        let n = window.counts.configures;
        window.counts.configures += 1;
        emit(&format!(
            "SMITHAY_DYN CONFIG id={id} n={n} s={} w=64 h=48 a={}\n",
            u32::from(serial),
            u8::from(activated)
        ))
    }
    fn ack(&mut self, surface: WlSurface, configure: Configure) -> Result {
        let slot = self.owned_slot(&surface)?;
        let connection = self.connections[slot]
            .as_mut()
            .ok_or("missing ACK connection")?;
        let window = &mut connection.window;
        let Configure::Toplevel(configure) = configure else {
            return Err("unexpected popup ACK".into());
        };
        let (serial, active) = window.awaiting.ok_or("unsolicited configure ACK")?;
        require(
            configure.serial == serial
                && configure.state.size == Some((64, 48).into())
                && configure
                    .state
                    .states
                    .contains(xdg_toplevel::State::Activated)
                    == active,
            "configure ACK mismatch",
        )?;
        window.awaiting = None;
        let n = window.counts.acks;
        window.counts.acks += 1;
        emit(&format!(
            "SMITHAY_DYN ACK id={} n={n} s={}\n",
            connection.key.id,
            u32::from(serial)
        ))
    }
    fn commit_surface(&mut self, surface: &WlSurface) -> Result {
        let slot = self.owned_slot(surface)?;
        let id = self.connections[slot]
            .as_ref()
            .ok_or("missing commit connection")?
            .key
            .id;
        on_commit_buffer_handler::<Self>(surface);
        let attached =
            with_renderer_surface_state(surface, |state| state.buffer().is_some()).unwrap_or(false);
        if attached {
            let window = self.window_mut(id)?;
            require(
                window.awaiting.is_none()
                    && window.counts.acks > 0
                    && !window.callback_pending
                    && !window.closing,
                "commit before ACK or previous frame",
            )?;
            require(
                with_renderer_surface_state(surface, |state| state.buffer_size()).flatten()
                    == Some((64, 48).into()),
                "unexpected buffer geometry",
            )?;
            let frame = window.counts.commits;
            let seed = seed(id, frame)?;
            let newly_mapped = !window.mapped;
            window.mapped = true;
            window.counts.commits += 1;
            window.callback_pending = true;
            emit(&format!(
                "SMITHAY_DYN COMMIT id={id} frame={frame} seed={seed}\n"
            ))?;
            if newly_mapped {
                self.scene
                    .insert(Window {
                        id,
                        rect: placement(id),
                    })
                    .map_err(|_| "scene insertion failed")?;
                self.scene.focus_raise(id).map_err(|_| "map focus failed")?;
                self.apply_focus("map")?;
            }
        } else if self.window(id)?.counts.configures == 0 {
            self.configure(id, true)?;
        } else {
            let window = self.window_mut(id)?;
            require(
                window.mapped && window.closing && !window.callback_pending,
                "unexpected null commit",
            )?;
            window.mapped = false;
            window.counts.detaches += 1;
            self.scene.remove(id).map_err(|_| "normal unmap failed")?;
            self.apply_focus("unmap")?;
            emit(&format!("SMITHAY_DYN UNMAP id={id}\n"))?;
        }
        Ok(())
    }
    fn apply_focus(&mut self, reason: &str) -> Result {
        let new = self.scene.focus();
        if self.keyboard_focus == new {
            return Ok(());
        }
        let old = self.keyboard_focus;
        let updates = self
            .connections
            .iter()
            .flatten()
            .filter(|connection| {
                connection.window.mapped
                    && connection.window.activated != (new == Some(connection.key.id))
            })
            .map(|connection| connection.key.id)
            .collect::<Vec<_>>();
        for id in updates {
            self.configure(id, new == Some(id))?;
        }
        let surface = new.map(|id| self.surface(id)).transpose()?;
        let keyboard = self.seat.get_keyboard().ok_or("missing keyboard")?;
        keyboard.set_focus(self, surface, SERIAL_COUNTER.next_serial());
        self.keyboard_focus = new;
        emit(&format!(
            "SMITHAY_DYN FOCUS previous={} current={} reason={reason}\n",
            old.unwrap_or(0),
            new.unwrap_or(0)
        ))
    }
    fn retire_disconnected(&mut self) -> Result {
        for slot in 0..self.connections.len() {
            let Some(connection) = self.connections[slot].as_ref() else {
                continue;
            };
            require(
                !connection.data.protocol_error.load(Ordering::Acquire),
                "client protocol error",
            )?;
            if !connection.data.disconnected.load(Ordering::Acquire) {
                continue;
            }
            let window = &connection.window;
            require(
                window.toplevel.is_none()
                    && window.surface_destroyed
                    && window.counts.destroyed == 1
                    && !window.callback_pending,
                "disconnect resource destruction incomplete",
            )?;
            let id = connection.key.id;
            let graceful = window.closing;
            require(
                if graceful {
                    !window.mapped && window.counts.detaches == 1
                } else {
                    window.mapped && window.counts.detaches == 0
                },
                "disconnect lifecycle mismatch",
            )?;
            if !graceful {
                self.scene
                    .remove(id)
                    .map_err(|_| "abrupt window removal failed")?;
                self.window_mut(id)?.mapped = false;
                emit(&format!("SMITHAY_DYN REMOVE id={id} why=disconnect\n"))?;
                self.apply_focus("disconnect")?;
            }
            let connection = self.connections[slot]
                .take()
                .ok_or("retire missing connection")?;
            let owner = connection.client.id();
            self.registry
                .remove(connection.key, &owner)
                .map_err(|_| "retire registry mismatch")?;
            *self
                .history
                .get_mut((id - 1) as usize)
                .ok_or("retired identity outside fixture")? = Some(connection.window.counts);
            self.retired_key = Some((connection.key, owner));
            emit(&format!(
                "SMITHAY_DYN RETIRED id={id} why={}\n",
                if graceful { "graceful" } else { "abrupt" }
            ))?;
        }
        Ok(())
    }
    fn input(&mut self, action: InputAction) -> Result {
        require(
            self.next_scene > 0 && self.next_scene < 12 && !self.step_done,
            "input outside captured scene",
        )?;
        let n = self.next_scene - 1;
        let InputAction::Key { code, pressed } = action else {
            return Err("unexpected non-key input".into());
        };
        let expected = match n {
            1 | 3 | 5 | 7 | 9 => 32,
            4 | 10 => 16,
            8 => 45,
            _ => 0,
        };
        require(
            code == expected && expected != 0 && self.key_down != pressed,
            "unexpected key phase",
        )?;
        let id = self.keyboard_focus.ok_or("key without focus")?;
        let serial = SERIAL_COUNTER.next_serial();
        emit(&format!(
            "SMITHAY_DYN KEY n={n} id={id} code={code} state={} s={}\n",
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
            InputTime::now(),
            |_, _, _| FilterResult::Forward,
        );
        self.key_down = pressed;
        if !pressed {
            self.step_done = true;
            emit(&format!("SMITHAY_DYN INPUT n={n} kind=key code={code}\n"))?;
            if code == 16 {
                let window = self.window_mut(id)?;
                require(!window.closing, "duplicate close")?;
                window.closing = true;
                window
                    .toplevel
                    .as_ref()
                    .ok_or("missing close toplevel")?
                    .send_close();
                emit(&format!("SMITHAY_DYN CLOSE id={id}\n"))?;
            }
        }
        Ok(())
    }
    fn ready(&self) -> bool {
        if self.next_scene >= 12
            || self
                .connections
                .iter()
                .flatten()
                .any(|connection| connection.window.awaiting.is_some())
        {
            return false;
        }
        if !matches!(self.next_scene, 0 | 1 | 3 | 7) && !self.step_done {
            return false;
        }
        let expected = [
            (0, 0, 0),
            (1, 0, 0),
            (2, 0, 0),
            (2, 1, 0),
            (2, 2, 0),
            (2, 2, 0),
            (3, 2, 0),
            (3, 2, 1),
            (3, 2, 2),
            (3, 2, 2),
            (4, 2, 2),
            (4, 2, 2),
        ][self.next_scene];
        if (
            self.counts(1).commits,
            self.counts(2).commits,
            self.counts(3).commits,
        ) != expected
        {
            return false;
        }
        match self.next_scene {
            0 => self.admissions == 0 && self.scene.len() == 0,
            1 | 2 => self.registry.len() == 1 && self.scene.len() == 1,
            3 | 4 => self.registry.len() == 2 && self.scene.len() == 2,
            5 | 6 => self.history[1].is_some() && self.rejections == 1 && self.registry.len() == 1,
            7 | 8 => self.admissions == 3 && self.registry.len() == 2 && self.stale_checks == 1,
            9 | 10 => self.history[2].is_some() && self.registry.len() == 1,
            11 => {
                self.history.iter().all(Option::is_some)
                    && self.registry.len() == 0
                    && self.scene.len() == 0
            }
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
                    app.window(window.id)?.counts.commits - 1,
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
    let ids = app
        .connections
        .iter()
        .flatten()
        .map(|connection| connection.key.id)
        .collect::<Vec<_>>();
    for id in ids {
        if !app.window(id)?.callback_pending {
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
        app.window_mut(id)?.callback_pending = false;
    }
    for window in app.scene.top_to_bottom() {
        emit(&format!(
            "SMITHAY_DYN GEOM n={} id={} x={} y={} w={} h={}\n",
            app.next_scene,
            window.id,
            window.rect.x,
            window.rect.y,
            window.rect.width,
            window.rect.height
        ))?;
    }
    emit(&format!(
        "SMITHAY_DYN SCENE n={} top={} focus={} win={}\n",
        app.next_scene,
        label(app.scene.top_to_bottom().next().map(|window| window.id)),
        label(app.scene.focus()),
        app.scene.len()
    ))?;
    app.next_scene += 1;
    app.step_done = false;
    Ok(())
}

fn run() -> Result {
    // SAFETY: Initialization precedes all libraries on the sole process thread.
    unsafe {
        std::env::set_var("LIBGL_ALWAYS_SOFTWARE", "true");
        std::env::set_var("GALLIUM_DRIVER", "softpipe");
        std::env::set_var("MESA_SHADER_CACHE_DISABLE", "true");
    }
    // Binding acquires ownership. Never unlink at startup: an existing endpoint
    // belongs to its current server and must cause EADDRINUSE instead.
    let listener = UnixListener::bind(SOCKET_PATH)?;
    listener.set_nonblocking(true)?;
    emit(&format!("SMITHAY_DYN LISTEN path={SOCKET_PATH}\n"))?;
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
        registry: Registry::new(),
        connections: std::array::from_fn(|_| None),
        history: [None; 3],
        retired_key: None,
        rejections: 0,
        admissions: 0,
        stale_checks: 0,
        scene: Scene::new(),
        seats,
        seat,
        keyboard_focus: None,
        next_scene: 0,
        step_done: false,
        key_down: false,
        error: None,
        live_surfaces: 0,
        destroyed_buffers: 0,
    };
    // SAFETY: EGL/context/renderer stay exclusively on this one thread.
    let egl = unsafe { EGLDisplay::new(EGLSurfacelessDisplay)? };
    let context = EGLContext::new(&egl)?;
    // SAFETY: The newly created context is exclusively owned by this renderer.
    let mut renderer = unsafe { GlesRenderer::new(context)? };
    let softpipe = renderer.with_context(|gl| {
        // SAFETY: The renderer made its context current; GL returns a terminated string.
        unsafe {
            let name = gl.GetString(0x1F01);
            !name.is_null() && CStr::from_ptr(name.cast()).to_bytes() == b"softpipe"
        }
    })?;
    require(softpipe, "real Mesa softpipe required")?;
    let mut buffer: GlesRenderbuffer =
        renderer.create_buffer(Fourcc::Abgr8888, (WIDTH, HEIGHT).into())?;
    emit("SMITHAY_DYN READY wayland=1 gles=1 native=1 xdg=1 capacity=2\n")?;
    emit("SMITHAY_DYN CANVAS x=32 y=48 width=128 height=96\n")?;
    let mut decoder = InputDecoder::new();
    let deadline = Instant::now() + Duration::from_secs(240);
    while app.next_scene < 12 {
        require(
            Instant::now() < deadline,
            "dynamic client/input deadline exceeded",
        )?;
        app.accept(&listener, &mut dh)?;
        display.dispatch_clients(&mut app)?;
        if let Some(error) = app.error.take() {
            return Err(error.into());
        }
        app.retire_disconnected()?;
        if app.ready() {
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
        let mut fds = [
            libc::pollfd {
                fd: display.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: The complete two-element descriptor array is writable.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 5) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    require(
        app.registry.len() == 0
            && app.connections.iter().all(Option::is_none)
            && app.admissions == 3
            && app.rejections == 1
            && app.stale_checks == 1
            && app.live_surfaces == 0
            && app.destroyed_buffers == 8
            && app.scene.len() == 0
            && app.scene.focus().is_none()
            && app.keyboard_focus.is_none()
            && app.xdg.toplevel_surfaces().is_empty()
            && app.xdg.popup_surfaces().is_empty()
            && !app.key_down
            && app.history.iter().all(Option::is_some),
        "dynamic lifecycle cleanup incomplete",
    )?;
    for (i, expected) in [(0, (5, 4, 1)), (1, (1, 2, 1)), (2, (1, 2, 0))] {
        let counts = app.history[i].ok_or("missing retired history")?;
        require(
            (counts.configures, counts.commits, counts.detaches) == expected
                && counts.acks == counts.configures
                && counts.destroyed == 1,
            "retired protocol counts differ",
        )?;
    }
    drop(listener);
    std::fs::remove_file(SOCKET_PATH)?;
    let rebound = UnixListener::bind(SOCKET_PATH)?;
    emit("SMITHAY_DYN REBIND PASS\n")?;
    drop(rebound);
    std::fs::remove_file(SOCKET_PATH)?;
    emit("SMITHAY_DYN SOCKET CLEAN\n")?;
    drop(buffer);
    // SAFETY: with_context makes the owned context current.
    let error = renderer.with_context(|gl| unsafe { gl.GetError() })?;
    require(error == 0, "GL error after dynamic rendering")?;
    renderer.egl_context().unbind()?;
    drop(renderer);
    drop(egl);
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
    emit("SMITHAY_DYN TOTAL clients=3 cfg=7 acks=7 graceful=2 abrupt=1\n")?;
    emit("SMITHAY_DYN RESULT PASS scenes=12 commits=8 pixels=147456\n")
}
fn main() {
    if let Err(error) = run() {
        let _ = emit("SMITHAY_DYN FAIL\n");
        let prefix = "SMITHAY_DYN ERROR ";
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
