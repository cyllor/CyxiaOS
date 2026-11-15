// SPDX-License-Identifier: GPL-3.0-only
//! Actual cosmic-comp backend for Cyxia ABI v1 and Mesa surfaceless EGL.
//!
//! The native ABI has no page-flip timestamps, refresh query, hotplug, power
//! control, or DMA-BUF node. Presentation feedback therefore promises neither
//! vsync nor hardware timing; wl_shm remains the client buffer path.
mod delivery;
mod egl;
mod input;
mod locking;
mod native;
mod scheduling;

use crate::{
    backend::render::{self, CursorMode, ScreenFilterStorage, init_shaders},
    config::ScreenFilter,
    input::InputBackendId,
    shell::SessionLock,
    state::{BackendData, Common, State},
};
use anyhow::{Context, Result, bail};
use cosmic_comp_config::output::comp::{AdaptiveSync, OutputConfig, OutputState, TransformDef};
use input::{CyxiaDevice, CyxiaInput, InputBridge};
use locking::{LockBarrier, owner_is_live};
pub(crate) use locking::{LockFocusTarget, PendingInput, input_allowed, lock_focus_allowed};
use native::{InputAction, InputDecoder, NativeDisplay, presentation::PendingPresentation};
use scheduling::RenderSchedule;
use smithay::{
    backend::{
        allocator::Fourcc,
        egl::{EGLContext, EGLDisplay, native::EGLSurfacelessDisplay},
        input::{InputEvent, InputTime},
        renderer::{
            Bind, ExportMem, Offscreen, TextureMapping,
            damage::{OutputDamageTracker, RenderOutputResult},
            element::RenderElementStates,
            gles::{GlesMapping, GlesRenderbuffer},
            glow::GlowRenderer,
        },
    },
    desktop::utils::OutputPresentationFeedback,
    output::{Mode, Output, PhysicalProperties, Scale, Subpixel},
    reexports::{
        calloop::{
            EventLoop, RegistrationToken,
            timer::{TimeoutAction, Timer},
        },
        wayland_protocols::wp::presentation_time::server::wp_presentation_feedback,
        wayland_server::{DisplayHandle, Resource},
    },
    utils::{Rectangle, SERIAL_COUNTER, Transform},
    wayland::{presentation::Refresh, session_lock::SessionLocker},
};
use std::{
    borrow::BorrowMut,
    cell::RefCell,
    collections::HashMap,
    fmt,
    time::{Duration, Instant},
};
use tracing::{error, warn};

const INPUT_INTERVAL: Duration = Duration::from_millis(8);
const TILES_PER_TICK: usize = 16;

fn validate_output_config(info: native::DisplayInfo, config: &OutputConfig) -> Result<()> {
    if config.enabled != OutputState::Enabled
        || config.mode.0 != (info.width as i32, info.height as i32)
        || config.mode.1.is_some_and(|refresh| refresh != 60_000)
        || config.transform != TransformDef::Flipped180
        || config.vrr != AdaptiveSync::Disabled
        || config.max_bpc.is_some_and(|bits| bits != 8)
        || !config.scale.is_finite()
        || config.scale <= 0.0
    {
        bail!("Cyxia ABI v1 requires its fixed enabled framebuffer, 8-bit color and no VRR");
    }
    Ok(())
}

struct PendingFrame {
    mapping: GlesMapping,
    presentation: PendingPresentation,
    states: RenderElementStates,
    feedback: Option<OutputPresentationFeedback>,
}

impl Drop for PendingFrame {
    fn drop(&mut self) {
        if let Some(feedback) = self.feedback.as_mut() {
            feedback.discarded();
        }
    }
}

pub struct CyxiaState {
    lock_barrier: LockBarrier<SessionLocker>,
    // Drop any readback mapping before the framebuffer and EGL renderer.
    pending: Option<PendingFrame>,
    // Drop the framebuffer before its renderer even on an early init failure.
    buffer: GlesRenderbuffer,
    pub renderer: GlowRenderer,
    native: NativeDisplay,
    output: Output,
    damage_tracker: OutputDamageTracker,
    screen_filter_state: ScreenFilterStorage,
    decoder: InputDecoder,
    bridge: InputBridge,
    input_registered: bool,
    timer: Option<RegistrationToken>,
    schedule: RenderSchedule,
    failure: Option<anyhow::Error>,
}

impl fmt::Debug for CyxiaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CyxiaState")
            .field("output", &self.output)
            .field("schedule", &self.schedule)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl CyxiaState {
    pub fn input_suspended(&self) -> bool {
        self.lock_barrier.shielded()
    }
    pub fn all_outputs(&self) -> Vec<Output> {
        vec![self.output.clone()]
    }

    pub fn schedule_render(&mut self, output: &Output) {
        if output == &self.output {
            self.schedule.request();
        }
    }

    /// Validate before Common changes Output mode/geometry, including TEST_ONLY.
    pub fn validate_config(&self) -> Result<()> {
        let info = self.native.info();
        let config = self
            .output
            .user_data()
            .get::<RefCell<OutputConfig>>()
            .unwrap()
            .borrow();
        validate_output_config(info, &config)
    }

    pub fn apply_config_for_outputs(&mut self, test_only: bool) -> Result<()> {
        self.validate_config()?;
        if !test_only {
            self.schedule.request();
        }
        Ok(())
    }

    pub fn update_screen_filter(&mut self, filter: &ScreenFilter) -> Result<()> {
        self.screen_filter_state.filter = filter.clone();
        self.schedule.request();
        Ok(())
    }

    fn poll_input(&mut self) -> Result<Vec<InputAction>> {
        let mut actions = Vec::new();
        // Cap work per dispatch so sustained input cannot starve Wayland/DBus.
        for _ in 0..4 {
            let mut events = [native::InputEvent::default(); 32];
            let count = native::read_input(&mut events).context("Cyxia input read")?;
            for event in &events[..count] {
                match self.decoder.push(*event) {
                    Ok(Some(frame)) => {
                        for action in frame {
                            if action == InputAction::Resync {
                                actions.extend(
                                    self.decoder.resynchronize(native::input_key_state()?)?,
                                );
                            } else {
                                actions.push(action);
                            }
                        }
                    }
                    Ok(None) => {}
                    // The decoder drops the whole packet and recovers at the
                    // next SYN_REPORT. Do not commit its incomplete transitions.
                    Err(err) if err.kind() == std::io::ErrorKind::Unsupported => {
                        warn!(?err, "Unsupported native input packet; resynchronizing");
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            if count < events.len() {
                break;
            }
        }
        Ok(actions)
    }

    fn render_output(&mut self, common: &mut Common) -> Result<()> {
        // Clear at rendering, never at tile completion: commits received while
        // presentation is pending must remain dirty for the next real frame.
        self.schedule.begin();
        let mut fb = self
            .renderer
            .bind(&mut self.buffer)
            .context("Bind Cyxia framebuffer")?;
        let RenderOutputResult {
            sync,
            damage,
            states,
        } = render::render_output(
            None,
            &mut self.renderer,
            &mut fb,
            &mut self.damage_tracker,
            1,
            &common.shell,
            common.clock.now(),
            &self.output,
            CursorMode::All,
            &mut self.screen_filter_state,
            &common.event_loop_handle,
        )
        .context("Render COSMIC output for Cyxia")?;
        sync.wait().context("Wait for COSMIC rendering")?;
        let mapping = if damage.is_some() {
            let info = self.native.info();
            Some(
                self.renderer
                    .copy_framebuffer(
                        &fb,
                        Rectangle::from_size((info.width as i32, info.height as i32).into()),
                        Fourcc::Abgr8888,
                    )
                    .context("Read COSMIC framebuffer")?,
            )
        } else {
            None
        };
        drop(fb);
        // Select actual rendered surfaces and snapshot their presentation
        // requests before yielding. A newer commit must not be reported as this
        // frame. No frame.done or presented event is sent by this selection.
        common.update_primary_output(&self.output, &states);
        let feedback = common
            .shell
            .read()
            .take_presentation_feedback(&self.output, &states);
        if let Some(mapping) = mapping {
            let presentation = PendingPresentation::new(self.native.info(), mapping.flipped())?;
            self.pending = Some(PendingFrame {
                mapping,
                presentation,
                states,
                feedback: Some(feedback),
            });
        } else {
            self.complete_frame(common, &states, feedback);
        }
        Ok(())
    }

    fn advance_presentation(&mut self, common: &mut Common) -> Result<()> {
        let Some(frame) = self.pending.as_mut() else {
            return Ok(());
        };
        let bytes = self
            .renderer
            .map_texture(&frame.mapping)
            .context("Map COSMIC framebuffer")?;
        if !frame
            .presentation
            .advance(bytes, TILES_PER_TICK)
            .context("Submit Cyxia display tiles")?
        {
            return Ok(());
        }
        let mut frame = self.pending.take().unwrap();
        let feedback = frame.feedback.take().unwrap();
        self.complete_frame(common, &frame.states, feedback);
        Ok(())
    }

    fn complete_frame(
        &mut self,
        common: &mut Common,
        states: &RenderElementStates,
        mut feedback: OutputPresentationFeedback,
    ) {
        // For damaged frames only the final successful native tile reaches
        // here. Freshly visible surfaces need primary selection before the
        // callback gate, because this backend may idle after this frame.
        common.update_primary_output(&self.output, states);
        common.send_frames(&self.output, None);
        common.send_dmabuf_feedback(&self.output, states, |_| None);
        feedback.presented(
            common.clock.now(),
            Refresh::Unknown,
            0,
            wp_presentation_feedback::Kind::empty(),
        );
        self.schedule.completed(Instant::now());
    }
}

fn dispatch_actions(state: &mut State, actions: Vec<InputAction>) {
    // Drain native decoding during blanking, but never record rejected events
    // as delivered. The ledger contains only transitions sent to COSMIC.
    if state.backend.cyxia().input_suspended() {
        return;
    }
    for action in actions {
        let event = state.backend.cyxia().bridge.event(action, InputTime::now());
        state.process_input_event(event, InputBackendId::Normal);
    }
}

fn tick(state: &mut State) -> Result<()> {
    // init_backend_auto creates the real COSMIC seat after backend init.
    if !state.backend.cyxia().input_registered {
        state.process_input_event::<CyxiaInput>(
            InputEvent::DeviceAdded {
                device: CyxiaDevice,
            },
            InputBackendId::Normal,
        );
        state.backend.cyxia().input_registered = true;
        let actions = state
            .backend
            .cyxia()
            .decoder
            .resynchronize(native::input_key_state()?)?;
        dispatch_actions(state, actions);
    }
    let actions = state.backend.cyxia().poll_input()?;
    if state.backend.cyxia().input_suspended() {
        let owner = state
            .backend
            .cyxia()
            .lock_barrier
            .advance(TILES_PER_TICK, |locker| {
                locker.ext_session_lock().is_alive()
            })?;
        if let Some(locker) = owner {
            // The full native scanout is now opaque black. Preserve lock
            // surfaces configured against the provisional isolation barrier.
            state.accept_session_lock(locker);
            Common::refresh_focus(state);
            let backend = state.backend.cyxia();
            backend.damage_tracker = OutputDamageTracker::from_output(&backend.output);
            backend.schedule.request();
        }
        return Ok(());
    }
    let activity = !actions.is_empty();
    dispatch_actions(state, actions);
    let backend = state.backend.cyxia();
    if activity {
        backend.schedule.request();
    }
    if backend
        .schedule
        .due(Instant::now(), backend.pending.is_some())
    {
        backend.render_output(&mut state.common)?;
    }
    backend.advance_presentation(&mut state.common)?;
    Ok(())
}

impl State {
    pub(crate) fn begin_cyxia_lock(&mut self, locker: SessionLocker) {
        if !locker.ext_session_lock().is_alive() {
            return;
        }
        // A live current owner (including a pending provisional owner) wins.
        if self
            .common
            .shell
            .read()
            .session_lock
            .as_ref()
            .is_some_and(|lock| {
                owner_is_live(
                    lock.ext_session_lock.is_alive(),
                    self.common
                        .display_handle
                        .get_client(lock.ext_session_lock.id())
                        .is_ok(),
                )
            })
        {
            return;
        }
        if self
            .backend
            .cyxia()
            .lock_barrier
            .owner()
            .is_some_and(|owner| owner.ext_session_lock().is_alive())
        {
            return;
        }
        if self.backend.cyxia().lock_barrier.pending() {
            // Replace a dead pending owner, retaining isolation. Its old black
            // cursor can no longer acknowledge or submit after replacement.
            self.backend.cyxia().lock_barrier.cancel();
        }
        self.common.shell.write().session_lock = Some(SessionLock {
            ext_session_lock: locker.ext_session_lock().clone(),
            surfaces: HashMap::new(),
        });

        // Provisional shell isolation protects direct virtual-keyboard paths,
        // which do not pass through State::process_input_event. Clear old grabs
        // and focus immediately, then let the real lock focus policy take over.
        let seats = self
            .common
            .shell
            .read()
            .seats
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for seat in seats {
            let serial = SERIAL_COUNTER.next_serial();
            if let Some(keyboard) = seat.get_keyboard() {
                keyboard.unset_grab(self);
                keyboard.set_focus(self, None, serial);
            }
            if let Some(pointer) = seat.get_pointer() {
                let time = InputTime::now();
                pointer.unset_grab(self, serial, time);
                pointer.motion(
                    self,
                    None,
                    &smithay::input::pointer::MotionEvent {
                        location: pointer.current_location(),
                        serial,
                        time,
                    },
                );
                pointer.frame(self);
            }
        }
        let result = (|| -> Result<()> {
            let releases = self.backend.cyxia().bridge.delivered.releases()?;
            // Normally not shielded yet. For a dead-owner replacement the
            // previous transition already released this ledger completely.
            dispatch_actions(self, releases);
            let backend = self.backend.cyxia();
            let info = backend.native.info();
            backend.lock_barrier.begin(locker, info, || {
                backend.pending.take();
            })?;
            backend.damage_tracker = OutputDamageTracker::from_output(&backend.output);
            Ok(())
        })();
        if let Err(err) = result {
            error!(?err, "Native session lock blanking failed");
            self.backend.cyxia().pending.take();
            self.backend.cyxia().lock_barrier.cancel();
            self.backend.cyxia().failure = Some(err);
            self.common.should_stop = true;
        }
        Common::refresh_focus(self);
    }
}

pub fn init_backend(
    _dh: &DisplayHandle,
    event_loop: &mut EventLoop<'static, State>,
    state: &mut State,
) -> Result<()> {
    // Query the real kernel ABI before creating EGL or advertising any output.
    let native = NativeDisplay::connect().context("Connect Cyxia display ABI v1")?;
    let info = native.info();
    egl::load().context("Load linked Mesa EGL dispatch")?;
    // SAFETY: the backend exclusively owns this EGL display/context on the
    // event-loop thread. No native pointer or DRM fd is fabricated.
    let display =
        unsafe { EGLDisplay::new(EGLSurfacelessDisplay) }.context("Open surfaceless EGL")?;
    let context = EGLContext::new(&display).context("Create Cyxia EGL context")?;
    let mut renderer =
        unsafe { GlowRenderer::new(context) }.context("Create Cyxia Glow renderer")?;
    init_shaders(renderer.borrow_mut()).context("Initialize COSMIC shaders")?;
    let size = (info.width as i32, info.height as i32);
    let buffer = renderer
        .create_buffer(Fourcc::Abgr8888, size.into())
        .context("Allocate Cyxia output buffer")?;
    let output = Output::new(
        "CYXIA-0".into(),
        PhysicalProperties {
            size: (0, 0).into(),
            subpixel: Subpixel::Unknown,
            make: "CyxiaOS".into(),
            model: "Native display ABI v1".into(),
            serial_number: "Unknown".into(),
        },
    );
    let mode = Mode {
        size: size.into(),
        refresh: 60_000,
    };
    output.add_mode(mode);
    output.set_preferred(mode);
    output.change_current_state(
        Some(mode),
        Some(Transform::Flipped180),
        Some(Scale::Integer(1)),
        Some((0, 0).into()),
    );
    output.user_data().insert_if_missing(|| {
        RefCell::new(OutputConfig {
            mode: (size, None),
            transform: TransformDef::Flipped180,
            vrr: AdaptiveSync::Disabled,
            ..Default::default()
        })
    });
    let timer = event_loop
        .handle()
        .insert_source(Timer::immediate(), |_, _, state| {
            if state.common.should_stop {
                return TimeoutAction::Drop;
            }
            if let Err(err) = tick(state) {
                error!(?err, "Cyxia backend stopped");
                state.backend.cyxia().failure = Some(err);
                state.common.should_stop = true;
                return TimeoutAction::Drop;
            }
            TimeoutAction::ToDuration(INPUT_INTERVAL)
        })
        .map_err(|err| anyhow::anyhow!("Register Cyxia input/render timer: {err}"))?;
    state.backend = BackendData::Cyxia(CyxiaState {
        lock_barrier: LockBarrier::default(),
        pending: None,
        renderer,
        buffer,
        native,
        output: output.clone(),
        damage_tracker: OutputDamageTracker::from_output(&output),
        screen_filter_state: ScreenFilterStorage {
            filter: state.common.config.dynamic_conf.screen_filter().clone(),
            ..Default::default()
        },
        decoder: InputDecoder::new(),
        bridge: InputBridge::default(),
        input_registered: false,
        timer: Some(timer),
        schedule: RenderSchedule::new(Instant::now()),
        failure: None,
    });
    state
        .common
        .output_configuration_state
        .add_heads(std::iter::once(&output));
    state.common.add_output(&output);
    // Finish the temporary workspace update guard before error cleanup borrows
    // the full State again (including its input seats and backend resources).
    let config_result = state.common.config.read_outputs(
        &mut state.common.output_configuration_state,
        &mut state.backend,
        &state.common.shell,
        &state.common.event_loop_handle,
        &mut state.common.workspace_state.update(),
        &state.common.xdg_activation_state,
        state.common.startup_done.clone(),
        &state.common.clock,
    );
    if let Err(err) = config_result {
        let _ = shutdown(state);
        return Err(err).context("Configure Cyxia output");
    }
    state.common.refresh();
    if state.common.with_xwayland {
        state.launch_xwayland(None);
    } else {
        state.notify_ready();
    }
    Ok(())
}

/// Stop event sources, release held input, remove the output and unbind EGL.
/// Called after the event loop exits even when dispatch returned an error.
pub fn shutdown(state: &mut State) -> Result<()> {
    if !matches!(state.backend, BackendData::Cyxia(_)) {
        return Ok(());
    }
    if let Some(token) = state.backend.cyxia().timer.take() {
        state.common.event_loop_handle.remove(token);
    }
    let mut cleanup_error = None;
    if state.backend.cyxia().input_registered {
        match state.backend.cyxia().bridge.delivered.releases() {
            Ok(actions) => dispatch_actions(state, actions),
            Err(err) => cleanup_error = Some(anyhow::Error::from(err)),
        }
        state.process_input_event::<CyxiaInput>(
            InputEvent::DeviceRemoved {
                device: CyxiaDevice,
            },
            InputBackendId::Normal,
        );
        state.backend.cyxia().input_registered = false;
    }
    let output = state.backend.cyxia().output.clone();
    state
        .common
        .output_configuration_state
        .remove_heads(std::iter::once(&output));
    state.common.remove_output(&output);
    let BackendData::Cyxia(backend) = std::mem::replace(&mut state.backend, BackendData::Unset)
    else {
        unreachable!();
    };
    let failure = backend.failure;
    drop(backend.pending);
    drop(backend.lock_barrier);
    drop(backend.buffer);
    // Drop renderer-owned shader/filter objects while its EGL context is alive.
    drop(backend.screen_filter_state);
    let unbound = backend
        .renderer
        .egl_context()
        .unbind()
        .context("Unbind Cyxia EGL context");
    drop(backend.renderer);
    let released = egl::release_thread();
    if let Some(err) = failure.or(cleanup_error) {
        return Err(err);
    }
    unbound?;
    released
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> native::DisplayInfo {
        native::DisplayInfo {
            width: 800,
            height: 600,
            stride_bytes: 3200,
            format: 1,
            max_rect_bytes: 65536,
            abi: 1,
        }
    }
    fn config() -> OutputConfig {
        OutputConfig {
            mode: ((800, 600), None),
            transform: TransformDef::Flipped180,
            vrr: AdaptiveSync::Disabled,
            ..Default::default()
        }
    }

    #[test]
    fn fixed_output_rejects_unavailable_physical_capabilities() {
        for unsupported in [
            OutputConfig {
                mode: ((1024, 768), None),
                ..config()
            },
            OutputConfig {
                mode: ((800, 600), Some(144_000)),
                ..config()
            },
            OutputConfig {
                transform: TransformDef::_90,
                ..config()
            },
            OutputConfig {
                enabled: OutputState::Disabled,
                ..config()
            },
            OutputConfig {
                enabled: OutputState::Mirroring("another-output".into()),
                ..config()
            },
            OutputConfig {
                vrr: AdaptiveSync::Force,
                ..config()
            },
            OutputConfig {
                max_bpc: Some(10),
                ..config()
            },
            OutputConfig {
                scale: 0.0,
                ..config()
            },
            OutputConfig {
                scale: f64::NAN,
                ..config()
            },
        ] {
            assert!(
                validate_output_config(info(), &unsupported).is_err(),
                "{unsupported:?}"
            );
        }
    }

    #[test]
    fn logical_output_scale_position_and_current_color_are_allowed() {
        let request = OutputConfig {
            mode: ((800, 600), Some(60_000)),
            scale: 2.0,
            position: (100, 200),
            max_bpc: Some(8),
            ..config()
        };
        let saved = request.clone();
        assert!(validate_output_config(info(), &request).is_ok());
        assert_eq!(request, saved);
    }

    #[test]
    fn first_render_needs_primary_output_before_callback_eligibility() {
        use smithay::backend::renderer::element::{
            Id, PrimaryScanoutOutput, RenderElementPresentationState, RenderElementState,
            RenderElementStates, default_primary_scanout_output_compare,
        };
        let output = Output::new(
            "native-test".into(),
            PhysicalProperties {
                size: (0, 0).into(),
                subpixel: Subpixel::Unknown,
                make: "test".into(),
                model: "test".into(),
                serial_number: "test".into(),
            },
        );
        let id = Id::new();
        let mut states = RenderElementStates::default();
        states.states.insert(
            id.clone(),
            RenderElementState {
                visible_area: 100,
                presentation_state: RenderElementPresentationState::Rendering { reason: None },
                needs_capture: false,
            },
        );
        let mut primary = PrimaryScanoutOutput::default();
        // This is the actual Smithay state used by Common::send_frames' gate.
        // Sending first would leave a fresh surface's callback unsent at idle.
        assert_ne!(primary.current_output().as_ref(), Some(&output));
        primary.update_from_render_element_states(
            id,
            &output,
            None,
            &states,
            default_primary_scanout_output_compare,
        );
        assert_eq!(primary.current_output().as_ref(), Some(&output));
    }
}
