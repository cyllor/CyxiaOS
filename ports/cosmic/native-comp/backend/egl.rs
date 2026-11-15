// SPDX-License-Identifier: GPL-3.0-only
//! Bootstrap Smithay's real EGL dispatch from the linked Mesa implementation.
//! Cyxia's static musl process has no libEGL.so.1 loader. Keep this confined to
//! native backend startup; the existing backends retain Smithay's normal loader.
use anyhow::{Result, bail};
use smithay::backend::egl::ffi::egl;
use std::{
    ffi::{CString, c_char, c_void},
    sync::atomic::{AtomicBool, Ordering},
};

static OWNED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    #[link_name = "eglGetProcAddress"]
    fn linked_get_proc_address(name: *const c_char) -> Option<unsafe extern "system" fn()>;
}

fn resolve(symbol: &str) -> *const c_void {
    if symbol == "eglGetProcAddress" {
        return linked_get_proc_address as *const c_void;
    }
    let Ok(name) = CString::new(symbol) else {
        return std::ptr::null();
    };
    // SAFETY: the linked Mesa entry point owns returned functions for the
    // process lifetime; name remains NUL-terminated throughout this call.
    unsafe { linked_get_proc_address(name.as_ptr()) }
        .map_or(std::ptr::null(), |function| function as *const c_void)
}

pub fn load() -> Result<()> {
    // This same public Once guards Smithay's loader. Do not overwrite dispatch
    // installed by another backend, and never mutate its dependency checkout.
    egl::LOAD.call_once(|| {
        egl::load_with(resolve);
        egl::BindWaylandDisplayWL::load_with(resolve);
        egl::UnbindWaylandDisplayWL::load_with(resolve);
        egl::QueryWaylandBufferWL::load_with(resolve);
        egl::DebugMessageControlKHR::load_with(resolve);
        OWNED.store(true, Ordering::Release);
    });
    if !OWNED.load(Ordering::Acquire) {
        bail!("Cyxia cannot replace an already initialized EGL provider");
    }
    macro_rules! require {
        ($($name:ident),+ $(,)?) => { $(
            if !egl::$name::is_loaded() { bail!(concat!("Linked Mesa lacks egl", stringify!($name))); }
        )+ };
    }
    require!(
        GetProcAddress,
        GetError,
        QueryString,
        GetPlatformDisplayEXT,
        Initialize,
        Terminate,
        BindAPI,
        ChooseConfig,
        GetConfigAttrib,
        CreateContext,
        DestroyContext,
        MakeCurrent,
        GetCurrentContext,
        GetCurrentDisplay,
        QueryContext,
        ReleaseThread
    );
    // Smithay calls this unconditionally when Mesa advertises EGL_KHR_debug.
    // Require it up front instead of allowing a generated missing-entry panic.
    require!(DebugMessageControlKHR);
    Ok(())
}

/// Called only after the native renderer and its context have been dropped.
pub fn release_thread() -> Result<()> {
    // SAFETY: native shutdown has destroyed its only renderer on this thread.
    // Query and release are real linked Mesa functions, validated in load().
    unsafe {
        if egl::GetCurrentContext() != egl::NO_CONTEXT || egl::ReleaseThread() == egl::FALSE {
            bail!("Cyxia EGL thread cleanup failed");
        }
    }
    Ok(())
}
