//! Real upstream Smithay EGL and GLES renderer on the static CyxiaOS Mesa SDK.
use smithay::backend::{
    allocator::Fourcc,
    egl::{EGLContext, EGLDisplay, ffi::egl, native::EGLSurfacelessDisplay},
    renderer::{
        Bind, Color32F, ExportMem, Frame, ImportMem, Offscreen, Renderer,
        gles::{GlesRenderbuffer, GlesRenderer, GlesTarget},
    },
};
use smithay::utils::{Buffer, Rectangle, Size, Transform};
use std::{error::Error, ffi::CStr, io::Write};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn emit(text: &str) -> Result {
    std::io::stdout().lock().write_all(text.as_bytes())?;
    Ok(())
}

fn check(condition: bool, name: &str) -> Result {
    if !condition {
        return Err(format!("assertion failed: {name}").into());
    }
    emit(&format!("SMITHAY CHECK name={name} result=PASS\n"))
}

fn pixels(
    renderer: &mut GlesRenderer,
    target: &GlesTarget<'_>,
    size: Size<i32, Buffer>,
    expected: [u8; 4],
    name: &str,
) -> Result {
    // Upstream ExportMem performs the actual framebuffer-to-PBO readback and
    // maps that buffer. Uniform colors intentionally avoid orientation ambiguity.
    let mapping =
        renderer.copy_framebuffer(target, Rectangle::from_size(size), Fourcc::Abgr8888)?;
    let bytes = renderer.map_texture(&mapping)?;
    check(
        bytes.len() == (size.w * size.h * 4) as usize
            && bytes.chunks_exact(4).all(|pixel| pixel == expected),
        name,
    )
}

fn run() -> Result {
    // SAFETY: This program has not created threads or initialized Mesa yet.
    unsafe {
        std::env::set_var("LIBGL_ALWAYS_SOFTWARE", "true");
        std::env::set_var("GALLIUM_DRIVER", "softpipe");
        std::env::set_var("MESA_SHADER_CACHE_DISABLE", "true");
    }
    // SAFETY: Smithay exclusively owns all EGL displays and contexts in this
    // process; all creation, rendering, readback and destruction use this thread.
    let display = unsafe { EGLDisplay::new(EGLSurfacelessDisplay)? };
    check(display.get_egl_version() >= (1, 5), "upstream-egl-display")?;
    let context = EGLContext::new(&display)?;
    check(
        context.get_context_handle() != egl::NO_CONTEXT,
        "upstream-egl-context",
    )?;
    // SAFETY: The new context has never been used by another thread. Ownership
    // moves into the real upstream renderer and is released by its destructor.
    let mut renderer = unsafe { GlesRenderer::new(context)? };
    check(true, "upstream-gles-renderer")?;
    let renderer_name = renderer.with_context(|gl| {
        // SAFETY: with_context makes this context current; GL owns the returned
        // terminated string for its lifetime. Handle a missing string explicitly.
        unsafe {
            let pointer = gl.GetString(0x1F01);
            (!pointer.is_null()).then(|| {
                CStr::from_ptr(pointer.cast())
                    .to_string_lossy()
                    .into_owned()
            })
        }
    })?;
    check(
        renderer_name.as_deref() == Some("softpipe"),
        "real-softpipe",
    )?;
    // SAFETY: EGL is initialized and its generated entry table is loaded.
    check(
        unsafe { smithay::backend::egl::get_proc_address("cyxiaNonexistentSmithaySymbol") }
            .is_null(),
        "unknown-symbol-null",
    )?;

    let size: Size<i32, Buffer> = (16, 16).into();
    let full = Rectangle::from_size((16, 16).into());
    let mut buffer: GlesRenderbuffer = renderer.create_buffer(Fourcc::Abgr8888, size)?;
    let mut target = renderer.bind(&mut buffer)?;
    check(true, "upstream-offscreen-renderbuffer")?;
    {
        let mut frame = renderer.render(&mut target, (16, 16).into(), Transform::Normal)?;
        frame.clear(Color32F::new(1.0, 0.0, 0.0, 1.0), &[full])?;
        frame.finish()?.wait()?;
    }
    pixels(
        &mut renderer,
        &target,
        size,
        [255, 0, 0, 255],
        "clear-256-pixels",
    )?;
    {
        let mut frame = renderer.render(&mut target, (16, 16).into(), Transform::Normal)?;
        Frame::draw_solid(&mut frame, full, &[full], Color32F::new(0.0, 1.0, 0.0, 1.0))?;
        frame.finish()?.wait()?;
    }
    pixels(
        &mut renderer,
        &target,
        size,
        [0, 255, 0, 255],
        "solid-shader-256-pixels",
    )?;

    let blue = [0, 0, 255, 255].repeat(4);
    let texture = renderer.import_memory(&blue, Fourcc::Abgr8888, (2, 2).into(), false)?;
    for (expected, name) in [
        ([0, 0, 255, 255], "texture-shader-256-pixels"),
        ([255, 255, 0, 255], "updated-texture-256-pixels"),
    ] {
        if expected[0] != 0 {
            renderer.update_memory(
                &texture,
                &expected.repeat(4),
                Rectangle::from_size((2, 2).into()),
            )?;
        }
        let mut frame = renderer.render(&mut target, (16, 16).into(), Transform::Normal)?;
        Frame::render_texture_from_to(
            &mut frame,
            &texture,
            Rectangle::from_size((2.0, 2.0).into()),
            full,
            &[full],
            &[full],
            Transform::Normal,
            1.0,
        )?;
        frame.finish()?.wait()?;
        pixels(&mut renderer, &target, size, expected, name)?;
    }
    drop(texture);
    drop(target);
    drop(buffer);

    let size: Size<i32, Buffer> = (9, 7).into();
    let mut buffer: GlesRenderbuffer = renderer.create_buffer(Fourcc::Abgr8888, size)?;
    let mut target = renderer.bind(&mut buffer)?;
    {
        let mut frame = renderer.render(&mut target, (9, 7).into(), Transform::Normal)?;
        frame.clear(
            Color32F::new(1.0, 0.0, 1.0, 1.0),
            &[Rectangle::from_size((9, 7).into())],
        )?;
        frame.finish()?.wait()?;
    }
    pixels(
        &mut renderer,
        &target,
        size,
        [255, 0, 255, 255],
        "replacement-target-63-pixels",
    )?;
    drop(target);
    drop(buffer);
    let gl_error = renderer.with_context(|gl| {
        // SAFETY: The renderer owns the current GL context on this thread.
        unsafe { gl.GetError() }
    })?;
    check(gl_error == 0, "gl-errors-clear")?;
    renderer.egl_context().unbind()?;
    drop(renderer);
    drop(display);
    // SAFETY: All Smithay objects have been dropped on their creating thread.
    check(
        unsafe {
            egl::GetCurrentContext() == egl::NO_CONTEXT && egl::ReleaseThread() != egl::FALSE
        },
        "upstream-lifecycle-cleanup",
    )?;
    emit("SMITHAY PASS static=1 upstream=egl-context-gles-renderer pixels=1087 cosmic=0\n")
}

fn main() {
    if let Err(error) = run() {
        let _ = emit(&format!("SMITHAY FAIL {error}\n"));
        std::process::exit(1);
    }
}
