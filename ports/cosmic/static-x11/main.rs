use std::{error::Error, ptr};
use x11rb::connection::Connection;
fn main() -> Result<(), Box<dyn Error>> {
    let xkb = xkbcommon_dl::xkbcommon_handle();
    unsafe {
        let context = (xkb.xkb_context_new)(xkbcommon_dl::xkb_context_flags::XKB_CONTEXT_NO_DEFAULT_INCLUDES);
        if context.is_null() { return Err("xkb context allocation failed".into()); }
        let symbol = (xkb.xkb_keysym_from_name)(c"a".as_ptr(), xkbcommon_dl::xkb_keysym_flags::XKB_KEYSYM_NO_FLAGS);
        (xkb.xkb_context_unref)(context);
        if symbol != 0x61 { return Err("incorrect linked xkb symbol".into()); }
    }
    println!("static-xkb core PASS");
    if std::env::args().any(|a| a == "--no-display") { return Ok(()); }
    let xlib = x11_dl::xlib::Xlib::open()?;
    let xcb = x11_dl::xlib_xcb::Xlib_xcb::open()?;
    let input = x11_dl::xinput2::XInput2::open()?;
    unsafe {
        if (xlib.XInitThreads)() == 0 { return Err("XInitThreads failed".into()); }
        let display = (xlib.XOpenDisplay)(ptr::null());
        if display.is_null() { return Err("real X display connection failed".into()); }
        let result = (|| -> Result<(), Box<dyn Error>> {
            let connection = (xcb.XGetXCBConnection)(display);
            if connection.is_null() { return Err("XCB connection missing".into()); }
            let borrowed = x11rb::xcb_ffi::XCBConnection::from_raw_xcb_connection(connection.cast(), false)?;
            borrowed.flush()?;
            let xkb_x11 = xkbcommon_dl::x11::xkbcommon_x11_handle();
            let ok = (xkb_x11.xkb_x11_setup_xkb_extension)(connection.cast(), 1, 0,
                xkbcommon_dl::x11::xkb_x11_setup_xkb_extension_flags::XKB_X11_SETUP_XKB_EXTENSION_NO_FLAGS,
                ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            if ok == 0 { return Err("real XKB extension unavailable".into()); }
            let mut major=2; let mut minor=0;
            if (input.XIQueryVersion)(display, &mut major, &mut minor) != 0 {
                return Err("real XInput2 extension unavailable".into());
            }
            println!("static-x11 Xlib XCB XInput2 XKB PASS");
            Ok(())
        })();
        (xlib.XCloseDisplay)(display);
        result?;
    }
    Ok(())
}
