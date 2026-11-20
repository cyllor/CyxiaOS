//! Exercise the same genuine XKB loader API used by winit's Wayland keyboard.
use xkbcommon_dl::*;
fn main() {
    println!("XKB_DL_PROBE START");
    let xkb = xkbcommon_handle();
    let compose = xkbcommon_compose_handle();
    println!("XKB_DL_PROBE BINDINGS PASS");
    unsafe {
        let context = (xkb.xkb_context_new)(xkb_context_flags::XKB_CONTEXT_NO_FLAGS);
        assert!(!context.is_null());
        println!("XKB_DL_PROBE CONTEXT PASS");
        assert_eq!((xkb.xkb_keysym_from_name)(c"Return".as_ptr(), xkb_keysym_flags::XKB_KEYSYM_NO_FLAGS), 0xff0d);
        let mut text = [0i8; 16];
        let count = (xkb.xkb_keysym_to_utf8)(0x01004e2d, text.as_mut_ptr(), text.len());
        assert_eq!(count, 4);
        assert_eq!(std::ffi::CStr::from_ptr(text.as_ptr()).to_str().unwrap(), "中");
        println!("XKB_DL_PROBE KEYSYM_UTF8 PASS");
        let table = (compose.xkb_compose_table_new_from_locale)(context, c"en_US.UTF-8".as_ptr(), xkb_compose_compile_flags::XKB_COMPOSE_COMPILE_NO_FLAGS);
        assert!(!table.is_null());
        let state = (compose.xkb_compose_state_new)(table, xkb_compose_state_flags::XKB_COMPOSE_STATE_NO_FLAGS);
        assert!(!state.is_null());
        (compose.xkb_compose_state_feed)(state, 0xfe51); // dead_acute
        (compose.xkb_compose_state_feed)(state, b'e' as u32);
        assert_eq!((compose.xkb_compose_state_get_status)(state), xkb_compose_status::XKB_COMPOSE_COMPOSED);
        assert_eq!((compose.xkb_compose_state_get_utf8)(state, text.as_mut_ptr(), text.len()), 2);
        assert_eq!(std::ffi::CStr::from_ptr(text.as_ptr()).to_str().unwrap(), "é");
        println!("XKB_DL_PROBE COMPOSE PASS");
        (compose.xkb_compose_state_unref)(state);
        (compose.xkb_compose_table_unref)(table);
        (xkb.xkb_context_unref)(context);
    }
    println!("XKB_DL_PROBE CLEANUP PASS");
    println!("XKB_DL_PROBE PASS");
}
