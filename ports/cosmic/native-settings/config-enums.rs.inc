#[cfg(feature = "libinput")]
pub use input::{AccelProfile, ClickMethod, ScrollMethod, TapButtonMap};
use serde::{Deserialize, Serialize};

// Backend-independent configuration values. Their RON representation is exactly
// the same as the native libinput enums below; no device API is emulated.
#[cfg(not(feature = "libinput"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccelProfile {
    Flat,
    Adaptive,
}
#[cfg(not(feature = "libinput"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClickMethod {
    ButtonAreas,
    Clickfinger,
}
#[cfg(not(feature = "libinput"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrollMethod {
    NoScroll,
    TwoFinger,
    Edge,
    OnButtonDown,
}
#[cfg(not(feature = "libinput"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapButtonMap {
    LeftRightMiddle,
    LeftMiddleRight,
}
