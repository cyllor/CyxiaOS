// SPDX-License-Identifier: GPL-3.0-only
// These tests compile the policy module from the applied upstream patch.
use policy::{DevicePreference, NodePair};

#[test]
fn output_capture_renders_on_output_and_copies_to_client_device() {
    assert_eq!(
        DevicePreference::Output {
            output: Some(20),
            target: Some(30),
        }
        .select(Some(10)),
        Some(NodePair { render: 20, target: 30 })
    );
}

#[test]
fn output_capture_without_output_device_uses_primary() {
    assert_eq!(
        DevicePreference::Output { output: None, target: Some(30) }.select(Some(10)),
        Some(NodePair { render: 10, target: 30 })
    );
}

#[test]
fn output_capture_without_client_device_renders_and_copies_on_output() {
    assert_eq!(
        DevicePreference::Output { output: Some(20), target: None }.select(Some(10)),
        Some(NodePair { render: 20, target: 20 })
    );
}

#[test]
fn target_buffer_alone_does_not_invent_an_output_renderer() {
    assert_eq!(
        DevicePreference::Output { output: None, target: Some(30) }.select(None),
        None
    );
}

#[test]
fn toplevel_capture_prefers_client_buffer_then_surface_then_primary() {
    for (target, surface, primary, expected) in [
        (Some(30), Some(20), Some(10), Some(NodePair { render: 30, target: 30 })),
        (None, Some(20), Some(10), Some(NodePair { render: 20, target: 20 })),
        (None, None, Some(10), Some(NodePair { render: 10, target: 10 })),
        (Some(30), None, None, Some(NodePair { render: 30, target: 30 })),
        (None, Some(20), None, Some(NodePair { render: 20, target: 20 })),
        (None, None, None, None),
    ] {
        assert_eq!(DevicePreference::Surface { surface, target }.select(primary), expected);
    }
}

#[test]
fn cursor_capture_uses_primary_or_software_fallback() {
    assert_eq!(
        DevicePreference::Primary.select(Some(10)),
        Some(NodePair { render: 10, target: 10 })
    );
    assert_eq!(DevicePreference::<u32>::Primary.select(None), None);
}

#[test]
fn screenshot_advertised_device_precedes_primary() {
    assert_eq!(
        DevicePreference::Surface { surface: Some(20), target: None }.select(Some(10)),
        Some(NodePair { render: 20, target: 20 })
    );
}
