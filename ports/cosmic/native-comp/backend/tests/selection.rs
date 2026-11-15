#[test]
fn explicit_native_selection_is_feature_gated() {
    #[cfg(feature = "backend-cyxia")]
    assert_eq!(
        selection::candidates(Some("cyxia"), true),
        Ok(&[selection::Backend::Cyxia][..])
    );
    #[cfg(not(feature = "backend-cyxia"))]
    assert_eq!(
        selection::candidates(Some("cyxia"), false),
        Err("Requested COSMIC backend is disabled at build time")
    );
    assert_eq!(
        selection::candidates(Some("fixture"), false),
        Err("Unknown COSMIC_BACKEND value")
    );
}

#[test]
fn default_kms_selection_is_preserved() {
    #[cfg(feature = "backend-kms")]
    assert_eq!(
        selection::candidates(None, false),
        Ok(&[selection::Backend::Kms][..])
    );
}

#[test]
fn nested_default_priority_is_preserved() {
    #[cfg(any(feature = "backend-x11", feature = "backend-winit"))]
    {
        let expected = &[
            #[cfg(feature = "backend-x11")]
            selection::Backend::X11,
            #[cfg(feature = "backend-winit")]
            selection::Backend::Winit,
        ];
        assert_eq!(selection::candidates(None, true), Ok(expected.as_slice()));
    }
}

#[test]
fn native_only_ignores_inherited_nested_environment() {
    #[cfg(all(
        feature = "backend-cyxia",
        not(any(
            feature = "backend-kms",
            feature = "backend-winit",
            feature = "backend-x11"
        ))
    ))]
    for nested in [false, true] {
        assert_eq!(
            selection::candidates(None, nested),
            Ok(&[selection::Backend::Cyxia][..])
        );
    }
}
