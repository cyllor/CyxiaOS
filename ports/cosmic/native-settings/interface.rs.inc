#[zbus::interface(name = "com.system76.CosmicSettingsDaemon")]
impl SettingsDaemon {
    #[zbus(property)]
    async fn display_brightness(&self) -> i32 {
        #[cfg(feature = "backlight")]
        {
            self.display_brightness_device
                .brightness()
                .await
                .ok()
                .map(|x| x as i32)
                .unwrap_or(-1)
        }
        #[cfg(not(feature = "backlight"))]
        { -1 }
    }

    /// Take the current xkb config and switch the active input source.
    async fn input_source_switch(&self) {
        let _ = self.wayland_sender.send(wayland::Cmd::InputSourceSwitch);
    }

    #[zbus(property)]
    async fn max_display_brightness(&self) -> i32 {
        #[cfg(feature = "backlight")]
        { self.display_brightness_device.max_brightness() }
        #[cfg(not(feature = "backlight"))]
        { -1 }
    }

    #[zbus(property)]
    async fn set_display_brightness(&self, value: i32) -> zbus::fdo::Result<()> {
        #[cfg(feature = "backlight")]
        {
            if let Some(logind_session) = self.logind_session.as_ref() {
                // Preserve the ordinary backend's clamp and device behavior.
                let max = self.display_brightness_device.max_brightness();
                let min = self.display_brightness_device.min_brightness() as i32;
                if min > max {
                    return Ok(());
                }
                let clamped = value.clamp(min, max);
                _ = self.display_brightness_device
                    .set_brightness(logind_session, clamped as u32).await;
            }
            Ok(())
        }
        #[cfg(not(feature = "backlight"))]
        {
            let _ = value;
            Err(zbus::fdo::Error::NotSupported("Backlight integration is unavailable in this build".into()))
        }
    }

    #[zbus(property)]
    async fn keyboard_brightness(&self) -> i32 { -1 }

    #[zbus(property)]
    async fn set_keyboard_brightness(&self, _value: i32) -> zbus::fdo::Result<()> {
        #[cfg(feature = "backlight")]
        { Ok(()) }
        #[cfg(not(feature = "backlight"))]
        { Err(zbus::fdo::Error::NotSupported("Keyboard backlight integration is unavailable in this build".into())) }
    }

    async fn increase_display_brightness(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        #[cfg(feature = "backlight")]
        {
            let value = self.display_brightness().await;
            let max_raw = self.max_display_brightness().await;
            let target = next_target_raw(value, max_raw, 1);
            self.set_display_brightness(target).await?;
            _ = self.display_brightness_changed(&emitter).await;
            Ok(())
        }
        #[cfg(not(feature = "backlight"))]
        {
            let _ = emitter;
            Err(zbus::fdo::Error::NotSupported("Backlight integration is unavailable in this build".into()))
        }
    }

    async fn decrease_display_brightness(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        #[cfg(feature = "backlight")]
        {
            let value = self.display_brightness().await;
            let max_raw = self.max_display_brightness().await;
            let target = next_target_raw(value, max_raw, -1);
            self.set_display_brightness(target).await?;
            _ = self.display_brightness_changed(&emitter).await;
            Ok(())
        }
        #[cfg(not(feature = "backlight"))]
        {
            let _ = emitter;
            Err(zbus::fdo::Error::NotSupported("Backlight integration is unavailable in this build".into()))
        }
    }

    async fn increase_keyboard_brightness(&self) -> zbus::fdo::Result<()> {
        #[cfg(feature = "backlight")]
        { Ok(()) }
        #[cfg(not(feature = "backlight"))]
        { Err(zbus::fdo::Error::NotSupported("Keyboard backlight integration is unavailable in this build".into())) }
    }

    async fn decrease_keyboard_brightness(&self) -> zbus::fdo::Result<()> {
        #[cfg(feature = "backlight")]
        { Ok(()) }
        #[cfg(not(feature = "backlight"))]
        { Err(zbus::fdo::Error::NotSupported("Keyboard backlight integration is unavailable in this build".into())) }
    }

    async fn screen_reader(&mut self) {
        if let Some(a11y) = self.a11y_session.as_ref() {
            let guard = a11y.lock().await;
            let Ok(current_state) = guard.is_enabled().await else {
                log::error!("Failed to toggle screen reader. Could not read current state.");
                return;
            };
            let new_state = !current_state;
            if let Err(err) = guard.set_is_enabled(new_state).await {
                log::error!("Failed to toggle screen reader. Could not apply current state. {err:?}");
                return;
            }
            if let Err(err) = guard.set_screen_reader_enabled(new_state).await {
                log::error!("Failed to toggle screen reader. Could not apply current state. {err:?}");
            }
        } else {
            log::error!("Failed to toggle screen reader.")
        }
    }

    async fn volume_up(&self) -> zbus::fdo::Result<()> {
        #[cfg(feature = "audio")]
        {
            if let Err(why) = self.varlink_daemon.lock().await.audio_server.sink_volume_raise().await {
                log::error!("Failed to raise volume: {}", why);
            }
            Ok(())
        }
        #[cfg(not(feature = "audio"))]
        { Err(zbus::fdo::Error::NotSupported("Audio integration is unavailable in this build".into())) }
    }

    async fn volume_down(&self) -> zbus::fdo::Result<()> {
        #[cfg(feature = "audio")]
        {
            if let Err(why) = self.varlink_daemon.lock().await.audio_server.sink_volume_lower().await {
                log::error!("Failed to lower volume: {}", why);
            }
            Ok(())
        }
        #[cfg(not(feature = "audio"))]
        { Err(zbus::fdo::Error::NotSupported("Audio integration is unavailable in this build".into())) }
    }

    async fn watch_config(
        &mut self,
        id: &str,
        version: u64,
    ) -> zbus::fdo::Result<(ObjectPath<'static>, WellKnownName<'static>)> {
        Self::watch_config_inner(self, Config::new_config(), id, version).await
    }

    async fn watch_state(
        &mut self,
        id: &str,
        version: u64,
    ) -> zbus::fdo::Result<(ObjectPath<'static>, WellKnownName<'static>)> {
        Self::watch_config_inner(self, Config::new_state(), id, version).await
    }
}
