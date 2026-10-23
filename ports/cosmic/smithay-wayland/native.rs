//! CyxiaOS ABI v1 display/input adapter. Pixels come from Smithay readback.
use std::io;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct DisplayInfo {
    pub width: u32,
    pub height: u32,
    pub stride_bytes: u32,
    pub format: u32,
    pub max_rect_bytes: u32,
    pub abi: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct InputEvent {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
}

const _: () = assert!(std::mem::size_of::<DisplayInfo>() == 24);
const _: () = assert!(std::mem::size_of::<InputEvent>() == 8);

#[derive(Clone, Copy, Debug)]
struct Rectangle {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn validate_info(info: DisplayInfo) -> io::Result<()> {
    if info.abi != 1
        || info.format != 1
        || !(1..=4096).contains(&info.width)
        || !(1..=4096).contains(&info.height)
        || info.stride_bytes < info.width * 4
        || !info.stride_bytes.is_multiple_of(4)
        || !(4..=65536).contains(&info.max_rect_bytes)
        || !info.max_rect_bytes.is_multiple_of(4)
    {
        return Err(invalid("unsupported native display layout"));
    }
    Ok(())
}

fn present_with(
    info: DisplayInfo,
    rectangle: Rectangle,
    rgba: &[u8],
    flipped: bool,
    mut submit: impl FnMut(Rectangle, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    validate_info(info)?;
    let Rectangle {
        x,
        y,
        width,
        height,
    } = rectangle;
    if width == 0
        || height == 0
        || x.checked_add(width).is_none_or(|end| end > info.width)
        || y.checked_add(height).is_none_or(|end| end > info.height)
        || u64::from(width) * u64::from(height) * 4 != rgba.len() as u64
    {
        return Err(invalid("out-of-bounds or incorrectly packed RGBA frame"));
    }
    // One reusable <=16KiB CPU staging allocation, independent of screen size.
    // It follows the normal guest allocator/AI admission path.
    let capacity = (info.max_rect_bytes as usize).min(16384);
    let mut tile = Vec::new();
    tile.try_reserve_exact(capacity)
        .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "display staging allocation"))?;
    tile.resize(capacity, 0);
    let mut left = 0;
    while left < width {
        let columns = (width - left).min(capacity as u32 / 4);
        let max_rows = capacity as u32 / (columns * 4);
        let mut top = 0;
        while top < height {
            let rows = (height - top).min(max_rows);
            let length = (columns * rows * 4) as usize;
            for row in 0..rows {
                let source_row = if flipped {
                    height - 1 - top - row
                } else {
                    top + row
                };
                for column in 0..columns {
                    let source = ((source_row * width + left + column) * 4) as usize;
                    let target = ((row * columns + column) * 4) as usize;
                    // Smithay ABGR8888 readback is RGBA bytes. Native XRGB8888
                    // is B,G,R,unused on little-endian ARM; alpha is already
                    // composited against the renderer's opaque background.
                    tile[target..target + 4].copy_from_slice(&[
                        rgba[source + 2],
                        rgba[source + 1],
                        rgba[source],
                        0,
                    ]);
                }
            }
            submit(
                Rectangle {
                    x: x + left,
                    y: y + top,
                    width: columns,
                    height: rows,
                },
                &tile[..length],
            )?;
            top += rows;
        }
        left += columns;
    }
    Ok(())
}

/// Validated native output. A successful present has completed every GPU fence.
pub struct NativeDisplay {
    info: DisplayInfo,
}

fn syscall_result(value: i64) -> io::Result<usize> {
    if value < 0 {
        let errno = value
            .checked_neg()
            .and_then(|n| i32::try_from(n).ok())
            .filter(|n| (1..=4095).contains(n));
        Err(errno
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| io::Error::other("invalid native syscall result")))
    } else {
        usize::try_from(value).map_err(|_| io::Error::other("native result overflow"))
    }
}

// SAFETY: Callers validate the ABI and keep all user buffers alive, uniquely
// writable for output and readable for input, for the whole synchronous call.
unsafe fn syscall6(number: u64, args: [u64; 6]) -> i64 {
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "musl"))]
    {
        let mut result = args[0];
        // SAFETY: CyxiaOS's Linux personality preserves x1..x5/x8 across SVC,
        // and copies/validates user pointers. No borrowed data outlives SVC.
        unsafe {
            std::arch::asm!(
                "svc #0",
                inlateout("x0") result,
                in("x1") args[1], in("x2") args[2], in("x3") args[3],
                in("x4") args[4], in("x5") args[5], in("x8") number,
                options(nostack),
            );
        }
        result as i64
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux", target_env = "musl")))]
    {
        let _ = (number, args);
        -38
    }
}

fn retry_submission(
    deadline: std::time::Instant,
    mut submit: impl FnMut() -> io::Result<usize>,
) -> io::Result<()> {
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native display busy",
            ));
        }
        match submit() {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(io::Error::other("invalid display completion")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

impl NativeDisplay {
    pub fn connect() -> io::Result<Self> {
        let mut info = DisplayInfo::default();
        // SAFETY: repr(C) has the exact24-byte ABI; the exclusive reference
        // remains valid until the kernel finishes copying the result.
        let count = syscall_result(unsafe {
            syscall6(
                0x43595801,
                [&mut info as *mut DisplayInfo as u64, 0, 0, 0, 0, 0],
            )
        })?;
        if count != 0 {
            return Err(io::Error::other("invalid display info result"));
        }
        validate_info(info)?;
        Ok(Self { info })
    }

    pub fn info(&self) -> DisplayInfo {
        self.info
    }

    /// Convert tightly packed RGBA readback into native tiles. `flipped` is
    /// Smithay TextureMapping::flipped(), not an inferred host orientation.
    /// Failed partial presentation is reported as an error, never frame.done.
    pub fn present_rgba(
        &self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        rgba: &[u8],
        flipped: bool,
    ) -> io::Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        present_with(
            self.info,
            Rectangle {
                x,
                y,
                width,
                height,
            },
            rgba,
            flipped,
            |tile, bytes| {
                retry_submission(deadline, || {
                    // SAFETY: tile bounds, byte length and packing were checked
                    // before any submission; this slice lives through the fence.
                    syscall_result(unsafe {
                        syscall6(
                            0x43595802,
                            [
                                u64::from(tile.x),
                                u64::from(tile.y),
                                u64::from(tile.width),
                                u64::from(tile.height),
                                bytes.as_ptr() as u64,
                                bytes.len() as u64,
                            ],
                        )
                    })
                })
            },
        )
    }
}

/// Raw ordered evdev records; an empty device queue returns zero.
/// Consumers retain partial SYN frames and resynchronize after SYN_DROPPED.
pub fn read_input(events: &mut [InputEvent]) -> io::Result<usize> {
    if events.is_empty() || events.len() > 32 {
        return Err(invalid("native input batch must contain 1..32 records"));
    }
    // SAFETY: repr(C) records are exactly8bytes and the kernel may write only
    // this exclusively borrowed initialized slice.
    match syscall_result(unsafe {
        syscall6(
            0x43595803,
            [events.as_mut_ptr() as u64, events.len() as u64, 0, 0, 0, 0],
        )
    }) {
        Ok(count) if count <= events.len() => Ok(count),
        Ok(_) => Err(io::Error::other("invalid native input count")),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
        Err(error) => Err(error),
    }
}

pub fn input_key_state() -> io::Result<[u8; 96]> {
    let mut bits = [0; 96];
    // SAFETY: the ABI copies exactly96bytes to this exclusive local buffer.
    let result =
        syscall_result(unsafe { syscall6(0x43595804, [bits.as_mut_ptr() as u64, 0, 0, 0, 0, 0]) })?;
    if result != 0 {
        return Err(io::Error::other("invalid native key state result"));
    }
    Ok(bits)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputAction {
    Key { code: u16, pressed: bool },
    Button { code: u16, pressed: bool },
    Motion { dx: i32, dy: i32 },
    Resync,
}

pub struct InputDecoder {
    pending: Vec<InputEvent>,
    held: [u8; 96],
    dropped: bool,
}

impl Default for InputDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl InputDecoder {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            held: [0; 96],
            dropped: false,
        }
    }
    pub fn push(&mut self, event: InputEvent) -> io::Result<Option<Vec<InputAction>>> {
        if event.kind == 0 && event.code == 3 {
            self.pending.clear();
            self.dropped = true;
            return Ok(None);
        }
        if event.kind == 0 && event.code == 0 {
            if self.dropped {
                let mut actions = Vec::new();
                actions.try_reserve_exact(1).map_err(|_| {
                    io::Error::new(io::ErrorKind::OutOfMemory, "input loss receipt")
                })?;
                actions.push(InputAction::Resync);
                return Ok(Some(actions));
            }
            let mut actions = Vec::new();
            actions
                .try_reserve_exact(self.pending.len() + 1)
                .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "input actions"))?;
            let mut dx: i32 = 0;
            let mut dy: i32 = 0;
            let flush_motion = |actions: &mut Vec<InputAction>, dx: &mut i32, dy: &mut i32| {
                if *dx != 0 || *dy != 0 {
                    actions.push(InputAction::Motion { dx: *dx, dy: *dy });
                    *dx = 0;
                    *dy = 0;
                }
            };
            for event in self.pending.drain(..) {
                if event.kind == 2 {
                    let axis = if event.code == 0 { &mut dx } else { &mut dy };
                    *axis = axis.saturating_add(event.value).clamp(-32767, 32767);
                } else {
                    flush_motion(&mut actions, &mut dx, &mut dy);
                    if event.value == 2 {
                        continue;
                    } // Client-side repeat owns repetition.
                    let pressed = event.value == 1;
                    let byte = &mut self.held[usize::from(event.code) / 8];
                    let mask = 1 << (event.code % 8);
                    if (*byte & mask != 0) != pressed {
                        if pressed {
                            *byte |= mask;
                        } else {
                            *byte &= !mask;
                        }
                        actions.push(Self::key_action(event.code, pressed));
                    }
                }
            }
            flush_motion(&mut actions, &mut dx, &mut dy);
            return Ok(Some(actions));
        }
        if self.dropped {
            return Ok(None);
        }
        // This first native backend supports relative pointer and a keyboard.
        // Wheel and absolute tablet scaling require their own advertised API.
        let supported = match event.kind {
            1 => {
                (event.code < 248 || (272..=274).contains(&event.code))
                    && (0..=2).contains(&event.value)
            }
            2 => event.code <= 1,
            4 => return Ok(None), // EV_MSC is metadata, not an input transition.
            _ => false,
        };
        if !supported {
            self.pending.clear();
            self.dropped = true;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported native input record",
            ));
        }
        if self.pending.len() == 128 {
            self.pending.clear();
            self.dropped = true;
            return Ok(None);
        }
        if self.pending.capacity() < 128 {
            self.pending
                .try_reserve_exact(128 - self.pending.len())
                .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "input packet"))?;
        }
        self.pending.push(event);
        Ok(None)
    }
    fn key_action(code: u16, pressed: bool) -> InputAction {
        if (272..=274).contains(&code) {
            InputAction::Button { code, pressed }
        } else {
            InputAction::Key { code, pressed }
        }
    }
    /// Reconcile authoritative held state after loss. Relative motion cannot
    /// be reconstructed; no synthetic movement is invented.
    pub fn resynchronize(&mut self, bits: [u8; 96]) -> io::Result<Vec<InputAction>> {
        let mut actions = Vec::new();
        actions
            .try_reserve_exact(251)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "input resynchronization"))?;
        for code in (0u16..248).chain(272..=274) {
            let index = usize::from(code) / 8;
            let mask = 1 << (code % 8);
            let pressed = bits[index] & mask != 0;
            if (self.held[index] & mask != 0) != pressed {
                actions.push(Self::key_action(code, pressed));
            }
        }
        self.held = bits;
        self.pending.clear();
        self.dropped = false;
        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> DisplayInfo {
        DisplayInfo {
            width: 8,
            height: 7,
            stride_bytes: 32,
            format: 1,
            max_rect_bytes: 16,
            abi: 1,
        }
    }

    #[test]
    fn native_info_requires_exact_known_layout_and_bounded_tiles() {
        assert!(validate_info(info()).is_ok());
        for bad in [
            DisplayInfo { abi: 2, ..info() },
            DisplayInfo {
                format: 2,
                ..info()
            },
            DisplayInfo { width: 0, ..info() },
            DisplayInfo {
                height: 4097,
                ..info()
            },
            DisplayInfo {
                stride_bytes: 31,
                ..info()
            },
            DisplayInfo {
                max_rect_bytes: 65540,
                ..info()
            },
            DisplayInfo {
                max_rect_bytes: 7,
                ..info()
            },
        ] {
            assert!(validate_info(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn asymmetric_rgba_is_converted_and_globally_flipped_across_tiles() {
        let rectangle = Rectangle {
            x: 1,
            y: 2,
            width: 6,
            height: 3,
        };
        let rgba: Vec<u8> = (0..18).flat_map(|i| [i, i + 20, i + 40, 255]).collect();
        for flipped in [false, true] {
            let mut screen = vec![77u8; 8 * 7 * 4];
            let mut visits = [0; 18];
            present_with(info(), rectangle, &rgba, flipped, |tile, pixels| {
                assert!(pixels.len() <= 16);
                assert_eq!(pixels.len(), (tile.width * tile.height * 4) as usize);
                for y in 0..tile.height {
                    for x in 0..tile.width {
                        let dx = tile.x + x;
                        let dy = tile.y + y;
                        let src = ((y * tile.width + x) * 4) as usize;
                        let dst = ((dy * 8 + dx) * 4) as usize;
                        screen[dst..dst + 4].copy_from_slice(&pixels[src..src + 4]);
                        visits[((dy - 2) * 6 + dx - 1) as usize] += 1;
                    }
                }
                Ok(())
            })
            .unwrap();
            assert!(visits.iter().all(|n| *n == 1));
            for y in 0..7 {
                for x in 0..8 {
                    let dst = (y * 8 + x) * 4;
                    if (1..7).contains(&x) && (2..5).contains(&y) {
                        let row = if flipped { 4 - y } else { y - 2 };
                        let n = (row * 6 + x - 1) as u8;
                        assert_eq!(&screen[dst..dst + 4], &[n + 40, n + 20, n, 0]);
                    } else {
                        assert_eq!(&screen[dst..dst + 4], &[77; 4]);
                    }
                }
            }
        }
    }

    #[test]
    fn rejected_frames_submit_nothing_and_device_error_stops_submission() {
        let rectangle = Rectangle {
            x: 1,
            y: 1,
            width: 6,
            height: 3,
        };
        let rgba = [255; 72];
        for (rect, bytes) in [
            (
                Rectangle {
                    x: u32::MAX,
                    ..rectangle
                },
                rgba.as_slice(),
            ),
            (Rectangle { y: 5, ..rectangle }, rgba.as_slice()),
            (
                Rectangle {
                    width: 0,
                    ..rectangle
                },
                rgba.as_slice(),
            ),
            (rectangle, &rgba[..71]),
            (rectangle, &[0; 76]),
        ] {
            assert!(
                present_with(info(), rect, bytes, false, |_, _| {
                    panic!("invalid frame reached device")
                })
                .is_err()
            );
        }
        let mut calls = 0;
        let result = present_with(info(), rectangle, &rgba, false, |_, _| {
            calls += 1;
            Err(io::Error::from_raw_os_error(19))
        });
        assert_eq!(result.unwrap_err().raw_os_error(), Some(19));
        assert_eq!(calls, 1);
    }

    #[test]
    fn retry_never_treats_busy_or_partial_result_as_completion() {
        use std::time::{Duration, Instant};
        let mut calls = 0;
        retry_submission(Instant::now() + Duration::from_secs(1), || {
            calls += 1;
            if calls < 3 {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(0)
            }
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert!(retry_submission(Instant::now(), || panic!("expired deadline")).is_err());
        assert!(retry_submission(Instant::now() + Duration::from_secs(1), || Ok(1)).is_err());
        // raw errno is preserved; host macOS uses a different errno numbering
        // from the actual ARM Linux-personality target.
        assert_eq!(syscall_result(-11).unwrap_err().raw_os_error(), Some(11));
        assert!(syscall_result(i64::MIN).is_err());
    }

    fn ev(kind: u16, code: u16, value: i32) -> InputEvent {
        InputEvent { kind, code, value }
    }

    #[test]
    fn input_frames_coalesce_axes_and_preserve_key_button_order() {
        let mut d = InputDecoder::new();
        for e in [
            ev(2, 0, 4),
            ev(2, 1, 3),
            ev(1, 272, 1),
            ev(1, 272, 0),
            ev(1, 30, 1),
            ev(1, 30, 2),
        ] {
            assert_eq!(d.push(e).unwrap(), None);
        }
        assert_eq!(
            d.push(ev(0, 0, 0)).unwrap(),
            Some(vec![
                InputAction::Motion { dx: 4, dy: 3 },
                InputAction::Button {
                    code: 272,
                    pressed: true
                },
                InputAction::Button {
                    code: 272,
                    pressed: false
                },
                InputAction::Key {
                    code: 30,
                    pressed: true
                },
            ])
        );
        d.push(ev(1, 30, 1)).unwrap();
        d.push(ev(1, 30, 0)).unwrap();
        assert_eq!(
            d.push(ev(0, 0, 0)).unwrap(),
            Some(vec![InputAction::Key {
                code: 30,
                pressed: false
            },])
        );
    }

    #[test]
    fn input_loss_discards_uncommitted_keys_and_resync_reconciles_state() {
        let mut d = InputDecoder::new();
        d.push(ev(1, 30, 1)).unwrap();
        d.push(ev(0, 0, 0)).unwrap();
        d.push(ev(1, 16, 1)).unwrap();
        d.push(ev(0, 3, 0)).unwrap();
        d.push(ev(1, 272, 1)).unwrap();
        assert_eq!(
            d.push(ev(0, 0, 0)).unwrap(),
            Some(vec![InputAction::Resync])
        );
        assert_eq!(
            d.resynchronize([0; 96]).unwrap(),
            vec![InputAction::Key {
                code: 30,
                pressed: false
            },]
        );
        for _ in 0..129 {
            d.push(ev(2, 0, 1)).unwrap();
        }
        assert_eq!(
            d.push(ev(0, 0, 0)).unwrap(),
            Some(vec![InputAction::Resync])
        );
        let mut bits = [0; 96];
        bits[272 / 8] = 1 << (272 % 8);
        assert_eq!(
            d.resynchronize(bits).unwrap(),
            vec![InputAction::Button {
                code: 272,
                pressed: true
            },]
        );
    }

    #[test]
    fn unsupported_or_malformed_input_cannot_commit_a_partial_frame() {
        for bad in [ev(3, 0, 10), ev(2, 8, 1), ev(1, 30, -1), ev(1, 280, 1)] {
            let mut d = InputDecoder::new();
            d.push(ev(1, 30, 1)).unwrap();
            assert!(d.push(bad).is_err());
            assert_eq!(
                d.push(ev(0, 0, 0)).unwrap(),
                Some(vec![InputAction::Resync])
            );
            assert!(d.resynchronize([0; 96]).unwrap().is_empty());
        }
    }
}
