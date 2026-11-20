// SPDX-License-Identifier: GPL-3.0-only
//! Bounded, resumable native tile submission for the actual COSMIC event loop.
#[cfg(feature = "backend-cyxia")]
use super::super::phase::{self, Phase};
use super::{DisplayInfo, Rectangle, invalid, syscall_result, syscall6, validate_info};
use std::{
    io,
    time::{Duration, Instant},
};

const STALL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct PendingPresentation {
    info: DisplayInfo,
    flipped: bool,
    left: u32,
    top: u32,
    tile: Vec<u8>,
    ready: bool,
    failed: bool,
    observe_first_frame: bool,
    // Only an actually completed tile renews this no-progress watchdog.
    deadline: Instant,
}

fn submit_tile(rect: Rectangle, bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: the validated cursor emits in-bounds, tightly packed tiles.
    // The slice stays alive through the synchronous ABI call.
    syscall_result(unsafe {
        syscall6(
            0x43595802,
            [
                u64::from(rect.x),
                u64::from(rect.y),
                u64::from(rect.width),
                u64::from(rect.height),
                bytes.as_ptr() as u64,
                bytes.len() as u64,
            ],
        )
    })
}

impl PendingPresentation {
    pub fn new(info: DisplayInfo, flipped: bool) -> io::Result<Self> {
        validate_info(info)?;
        let capacity = (info.max_rect_bytes as usize).min(16384);
        let mut tile = Vec::new();
        tile.try_reserve_exact(capacity)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "native tile allocation"))?;
        tile.resize(capacity, 0);
        Ok(Self {
            info,
            flipped,
            left: 0,
            top: 0,
            tile,
            ready: false,
            failed: false,
            observe_first_frame: false,
            deadline: Instant::now() + STALL_TIMEOUT,
        })
    }

    /// Observe only the cursor bound to the first actual render attempt.
    pub fn observe_first_frame(&mut self, observe: bool) {
        self.observe_first_frame = observe;
    }

    pub fn observes_first_frame(&self) -> bool {
        self.observe_first_frame
    }

    /// At most `budget` syscalls, no sleeping or retry loop on EAGAIN/EINTR.
    /// `Ok(true)` means every tile completed; every other result forbids frame
    /// or presentation completion. The mapping must remain unchanged until done.
    pub fn advance(&mut self, rgba: &[u8], budget: usize) -> io::Result<bool> {
        self.advance_pixels(Some(rgba), budget, submit_tile)
    }

    /// Submit opaque black scanout without allocating a full framebuffer.
    pub fn advance_black(&mut self, budget: usize) -> io::Result<bool> {
        self.advance_pixels(None, budget, submit_tile)
    }

    #[cfg(test)]
    pub(crate) fn advance_black_with(
        &mut self,
        budget: usize,
        mut submit: impl FnMut((u32, u32, u32, u32), &[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        self.advance_pixels(None, budget, |rect, bytes| {
            submit((rect.x, rect.y, rect.width, rect.height), bytes)
        })
    }

    fn advance_with(
        &mut self,
        rgba: &[u8],
        budget: usize,
        submit: impl FnMut(Rectangle, &[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        self.advance_pixels(Some(rgba), budget, submit)
    }

    fn advance_pixels(
        &mut self,
        rgba: Option<&[u8]>,
        budget: usize,
        submit: impl FnMut(Rectangle, &[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        self.advance_pixels_with_clock(rgba, budget, submit, Instant::now)
    }

    fn advance_pixels_with_clock(
        &mut self,
        rgba: Option<&[u8]>,
        budget: usize,
        mut submit: impl FnMut(Rectangle, &[u8]) -> io::Result<usize>,
        mut now: impl FnMut() -> Instant,
    ) -> io::Result<bool> {
        if self.failed {
            return Err(io::Error::other("native presentation already failed"));
        }
        if rgba.is_some_and(|rgba| {
            rgba.len() as u64 != u64::from(self.info.width) * u64::from(self.info.height) * 4
        }) || budget == 0
        {
            self.failed = true;
            return Err(invalid("invalid native framebuffer or tile budget"));
        }
        for _ in 0..budget {
            if self.left == self.info.width {
                return Ok(true);
            }
            if now() >= self.deadline {
                self.failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native presentation stalled",
                ));
            }
            let columns = (self.info.width - self.left).min(self.tile.len() as u32 / 4);
            let rows = (self.info.height - self.top).min(self.tile.len() as u32 / (columns * 4));
            let length = (columns * rows * 4) as usize;
            if !self.ready {
                if let Some(rgba) = rgba {
                    for row in 0..rows {
                        let source_row = if self.flipped {
                            self.info.height - 1 - self.top - row
                        } else {
                            self.top + row
                        };
                        for column in 0..columns {
                            let source =
                                ((source_row * self.info.width + self.left + column) * 4) as usize;
                            let target = ((row * columns + column) * 4) as usize;
                            self.tile[target..target + 4].copy_from_slice(&[
                                rgba[source + 2],
                                rgba[source + 1],
                                rgba[source],
                                0,
                            ]);
                        }
                    }
                } else {
                    self.tile[..length].fill(0); // Native XRGB black, alpha unused.
                }
                self.ready = true;
            }
            let rect = Rectangle {
                x: self.left,
                y: self.top,
                width: columns,
                height: rows,
            };
            #[cfg(feature = "backend-cyxia")]
            if self.observe_first_frame && rgba.is_some() {
                phase::mark_once(Phase::FirstTileSubmitBegin);
            }
            match submit(rect, &self.tile[..length]) {
                Ok(0) => {
                    self.ready = false;
                    self.top += rows;
                    if self.top == self.info.height {
                        self.top = 0;
                        self.left += columns;
                    }
                    // A whole frame can span many event-loop turns under
                    // load. Renew only after the native ABI reports that this
                    // tile completed; retries and dispatches are not progress.
                    self.deadline = now() + STALL_TIMEOUT;
                    #[cfg(feature = "backend-cyxia")]
                    if self.observe_first_frame && rgba.is_some() {
                        phase::mark_once(Phase::FirstTileSubmitEnd);
                        if self.left == self.info.width {
                            phase::mark_once(Phase::FirstFullScanoutComplete);
                        }
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(false);
                }
                result => {
                    self.failed = true;
                    return Err(match result {
                        Err(err) => err,
                        Ok(_) => io::Error::other("invalid native tile completion"),
                    });
                }
            }
        }
        Ok(self.left == self.info.width)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn info() -> DisplayInfo {
        DisplayInfo {
            width: 6,
            height: 3,
            stride_bytes: 24,
            format: 1,
            max_rect_bytes: 16,
            abi: 1,
        }
    }
    fn pixels() -> Vec<u8> {
        (0..18).flat_map(|i| [i, i + 20, i + 40, 255]).collect()
    }

    #[test]
    fn completed_tiles_refresh_stall_watchdog_beyond_total_five_seconds() {
        // The same cursor drives ordinary pixels and the session-lock blank.
        for black in [false, true] {
            let start = Instant::now();
            let now = Cell::new(start);
            let mut pending = PendingPresentation::new(info(), false).unwrap();
            pending.deadline = start + Duration::from_secs(5);
            let rgba = pixels();
            let mut calls = 0;
            for tile in 1..=5 {
                let done = pending
                    .advance_pixels_with_clock(
                        (!black).then_some(rgba.as_slice()),
                        1,
                        |_, bytes| {
                            calls += 1;
                            if black {
                                assert!(bytes.iter().all(|byte| *byte == 0));
                            }
                            // Genuine completion every four seconds; the full
                            // frame takes twenty, without a five-second stall.
                            now.set(now.get() + Duration::from_secs(4));
                            Ok(0)
                        },
                        || now.get(),
                    )
                    .unwrap();
                assert_eq!(calls, tile);
                assert_eq!(done, tile == 5, "partial frame was reported complete");
            }
            assert_eq!(now.get().duration_since(start), Duration::from_secs(20));
        }
    }

    #[test]
    fn busy_and_interrupted_attempts_do_not_refresh_stall_watchdog() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::Interrupted] {
            let start = Instant::now();
            let now = Cell::new(start);
            let mut pending = PendingPresentation::new(info(), false).unwrap();
            pending.deadline = start + Duration::from_secs(5);
            let rgba = pixels();
            let cursor = (pending.left, pending.top);
            for second in [1, 2, 3, 4] {
                now.set(start + Duration::from_secs(second));
                let mut attempts = 0;
                assert!(!pending
                    .advance_pixels_with_clock(Some(&rgba), 16, |_, _| {
                        attempts += 1;
                        Err(kind.into())
                    }, || now.get())
                    .unwrap());
                assert_eq!(attempts, 1);
                assert_eq!((pending.left, pending.top), cursor);
            }
            // No completed tile in five seconds: no syscall at the deadline.
            now.set(start + Duration::from_secs(5));
            assert_eq!(pending
                .advance_pixels_with_clock(Some(&rgba), 16, |_, _| panic!("expired cursor submitted"), || now.get())
                .unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert!(pending
                .advance_pixels_with_clock(Some(&rgba), 1, |_, _| panic!("timed-out cursor revived"), || now.get())
                .is_err());
        }
    }

    #[test]
    fn permanent_failure_is_terminal_despite_later_clock_or_progress_opportunity() {
        let start = Instant::now();
        let now = Cell::new(start);
        let mut pending = PendingPresentation::new(info(), false).unwrap();
        pending.deadline = start + Duration::from_secs(5);
        let rgba = pixels();
        assert!(!pending
            .advance_pixels_with_clock(Some(&rgba), 1, |_, _| Ok(0), || now.get())
            .unwrap());
        assert_eq!(pending
            .advance_pixels_with_clock(Some(&rgba), 1, |_, _| Err(io::Error::from_raw_os_error(19)), || now.get())
            .unwrap_err().raw_os_error(), Some(19));
        now.set(start + Duration::from_secs(30));
        assert!(pending
            .advance_pixels_with_clock(Some(&rgba), 16, |_, _| panic!("failed cursor revived"), || now.get())
            .is_err());
    }

    #[test]
    fn busy_yields_after_one_attempt_and_retains_the_exact_tile() {
        let mut pending = PendingPresentation::new(info(), false).unwrap();
        let rgba = pixels();
        let mut attempts = 0;
        let mut blocked = Vec::new();
        assert!(
            !pending
                .advance_with(&rgba, 16, |rect, bytes| {
                    attempts += 1;
                    assert_eq!((rect.x, rect.y), (0, 0));
                    blocked = bytes.to_vec();
                    Err(io::ErrorKind::WouldBlock.into())
                })
                .unwrap()
        );
        assert_eq!(attempts, 1);
        assert_eq!((pending.left, pending.top), (0, 0));
        assert!(
            !pending
                .advance_with(&rgba, 1, |rect, bytes| {
                    assert_eq!((rect.x, rect.y), (0, 0));
                    assert_eq!(bytes, blocked);
                    Ok(0)
                })
                .unwrap()
        );
        assert_eq!((pending.left, pending.top), (0, 1));
    }

    #[test]
    fn bounded_ticks_submit_every_pixel_once_with_global_flip() {
        for flipped in [false, true] {
            let mut pending = PendingPresentation::new(info(), flipped).unwrap();
            let rgba = pixels();
            let mut screen = vec![255; rgba.len()];
            let mut visits = [0; 18];
            let mut done = false;
            let mut ticks = 0;
            while !done {
                let mut calls = 0;
                done = pending
                    .advance_with(&rgba, 1, |rect, bytes| {
                        calls += 1;
                        for y in 0..rect.height {
                            for x in 0..rect.width {
                                let dst = ((rect.y + y) * 6 + rect.x + x) as usize;
                                let src = ((y * rect.width + x) * 4) as usize;
                                screen[dst * 4..dst * 4 + 4].copy_from_slice(&bytes[src..src + 4]);
                                visits[dst] += 1;
                            }
                        }
                        Ok(0)
                    })
                    .unwrap();
                assert_eq!(calls, 1);
                ticks += 1;
                assert!(ticks <= 5);
                if ticks < 5 {
                    assert!(!done);
                }
            }
            assert_eq!(ticks, 5);
            assert!(visits.iter().all(|v| *v == 1));
            for y in 0..3 {
                for x in 0..6 {
                    let n = (if flipped { 2 - y } else { y }) * 6 + x;
                    let dst = (y * 6 + x) * 4;
                    assert_eq!(
                        &screen[dst..dst + 4],
                        &[n as u8 + 40, n as u8 + 20, n as u8, 0]
                    );
                }
            }
            assert!(
                pending
                    .advance_with(&rgba, 1, |_, _| panic!("already complete"))
                    .unwrap()
            );
        }
    }

    #[test]
    fn interruption_or_error_cannot_commit_an_incomplete_frame() {
        let rgba = pixels();
        let mut pending = PendingPresentation::new(info(), false).unwrap();
        assert!(
            !pending
                .advance_with(&rgba, 2, |_, _| Err(io::ErrorKind::Interrupted.into()))
                .unwrap()
        );
        assert_eq!((pending.left, pending.top), (0, 0));
        assert!(!pending.advance_with(&rgba, 1, |_, _| Ok(0)).unwrap());
        assert!(
            pending
                .advance_with(&rgba, 2, |_, _| Err(io::Error::from_raw_os_error(19)))
                .is_err()
        );
        assert!(
            pending
                .advance_with(&rgba, 2, |_, _| panic!("failed cursor reused"))
                .is_err()
        );
        let mut invalid_result = PendingPresentation::new(info(), false).unwrap();
        assert!(invalid_result.advance_with(&rgba, 1, |_, _| Ok(1)).is_err());
    }

    #[test]
    fn malformed_mapping_and_expiry_submit_nothing() {
        let rgba = pixels();
        let mut pending = PendingPresentation::new(info(), false).unwrap();
        assert!(
            pending
                .advance_with(&rgba[..71], 1, |_, _| panic!("invalid frame"))
                .is_err()
        );
        let mut expired = PendingPresentation::new(info(), false).unwrap();
        expired.deadline = Instant::now();
        assert_eq!(
            expired
                .advance_with(&rgba, 1, |_, _| panic!("expired frame"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
