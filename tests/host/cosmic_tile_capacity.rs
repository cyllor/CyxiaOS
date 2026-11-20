// Runs inside the real native presentation module; submit is the ABI boundary.
#[cfg(test)]
mod capacity_contract {
    use super::*;

    fn info(height: u32, capacity: u32) -> DisplayInfo {
        DisplayInfo { width: 1024, height, stride_bytes: 4096,
                      format: 1, max_rect_bytes: capacity, abi: 1 }
    }

    fn exercise(height: u32, capacity: u32, flipped: bool, black: bool) -> usize {
        let info = info(height, capacity);
        let pixels = (info.width * info.height) as usize;
        let rgba: Vec<u8> = (0..pixels).flat_map(|i| [i as u8, (i >> 8) as u8, 97, 255]).collect();
        let mut screen = vec![255u8; pixels * 4];
        let mut visits = vec![0u8; pixels];
        let mut cursor = PendingPresentation::new(info, flipped).unwrap();
        let mut submissions = 0;
        let mut done = false;
        while !done {
            let mut per_turn = 0;
            done = cursor.advance_pixels((!black).then_some(rgba.as_slice()), 16, |rect, bytes| {
                per_turn += 1;
                submissions += 1;
                assert!(rect.x + rect.width <= info.width && rect.y + rect.height <= info.height);
                assert_eq!(bytes.len(), (rect.width * rect.height * 4) as usize);
                assert!(bytes.len() <= capacity as usize);
                for row in 0..rect.height {
                    for col in 0..rect.width {
                        let dst = ((rect.y + row) * info.width + rect.x + col) as usize;
                        let src = ((row * rect.width + col) * 4) as usize;
                        visits[dst] += 1;
                        screen[dst * 4..dst * 4 + 4].copy_from_slice(&bytes[src..src + 4]);
                    }
                }
                Ok(0)
            }).unwrap();
            assert!(per_turn <= 16);
            assert!(submissions <= pixels);
        }
        assert!(visits.iter().all(|&n| n == 1));
        for (pixel, actual) in screen.chunks_exact(4).enumerate() {
            let source = if flipped {
                ((info.height as usize - 1 - pixel / 1024) * 1024) + pixel % 1024
            } else { pixel };
            let expected = if black { [0, 0, 0, 0] }
                else { [97, (source >> 8) as u8, source as u8, 0] };
            assert_eq!(actual, expected);
        }
        submissions
    }

    #[test]
    fn one_advertised_tile_needs_one_completed_submission() {
        let calls = exercise(16, 65536, false, false);
        println!("NATIVE_TILE_CAPACITY minimal_calls={calls} expected=1");
        assert_eq!(calls, 1, "valid 64 KiB ABI tile was split below the advertised limit");
    }

    #[test]
    fn real_scanout_needs_48_completed_submissions() {
        let calls = exercise(768, 65536, true, false);
        println!("NATIVE_TILE_CAPACITY frame_calls={calls} expected=48");
        assert_eq!(calls, 48);
    }

    #[test]
    fn lock_blank_retains_full_coverage_at_advertised_capacity() {
        assert_eq!(exercise(768, 65536, false, true), 48);
    }

    #[test]
    fn smaller_limits_and_partial_tail_preserve_pixel_coverage() {
        for limit in [4096, 16384, 65536] {
            for flipped in [false, true] {
                let calls = exercise(19, limit, flipped, false);
                assert_eq!(calls, (19 * 4096usize).div_ceil(limit as usize));
            }
        }
    }

    #[test]
    fn large_tile_retries_retain_bytes_and_only_completion_advances() {
        let rgba = vec![71u8; 1024 * 16 * 4];
        let mut cursor = PendingPresentation::new(info(16, 65536), false).unwrap();
        let mut saved = Vec::new();
        assert!(!cursor.advance_with(&rgba, 16, |_, bytes| {
            saved = bytes.to_vec();
            Err(io::ErrorKind::WouldBlock.into())
        }).unwrap());
        assert_eq!(saved.len(), 65536);
        assert!(!cursor.advance_with(&rgba, 16, |_, bytes| {
            assert_eq!(bytes, saved);
            Err(io::ErrorKind::Interrupted.into())
        }).unwrap());
        assert!(cursor.advance_with(&rgba, 1, |_, bytes| {
            assert_eq!(bytes, saved);
            Ok(0)
        }).unwrap());
    }

    #[test]
    fn large_tile_error_cannot_report_or_resume_completed_frame() {
        let rgba = vec![71u8; 1024 * 32 * 4];
        let mut cursor = PendingPresentation::new(info(32, 65536), false).unwrap();
        let mut calls = 0;
        assert!(cursor.advance_with(&rgba, 16, |_, _| {
            calls += 1;
            if calls == 1 { Ok(0) } else { Err(io::Error::from_raw_os_error(19)) }
        }).is_err());
        assert!(cursor.advance_with(&rgba, 16, |_, _| panic!("failed cursor revived")).is_err());
    }
}
