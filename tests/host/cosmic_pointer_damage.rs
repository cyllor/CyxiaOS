// Runs inside the actual native presentation module. Only submit is injected.
#[cfg(test)]
mod damage_contract {
    use super::*;

    fn info() -> DisplayInfo {
        DisplayInfo { width: 1024, height: 768, stride_bytes: 4096,
                      format: 1, max_rect_bytes: 65536, abi: 1 }
    }

    fn pending(flipped: bool, damage: &[(i32, i32, i32, i32)]) -> io::Result<PendingPresentation> {
        #[cfg(cyxia_damage_baseline)]
        {
            // Matches the old actual render_output: damage.is_some() was its
            // only damage check; the selected cursor always covered the screen.
            let _ = damage;
            PendingPresentation::new(info(), flipped)
        }
        #[cfg(not(cyxia_damage_baseline))]
        { PendingPresentation::for_damage(info(), flipped, damage.iter().copied()) }
    }

    fn pixels() -> Vec<u8> {
        (0..1024 * 768usize).flat_map(|i| [i as u8, (i >> 8) as u8, 97, 255]).collect()
    }

    fn collect(flipped: bool, damage: &[(i32, i32, i32, i32)])
        -> (usize, Vec<(u32, u32, u32, u32)>, Vec<u8>, Vec<u8>)
    {
        let mut cursor = pending(flipped, damage).unwrap();
        let rgba = pixels();
        let mut screen = vec![255; rgba.len()];
        let mut visits = vec![0; rgba.len() / 4];
        let mut rectangles = Vec::new();
        let mut done = false;
        while !done {
            let before = rectangles.len();
            done = cursor.advance_with(&rgba, 16, |rect, bytes| {
                assert!(rect.width > 0 && rect.height > 0);
                assert!(rect.x + rect.width <= 1024 && rect.y + rect.height <= 768);
                assert_eq!(bytes.len(), (rect.width * rect.height * 4) as usize);
                assert!(bytes.len() <= 65536);
                rectangles.push((rect.x, rect.y, rect.width, rect.height));
                for row in 0..rect.height {
                    for col in 0..rect.width {
                        let dst = ((rect.y + row) * 1024 + rect.x + col) as usize;
                        let src = ((row * rect.width + col) * 4) as usize;
                        visits[dst] += 1;
                        screen[dst * 4..dst * 4 + 4].copy_from_slice(&bytes[src..src + 4]);
                    }
                }
                Ok(0)
            }).unwrap();
            assert!(rectangles.len() - before <= 16);
            assert!(rectangles.len() <= 1024 * 768);
        }
        (rectangles.len(), rectangles, screen, visits)
    }

    #[test]
    fn small_cursor_motion_submits_one_damage_tile() {
        let (count, rects, _, _) = collect(true, &[(639, 511, 20, 30), (647, 511, 20, 30)]);
        println!("NATIVE_POINTER_DAMAGE submissions={count} expected=1");
        assert_eq!(count, 1, "small pointer motion still waits for full-screen tile submission");
        assert_eq!(rects, [(639, 511, 28, 30)]);
    }

    #[test]
    fn horizontal_vertical_and_diagonal_motion_have_bounded_work() {
        for (damage, expected) in [
            (vec![(255, 191, 20, 30), (639, 191, 20, 30)], 1),
            (vec![(639, 191, 20, 30), (639, 511, 20, 30)], 1),
            (vec![(0, 0, 20, 30), (255, 191, 20, 30)], 4),
        ] {
            assert_eq!(collect(false, &damage).0, expected);
        }
    }

    #[test]
    fn damage_pixels_match_full_frame_at_global_coordinates_in_both_orientations() {
        for flipped in [false, true] {
            let (_, _, screen, visits) = collect(flipped, &[(20, 30, 10, 9), (9, 60, 6, 20)]);
            let rgba = pixels();
            for (index, (actual, &count)) in screen.chunks_exact(4).zip(&visits).enumerate() {
                let x = index % 1024;
                let y = index / 1024;
                let inside = (9..30).contains(&x) && (30..80).contains(&y);
                assert_eq!(count, u8::from(inside));
                if inside {
                    let source_y = if flipped { 767 - y } else { y };
                    let at = (source_y * 1024 + x) * 4;
                    assert_eq!(actual, [rgba[at + 2], rgba[at + 1], rgba[at], 0]);
                } else {
                    assert_eq!(actual, [255; 4], "unchanged pixel was submitted");
                }
            }
        }
    }

    #[test]
    fn clipped_damage_uses_wide_arithmetic_and_empty_damage_falls_back_to_full_frame() {
        assert_eq!(collect(false, &[(-5, -3, 10, 9)]).1, [(0, 0, 5, 6)]);
        assert_eq!(collect(false, &[(1020, 765, i32::MAX, i32::MAX)]).1,
                   [(1020, 765, 4, 3)]);
        assert!(pending(false, &[(0, 0, -1, 4)]).is_err());
        for damage in [vec![], vec![(i32::MIN, 0, 1, 1)], vec![(4, 5, 0, 0)]] {
            let (count, _, _, visits) = collect(false, &damage);
            assert_eq!(count, 48);
            assert!(visits.iter().all(|n| *n == 1));
        }
    }

    #[test]
    fn region_retries_keep_bytes_and_coordinates_until_actual_completion() {
        let mut cursor = pending(true, &[(639, 511, 20, 30)]).unwrap();
        let rgba = pixels();
        let mut saved = Vec::new();
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::Interrupted] {
            assert!(!cursor.advance_with(&rgba, 16, |rect, bytes| {
                assert_eq!((rect.x, rect.y, rect.width, rect.height), (639, 511, 20, 30));
                if saved.is_empty() { saved = bytes.to_vec(); }
                assert_eq!(bytes, saved);
                Err(kind.into())
            }).unwrap());
        }
        assert!(cursor.advance_with(&rgba, 1, |_, bytes| {
            assert_eq!(bytes, saved);
            Ok(0)
        }).unwrap());
    }
}
