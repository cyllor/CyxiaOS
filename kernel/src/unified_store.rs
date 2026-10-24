//! CPU0 journal broker for append-only immutable protocol records. Partial SVC
//! chunks never mutate disk. Only a complete bounded record reaches commit.
use cyxia_prototype::cluster::{
    MAX_EFFECT,
    volume::{Cursor, Volume, VolumeScratch},
};
static mut WORK: VolumeScratch = [[0; 4096]; 16];
static mut VOLUME: Option<Volume> = None;
static mut STAGE: [u8; MAX_EFFECT] = [0; MAX_EFFECT];
static mut READ: [u8; MAX_EFFECT] = [0; MAX_EFFECT];
static mut STAGED: (u64, usize, usize) = (0, 0, 0);
static mut CACHED: (u64, usize) = (0, 0);
static mut FAILED: bool = false;
pub fn init() {
    crate::prototype_storage::with_journal(|j, d, s| unsafe {
        *core::ptr::addr_of_mut!(VOLUME) = Some(
            Volume::open(j, d, s, &mut *core::ptr::addr_of_mut!(WORK))
                .expect("reserved cluster volume"),
        );
    });
}
pub fn request(
    write: bool,
    key: u64,
    total: u64,
    phase: u64,
    offset: u64,
    payload: &mut [u8; 4096],
    len: usize,
    progress: &mut dyn FnMut(),
) -> (u64, usize, u64) {
    assert_eq!(cyxia_arch_aarch64::cpu::slot(), 0);
    unsafe {
        if *core::ptr::addr_of!(FAILED) || (!write && key == 0) {
            return (3, 0, 0);
        }
        if write {
            if total == 0
                || total > MAX_EFFECT as u64
                || phase > 1
                || offset.checked_add(len as u64).is_none_or(|end| end > total)
            {
                return (3, 0, 0);
            }
            let stage = &mut *core::ptr::addr_of_mut!(STAGED);
            if offset == 0 {
                *stage = (key, total as usize, 0);
            }
            if *stage != (key, total as usize, offset as usize) {
                return (3, 0, 0);
            }
            core::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                core::ptr::addr_of_mut!(STAGE)
                    .cast::<u8>()
                    .add(offset as usize),
                len,
            );
            stage.2 += len;
            if phase == 0 {
                return (0, 0, key);
            }
            if stage.2 != stage.1 {
                return (3, 0, 0);
            }
            let body = &(&*core::ptr::addr_of!(STAGE))[..stage.1];
            // Only known recovery/closing event kinds may consume the closing reserve.
            if key == 0
                && (body.len() != 85
                    || &body[..5] != b"CXID1"
                    || (&*core::ptr::addr_of!(VOLUME)).as_ref().unwrap().used() != 0)
            {
                return (3, 0, 0);
            }
            let closing = body.len() >= 13
                && &body[..4] == b"CXE1"
                && (matches!(body[12], 5..=9 | 12 | 13)
                    || (matches!(body[12], 4 | 10) && body.last() == Some(&5)));
            let result = crate::prototype_storage::with_progress(progress, |j, d, s| {
                (&mut *core::ptr::addr_of_mut!(VOLUME))
                    .as_mut()
                    .unwrap()
                    .append(j, d, s, &mut *core::ptr::addr_of_mut!(WORK), body, closing)
            });
            (*core::ptr::addr_of_mut!(STAGE)).fill(0);
            *stage = (0, 0, 0);
            if matches!(
                result,
                Err(cyxia_prototype::cluster::volume::Error::Capacity)
            ) {
                return (5, 0, 0);
            }
            if result.is_err() {
                *core::ptr::addr_of_mut!(FAILED) = true;
                return (3, 0, 0);
            }
            (0, 0, key)
        } else {
            let cache = &mut *core::ptr::addr_of_mut!(CACHED);
            if cache.0 != key {
                // The search mutates READ even when the requested ordinal is absent.
                *cache = (0, 0);
                let found = crate::prototype_storage::with_progress(progress, |j, d, s| {
                    let volume = (&*core::ptr::addr_of!(VOLUME)).as_ref().unwrap();
                    let mut cursor = Cursor::new();
                    let mut found = None;
                    for _ in 0..key {
                        match volume.next(
                            j,
                            d,
                            s,
                            &mut *core::ptr::addr_of_mut!(WORK),
                            &mut cursor,
                            &mut *core::ptr::addr_of_mut!(READ),
                        ) {
                            Ok(Some(n)) => found = Some(n),
                            Ok(None) => return Ok(None),
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(found)
                });
                match found {
                    Ok(Some(n)) => *cache = (key, n),
                    Ok(None) => return (4, 0, 0),
                    Err(_) => {
                        *core::ptr::addr_of_mut!(FAILED) = true;
                        return (3, 0, 0);
                    }
                }
            }
            if offset > cache.1 as u64 {
                return (3, 0, 0);
            }
            let n = len.min(cache.1 - offset as usize);
            payload[..n].copy_from_slice(
                &(&*core::ptr::addr_of!(READ))[offset as usize..offset as usize + n],
            );
            (0, n, cache.1 as u64)
        }
    }
}
