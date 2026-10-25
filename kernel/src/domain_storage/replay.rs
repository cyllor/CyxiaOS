//! Actual journal-backed replay working set. Reset writes and reads the same
//! bytes through ordinary filesystem calls, then drops only its clean pages.
use super::*;
use core::cell::UnsafeCell;
use sha2::{Digest, Sha256};

const PATH: &str = "/native-replay-data";
const BYTES: usize = 32768;
const CHUNKS: usize = 16;
pub const FILE_BYTES: u64 = (BYTES * CHUNKS) as u64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    Open,
    Write,
    Sync,
    Readback,
    Cold,
    Ready,
    Work,
    Drain,
    AbortOpen,
    Closed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    pub object: ObjectKey,
    pub digest: [u8; 32],
    pub bytes: u64,
}
#[derive(Clone, Copy)]
struct Work {
    id: u64,
    chunk: usize,
    write: bool,
    phase: u8,
}
struct State {
    phase: Phase,
    seed: u64,
    handle: Option<Handle>,
    object: Option<ObjectKey>,
    cursor: usize,
    hash: Option<Sha256>,
    image: Option<Image>,
    versions: [u64; CHUNKS],
    readback: Option<usize>,
    work: Option<Work>,
    completed: Option<(u64, Result<u64, Error>)>,
    buffer: [u8; BYTES],
    error: Option<Error>,
    aborting: bool,
}
struct Cell(UnsafeCell<State>);
unsafe impl Sync for Cell {}
static STATE: Cell = Cell(UnsafeCell::new(State {
    phase: Phase::Idle,
    seed: 0,
    handle: None,
    object: None,
    cursor: 0,
    hash: None,
    image: None,
    versions: [0; CHUNKS],
    readback: None,
    work: None,
    completed: None,
    buffer: [0; BYTES],
    error: None,
    aborting: false,
}));
static GATE: AtomicBool = AtomicBool::new(false);
struct Gate;
impl Drop for Gate {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _g = Gate;
    f(unsafe { &mut *STATE.0.get() })
}
fn word(seed: u64, chunk: usize, version: u64, at: usize) -> u64 {
    seed.rotate_left(17)
        ^ (chunk as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ version.rotate_left(31)
        ^ (at as u64).wrapping_mul(0x1000_0000_01b3)
}
fn fill(s: &mut State, chunk: usize, version: u64) {
    for (i, b) in s.buffer.chunks_exact_mut(8).enumerate() {
        b.copy_from_slice(&word(s.seed, chunk, version, i).to_le_bytes());
    }
}
fn verify(s: &State, chunk: usize, version: u64) -> Result<(), Error> {
    if s.buffer
        .chunks_exact(8)
        .enumerate()
        .any(|(i, b)| b != word(s.seed, chunk, version, i).to_le_bytes())
    {
        Err(Error::Io)
    } else {
        Ok(())
    }
}
pub fn prepare(seed: u64) -> Result<Option<Image>, Error> {
    owner()?;
    with(|s| {
        if s.aborting {
            return Err(Error::Busy);
        }
        if matches!(s.phase, Phase::Idle | Phase::Closed) {
            if s.handle.is_some() || s.work.is_some() || s.completed.is_some() {
                return Err(Error::Busy);
            }
            s.phase = Phase::Open;
            s.seed = seed;
            s.cursor = 0;
            s.hash = None;
            s.image = None;
            s.versions.fill(0);
            s.error = None;
            s.readback = None;
        }
        if s.seed != seed {
            return Err(Error::Conflict);
        }
        if let Some(e) = s.error {
            return Err(e);
        }
        Ok((s.phase == Phase::Ready).then_some(s.image).flatten())
    })
}
pub fn submit(id: u64, write: bool) -> Result<(), Error> {
    owner()?;
    with(|s| {
        if let Some(e) = s.error {
            return Err(e);
        }
        if s.work.is_some_and(|w| w.id == id) || s.completed.is_some_and(|(old, _)| old == id) {
            return Ok(());
        }
        if s.phase != Phase::Ready || s.work.is_some() || s.completed.is_some() || id == 0 {
            return Err(Error::Busy);
        }
        s.work = Some(Work {
            id,
            chunk: (id as usize - 1) % CHUNKS,
            write,
            phase: 0,
        });
        s.phase = Phase::Work;
        Ok(())
    })
}
pub fn take(id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    owner()?;
    with(|s| match s.completed {
        Some((old, outcome)) if old == id => {
            s.completed = None;
            Ok(Some(outcome))
        }
        Some(_) => Err(Error::Conflict),
        None => Ok(None),
    })
}
pub fn drain() -> Result<bool, Error> {
    owner()?;
    with(|s| {
        if s.work.is_some() || s.completed.is_some() {
            return Ok(false);
        }
        if s.phase == Phase::Ready {
            s.phase = Phase::Drain;
            s.cursor = 0;
        }
        if let Some(e) = s.error {
            return Err(e);
        }
        Ok(s.phase == Phase::Closed && s.handle.is_none())
    })
}
/// A failed reset still owns its real file/dirty data. Stop further reset work
/// and use ordinary fsync/close to settle it; an I/O error is retained while
/// those operations retry, never converted to a successful reset image.
pub fn abort_prepared() -> Result<bool, Error> {
    owner()?;
    with(|s| {
        if s.work.is_some() || s.completed.is_some() {
            return Err(Error::Busy);
        }
        if !s.aborting {
            s.aborting = true;
            s.cursor = 0;
            if !matches!(s.phase, Phase::Idle | Phase::Closed) {
                s.phase = if s.handle.is_some() {
                    Phase::Drain
                } else {
                    Phase::AbortOpen
                };
            }
        }
        Ok(matches!(s.phase, Phase::Idle | Phase::Closed) && s.handle.is_none())
    })
}
pub fn release_prepared() -> Result<(), Error> {
    owner()?;
    with(|s| {
        if !s.aborting
            || !matches!(s.phase, Phase::Idle | Phase::Closed)
            || s.handle.is_some()
            || s.work.is_some()
            || s.completed.is_some()
        {
            return Err(Error::Busy);
        }
        s.phase = Phase::Idle;
        s.aborting = false;
        s.error = None;
        s.hash = None;
        s.image = None;
        s.readback = None;
        Ok(())
    })
}
pub fn needs_io() -> bool {
    with(|s| {
        Ok(
            !matches!(s.phase, Phase::Idle | Phase::Ready | Phase::Closed)
                && (s.error.is_none() || s.aborting),
        )
    })
    .unwrap_or(false)
}
/// Exactly one owner piece. The caller supplies the same suspend/reacquire
/// progress convention as the ordinary file syscall pump.
pub fn step(progress: &mut dyn FnMut()) -> Result<bool, Error> {
    owner()?;
    with(|s| {
        if let Some(e) = s.error.filter(|_| !s.aborting) {
            return Err(e);
        }
        let result = (|| {
            match s.phase {
                Phase::Idle | Phase::Ready | Phase::Closed => return Ok(false),
                Phase::Open => {
                    let object = match super::stat(PATH, progress) {
                        // A previous excluded reset may have durably closed a
                        // real prefix. Overwrite the whole bounded image and
                        // verify it before claiming a new complete reset.
                        Ok(stat) if stat.size <= FILE_BYTES => stat.object,
                        Ok(_) => return Err(Error::Conflict),
                        Err(Error::NotFound) => super::create(PATH, progress)?,
                        Err(e) => return Err(e),
                    };
                    s.object = Some(object);
                    s.handle = Some(super::open(PATH, OpenMode::ReadWrite, progress)?);
                    s.cursor = 0;
                    s.phase = Phase::Write;
                }
                Phase::Write => {
                    fill(s, s.cursor, 0);
                    if super::write(
                        s.handle.ok_or(Error::Stale)?,
                        (s.cursor * BYTES) as u64,
                        &s.buffer,
                        progress,
                    )? != BYTES
                    {
                        return Err(Error::Io);
                    }
                    s.cursor += 1;
                    if s.cursor == CHUNKS {
                        s.phase = Phase::Sync;
                    }
                }
                Phase::Sync => {
                    let receipt = super::fsync(s.handle.ok_or(Error::Stale)?, progress)?;
                    let stat = super::stat(PATH, progress)?;
                    if stat.object != s.object.ok_or(Error::Stale)?
                        || stat.size != FILE_BYTES
                        || stat.write_seq != stat.durable_write_seq
                        || receipt.write_seq != stat.write_seq
                    {
                        return Err(Error::Io);
                    }
                    let mut h = Sha256::new();
                    h.update(b"CYXIA_RESTORED_FILE_IMAGE_1.3\0");
                    h.update(stat.object.id.to_le_bytes());
                    h.update(stat.object.generation.to_le_bytes());
                    h.update(stat.size.to_le_bytes());
                    h.update(s.seed.to_le_bytes());
                    s.hash = Some(h);
                    s.cursor = 0;
                    s.phase = Phase::Readback;
                }
                Phase::Readback => {
                    if let Some(first) = s.readback {
                        let end = (first + 4096).min(BYTES);
                        for (i, bytes) in s.buffer[first..end].chunks_exact(8).enumerate() {
                            if bytes != word(s.seed, s.cursor, 0, first / 8 + i).to_le_bytes() {
                                return Err(Error::Io);
                            }
                        }
                        s.hash
                            .as_mut()
                            .ok_or(Error::Conflict)?
                            .update(&s.buffer[first..end]);
                        if end == BYTES {
                            s.readback = None;
                            s.cursor += 1;
                            if s.cursor == CHUNKS {
                                s.cursor = 0;
                                s.phase = Phase::Cold;
                            }
                        } else {
                            s.readback = Some(end);
                        }
                    } else {
                        if super::read(
                            s.handle.ok_or(Error::Stale)?,
                            (s.cursor * BYTES) as u64,
                            &mut s.buffer,
                            progress,
                        )? != BYTES
                        {
                            return Err(Error::Io);
                        }
                        s.readback = Some(0);
                    }
                }
                Phase::Cold => {
                    let object = s.object.ok_or(Error::Stale)?;
                    s.cursor = with_files(|f| f.discard_clean_object_cache(object, s.cursor, 64))?;
                    if s.cursor == 4096 {
                        let mut h = s.hash.take().ok_or(Error::Conflict)?;
                        h.update(b"object-cache-empty;durable;no-owned-io\0");
                        s.image = Some(Image {
                            object,
                            digest: h.finalize().into(),
                            bytes: FILE_BYTES,
                        });
                        s.phase = Phase::Ready;
                    }
                }
                Phase::Work => {
                    let mut w = s.work.ok_or(Error::Conflict)?;
                    let handle = s.handle.ok_or(Error::Stale)?;
                    if w.write && w.phase == 0 {
                        fill(s, w.chunk, w.id);
                        if super::write(handle, (w.chunk * BYTES) as u64, &s.buffer, progress)?
                            != BYTES
                        {
                            return Err(Error::Io);
                        }
                        s.versions[w.chunk] = w.id;
                        w.phase = 1;
                        s.work = Some(w);
                    } else {
                        if super::read(handle, (w.chunk * BYTES) as u64, &mut s.buffer, progress)?
                            != BYTES
                        {
                            return Err(Error::Io);
                        }
                        verify(s, w.chunk, s.versions[w.chunk])?;
                        s.completed = Some((w.id, Ok(Board.now_ns())));
                        s.work = None;
                        s.phase = Phase::Ready;
                    }
                }
                Phase::Drain => {
                    let handle = s.handle.ok_or(Error::Stale)?;
                    if s.cursor == 0 {
                        super::fsync(handle, progress)?;
                        s.cursor = 1;
                    } else {
                        super::close(handle)?;
                        s.handle = None;
                        s.phase = Phase::Closed;
                    }
                }
                Phase::AbortOpen => match super::stat(PATH, progress) {
                    Err(Error::NotFound) => {
                        s.phase = Phase::Closed;
                    }
                    Err(error) => return Err(error),
                    Ok(stat) => {
                        s.object = Some(stat.object);
                        s.handle = Some(super::open(PATH, OpenMode::ReadWrite, progress)?);
                        s.cursor = 0;
                        s.phase = Phase::Drain;
                    }
                },
            }
            Ok(true)
        })();
        if let Err(e) = result {
            if !matches!(
                e,
                Error::Busy | Error::Again | Error::NotReady | Error::Budget
            ) {
                if let Some(w) = s.work.take() {
                    s.completed = Some((w.id, Err(e)));
                }
                s.error.get_or_insert(e);
            }
        }
        result
    })
}
