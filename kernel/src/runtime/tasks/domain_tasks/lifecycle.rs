//! Bounded lifecycle selection under the actual task gate. Deadline work is
//! ready even when the task cannot become runnable or produce another return.
//! A file operation still in custody must finish before timeout cleanup.
#[derive(Clone, Copy)]
pub(super) struct View {
    pub occupied: bool,
    pub exiting: bool,
    pub deadline_ns: u64,
    pub return_pending: bool,
    pub file_done: bool,
    pub file_busy: bool,
}

/// Select one ready item from the rotating cursor, falling back to that cursor
/// when all work is idle. The caller advances past the returned index even if
/// cleanup must retry, so no perpetually busy item owns the next turn.
pub(super) fn select<const N: usize>(
    cursor: usize,
    now_ns: u64,
    mut view: impl FnMut(usize) -> View,
) -> usize {
    assert!(N != 0 && cursor < N);
    (0..N)
        .map(|offset| (cursor + offset) % N)
        .find(|&i| {
            let task = view(i);
            task.return_pending
                || task.file_done
                || task.exiting
                || task.occupied && !task.file_busy && now_ns >= task.deadline_ns
        })
        .unwrap_or(cursor)
}
