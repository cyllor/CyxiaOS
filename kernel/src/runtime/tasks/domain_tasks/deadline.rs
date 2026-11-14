pub const ORDINARY_NS: u64 = 60_000_000_000;

pub fn valid(now: u64, deadline: u64, recipe: u16, maximum_ns: u64) -> bool {
    deadline > now && (recipe != 0 || deadline.saturating_sub(now) <= maximum_ns)
}
