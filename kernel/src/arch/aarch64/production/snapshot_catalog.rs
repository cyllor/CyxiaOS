//! CPU0-only read endpoint for the verified empty scratch catalog.
//!
//! Only the stopped PIE caller's synchronous SVC and the CPU0 driver access
//! STATE. The driver releases every borrow before entering EL0. Copy-in and
//! copy-out use the CPU0 temporary TTBR1 window over the pinned role stack.

use super::*;
use core::ptr::{addr_of, addr_of_mut};
use cyxia_kernel_core::security::{
    file_media_unified_v1::{SNAP_MAX_REPLY_BYTES, SNAP_MAX_REQUEST_BYTES},
    file_service_v4::{REPLY_HEADER, REQUEST_HEADER},
    snapshot_list_v4::{EmptyCatalog, LIST_ENDPOINT, LIST_SELECTOR, ListError, ListRequest},
};
#[cfg(feature = "v020-production-snapshot-read")]
use cyxia_kernel_core::security::{
    file_media_unified_v1::{SNAP_OP_HISTORY_OPEN, SNAP_OP_QUERY},
    snapshot_read_v4::{EmptySnapshotView, HISTORY_SELECTOR, ReadRequest, history_prefix_digest},
};

#[cfg(feature = "v020-production-snapshot-read")]
pub(super) type MountedCatalog = EmptySnapshotView;
#[cfg(not(feature = "v020-production-snapshot-read"))]
pub(super) type MountedCatalog = EmptyCatalog;

const ESTALE: i64 = -4;
const FATAL_CATALOG: u64 = 0x5732_1650;
const SERVICE_GENERATION: u64 = 3;
const WRONG_ROLE: u8 = 1 << 0;
const WRONG_SELECTOR: u8 = 1 << 1;
const FORMAT: u8 = 1 << 2;
const SCHEMA: u8 = 1 << 3;
const UNSUPPORTED: u8 = 1 << 4;
const OVERLAP: u8 = 1 << 5;
const INVALID_LENGTH: u8 = 1 << 6;
const REQUIRED_REJECTIONS: u8 =
    WRONG_ROLE | WRONG_SELECTOR | FORMAT | SCHEMA | UNSUPPORTED | OVERLAP | INVALID_LENGTH;
#[cfg(feature = "v020-production-snapshot-read")]
const HISTORY_PREFIX: &[u8] = b"/readme.txt";

struct ListGrant {
    holder: NativeRole,
    pie_cap: u64,
    service_generation: u64,
    catalog: Option<EmptyCatalog>,
    #[cfg(feature = "v020-production-snapshot-read")]
    view: EmptySnapshotView,
    #[cfg(feature = "v020-production-snapshot-read")]
    history_prefix_digest: [u8; 32],
}

#[derive(Clone, Copy)]
struct Checks {
    unready: bool,
    rejected: u8,
    read_count: usize,
    read_ids: [u64; 2],
    stale: bool,
}

#[cfg(feature = "v020-production-snapshot-read")]
#[derive(Clone, Copy)]
struct ReadChecks {
    query_missing: bool,
    history_missing: bool,
    denials: u8,
    stale: bool,
}

#[cfg(feature = "v020-production-snapshot-read")]
impl ReadChecks {
    fn active_checks_complete(self) -> bool {
        self.query_missing && self.history_missing && self.denials == 0b1_1111
    }
}

struct State {
    grant: Option<ListGrant>,
    checks: Checks,
    #[cfg(feature = "v020-production-snapshot-read")]
    read_checks: ReadChecks,
}

impl State {
    fn mounted(&self) -> bool {
        self.grant.as_ref().is_some_and(|g| g.catalog.is_some())
    }
}

static mut STATE: State = State {
    grant: None,
    checks: Checks {
        unready: false,
        rejected: 0,
        read_count: 0,
        read_ids: [0; 2],
        stale: false,
    },
    #[cfg(feature = "v020-production-snapshot-read")]
    read_checks: ReadChecks {
        query_missing: false,
        history_missing: false,
        denials: 0,
        stale: false,
    },
};

pub(super) const fn protected_bytes() -> usize {
    size_of::<State>()
}

fn caller_cap(index: usize, member: NativeRole, endpoint: u64) -> Result<u64, i64> {
    if endpoint != LIST_ENDPOINT {
        return Err(E_AUTH);
    }
    trapped_pie_cap(index, member)
}

fn check_grant(state: &mut State, member: NativeRole, cap: u64, selector: u64) -> Result<(), i64> {
    if member.role != Role::Supervisor {
        if member.role == Role::Operations && selector == LIST_SELECTOR {
            state.checks.rejected |= WRONG_ROLE;
        }
        return Err(E_AUTH);
    }
    if state
        .grant
        .as_ref()
        .is_some_and(|g| g.holder != member || g.pie_cap != cap)
    {
        return Err(E_AUTH);
    }
    if selector == LIST_SELECTOR {
        return Ok(());
    }
    #[cfg(feature = "v020-production-snapshot-read")]
    if selector == HISTORY_SELECTOR {
        return Ok(());
    }
    if state.mounted() {
        state.checks.rejected |= WRONG_SELECTOR;
    }
    Err(E_AUTH)
}

struct Buffers {
    source: copy_window::StackSpan,
    dest: copy_window::StackSpan,
    len: usize,
    overlap: bool,
}

fn checked_buffers(index: usize, member: NativeRole, args: [u64; 6]) -> Result<Buffers, i64> {
    let len = usize::try_from(args[2]).map_err(|_| E_FORMAT)?;
    if !(REQUEST_HEADER..=SNAP_MAX_REQUEST_BYTES).contains(&len) {
        return Err(E_FORMAT);
    }
    let reply_cap = usize::try_from(args[5]).map_err(|_| EFAULT)?;
    if !(REPLY_HEADER..=SNAP_MAX_REPLY_BYTES).contains(&reply_cap) {
        return Err(EFAULT);
    }
    let source = copy_window::StackSpan::verify(index, member, args[1], len, false)?;
    let dest = copy_window::StackSpan::verify(index, member, args[4], reply_cap, true)?;
    // Both half-open ends were checked by stack_span.
    let overlap = args[1] < args[4] + args[5] && args[4] < args[1] + args[2];
    Ok(Buffers {
        source,
        dest,
        len,
        overlap,
    })
}

/// This branch handles failures of the shared ABI's register preflight.
/// It can record an authenticated overlap refusal without touching user bytes.
pub(super) fn reject_preflight(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    let cap = match caller_cap(index, member, args[0]) {
        Ok(cap) => cap,
        Err(error) => return error as u64,
    };
    let state = unsafe { &mut *addr_of_mut!(STATE) };
    if let Err(error) = check_grant(state, member, cap, args[3]) {
        return error as u64;
    }
    match checked_buffers(index, member, args) {
        Ok(buffers) if buffers.overlap && state.mounted() => {
            state.checks.rejected |= OVERLAP;
            EFAULT as u64
        }
        Err(error) => {
            if error == E_FORMAT && state.mounted() {
                state.checks.rejected |= INVALID_LENGTH;
            }
            error as u64
        }
        Ok(_) => EFAULT as u64,
    }
}

pub(super) fn dispatch(index: usize, member: NativeRole, args: [u64; 6]) -> u64 {
    serve(index, member, args).map_or_else(|error| error as u64, |()| 0)
}

fn serve(index: usize, member: NativeRole, args: [u64; 6]) -> Result<(), i64> {
    let cap = caller_cap(index, member, args[0])?;
    let state = unsafe { &mut *addr_of_mut!(STATE) };
    check_grant(state, member, cap, args[3])?;
    let buffers = checked_buffers(index, member, args)?;
    if buffers.overlap {
        return Err(EFAULT);
    }
    let mut wire = [0; SNAP_MAX_REQUEST_BYTES];
    buffers.source.copy_in(&mut wire[..buffers.len])?;
    let wire = &wire[..buffers.len];
    #[cfg(feature = "v020-production-snapshot-read")]
    if matches!(
        u16::from_le_bytes([wire[8], wire[9]]),
        SNAP_OP_QUERY | SNAP_OP_HISTORY_OPEN
    ) {
        return serve_read(state, args[3], wire);
    }
    let request = ListRequest::decode(wire).map_err(|error| {
        if state.mounted() {
            state.checks.rejected |= match error {
                ListError::Format => FORMAT,
                ListError::Schema => SCHEMA,
                ListError::Unsupported => UNSUPPORTED,
            };
        }
        error.errno()
    })?;
    if args[3] != LIST_SELECTOR {
        return Err(E_AUTH);
    }
    if let Some(error) = media_staging::ordinary_file_refusal() {
        return Err(error);
    }

    let Some(grant) = &state.grant else {
        state.checks.unready |= request.request_id == 1;
        return Err(EAGAIN);
    };
    let Some(view) = &grant.catalog else {
        state.checks.stale |= request.request_id == 12;
        return Err(ESTALE);
    };
    let reply = view
        .reply(request, grant.service_generation)
        .map_err(|_| E_FORMAT)?;
    if !buffers.dest.copy_out_and_check(&reply)? {
        fatal(FATAL_CATALOG + 5);
    }
    if let Some(id) = state.checks.read_ids.get_mut(state.checks.read_count) {
        *id = request.request_id;
    }
    state.checks.read_count = state.checks.read_count.saturating_add(1);
    Ok(())
}

#[cfg(feature = "v020-production-snapshot-read")]
fn serve_read(state: &mut State, selector: u64, wire: &[u8]) -> Result<(), i64> {
    let request = ReadRequest::decode(wire).map_err(|error| {
        if error == ListError::Format
            && selector == LIST_SELECTOR
            && state.mounted()
            && wire[8..10] == SNAP_OP_QUERY.to_le_bytes()
            && wire[16..24] == 26u64.to_le_bytes()
        {
            state.read_checks.denials |= 1 << 4;
        }
        error.errno()
    })?;
    if !request.selector_matches(selector) {
        if state.mounted() {
            state.read_checks.denials |= match (request.op, request.request_id, selector) {
                (SNAP_OP_HISTORY_OPEN, 24, LIST_SELECTOR) => 1 << 2,
                (SNAP_OP_QUERY, 25, HISTORY_SELECTOR) => 1 << 3,
                _ => 0,
            };
        }
        return Err(E_AUTH);
    }
    if let Some(error) = media_staging::ordinary_file_refusal() {
        return Err(error);
    }
    let Some(grant) = &state.grant else {
        return Err(EAGAIN);
    };
    if !request.authorized(
        selector,
        &grant.view,
        HISTORY_PREFIX,
        &grant.history_prefix_digest,
    ) {
        if grant.catalog.is_some() {
            state.read_checks.denials |= match (request.op, request.request_id, selector) {
                (SNAP_OP_QUERY, 22, LIST_SELECTOR) => 1 << 0,
                (SNAP_OP_HISTORY_OPEN, 23, HISTORY_SELECTOR) => 1 << 1,
                _ => 0,
            };
        }
        return Err(E_AUTH);
    }
    let same_live_path = request.path() == Some(HISTORY_PREFIX);
    if grant.catalog.is_none() {
        state.read_checks.stale |= same_live_path && request.request_id == 27;
        return Err(ESTALE);
    }
    state.read_checks.query_missing |= request.op == SNAP_OP_QUERY && request.request_id == 20;
    state.read_checks.history_missing |= same_live_path && request.request_id == 21;
    // The attested slot range is empty. No handle is minted and there is no
    // path from this view to the live file service or to the caller's buffers.
    Err(E_AUTH)
}

fn checks() -> Checks {
    unsafe { addr_of!(STATE.checks).read() }
}

#[cfg(feature = "v020-production-snapshot-read")]
fn read_checks() -> ReadChecks {
    unsafe { addr_of!(STATE.read_checks).read() }
}

pub(super) fn drive(
    contexts: &mut [user::Context; ROLE_COUNT],
    manifest: &NativeRoleManifest,
    view: MountedCatalog,
) {
    if cpu::slot() != 0 || manifest.validate().is_err() {
        fatal(FATAL_CATALOG);
    }
    let (initial_read_windows, initial_write_windows, initial_closed) =
        copy_window::closed_counts();
    if !initial_closed {
        fatal(FATAL_CATALOG + 6);
    }
    let ops = ROLES
        .iter()
        .position(|&role| role == Role::Operations)
        .unwrap();
    let supervisor = ROLES
        .iter()
        .position(|&role| role == Role::Supervisor)
        .unwrap();
    let holder = manifest.members[supervisor];
    let Some(pie_cap) = registered_pie_cap(supervisor, holder) else {
        fatal(FATAL_CATALOG);
    };
    let until = deadline();
    wait_for_role_yield(ops, &mut contexts[ops], until, FATAL_CATALOG + 1, || {
        checks().rejected & WRONG_ROLE != 0
    });
    let ctx = &mut contexts[supervisor];
    wait_for_role_yield(supervisor, ctx, until, FATAL_CATALOG + 2, || {
        checks().unready
    });

    #[cfg(feature = "v020-production-snapshot-read")]
    let catalog = view.catalog();
    #[cfg(not(feature = "v020-production-snapshot-read"))]
    let catalog = view;
    {
        let grant = unsafe { &mut *addr_of_mut!(STATE.grant) };
        if grant.is_some() {
            fatal(FATAL_CATALOG);
        }
        *grant = Some(ListGrant {
            holder,
            pie_cap,
            service_generation: SERVICE_GENERATION,
            catalog: Some(catalog),
            #[cfg(feature = "v020-production-snapshot-read")]
            view,
            #[cfg(feature = "v020-production-snapshot-read")]
            history_prefix_digest: history_prefix_digest(HISTORY_PREFIX),
        });
    }
    wait_for_role_yield(supervisor, ctx, until, FATAL_CATALOG + 3, || {
        let checks = checks();
        #[cfg(feature = "v020-production-snapshot-read")]
        if !read_checks().active_checks_complete() {
            return false;
        }
        checks.rejected == REQUIRED_REJECTIONS
            && checks.read_count == 2
            && checks.read_ids == [10, 11]
    });
    let service_generation = {
        let grant = unsafe { &mut *addr_of_mut!(STATE.grant) };
        // Keep the holder and scope so its next authorized request sees ESTALE.
        let grant = grant.as_mut().expect("mounted catalog grant");
        grant.catalog = None;
        grant.service_generation
    };
    wait_for_role_yield(supervisor, ctx, until, FATAL_CATALOG + 4, || {
        #[cfg(feature = "v020-production-snapshot-read")]
        if !read_checks().stale {
            return false;
        }
        checks().stale
    });

    let checks = checks();
    let boot = catalog.boot_epoch();
    let generation = catalog.generation();
    let reads = checks.read_count as u64;
    let unready = u64::from(checks.unready);
    let rejected = u64::from(checks.rejected.count_ones());
    let stale = u64::from(checks.stale);
    evidence::put(evidence::W16_CATALOG_BOOT, boot);
    evidence::put(evidence::W16_CATALOG_GENERATION, generation);
    evidence::put(evidence::W16_CATALOG_READS, reads);
    evidence::put(evidence::W16_CATALOG_UNREADY, unready);
    evidence::put(evidence::W16_CATALOG_REJECTS, rejected);
    evidence::put(evidence::W16_CATALOG_STALE, stale);
    evidence::put(evidence::W16_CATALOG_SERVICE_GENERATION, service_generation);
    for (i, word) in catalog.digest().chunks_exact(8).enumerate() {
        evidence::put(
            evidence::W16_CATALOG_DIGEST + i,
            u64::from_le_bytes(word.try_into().unwrap()),
        );
    }
    report("V020_W16_CATALOG", boot, generation, reads);
    report("V020_W16_CATALOG_CHECKS", unready, rejected, stale);
    let (read_windows, write_windows, closed) = copy_window::closed_counts();
    let read_windows = read_windows.saturating_sub(initial_read_windows);
    let write_windows = write_windows.saturating_sub(initial_write_windows);
    if !closed || read_windows == 0 || write_windows < reads {
        fatal(FATAL_CATALOG + 6);
    }
    report(
        "V020_SEC_M_COPY_WINDOW",
        read_windows,
        write_windows,
        u64::from(closed),
    );
    report(
        "V020_W16_CATALOG_BINDING",
        service_generation,
        holder.actor.generation,
        boot,
    );
    #[cfg(feature = "v020-production-snapshot-read")]
    publish_read(boot, view.slot_digest(), read_checks());
}

#[cfg(feature = "v020-production-snapshot-read")]
fn publish_read(boot: u64, slot_digest: [u8; 32], checks: ReadChecks) {
    let query = u64::from(checks.query_missing);
    let history = u64::from(checks.history_missing);
    let denials = u64::from(checks.denials);
    let stale = u64::from(checks.stale);
    evidence::put(evidence::W19_SNAPSHOT_BOOT, boot);
    evidence::put(evidence::W19_SNAPSHOT_QUERY_MISSING, query);
    evidence::put(evidence::W19_SNAPSHOT_HISTORY_MISSING, history);
    evidence::put(evidence::W19_SNAPSHOT_DENIALS, denials);
    evidence::put(evidence::W19_SNAPSHOT_STALE, stale);
    for (i, word) in slot_digest.chunks_exact(8).enumerate() {
        evidence::put(
            evidence::W19_SNAPSHOT_SLOT_DIGEST + i,
            u64::from_le_bytes(word.try_into().unwrap()),
        );
    }
    report("V020_W19_SNAPSHOT_READ", boot, query, history);
    report("V020_W19_SNAPSHOT_CHECKS", denials, stale, 0);
}
