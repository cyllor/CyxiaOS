//! Isolated EL0 Signer v2. One stopped owner holds the mailbox, exact
//! pending CertificateVerify and its saved context between bounded entries.
use super::*;
use core::task::Poll;
#[cfg(cyxia_resident_net)]
use cyxia_contracts::tls_signer::{KEY_DER_MAX, KEY_DER_OFFSET, KEY_PAGE_VA};
use cyxia_contracts::tls_signer::{
    Request, SIGN_TIMEOUT_NS, SIGNATURE_BYTES, TRANSCRIPT_BYTES, WIRE_BYTES,
};
use cyxia_kernel_core::security::network::deployment::SIGNER_FRAMES;

#[cfg(feature = "v020-production-authenticated-net")]
pub(super) const SIGNER_ELF: &[u8] =
    include_bytes!("../../../../../target/aarch64-unknown-none/release/cyxia-echo-signer");
const SIGNER_ASID: u8 = 0x41;
const SIGNER_STACK_PAGES: usize = 16;
#[unsafe(link_section = ".bss.sec_n")]
#[unsafe(export_name = "V020_SEC_N_SIGNER_SPACE_PAGES")]
static mut SIGNER: AddressSpace<SIGNER_FRAMES, SIGNER_STACK_PAGES> = AddressSpace::ZERO;

#[cfg(cyxia_resident_net)]
const KEY_BYTES: usize = include_bytes!(env!("CYXIA_DEPLOYMENT_SIGNER_DER")).len();
#[cfg(cyxia_resident_net)]
const _: () = {
    assert!(KEY_BYTES > 0 && KEY_BYTES <= KEY_DER_MAX);
    assert!(KEY_PAGE_VA as u64 == SHARED_VA + PAGE as u64);
};
#[cfg(cyxia_resident_net)]
#[repr(C, align(4096))]
struct KeyStaging([u8; KEY_BYTES]);
#[cfg(cyxia_resident_net)]
#[unsafe(link_section = ".data.sec_n_signer_input")]
static mut KEY_STAGING: KeyStaging =
    KeyStaging(*include_bytes!(env!("CYXIA_DEPLOYMENT_SIGNER_DER")));

pub(crate) struct Signer<'a> {
    memory: Memory,
    layout: Layout,
    identity: BootIdentity<'a>,
    issued: Option<(Request, Option<[u8; SIGNATURE_BYTES]>)>,
    pending: Option<user::Context>,
    retired_through: u64,
}

impl<'a> Signer<'a> {
    pub(super) fn issued_for(&self, generation: u64) -> bool {
        matches!(self.issued, Some((request, Some(_))) if request.conn_generation == generation)
    }

    #[cfg(feature = "v020-production-authenticated-net")]
    pub(crate) fn load(identity: BootIdentity<'a>) -> Self {
        // SAFETY: CPU0 loads the diagnostic root once and owns it until stop.
        let memory = unsafe { AddressSpace::memory(core::ptr::addr_of_mut!(SIGNER)) };
        let layout = load_image(SIGNER_ELF, &memory, SHARED_PAGES, true);
        Self::loaded(memory, layout, identity)
    }

    #[cfg(cyxia_resident_net)]
    pub(crate) fn load_deployed(
        identity: BootIdentity<'a>,
        image: &'static [u8],
    ) -> Result<Self, cyxia_kernel_core::security::Error> {
        use cyxia_kernel_core::security::Error;
        if cpu::registered_slot() != Some(0) || identity.confirmed_installation().is_none() {
            return Err(Error::Unauthorized);
        }
        let staged = core::ptr::addr_of_mut!(KEY_STAGING).cast::<u8>();
        // SAFETY: this input has a single CPU0 owner until the stopped Signer
        // is handed off. A second load must never reuse consumed material.
        if !(0..KEY_BYTES).any(|i| unsafe { staged.add(i).read_volatile() != 0 }) {
            return Err(Error::Stale);
        }
        let memory = unsafe { AddressSpace::memory(core::ptr::addr_of_mut!(SIGNER)) };
        let key = unsafe { memory.shared.add(1).cast::<u8>() };
        let key_pa = phys(key as u64);
        let alias = high_leaf(key_pa);
        if unsafe { alias.read_volatile() } != (key_pa | 0x0060_0000_0000_0703) {
            return Err(Error::Conflict);
        }
        let layout = load_image(image, &memory, 1, true);
        // SAFETY: the dedicated page is still reachable by EL1 only. The
        // loaded root is stopped. Move the secret, erase the staging bytes,
        // then remove the direct alias before any observer can run the root.
        unsafe {
            key.cast::<u64>().write_volatile(KEY_BYTES as u64);
            for i in 0..KEY_BYTES {
                key.add(KEY_DER_OFFSET + i)
                    .write_volatile(staged.add(i).read_volatile());
            }
        }
        Self::discard_deployment_input();
        memory.map_page(KEY_PAGE_VA as u64, key_pa, false, false);
        unsafe { alias.write_volatile(0) };
        tlbi();
        Ok(Self::loaded(memory, layout, identity))
    }

    #[cfg(cyxia_resident_net)]
    pub(crate) fn discard_deployment_input() {
        // SAFETY: the staging slot is used only by the boot owner on CPU0,
        // and no EL0 address space maps the slot.
        assert_eq!(cpu::registered_slot(), Some(0));
        let staged = core::ptr::addr_of_mut!(KEY_STAGING).cast::<u8>();
        unsafe {
            for i in 0..KEY_BYTES {
                staged.add(i).write_volatile(0);
            }
            core::arch::asm!("dsb ishst", options(nostack));
        }
    }

    fn loaded(memory: Memory, layout: Layout, identity: BootIdentity<'a>) -> Self {
        report(
            "V020_SEC_N_SIGNER_SPACE",
            u64::from(SIGNER_ASID),
            layout.used_frames as u64,
            0,
        );
        Self {
            memory,
            layout,
            identity,
            issued: None,
            pending: None,
            retired_through: 0,
        }
    }

    pub(super) fn begin_certificate_verify(
        &mut self,
        connection: u64,
        pending_expires_ns: u64,
        transcript_hash: [u8; TRANSCRIPT_BYTES],
    ) -> bool {
        let now = now_ns();
        if let Some((request, _)) = self.issued {
            return request.conn_generation == connection
                && request.transcript_hash == transcript_hash
                && now < request.expires_ns;
        }
        let Some(maximum) = now.checked_add(SIGN_TIMEOUT_NS) else {
            return false;
        };
        let expires_ns = pending_expires_ns.min(maximum);
        if expires_ns <= now || connection <= self.retired_through {
            return false;
        }
        let request = Request {
            boot_epoch: self.identity.boot_epoch(),
            verifier_generation: self.identity.verifier_generation(),
            conn_id: connection,
            conn_generation: connection,
            key_generation: self.identity.tls().key_generation,
            nonce: connection,
            expires_ns,
            transcript_hash,
        };
        let mut ctx = user::Context::empty();
        ctx.pc = self.layout.entry;
        ctx.sp = STACK_VA + (SIGNER_STACK_PAGES * PAGE) as u64;
        #[cfg(cyxia_resident_net)]
        let local_pin = self.identity.local_pin();
        #[cfg(not(cyxia_resident_net))]
        let local_pin = LOCAL_NODE;
        for (reg, bytes) in ctx.regs[..4].iter_mut().zip(local_pin.chunks_exact(8)) {
            *reg = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        ctx.regs[4] = request.boot_epoch;
        ctx.regs[5] = request.verifier_generation;
        ctx.regs[6] = request.key_generation;
        self.issued = Some((request, None));
        self.pending = Some(ctx);
        // SAFETY: EL0 is stopped and no other role maps the Signer mailbox.
        unsafe { self.mailbox().write_volatile(request.encode()) };
        true
    }

    pub(super) fn poll_certificate_verify(
        &mut self,
        deadline_ns: u64,
    ) -> Poll<Option<[u8; SIGNATURE_BYTES]>> {
        let Some((request, cached)) = self.issued else {
            return Poll::Ready(None);
        };
        let now = now_ns();
        if now >= request.expires_ns {
            self.scrub_request();
            return Poll::Ready(None);
        }
        let Some(ctx) = self.pending.as_mut() else {
            return Poll::Ready(cached);
        };
        if now >= deadline_ns {
            return Poll::Pending;
        }
        step(
            ctx,
            phys(self.memory.root as u64),
            SIGNER_ASID,
            ticks_at_ns(request.expires_ns.min(deadline_ns)),
        );
        if ctx.kind == 9 && now_ns() < request.expires_ns {
            return Poll::Pending;
        }
        let ok = ctx.kind == 8
            && ctx.esr >> 26 == 0x15
            && ctx.esr & 0xffff == 0x44
            && ctx.regs[0] == 1
            && now_ns() < request.expires_ns;
        // SAFETY: the Signer trapped and its private mailbox is quiescent.
        let signature = ok
            .then(|| unsafe { self.mailbox().read_volatile() })
            .and_then(|reply| request.reply_signature(&reply));
        self.scrub_request();
        let signature = signature.filter(|_| now_ns() < request.expires_ns);
        self.issued = Some((request, signature));
        #[cfg(feature = "v020-production-authenticated-net")]
        if signature.is_some() {
            report(
                "V020_SEC_N_SIGNER_IDENTITY",
                request.boot_epoch,
                request.verifier_generation,
                request.key_generation,
            );
            report("V020_SEC_N_SIGNER_REPLY", request.conn_id, request.nonce, 1);
        }
        Poll::Ready(signature)
    }

    #[cfg(feature = "v020-production-authenticated-net")]
    pub(super) fn certificate_verify(
        &mut self,
        connection: u64,
        expires_ns: u64,
        transcript_hash: [u8; TRANSCRIPT_BYTES],
    ) -> Option<[u8; SIGNATURE_BYTES]> {
        if !self.begin_certificate_verify(connection, expires_ns, transcript_hash) {
            return None;
        }
        loop {
            if let Poll::Ready(result) = self.poll_certificate_verify(expires_ns) {
                return result;
            }
        }
    }

    /// Called after the native owner proves completion for this exact
    /// generation. A later connection never reuses the previous nonce.
    #[cfg(cyxia_resident_net)]
    pub(crate) fn retire(&mut self, connection: u64) -> bool {
        self.issued_for(connection) && self.reject(connection)
    }

    /// A positive transport reset witness relinquishes a pending connection
    /// once its Signer context has stopped.
    #[cfg(cyxia_resident_net)]
    pub(crate) fn reject(&mut self, connection: u64) -> bool {
        if connection <= self.retired_through
            || self.pending.is_some()
            || self
                .issued
                .is_some_and(|(request, _)| request.conn_generation != connection)
        {
            return false;
        }
        self.issued = None;
        self.retired_through = connection;
        true
    }

    pub(crate) fn discard(mut self) {
        self.scrub_request();
        #[cfg(cyxia_resident_net)]
        {
            // SAFETY: the Signer is stopped and this is its final teardown.
            // Disconnect the user root before remapping the isolated page
            // for the existing volatile backing scrub.
            let key_pa = phys(unsafe { self.memory.shared.add(1) } as u64);
            unsafe { (*self.memory.root).0.as_mut_ptr().write_volatile(0) };
            tlbi();
            unsafe {
                high_leaf(key_pa).write_volatile(key_pa | 0x0060_0000_0000_0703);
                core::arch::asm!("dsb ishst", "isb", options(nostack));
            }
        }
        let pages = discard_role_space(&self.memory, &self.layout);
        #[cfg(feature = "v020-production-authenticated-net")]
        report(
            "V020_SEC_N_SIGNER_DISCARDED",
            self.identity.boot_epoch(),
            self.identity.tls().key_generation,
            pages as u64,
        );
        #[cfg(not(feature = "v020-production-authenticated-net"))]
        let _ = pages;
    }

    fn mailbox(&self) -> *mut [u8; WIRE_BYTES] {
        self.memory.shared.cast()
    }

    fn scrub_request(&mut self) {
        if let Some(ctx) = self.pending.as_mut() {
            // SAFETY: EL0 has stopped. This owner exclusively owns its
            // mailbox, saved registers and complete private stack.
            unsafe {
                core::ptr::write_volatile(ctx, user::Context::empty());
                self.memory
                    .shared
                    .cast::<[u8; WIRE_BYTES]>()
                    .write_volatile([0; WIRE_BYTES]);
                for page in 0..SIGNER_STACK_PAGES {
                    self.memory.stack.add(page).write_volatile(Page::ZERO);
                }
            }
            self.pending = None;
        }
    }
}
