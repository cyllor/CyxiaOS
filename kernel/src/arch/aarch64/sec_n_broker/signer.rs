//! CPU0 owns the isolated EL0 Signer v2 fixture endpoint and all in-flight state.
use super::*;
use cyxia_contracts::tls_signer::{
    Request, SIGN_TIMEOUT_NS, SIGNATURE_BYTES, TRANSCRIPT_BYTES, WIRE_BYTES,
};

pub(super) const SIGNER_ELF: &[u8] =
    include_bytes!("../../../../../target/aarch64-unknown-none/release/cyxia-echo-signer");
const SIGNER_ASID: u8 = 0x41;
const SIGNER_FRAMES: usize = 64;
const SIGNER_STACK_PAGES: usize = 16;
#[unsafe(link_section = ".bss.sec_n")]
#[unsafe(export_name = "V020_SEC_N_SIGNER_SPACE_PAGES")]
static mut SIGNER: AddressSpace<SIGNER_FRAMES, SIGNER_STACK_PAGES> = AddressSpace::ZERO;

pub(crate) struct Signer<'a> {
    memory: Memory,
    layout: Layout,
    identity: BootIdentity<'a>,
    issued: Option<(Request, Option<[u8; SIGNATURE_BYTES]>)>,
}

impl<'a> Signer<'a> {
    pub(super) fn issued_for(&self, generation: u64) -> bool {
        matches!(self.issued, Some((request, Some(_))) if request.conn_generation == generation)
    }

    pub(crate) fn load(identity: BootIdentity<'a>) -> Self {
        // SAFETY: the single CPU0 network owner loads this address space once.
        // Its key pages are separate from the verifier's virtual address space.
        let memory = unsafe { AddressSpace::memory(core::ptr::addr_of_mut!(SIGNER)) };
        let layout = load_image(SIGNER_ELF, &memory, SHARED_PAGES, true);
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
        }
    }

    pub(super) fn certificate_verify(
        &mut self,
        connection: u64,
        pending_expires_ns: u64,
        transcript_hash: [u8; TRANSCRIPT_BYTES],
    ) -> Option<[u8; SIGNATURE_BYTES]> {
        let now = now_ns();
        let expires_ns = pending_expires_ns.min(now.checked_add(SIGN_TIMEOUT_NS)?);
        if expires_ns <= now {
            return None;
        }
        if let Some((request, signature)) = self.issued {
            return if request.conn_generation == connection
                && request.transcript_hash == transcript_hash
                && now < request.expires_ns
            {
                signature
            } else {
                None
            };
        }
        // This profile admits one connection per boot. Consume the one-shot
        // authorization before entering the signer; failure cannot issue a
        // second nonce for the same pending connection.
        let request = Request {
            boot_epoch: self.identity.boot_epoch(),
            verifier_generation: self.identity.verifier_generation(),
            conn_id: connection,
            conn_generation: connection,
            key_generation: self.identity.tls().key_generation,
            nonce: 1,
            expires_ns,
            transcript_hash,
        };
        self.issued = Some((request, None));
        let signature = self.sign(&request)?;
        self.issued = Some((request, Some(signature)));
        report(
            "V020_SEC_N_SIGNER_IDENTITY",
            request.boot_epoch,
            request.verifier_generation,
            request.key_generation,
        );
        report("V020_SEC_N_SIGNER_REPLY", connection, request.nonce, 1);
        Some(signature)
    }

    /// This one-shot network owner will never enter the stopped root
    /// again. Seal off the loaded private key and scrub writable pages.
    pub(crate) fn discard(self) {
        let pages = discard_role_space(&self.memory, &self.layout);
        report(
            "V020_SEC_N_SIGNER_DISCARDED",
            self.identity.boot_epoch(),
            self.identity.tls().key_generation,
            pages as u64,
        );
    }

    fn sign(&mut self, request: &Request) -> Option<[u8; SIGNATURE_BYTES]> {
        let mailbox = self.memory.shared.cast::<[u8; WIRE_BYTES]>();
        // SAFETY: the separate address space is stopped. Its only user of
        // the mailbox and private stack is entered synchronously below.
        unsafe { mailbox.write_volatile(request.encode()) };
        let mut ctx = user::Context::empty();
        ctx.pc = self.layout.entry;
        ctx.sp = STACK_VA + (SIGNER_STACK_PAGES * PAGE) as u64;
        // This EL1 pin is independent of both ELF images and the request.
        for (reg, bytes) in ctx.regs[..4].iter_mut().zip(LOCAL_NODE.chunks_exact(8)) {
            *reg = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        let root = phys(self.memory.root as u64);
        let mut signature = None;
        while now_ns() < request.expires_ns {
            step(&mut ctx, root, SIGNER_ASID, ticks_at_ns(request.expires_ns));
            if ctx.kind == 9 {
                continue;
            }
            if ctx.kind == 8
                && ctx.esr >> 26 == 0x15
                && ctx.esr & 0xffff == 0x44
                && ctx.regs[0] == 1
                && now_ns() < request.expires_ns
            {
                // The signer has stopped, and this page is private to its root.
                let reply = unsafe { mailbox.read_volatile() };
                signature = request.reply_signature(&reply);
            }
            break;
        }
        // Discard ephemeral signing state after the signer has stopped.
        unsafe {
            mailbox.write_volatile([0; WIRE_BYTES]);
            core::ptr::write_volatile(&mut ctx, user::Context::empty());
            for page in 0..SIGNER_STACK_PAGES {
                self.memory.stack.add(page).write_volatile(Page::ZERO);
            }
        }
        signature.filter(|_| now_ns() < request.expires_ns)
    }
}
