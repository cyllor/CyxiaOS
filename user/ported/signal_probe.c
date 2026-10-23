/* Real target-musl signal ABI probe. No host signal emulation or test syscalls. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static _Thread_local volatile unsigned tls_cookie = 0x43595849;
static volatile sig_atomic_t usr1_calls, usr2_calls, segv_calls, ill_calls;
static volatile sig_atomic_t bad_handler, seen_user, seen_tkill;
static volatile sig_atomic_t fp_test, nested_test, corrupt_frame;
static pid_t own_pid;

static int fail(const char *stage)
{
    printf("SIGNAL_PROBE FAIL %s errno=%d bad=%d\n", stage, errno, bad_handler);
    return 1;
}

static void handler(int number, siginfo_t *info, void *opaque)
{
    ucontext_t *context = opaque;
    if (!info || !context || info->si_signo != number || tls_cookie != 0x43595849) {
        bad_handler = 1;
        return;
    }
    struct fpsimd_context *fp = (void *)context->uc_mcontext.__reserved;
    if (fp->head.magic != FPSIMD_MAGIC || fp->head.size != sizeof *fp)
        bad_handler = 2;
    if (number == SIGUSR1) {
        ++usr1_calls;
        if (info->si_pid != own_pid) bad_handler = 3;
        if (info->si_code == SI_USER) seen_user = 1;
        else if (info->si_code == SI_TKILL) seen_tkill = 1;
        else bad_handler = 4;
        if (fp_test) {
            context->uc_mcontext.regs[0] = 0x5a17;
            if (fp->vregs[0] != (((__uint128_t)0x5a5a5a5a5a5a5a5aULL << 64)
                                | 0x5a5a5a5a5a5a5a5aULL)) bad_handler = 5;
            /* Deliberately clobber both halves of caller-saved SIMD registers
             * plus FP control/status. rt_sigreturn must restore the real frame. */
            __asm__ volatile ("movi v0.16b, #0\n"
                              "movi v31.16b, #0\n"
                              "msr fpcr, %0\nmsr fpsr, %0"
                              :: "r"(0ULL) : "v0", "v31", "memory");
        }
        if (corrupt_frame) context->uc_mcontext.pstate = 5; /* Forbidden EL1h. */
    } else if (number == SIGUSR2) {
        ++usr2_calls;
        if (nested_test && usr2_calls == 1 && raise(SIGUSR2)) bad_handler = 6;
    } else if (number == SIGSEGV) {
        ++segv_calls;
        if (info->si_code != SEGV_MAPERR || info->si_addr != 0) bad_handler = 7;
        /* The controlled fault below is exactly one four-byte LDR instruction. */
        context->uc_mcontext.pc += 4;
        context->uc_mcontext.regs[0] = 0x5eed;
    } else if (number == SIGILL) {
        ++ill_calls;
        if (info->si_code != ILL_ILLOPC
            || (uintptr_t)info->si_addr != context->uc_mcontext.pc) bad_handler = 8;
        /* The controlled instruction is one unallocated AArch64 word. */
        context->uc_mcontext.pc += 4;
    } else {
        bad_handler = 9;
    }
}

static int install(int number, int flags)
{
    struct sigaction action = {0};
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO | flags;
    if (sigemptyset(&action.sa_mask)) return -1;
    return sigaction(number, &action, 0);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, 0, _IONBF, 0);
    own_pid = getpid();
    if (own_pid <= 0 || tls_cookie != 0x43595849) return fail("startup");
    printf("SIGNAL_PROBE START pid=%d\n", own_pid);
    if (argc > 1 && !strcmp(argv[1], "--default-term")) {
        raise(SIGTERM);
        return fail("default-term-returned");
    }
    if (install(SIGUSR1, 0)) return fail("sigaction");
    if (argc > 1 && !strcmp(argv[1], "--bad-frame")) {
        corrupt_frame = 1;
        raise(SIGUSR1);
        return fail("bad-frame-returned");
    }
    sigset_t mask, previous;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, &previous) || raise(SIGUSR1)) return fail("block-raise");
    if (usr1_calls) return fail("blocked-delivery");
    if (sigprocmask(SIG_SETMASK, &previous, 0) || usr1_calls != 1
        || !seen_tkill || bad_handler) return fail("pending-unblock");
    printf("SIGNAL_PROBE MASK_PENDING PASS\n");

    uint64_t before_fpcr, before_fpsr;
    __asm__ volatile ("mrs %0, fpcr\nmrs %1, fpsr" : "=r"(before_fpcr), "=r"(before_fpsr));
    uint64_t first_low, first_high, last_low, last_high, after_fpcr, after_fpsr;
    register long result __asm__("x0") = own_pid;
    register long number __asm__("x1") = SIGUSR1;
    register long syscall_number __asm__("x8") = 129; /* Linux AArch64 kill. */
    fp_test = 1;
    __asm__ volatile (
        "movi v0.16b, #0x5a\nmovi v31.16b, #0xa5\n"
        "msr fpcr, %[control]\nmsr fpsr, %[status]\n"
        "svc 0\n"
        "umov %[first_low], v0.d[0]\numov %[first_high], v0.d[1]\n"
        "umov %[last_low], v31.d[0]\numov %[last_high], v31.d[1]\n"
        "mrs %[after_fpcr], fpcr\nmrs %[after_fpsr], fpsr"
        : "+r"(result), "+r"(number), "+r"(syscall_number),
          [first_low] "=r"(first_low), [first_high] "=r"(first_high),
          [last_low] "=r"(last_low), [last_high] "=r"(last_high),
          [after_fpcr] "=r"(after_fpcr), [after_fpsr] "=r"(after_fpsr)
        : [control] "r"(0x400000ULL), [status] "r"(0x10ULL)
        : "v0", "v31", "memory", "cc");
    __asm__ volatile ("msr fpcr, %0\nmsr fpsr, %1"
                      :: "r"(before_fpcr), "r"(before_fpsr) : "memory");
    fp_test = 0;
    if (result != 0x5a17 || first_low != 0x5a5a5a5a5a5a5a5aULL
        || first_high != first_low || last_low != 0xa5a5a5a5a5a5a5a5ULL
        || last_high != last_low || after_fpcr != 0x400000 || after_fpsr != 0x10
        || !seen_user || usr1_calls != 2 || bad_handler || tls_cookie != 0x43595849)
        return fail("fp-tls-ucontext-return");
    printf("SIGNAL_PROBE FP_TLS_UCONTEXT PASS\n");

    if (install(SIGSEGV, 0) || install(SIGILL, 0)) return fail("fault-handlers");
    uint64_t repaired;
    __asm__ volatile ("mov x0, #0\nldr x0, [x0]\nmov %0, x0"
                      : "=r"(repaired) :: "x0", "memory");
    __asm__ volatile (".inst 0x00000000" ::: "memory");
    if (repaired != 0x5eed || segv_calls != 1 || ill_calls != 1 || bad_handler)
        return fail("synchronous-fault-recovery");
    printf("SIGNAL_PROBE FAULT_RECOVERY PASS\n");

    nested_test = 1;
    if (install(SIGUSR2, SA_NODEFER) || raise(SIGUSR2) || usr2_calls != 2 || bad_handler)
        return fail("nodefer-nesting");
    nested_test = 0;
    if (install(SIGUSR2, SA_RESETHAND) || raise(SIGUSR2)) return fail("resethand");
    struct sigaction action;
    if (sigaction(SIGUSR2, 0, &action) || action.sa_handler != SIG_DFL
        || usr2_calls != 3 || bad_handler) return fail("resethand-query");
    printf("SIGNAL_PROBE NODEFER_RESETHAND PASS\n");

    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGPIPE, &action, 0) || raise(SIGPIPE)) return fail("ignore-pipe");
    errno = 0;
    if (install(SIGUSR2, SA_RESTART) != -1 || errno != EINVAL)
        return fail("unsupported-restart");
    printf("SIGNAL_PROBE IGNORE_UNSUPPORTED PASS\n");
    printf("SIGNAL_PROBE PASS\n");
    return 0;
}
