/* CyxiaOS-private extensions to its Linux AArch64 syscall persona, ABI v1.
 * These numbers are not Linux syscalls. Return values use Linux -errno.
 */
#ifndef CYXIA_XORG_ABI_H
#define CYXIA_XORG_ABI_H

#include <stdint.h>
#include <stddef.h>

#define CYXIA_DISPLAY_INFO 0x43595801UL
#define CYXIA_DISPLAY_BLIT 0x43595802UL
#define CYXIA_INPUT_READ   0x43595803UL
#define CYXIA_INPUT_KEY_STATE 0x43595804UL
#define CYXIA_PIXEL_XRGB8888_LE 1U
#define CYXIA_MAX_RECT_BYTES 65536U
#define CYXIA_MAX_INPUT_EVENTS 32U

struct cyxia_display_info {
    uint32_t width, height, stride_bytes, format, max_rect_bytes, abi;
};

/* Linux evdev type/code/value encoding, retaining EV_SYN/SYN_REPORT and
 * SYN_DROPPED after overflow. Records are returned in device event order. */
struct cyxia_input_event {
    uint16_t type, code;
    int32_t value;
};

_Static_assert(sizeof(struct cyxia_display_info) == 24, "display ABI size");
_Static_assert(sizeof(struct cyxia_input_event) == 8, "input ABI size");

static inline long cyxia_syscall6(unsigned long number, unsigned long a,
                                unsigned long b, unsigned long c,
                                unsigned long d, unsigned long e,
                                unsigned long f)
{
    register unsigned long x0 __asm__("x0") = a;
    register unsigned long x1 __asm__("x1") = b;
    register unsigned long x2 __asm__("x2") = c;
    register unsigned long x3 __asm__("x3") = d;
    register unsigned long x4 __asm__("x4") = e;
    register unsigned long x5 __asm__("x5") = f;
    register unsigned long x8 __asm__("x8") = number;
    __asm__ volatile ("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                      "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
    return (long)x0;
}

/* ENODEV means no GPU. The kernel writes exactly 24 user bytes on success. */
static inline long cyxia_get_display_info(struct cyxia_display_info *info)
{
    return cyxia_syscall6(CYXIA_DISPLAY_INFO, (uintptr_t)info, 0, 0, 0, 0, 0);
}

/* Packed rows, exactly width*height*4 <= 65536 bytes. Success is returned only
 * after the GPU fence; EAGAIN means ownership/busy and requires later retry. */
static inline long cyxia_display_blit(uint32_t x, uint32_t y, uint32_t width,
                                     uint32_t height, const uint32_t *pixels,
                                     size_t bytes)
{
    return cyxia_syscall6(CYXIA_DISPLAY_BLIT, x, y, width, height,
                          (uintptr_t)pixels, bytes);
}

/* Return 0..count events, or EAGAIN when empty; count must be <=32. */
static inline long cyxia_read_input(struct cyxia_input_event *events, size_t count)
{
    return cyxia_syscall6(CYXIA_INPUT_READ, (uintptr_t)events, count, 0, 0, 0, 0);
}

/* After SYN_DROPPED, ignore intermediate events until SYN_REPORT, then obtain
 * the authoritative held-key/button bitset for evdev codes 0..767. */
static inline long cyxia_input_key_state(uint8_t bits[96])
{
    return cyxia_syscall6(CYXIA_INPUT_KEY_STATE, (uintptr_t)bits, 0, 0, 0, 0, 0);
}
#endif
