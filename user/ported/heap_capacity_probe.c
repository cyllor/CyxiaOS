/* Exercise the real musl mmap path beyond the legacy 16 MiB heap. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_BYTES ((size_t)4096)
#define MIB ((size_t)1024 * 1024)
#define LARGE_BYTES (4 * MIB)
#define CHUNK_BYTES ((size_t)64 * 1024)
#define LARGE_MAPS 5
#define MAX_MAPS 256

struct mapping {
    void *address;
    size_t bytes;
    unsigned tag;
};

/* Keep bookkeeping off the small user stack; no malloc is needed. */
static struct mapping mappings[MAX_MAPS];
static size_t mapping_count;
static size_t allocated_bytes;

static int fail(const char *stage, int error)
{
    printf("HEAP_CAPACITY_PROBE FAIL stage=%s error=%d mappings=%zu pages=%zu\n",
           stage, error, mapping_count, allocated_bytes / PAGE_BYTES);
    for (size_t i = 0; i < mapping_count; ++i) {
        if (mappings[i].bytes)
            munmap(mappings[i].address, mappings[i].bytes);
        mappings[i].address = NULL;
        mappings[i].bytes = 0;
    }
    return 1;
}

static uint64_t payload(unsigned tag, size_t word)
{
    /* Both the mapping and word have unique bits, including every page. */
    return UINT64_C(0xa700000000000000) | ((uint64_t)tag << 32) | word;
}

static int allocate_region(size_t slot, size_t bytes, unsigned tag)
{
    if (slot >= MAX_MAPS || mappings[slot].bytes)
        return EINVAL;
    void *address = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED)
        return errno;
    mappings[slot].address = address;
    mappings[slot].bytes = bytes;
    mappings[slot].tag = tag;
    if (mapping_count <= slot)
        mapping_count = slot + 1;
    allocated_bytes += bytes;
    return 0;
}

static void write_region(size_t slot, unsigned tag)
{
    struct mapping *mapping = &mappings[slot];
    volatile uint64_t *words = mapping->address;
    mapping->tag = tag;
    for (size_t word = 0; word < mapping->bytes / sizeof(*words); ++word)
        words[word] = payload(tag, word);
}

static int prepare_region(size_t slot, const char *stage)
{
    const struct mapping *mapping = &mappings[slot];
    const volatile uint64_t *words = mapping->address;
    /* Inspect the whole mapping, not only the first byte of each page. */
    for (size_t word = 0; word < mapping->bytes / sizeof(*words); ++word) {
        if (words[word] != 0) {
            printf("HEAP_CAPACITY_PROBE DETAIL mapping=%zu word=%zu\n", slot, word);
            return fail(stage, EIO);
        }
    }
    write_region(slot, mapping->tag);
    return 0;
}

static int check_payload(const char *stage)
{
    /* Reading every live mapping after writes detects physical page aliases. */
    for (size_t slot = 0; slot < mapping_count; ++slot) {
        const struct mapping *mapping = &mappings[slot];
        const volatile uint64_t *words = mapping->address;
        for (size_t word = 0; word < mapping->bytes / sizeof(*words); ++word) {
            if (words[word] != payload(mapping->tag, word)) {
                printf("HEAP_CAPACITY_PROBE DETAIL mapping=%zu word=%zu\n", slot, word);
                return fail(stage, EIO);
            }
        }
    }
    return 0;
}

static int release_region(size_t slot, const char *stage)
{
    struct mapping *mapping = &mappings[slot];
    if (munmap(mapping->address, mapping->bytes))
        return fail(stage, errno);
    allocated_bytes -= mapping->bytes;
    mapping->address = NULL;
    mapping->bytes = 0;
    return 0;
}

static int release_all(const char *stage)
{
    for (size_t slot = 0; slot < mapping_count; ++slot)
        if (mappings[slot].bytes && release_region(slot, stage))
            return 1;
    mapping_count = 0;
    return 0;
}

static int large_cycle(unsigned first_tag, const char *stage)
{
    for (size_t slot = 0; slot < LARGE_MAPS; ++slot) {
        int error = allocate_region(slot, LARGE_BYTES, first_tag + (unsigned)slot);
        if (error)
            return fail(stage, error);
        if (prepare_region(slot, stage))
            return 1;
    }
    return check_payload(stage);
}

int main(int argc, char **argv)
{
    (void)argv;
    if (setvbuf(stdout, NULL, _IONBF, 0))
        return fail("stdout", errno);
    if (argc != 1)
        return fail("arguments", EINVAL);
    if (sysconf(_SC_PAGESIZE) != (long)PAGE_BYTES)
        return fail("page-size", EINVAL);

    /* All five mappings remain live: the legacy heap cannot reach 20 MiB. */
    if (large_cycle(1, "above-legacy"))
        return 1;
    puts("HEAP_CAPACITY_PROBE ABOVE_LEGACY PASS");

    /* Test the request cap before exhaustion, with over 8 MiB still free. */
    int error = allocate_region(LARGE_MAPS, 8 * MIB + PAGE_BYTES, 1000);
    if (!error)
        return fail("oversize-accepted", EINVAL);
    if (error != ENOMEM)
        return fail("oversize-errno", error);
    if (check_payload("oversize-integrity"))
        return 1;

    int exhausted = 0;
    for (size_t slot = LARGE_MAPS; slot < MAX_MAPS; ++slot) {
        error = allocate_region(slot, CHUNK_BYTES, 1 + (unsigned)slot);
        if (error) {
            if (error != ENOMEM)
                return fail("reserve-errno", error);
            exhausted = 1;
            break;
        }
        if (prepare_region(slot, "reserve-zero"))
            return 1;
    }
    if (!exhausted)
        return fail("reserve-loop-bound", EOVERFLOW);
    if (allocated_bytes < 28 * MIB || allocated_bytes > 32 * MIB - 32 * PAGE_BYTES)
        return fail("reserve-capacity", EINVAL);
    if (check_payload("reserve-integrity"))
        return 1;
    printf("HEAP_CAPACITY_PROBE RESERVE PASS pages=%zu\n", allocated_bytes / PAGE_BYTES);

    /* Reclaim one whole allocation and verify its replacement is zeroed. */
    if (release_region(2, "reuse-unmap"))
        return 1;
    error = allocate_region(2, LARGE_BYTES, 1001);
    if (error)
        return fail("reuse-map", error);
    if (prepare_region(2, "reuse-zero") || check_payload("reuse-integrity"))
        return 1;

    if (mprotect(mappings[2].address, mappings[2].bytes, PROT_NONE))
        return fail("protect-none", errno);
    /* Do not access this allocation until read permission is restored. */
    if (mprotect(mappings[2].address, mappings[2].bytes, PROT_READ))
        return fail("protect-read", errno);
    if (check_payload("protect-read-integrity"))
        return 1;
    if (mprotect(mappings[2].address, mappings[2].bytes, PROT_READ | PROT_WRITE))
        return fail("protect-write", errno);
    write_region(2, 1002);
    if (check_payload("protect-write-integrity") || release_all("release-first"))
        return 1;

    /* A second 20 MiB allocation cycle exercises reuse of the whole arena. */
    if (large_cycle(2001, "second-cycle") || release_all("release-second"))
        return 1;
    puts("HEAP_CAPACITY_PROBE REUSE PASS");
    puts("HEAP_CAPACITY_PROBE PASS");
    return 0;
}
