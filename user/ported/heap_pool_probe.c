/* Real musl mappings and pthread stacks over the shared physical heap pool. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_BYTES ((size_t)4096)
#define MIB ((size_t)1024 * 1024)
#define SINGLE_BYTES (8 * MIB)
#define SINGLE_MAPS 5
#define HOLD_BYTES ((size_t)64 * 1024)
#define MAX_MAPS 960
#define WORKERS 3
#define TLS_INITIAL UINT64_C(0x64a7e5c3102bd98f)

struct mapping {
    void *address;
    size_t bytes;
    uint64_t tag;
};

struct worker {
    unsigned id;
    uintptr_t stack_address;
    uintptr_t tls_address;
};

/* Static bookkeeping does not consume the heap being measured. */
static struct mapping mappings[MAX_MAPS];
static size_t mapping_count, allocated_bytes;
static pid_t process_id;
static unsigned cycle;
static pthread_t threads[WORKERS];
static struct worker workers[WORKERS];
static size_t active_threads;
static unsigned workers_ready, workers_release, worker_error;
static _Thread_local uint64_t tls_marker = TLS_INITIAL;

static unsigned atomic_load(const unsigned *value)
{
    return __atomic_load_n(value, __ATOMIC_SEQ_CST);
}

static void atomic_store(unsigned *value, unsigned desired)
{
    __atomic_store_n(value, desired, __ATOMIC_SEQ_CST);
}

static int stop_workers(void)
{
    atomic_store(&workers_release, 1);
    while (active_threads) {
        size_t slot = --active_threads;
        void *result = NULL;
        int error = pthread_join(threads[slot], &result);
        if (error)
            return error;
        if (result != &workers[slot])
            return EIO;
    }
    return 0;
}

static int fail(const char *stage, int error)
{
    printf("HEAP_POOL_PROBE FAIL stage=%s errno=%d pid=%ld cycle=%u maps=%zu pages=%zu\n",
           stage, error, (long)process_id, cycle, mapping_count,
           allocated_bytes / PAGE_BYTES);
    (void)stop_workers();
    for (size_t slot = 0; slot < mapping_count; ++slot) {
        if (mappings[slot].bytes)
            (void)munmap(mappings[slot].address, mappings[slot].bytes);
    }
    return 1;
}

static uint64_t mapping_tag(size_t slot)
{
    /* The low 20 bits identify every word of an 8 MiB mapping. The next
     * 10 identify its slot, the next two its cycle, and the high 32 its PID. */
    return UINT64_C(0xa76c5e4d00000000) ^ ((uint64_t)(uint32_t)process_id << 32)
        ^ ((uint64_t)cycle << 30) ^ ((uint64_t)slot << 20);
}

static int allocate_region(size_t bytes)
{
    if (mapping_count == MAX_MAPS)
        return EOVERFLOW;
    void *address = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED)
        return errno;
    struct mapping *mapping = &mappings[mapping_count];
    mapping->address = address;
    mapping->bytes = bytes;
    mapping->tag = mapping_tag(mapping_count);
    ++mapping_count;
    allocated_bytes += bytes;
    volatile uint64_t *words = address;
    /* Check before writing so reuse by a different process proves that the
     * previous owner's payload was cleared, including every word of a page. */
    for (size_t word = 0; word < bytes / sizeof(*words); ++word) {
        if (words[word] != 0) {
            printf("HEAP_POOL_PROBE DETAIL stage=map-zero pid=%ld cycle=%u mapping=%zu word=%zu\n",
                   (long)process_id, cycle, mapping_count - 1, word);
            return EIO;
        }
    }
    for (size_t word = 0; word < bytes / sizeof(*words); ++word)
        words[word] = mapping->tag ^ word;
    return 0;
}

static int check_payload(void)
{
    for (size_t slot = 0; slot < mapping_count; ++slot) {
        const struct mapping *mapping = &mappings[slot];
        const volatile uint64_t *words = mapping->address;
        for (size_t word = 0; word < mapping->bytes / sizeof(*words); ++word) {
            if (words[word] != (mapping->tag ^ word)) {
                printf("HEAP_POOL_PROBE DETAIL pid=%ld mapping=%zu word=%zu\n",
                       (long)process_id, slot, word);
                return EIO;
            }
        }
    }
    return 0;
}

static int release_all(void)
{
    for (size_t slot = 0; slot < mapping_count; ++slot) {
        struct mapping *mapping = &mappings[slot];
        if (munmap(mapping->address, mapping->bytes))
            return errno;
        allocated_bytes -= mapping->bytes;
        mapping->address = NULL;
        mapping->bytes = 0;
    }
    mapping_count = 0;
    return 0;
}

static void *park_worker(void *argument)
{
    struct worker *worker = argument;
    volatile uint64_t local_page[PAGE_BYTES / sizeof(uint64_t)];
    uint64_t marker = TLS_INITIAL ^ ((uint64_t)cycle << 32) ^ worker->id;
    if (tls_marker != TLS_INITIAL)
        atomic_store(&worker_error, 1);
    tls_marker = marker;
    for (size_t word = 0; word < PAGE_BYTES / sizeof(*local_page); ++word)
        local_page[word] = marker ^ word;
    worker->stack_address = (uintptr_t)local_page;
    worker->tls_address = (uintptr_t)&tls_marker;
    __atomic_fetch_or(&workers_ready, 1u << (worker->id - 1), __ATOMIC_SEQ_CST);
    while (!atomic_load(&workers_release)) {
        if (usleep(1000) && errno != EINTR) {
            atomic_store(&worker_error, 2);
            break;
        }
    }
    if (tls_marker != marker)
        atomic_store(&worker_error, 3);
    for (size_t word = 0; word < PAGE_BYTES / sizeof(*local_page); ++word) {
        if (local_page[word] != (marker ^ word))
            atomic_store(&worker_error, 4);
    }
    return argument;
}

static int run_workers(void)
{
    pthread_attr_t attributes;
    int error = pthread_attr_init(&attributes);
    if (error)
        return fail("pthread-attr-init", error);
    error = pthread_attr_setstacksize(&attributes, 2 * MIB);
    if (error) {
        (void)pthread_attr_destroy(&attributes);
        return fail("pthread-stack-size", error);
    }
    error = pthread_attr_setguardsize(&attributes, PAGE_BYTES);
    if (error) {
        (void)pthread_attr_destroy(&attributes);
        return fail("pthread-guard-size", error);
    }
    atomic_store(&workers_ready, 0);
    atomic_store(&workers_release, 0);
    atomic_store(&worker_error, 0);
    tls_marker = TLS_INITIAL ^ UINT64_C(0xffff0000);
    for (size_t slot = 0; slot < WORKERS; ++slot) {
        workers[slot].id = (unsigned)slot + 1;
        error = pthread_create(&threads[slot], &attributes, park_worker, &workers[slot]);
        if (error) {
            (void)pthread_attr_destroy(&attributes);
            return fail("pthread-create", error);
        }
        ++active_threads;
    }
    error = pthread_attr_destroy(&attributes);
    if (error)
        return fail("pthread-attr-destroy", error);
    for (unsigned wait = 0; atomic_load(&workers_ready) != (1u << WORKERS) - 1; ++wait) {
        if (wait == 5000)
            return fail("pthread-ready-timeout", ETIMEDOUT);
        if (usleep(1000) && errno != EINTR)
            return fail("pthread-ready-sleep", errno);
    }
    if (atomic_load(&worker_error))
        return fail("pthread-worker-ready", EIO);
    for (size_t slot = 0; slot < WORKERS; ++slot) {
        if (workers[slot].tls_address == (uintptr_t)&tls_marker)
            return fail("pthread-main-tls-alias", EIO);
        for (size_t peer = 0; peer < slot; ++peer) {
            if (workers[slot].stack_address == workers[peer].stack_address ||
                workers[slot].tls_address == workers[peer].tls_address)
                return fail("pthread-worker-address-alias", EIO);
        }
    }
    error = check_payload();
    if (error)
        return fail("pthread-live-payload", error);
    printf("HEAP_POOL_PROBE THREADS_READY pid=%ld cycle=%u threads=%d pages=%zu\n",
           (long)process_id, cycle, WORKERS, allocated_bytes / PAGE_BYTES);
    error = stop_workers();
    if (error)
        return fail("pthread-join", error);
    if (atomic_load(&worker_error) || tls_marker != (TLS_INITIAL ^ UINT64_C(0xffff0000)))
        return fail("pthread-stack-tls-integrity", EIO);
    return 0;
}

static int run_single(void)
{
    for (cycle = 1; cycle <= 2; ++cycle) {
        for (size_t slot = 0; slot < SINGLE_MAPS; ++slot) {
            int error = allocate_region(SINGLE_BYTES);
            if (error)
                return fail("single-map-40m", error);
        }
        int error = check_payload();
        if (error)
            return fail("single-payload-before-threads", error);
        if (run_workers())
            return 1;
        error = check_payload();
        if (error)
            return fail("single-payload-after-threads", error);
        error = release_all();
        if (error)
            return fail("single-unmap", error);
        printf("HEAP_POOL_PROBE CYCLE PASS pid=%ld cycle=%u\n", (long)process_id, cycle);
    }
    printf("HEAP_POOL_PROBE PASS mode=single pid=%ld cycles=2\n", (long)process_id);
    return 0;
}

static int run_hold(void)
{
    char gate[96];
    int length = snprintf(gate, sizeof(gate), "/tmp/heap-pool-release-%ld", (long)process_id);
    if (length < 0 || (size_t)length >= sizeof(gate))
        return fail("hold-gate-path", EOVERFLOW);
    int exhausted = 0;
    cycle = 1;
    while (mapping_count < MAX_MAPS) {
        int error = allocate_region(HOLD_BYTES);
        if (error) {
            if (error != ENOMEM)
                return fail("hold-map-errno", error);
            exhausted = 1;
            break;
        }
    }
    int error = check_payload();
    if (error)
        return fail("hold-payload-before-gate", error);
    printf("HEAP_POOL_PROBE HELD pages=%zu maps=%zu pid=%ld exhausted=%d gate=%s\n",
           allocated_bytes / PAGE_BYTES, mapping_count, (long)process_id, exhausted, gate);
    for (;;) {
        if (!access(gate, F_OK))
            break;
        if (errno != ENOENT)
            return fail("hold-gate-access", errno);
        if (usleep(10000) && errno != EINTR)
            return fail("hold-gate-sleep", errno);
    }
    error = check_payload();
    if (error)
        return fail("hold-payload-after-gate", error);
    size_t held_pages = allocated_bytes / PAGE_BYTES;
    size_t held_maps = mapping_count;
    error = release_all();
    if (error)
        return fail("hold-unmap", error);
    printf("HEAP_POOL_PROBE PASS mode=hold pid=%ld pages=%zu maps=%zu exhausted=%d\n",
           (long)process_id, held_pages, held_maps, exhausted);
    return 0;
}

int main(int argc, char **argv)
{
    process_id = getpid();
    if (setvbuf(stdout, NULL, _IONBF, 0))
        return fail("stdout", errno);
    if (sysconf(_SC_PAGESIZE) != (long)PAGE_BYTES)
        return fail("page-size", EINVAL);
    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "single")))
        return run_single();
    if (argc == 2 && !strcmp(argv[1], "hold"))
        return run_hold();
    return fail("arguments", EINVAL);
}
