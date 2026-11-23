#define _GNU_SOURCE
#include <stddef.h>
#define main twice_main
int twice_main(int argc, char **argv);
int HiAE_init_library(void);
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);
#define tun_write bench_tun_write
#include "twice.c"
#undef main
#undef tun_write

#include <stdlib.h>

static uint64_t sink_bytes, sink_packets;

ssize_t bench_tun_write(int fd, const void *data, size_t size)
{
    (void) fd;
    (void) data;
    sink_bytes += size;
    sink_packets++;
    return (ssize_t) size;
}

static int      count_allocs;
static uint64_t alloc_count, alloc_bytes;

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);

void *__wrap_malloc(size_t n)
{
    if (count_allocs) {
        alloc_count++;
        alloc_bytes += n;
    }
    return __real_malloc(n);
}

void *__wrap_calloc(size_t a, size_t b)
{
    if (count_allocs) {
        alloc_count++;
        alloc_bytes += a * b;
    }
    return __real_calloc(a, b);
}

void *__wrap_realloc(void *p, size_t n)
{
    if (count_allocs) {
        alloc_count++;
        alloc_bytes += n;
    }
    return __real_realloc(p, n);
}

static uint64_t splitmix(uint64_t *s)
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
    z          = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z          = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static long status_kb(const char *field)
{
    FILE *f = fopen("/proc/self/status", "r");
    char  line[256];
    long  v = -1;
    size_t n = strlen(field);
    while (f && fgets(line, sizeof line, f)) {
        if (!strncmp(line, field, n)) {
            v = atol(line + n);
            break;
        }
    }
    if (f) {
        fclose(f);
    }
    return v;
}

typedef struct {
    uint64_t rv, ctr;
} Item;

static Item  *trace;
static size_t trace_len;

static void push(uint64_t rv, uint64_t ctr)
{
    trace[trace_len].rv  = rv;
    trace[trace_len].ctr = ctr;
    trace_len++;
}

static void gen_in_order(size_t n)
{
    for (size_t i = 0; i < n; i++) {
        push(7, 1 + i);
    }
}

static void gen_sparse(size_t n, uint64_t *seed)
{
    uint64_t base = 1;
    while (trace_len + 8 <= n) {
        uint64_t order[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
        if (splitmix(seed) % 4 == 0) {
            size_t k = splitmix(seed) % 7;
            uint64_t t = order[k];
            order[k] = order[k + 1];
            order[k + 1] = t;
        }
        for (int i = 0; i < 8; i++) {
            push(7, base + order[i]);
        }
        base += 8;
    }
}

static void gen_near_full(size_t n)
{
    uint64_t k = 1;
    while (trace_len + REORDER_WINDOW_SIZE <= n) {
        for (uint64_t i = 1; i < REORDER_WINDOW_SIZE; i++) {
            push(7, k + i);
        }
        push(7, k);
        k += REORDER_WINDOW_SIZE;
    }
}

static void gen_gaps(size_t n, uint64_t *seed)
{
    uint64_t k = 1;
    for (;;) {
        uint64_t depth = 1 + splitmix(seed) % 64;
        if (trace_len + depth + 1 > n) {
            break;
        }
        for (uint64_t i = 1; i <= depth; i++) {
            push(7, k + i);
        }
        push(7, k);
        k += depth + 1;
    }
}

static void gen_resets(size_t n)
{
    uint64_t rv = 7, c = 1;
    for (size_t i = 0; i < n; i++) {
        if (i % 64 == 0 && i != 0) {
            rv++;
            c = 1;
        }
        push(rv, c++);
    }
}

static int is_fulls(const char *s)
{
    return !strncmp(s, "full_packet", 11);
}

int main(int argc, char **argv)
{
    const char *scenario = "in_order";
    size_t      packets = 200000, payload = 1400, reps = 1;
    uint64_t    seed = 1;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--scenario")) {
            scenario = argv[i + 1];
        } else if (!strcmp(argv[i], "--packets")) {
            packets = strtoull(argv[i + 1], NULL, 10);
        } else if (!strcmp(argv[i], "--reps")) {
            reps = strtoull(argv[i + 1], NULL, 10);
        } else if (!strcmp(argv[i], "--payload")) {
            payload = strtoull(argv[i + 1], NULL, 10);
        } else if (!strcmp(argv[i], "--seed")) {
            seed = strtoull(argv[i + 1], NULL, 10);
        }
    }
    if (payload > MAX_PACKET_LEN) {
        return 2;
    }
    if (!freopen("/dev/null", "w", stderr)) {
        return 2;
    }

    trace = malloc((packets + 2 * REORDER_WINDOW_SIZE + 16) * sizeof(Item));
    uint64_t gseed = seed;
    int      timeout_mode = !strcmp(scenario, "timeout_drain");
    int      keyed = is_fulls(scenario);
    (void) timeout_mode;
    if (!strcmp(scenario, "in_order") || !strcmp(scenario, "full_packet_in_order")) {
        gen_in_order(packets);
    } else if (!strcmp(scenario, "sparse_reorder") || !strcmp(scenario, "full_packet_sparse")) {
        gen_sparse(packets, &gseed);
    } else if (!strcmp(scenario, "near_full_window")) {
        gen_near_full(packets);
    } else if (!strcmp(scenario, "repeated_gaps") || !strcmp(scenario, "large_payload")) {
        gen_gaps(packets, &gseed);
    } else if (!strcmp(scenario, "repeated_resets")) {
        gen_resets(packets);
    } else if (timeout_mode) {
        gen_in_order(0);
    } else {
        fprintf(stdout, "{\"error\":\"unknown scenario %s\"}\n", scenario);
        return 2;
    }

    uint64_t span = 0;
    for (size_t i = 0; i < trace_len; i++) {
        if (trace[i].ctr > span) {
            span = trace[i].ctr;
        }
    }
    int resets = !strcmp(scenario, "repeated_resets");
    unsigned char *data = malloc(MAX_PACKET_LEN);
    unsigned char *enc  = malloc(MAX_PACKET_LEN);
    unsigned char *dec  = malloc(MAX_PACKET_LEN);
    unsigned char *frame = malloc(sizeof(PacketHeader) + MAX_PACKET_LEN + HIAE_MACBYTES);
    uint64_t       pseed = seed + 99;
    for (size_t i = 0; i < MAX_PACKET_LEN; i++) {
        data[i] = (unsigned char) splitmix(&pseed);
    }
    uint8_t key[HIAE_KEYBYTES];
    for (int i = 0; i < HIAE_KEYBYTES; i++) {
        key[i] = (uint8_t) splitmix(&pseed);
    }

    Context *ctx = calloc(1, sizeof(Context));
    reorder_init(&ctx->reorder);
    HiAE_init_library();

    long rss_before = status_kb("VmRSS:");
    long vsz_before = status_kb("VmSize:");
    uint64_t elapsed = 0, counted = 0;

    for (int pass = 0; pass < 2; pass++) {
        reorder_cleanup(&ctx->reorder);
        reorder_init(&ctx->reorder);
        ctx->reorder.random_initialized = 1;
        ctx->reorder.random_value       = 7;
        sink_bytes = sink_packets = 0;
        if (pass == 1) {
            count_allocs = 1;
            alloc_count = alloc_bytes = 0;
        }
        uint64_t t_acc = 0;
        size_t   nreps = pass == 1 ? reps : 1;
        if (timeout_mode) {
            size_t   cycles = packets / 512 * nreps;
            uint64_t k = 1;
            for (size_t c = 0; c < cycles; c++) {
                ctx->reorder.expected_counter = k;
                uint64_t t1 = now_ns();
                for (uint64_t i = 1; i <= 512; i++) {
                    reorder_process_packet(ctx, 7, k + i, data, payload);
                }
                t_acc += now_ns() - t1;
                for (int s = 0; s < REORDER_WINDOW_SIZE; s++) {
                    if (ctx->reorder.buffer[s].occupied) {
                        ctx->reorder.buffer[s].timestamp.tv_sec  = 0;
                        ctx->reorder.buffer[s].timestamp.tv_nsec = 0;
                    }
                }
                t1 = now_ns();
                reorder_check_timeouts(ctx);
                t_acc += now_ns() - t1;
                k += 513;
            }
            counted = cycles * 512;
        } else if (keyed) {
            uint8_t tag[HIAE_MACBYTES];
            uint64_t t1 = now_ns();
            for (size_t r = 0; r < nreps; r++)
            for (size_t i = 0; i < trace_len; i++) {
                PacketHeader h = { trace[i].rv, trace[i].ctr + r * span };
                HiAE_encrypt(key, (uint8_t *) &h, data, enc, payload, NULL, 0, tag);
                memcpy(frame, &h, sizeof h);
                memcpy(frame + sizeof h, enc, payload);
                memcpy(frame + sizeof h + payload, tag, HIAE_MACBYTES);
                PacketHeader rh;
                memcpy(&rh, frame, sizeof rh);
                if (HiAE_decrypt(key, (uint8_t *) &rh, dec, frame + sizeof rh, payload, NULL, 0,
                                 frame + sizeof rh + payload) != 0) {
                    fprintf(stdout, "{\"error\":\"decrypt failed\"}\n");
                    return 1;
                }
                reorder_process_packet(ctx, endian_swap64(rh.random_value),
                                       endian_swap64(rh.counter), dec, payload);
            }
            t_acc   = now_ns() - t1;
            counted = trace_len * nreps;
        } else {
            uint64_t t1 = now_ns();
            for (size_t r = 0; r < nreps; r++) {
                for (size_t i = 0; i < trace_len; i++) {
                    reorder_process_packet(ctx, trace[i].rv + (resets ? r * 1000 : 0),
                                           trace[i].ctr + (resets ? 0 : r * span), data, payload);
                }
            }
            t_acc   = now_ns() - t1;
            counted = trace_len * nreps;
        }
        if (pass == 1) {
            elapsed = t_acc;
            count_allocs = 0;
        }
    }
    long rss_after = status_kb("VmRSS:");
    long hwm       = status_kb("VmHWM:");
    printf("{\"tool\":\"packet_bench\",\"lang\":\"c\",\"scenario\":\"%s\",\"packets\":%llu,"
           "\"payload\":%zu,\"elapsed_ns\":%llu,\"ns_per_packet\":%.4f,\"delivered\":%llu,"
           "\"delivered_bytes\":%llu,\"alloc_count\":%llu,\"alloc_bytes\":%llu,"
           "\"vmsize_kb_before\":%ld,\"rss_kb_before\":%ld,\"rss_kb_after\":%ld,"
           "\"hwm_kb\":%ld,\"retained_kb\":%ld,\"state_bytes\":%zu,\"window_slots\":%d,"
           "\"seed\":%llu}\n",
           scenario, (unsigned long long) counted, payload, (unsigned long long) elapsed,
           (double) elapsed / (double) counted, (unsigned long long) sink_packets,
           (unsigned long long) sink_bytes, (unsigned long long) alloc_count,
           (unsigned long long) alloc_bytes, vsz_before, rss_before, rss_after, hwm,
           rss_after - rss_before, sizeof(ReorderState), REORDER_WINDOW_SIZE,
           (unsigned long long) seed);
    return 0;
}
