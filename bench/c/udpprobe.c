#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define VERSION "1"
#define MAGIC 0x7570726f62650001ULL
#define MAX_PKT 65536
#define BITSET_BITS (1u << 26)

typedef struct {
    uint64_t magic, seq, tx_ns;
} Hdr;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static double cpu_seconds(void)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return (double) ru.ru_utime.tv_sec + (double) ru.ru_stime.tv_sec +
           ((double) ru.ru_utime.tv_usec + (double) ru.ru_stime.tv_usec) / 1e6;
}

static const char *arg(int argc, char **argv, const char *name, const char *dflt)
{
    for (int i = 2; i + 1 < argc; i++) {
        if (!strcmp(argv[i], name)) {
            return argv[i + 1];
        }
    }
    return dflt;
}

static int make_socket(const char *bind_ip, int port, int rcvbuf, int sndbuf)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    if (rcvbuf > 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    }
    if (sndbuf > 0) {
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
    }
    if (bind_ip) {
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t) port) };
        inet_pton(AF_INET, bind_ip, &a.sin_addr);
        if (bind(fd, (struct sockaddr *) &a, sizeof a) != 0) {
            perror("bind");
            exit(1);
        }
    }
    return fd;
}

static struct sockaddr_in dest_addr(const char *ip, int port)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t) port) };
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *) a, y = *(const uint64_t *) b;
    return x < y ? -1 : x > y;
}

static int mode_blast(int argc, char **argv)
{
    const char *dst = arg(argc, argv, "--dst", "127.0.0.1");
    int         port = atoi(arg(argc, argv, "--port", "9000"));
    size_t      size = strtoull(arg(argc, argv, "--size", "1200"), NULL, 10);
    double      pps = atof(arg(argc, argv, "--pps", "0"));
    double      secs = atof(arg(argc, argv, "--secs", "3"));
    int         fd = make_socket(NULL, 0, 0, 4 << 20);
    struct sockaddr_in to = dest_addr(dst, port);
    if (size < sizeof(Hdr)) {
        size = sizeof(Hdr);
    }
    enum { BATCH = 32 };
    static unsigned char bufs[BATCH][2048];
    struct mmsghdr       msgs[BATCH];
    struct iovec         iov[BATCH];
    for (int i = 0; i < BATCH; i++) {
        memset(bufs[i], 0xa5, sizeof bufs[i]);
        iov[i].iov_base = bufs[i];
        iov[i].iov_len  = size;
        memset(&msgs[i], 0, sizeof msgs[i]);
        msgs[i].msg_hdr.msg_iov     = &iov[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        msgs[i].msg_hdr.msg_name    = &to;
        msgs[i].msg_hdr.msg_namelen = sizeof to;
    }
    uint64_t start = now_ns(), end = start + (uint64_t) (secs * 1e9), seq = 0, sent = 0, errs = 0;
    double   cpu0 = cpu_seconds();
    uint64_t next = start;
    int      batch = pps > 0 && pps < 3200 ? 1 : BATCH;
    while (now_ns() < end) {
        if (pps > 0) {
            uint64_t t;
            while ((t = now_ns()) < next) {
                if (next - t > 200000) {
                    struct timespec ts = { 0, (long) (next - t - 100000) };
                    nanosleep(&ts, NULL);
                }
            }
            next += (uint64_t) ((double) batch * 1e9 / pps);
        }
        uint64_t t = now_ns();
        for (int i = 0; i < batch; i++) {
            Hdr h = { MAGIC, seq++, t };
            memcpy(bufs[i], &h, sizeof h);
        }
        int n = sendmmsg(fd, msgs, (unsigned) batch, 0);
        if (n < 0) {
            errs++;
            seq -= (uint64_t) batch;
            continue;
        }
        seq -= (uint64_t) (batch - n);
        sent += (uint64_t) n;
    }
    double wall = (double) (now_ns() - start) / 1e9;
    printf("{\"mode\":\"blast\",\"version\":\"" VERSION "\",\"size\":%zu,\"sent\":%llu,\"send_errors\":%llu,"
           "\"wall_s\":%.6f,\"target_pps\":%.2f,\"offered_pps\":%.2f,\"offered_mbps\":%.3f,\"cpu_s\":%.6f}\n",
           size, (unsigned long long) sent, (unsigned long long) errs, wall, pps, (double) sent / wall,
           (double) sent * (double) size * 8 / wall / 1e6, cpu_seconds() - cpu0);
    return 0;
}

static int mode_sink(int argc, char **argv)
{
    const char *bind_ip = arg(argc, argv, "--bind", "0.0.0.0");
    int         port = atoi(arg(argc, argv, "--port", "9000"));
    double      secs = atof(arg(argc, argv, "--secs", "6"));
    double      idle = atof(arg(argc, argv, "--idle-s", "0.7"));
    int         fd = make_socket(bind_ip, port, 8 << 20, 0);
    uint32_t   *seen = calloc(BITSET_BITS / 32, 4);
    static unsigned char buf[MAX_PKT];
    uint64_t    received = 0, bytes = 0, dups = 0, reordered = 0, max_seq = 0, last_seq = 0;
    uint64_t    first = 0, last = 0, start = now_ns(), deadline = start + (uint64_t) (secs * 1e9);
    int         have = 0;
    double      cpu0 = cpu_seconds();
    struct pollfd p = { fd, POLLIN, 0 };
    for (;;) {
        uint64_t t = now_ns();
        if (t >= deadline || (have && t - last > (uint64_t) (idle * 1e9))) {
            break;
        }
        if (poll(&p, 1, 50) <= 0) {
            continue;
        }
        for (int k = 0; k < 64; k++) {
            ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
            if (n < (ssize_t) sizeof(Hdr)) {
                break;
            }
            Hdr h;
            memcpy(&h, buf, sizeof h);
            if (h.magic != MAGIC) {
                continue;
            }
            t = now_ns();
            if (!have) {
                have  = 1;
                first = t;
            }
            last = t;
            if (h.seq < BITSET_BITS && (seen[h.seq >> 5] >> (h.seq & 31)) & 1) {
                dups++;
                continue;
            }
            if (h.seq < BITSET_BITS) {
                seen[h.seq >> 5] |= 1u << (h.seq & 31);
            }
            if (received && h.seq < last_seq) {
                reordered++;
            }
            last_seq = h.seq;
            if (h.seq > max_seq) {
                max_seq = h.seq;
            }
            received++;
            bytes += (uint64_t) n;
        }
    }
    double span = have && last > first ? (double) (last - first) / 1e9 : 0;
    uint64_t expected = have ? max_seq + 1 : 0;
    printf("{\"mode\":\"sink\",\"version\":\"" VERSION "\",\"received\":%llu,\"bytes\":%llu,\"duplicates\":%llu,"
           "\"reordered\":%llu,\"max_seq\":%llu,\"lost\":%llu,\"span_s\":%.6f,\"received_pps\":%.2f,"
           "\"received_mbps\":%.3f,\"cpu_s\":%.6f}\n",
           (unsigned long long) received, (unsigned long long) bytes, (unsigned long long) dups,
           (unsigned long long) reordered, (unsigned long long) max_seq,
           (unsigned long long) (expected > received ? expected - received : 0), span,
           span > 0 ? (double) received / span : 0.0, span > 0 ? (double) bytes * 8 / span / 1e6 : 0.0,
           cpu_seconds() - cpu0);
    return 0;
}

static volatile sig_atomic_t stop;

static void on_term(int s)
{
    (void) s;
    stop = 1;
}

static int mode_echo(int argc, char **argv)
{
    const char *bind_ip = arg(argc, argv, "--bind", "0.0.0.0");
    int         port = atoi(arg(argc, argv, "--port", "9001"));
    double      secs = atof(arg(argc, argv, "--secs", "30"));
    int         fd = make_socket(bind_ip, port, 1 << 20, 1 << 20);
    static unsigned char buf[MAX_PKT];
    uint64_t    deadline = now_ns() + (uint64_t) (secs * 1e9);
    struct pollfd p = { fd, POLLIN, 0 };
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    while (!stop && now_ns() < deadline) {
        if (poll(&p, 1, 100) <= 0) {
            continue;
        }
        struct sockaddr_in from;
        socklen_t          fl = sizeof from;
        ssize_t            n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *) &from, &fl);
        if (n > 0) {
            sendto(fd, buf, (size_t) n, 0, (struct sockaddr *) &from, fl);
        }
    }
    return 0;
}

static int mode_ping(int argc, char **argv)
{
    const char *dst = arg(argc, argv, "--dst", "127.0.0.1");
    int         port = atoi(arg(argc, argv, "--port", "9001"));
    size_t      size = strtoull(arg(argc, argv, "--size", "64"), NULL, 10);
    double      pps = atof(arg(argc, argv, "--pps", "500"));
    double      secs = atof(arg(argc, argv, "--secs", "4"));
    double      warm = atof(arg(argc, argv, "--warm-s", "0.5"));
    int         fd = make_socket(NULL, 0, 1 << 20, 1 << 20);
    struct sockaddr_in to = dest_addr(dst, port);
    if (size < sizeof(Hdr)) {
        size = sizeof(Hdr);
    }
    size_t    cap = (size_t) ((secs + warm) * pps) + 16;
    uint64_t *rtt = malloc(cap * sizeof(uint64_t));
    unsigned char buf[MAX_PKT];
    memset(buf, 0x5a, sizeof buf);
    uint64_t start = now_ns(), measure_from = start + (uint64_t) (warm * 1e9),
             end = measure_from + (uint64_t) (secs * 1e9), next = start, seq = 0, sent = 0, got = 0;
    uint64_t interval = (uint64_t) (1e9 / pps), first_measured_seq = UINT64_MAX;
    uint64_t drain_until = 0;
    double   cpu0 = cpu_seconds();
    for (;;) {
        uint64_t t = now_ns();
        if (t >= end) {
            if (!drain_until) {
                drain_until = t + 500000000ULL;
            }
            if (t >= drain_until) {
                break;
            }
        } else if (t >= next) {
            Hdr h = { MAGIC, seq, t };
            memcpy(buf, &h, sizeof h);
            if (sendto(fd, buf, size, 0, (struct sockaddr *) &to, sizeof to) > 0) {
                if (t >= measure_from) {
                    if (first_measured_seq == UINT64_MAX) {
                        first_measured_seq = seq;
                    }
                    sent++;
                }
                seq++;
            }
            next += interval;
            continue;
        }
        uint64_t wake = drain_until ? drain_until : next;
        int      ms   = wake > t ? (int) ((wake - t) / 1000000) : 0;
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, ms) > 0) {
            for (;;) {
                ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
                if (n < (ssize_t) sizeof(Hdr)) {
                    break;
                }
                Hdr h;
                memcpy(&h, buf, sizeof h);
                uint64_t tn = now_ns();
                if (h.magic == MAGIC && h.seq >= first_measured_seq && got < cap) {
                    rtt[got++] = tn - h.tx_ns;
                }
            }
        }
    }
    qsort(rtt, got, sizeof(uint64_t), cmp_u64);
    double mean = 0;
    for (uint64_t i = 0; i < got; i++) {
        mean += (double) rtt[i];
    }
    mean = got ? mean / (double) got : 0;
#define PCT(q) (got ? (double) rtt[(size_t) ((double) (got - 1) * (q))] / 1000.0 : 0.0)
    printf("{\"mode\":\"ping\",\"version\":\"" VERSION "\",\"size\":%zu,\"pps\":%.1f,\"sent\":%llu,\"received\":%llu,"
           "\"lost\":%llu,\"rtt_us_mean\":%.2f,\"rtt_us_p50\":%.2f,\"rtt_us_p90\":%.2f,\"rtt_us_p99\":%.2f,"
           "\"rtt_us_p999\":%.2f,\"rtt_us_max\":%.2f,\"cpu_s\":%.6f}\n",
           size, pps, (unsigned long long) sent, (unsigned long long) got,
           (unsigned long long) (sent > got ? sent - got : 0), mean / 1000.0, PCT(0.5), PCT(0.9),
           PCT(0.99), PCT(0.999), got ? (double) rtt[got - 1] / 1000.0 : 0.0, cpu_seconds() - cpu0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: udpprobe blast|sink|echo|ping [options]\n");
        return 2;
    }
    if (!strcmp(argv[1], "--version")) {
        puts("udpprobe " VERSION);
        return 0;
    }
    if (!strcmp(argv[1], "blast")) {
        return mode_blast(argc, argv);
    }
    if (!strcmp(argv[1], "sink")) {
        return mode_sink(argc, argv);
    }
    if (!strcmp(argv[1], "echo")) {
        return mode_echo(argc, argv);
    }
    if (!strcmp(argv[1], "ping")) {
        return mode_ping(argc, argv);
    }
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
}
