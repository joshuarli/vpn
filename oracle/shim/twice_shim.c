#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int HiAE_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *msg, uint8_t *ct,
                 size_t msg_len, const uint8_t *ad, size_t ad_len, uint8_t *tag);
int HiAE_decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *msg, const uint8_t *ct,
                 size_t ct_len, const uint8_t *ad, size_t ad_len, const uint8_t *tag);
int HiAE_mac(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
             uint8_t *tag);

int __open_2(const char *path, int flags);
int __open64_2(const char *path, int flags);
int __openat_2(int dirfd, const char *path, int flags);
int __openat64_2(int dirfd, const char *path, int flags);

#define X __attribute__((visibility("default")))
#define R(name) ({ if (!real_##name) real_##name = (typeof(&name)) dlsym(RTLD_NEXT, #name); real_##name; })

static typeof(&clock_gettime) real_clock_gettime;
static typeof(&gettimeofday) real_gettimeofday;
static typeof(&time) real_time;
static typeof(&poll) real_poll;
static typeof(&ppoll) real_ppoll;
static typeof(&read) real_read;
static typeof(&readv) real_readv;
static typeof(&write) real_write;
static typeof(&writev) real_writev;
static typeof(&recv) real_recv;
static typeof(&recvfrom) real_recvfrom;
static typeof(&recvmsg) real_recvmsg;
static typeof(&send) real_send;
static typeof(&sendto) real_sendto;
static typeof(&sendmsg) real_sendmsg;
static typeof(&close) real_close;
static typeof(&socket) real_socket;
static typeof(&connect) real_connect;
static typeof(&bind) real_bind;
static typeof(&setsockopt) real_setsockopt;
static typeof(&fcntl) real_fcntl;
static typeof(&ioctl) real_ioctl;
static typeof(&open) real_open;
static typeof(&open64) real_open64;
static typeof(&openat) real_openat;
static typeof(&openat64) real_openat64;
static typeof(&__open_2) real___open_2;
static typeof(&__open64_2) real___open64_2;
static typeof(&__openat_2) real___openat_2;
static typeof(&__openat64_2) real___openat64_2;
static typeof(&popen) real_popen;
static typeof(&pclose) real_pclose;
static typeof(&fork) real_fork;
static typeof(&execvp) real_execvp;
static typeof(&execv) real_execv;
static typeof(&execve) real_execve;
static typeof(&execvpe) real_execvpe;
static typeof(&waitpid) real_waitpid;
static typeof(&system) real_system;
static typeof(&posix_spawn) real_posix_spawn;
static typeof(&posix_spawnp) real_posix_spawnp;
static typeof(&signal) real_signal;
static typeof(&sigaction) real_sigaction;
static typeof(&_exit) real__exit;
static typeof(&sleep) real_sleep;
static typeof(&usleep) real_usleep;
static typeof(&nanosleep) real_nanosleep;
static typeof(&clock_nanosleep) real_clock_nanosleep;

enum { K_NONE, K_TUN, K_UDP, K_URANDOM };
enum { E_UDP, E_TUN, E_SIG, E_PERR };
enum { A_VALID, A_BADTAG, A_TRUNC, A_RAW, A_FLIP };

#define MAXFD 4096
#define MAXRULE 128
#define MONO_BASE_SEC 100000LL
#define REAL_BASE_SEC 1700000000LL

struct vfd {
    int                     kind;
    int                     flags;
    int                     fdflags;
    int                     bound;
    int                     connected;
    struct sockaddr_storage peer;
    socklen_t               peerlen;
};

struct ev {
    long long     t_ms;
    int           type;
    int           sig;
    int           fdkind;
    int           revents;
    char          from[128];
    unsigned char rnd[8];
    unsigned long long counter;
    int           auth;
    long          authn;
    unsigned char *data;
    size_t        len;
};

struct dgram {
    unsigned char          *p;
    size_t                  n;
    struct sockaddr_storage from;
    socklen_t               fl;
};

struct erule {
    char call[32];
    int  kind;
    char *path;
    int  nth;
    int  count;
    int  err;
    long shortn;
};

struct crule {
    char  kind[16];
    char *match;
    int   from;
    int   to;
    int   exit_code;
    int   term_sig;
    char *out;
    size_t outlen;
};

struct dnsent {
    char *name;
    char *value;
};

struct shared {
    int err_seen[MAXRULE];
    int rule_seen[MAXRULE];
};

struct sigdisp {
    void *handler;
    int   siginfo;
};

struct popen_ent {
    FILE *fp;
    int   status;
};

static struct vfd vfds[MAXFD];
static struct ev *evs;
static size_t     nev, evi;
static struct dgram *udp_q;
static size_t        udp_qn, udp_qcap, udp_qh;
static struct dgram *tun_q;
static size_t        tun_qn, tun_qcap, tun_qh;
static struct erule erules[MAXRULE];
static int          nerules;
static struct crule crules[MAXRULE];
static int          ncrules;
static struct dnsent dns[256];
static int           ndns;
static struct shared *shm;
static struct sigdisp disp[65];
static struct popen_ent popens[32];
static int pending_err[4];

static int       inited;
static pid_t     root_pid;
static int       out_fd = -1;
static int       verbose;
static long long now_ns;
static long long hang_ns = -1;
static long long mono_base = MONO_BASE_SEC, real_base = REAL_BASE_SEC;
static unsigned long long seed;
static unsigned char *ur_prefix;
static size_t         ur_prefix_len;
static unsigned long long ur_pos;
static unsigned char key[32];
static int           key_set;
static char          tun_name[IFNAMSIZ] = "tun0";
static char          passive_addr[64]   = "0.0.0.0";
static int           active_udp         = -1;

static char  *jb;
static size_t jlen, jcap;

static void jput(const char *s, size_t n)
{
    if (jlen + n + 1 > jcap) {
        size_t nc = jcap ? jcap : 4096;
        while (nc < jlen + n + 1) {
            nc *= 2;
        }
        jb   = realloc(jb, nc);
        jcap = nc;
    }
    memcpy(jb + jlen, s, n);
    jlen += n;
}

static void jprintf(const char *fmt, ...)
{
    char    tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n > 0) {
        jput(tmp, (size_t) n < sizeof tmp ? (size_t) n : sizeof tmp - 1);
    }
}

static void jesc(const char *s, size_t n)
{
    jput("\"", 1);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char) s[i];
        if (c == '"' || c == '\\') {
            char b[2] = { '\\', (char) c };
            jput(b, 2);
        } else if (c < 0x20 || c >= 0x7f) {
            jprintf("\\u%04x", c);
        } else {
            char b = (char) c;
            jput(&b, 1);
        }
    }
    jput("\"", 1);
}

static void jstr(const char *k, const char *s)
{
    jprintf(",\"%s\":", k);
    if (s == NULL) {
        jput("null", 4);
    } else {
        jesc(s, strlen(s));
    }
}

static void jhex(const char *k, const void *p, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    const unsigned char *b = p;
    jprintf(",\"%s\":\"", k);
    for (size_t i = 0; i < n; i++) {
        char two[2] = { hx[b[i] >> 4], hx[b[i] & 15] };
        jput(two, 2);
    }
    jput("\"", 1);
}

static void jint(const char *k, long long v)
{
    jprintf(",\"%s\":%lld", k, v);
}

static void juint(const char *k, unsigned long long v)
{
    jprintf(",\"%s\":%llu", k, v);
}

static void jbool(const char *k, int v)
{
    jprintf(",\"%s\":%s", k, v ? "true" : "false");
}

static void jbegin(const char *ev)
{
    jlen = 0;
    jprintf("{\"t_ms\":%lld,\"ev\":\"%s\"", now_ns / 1000000, ev);
}

static void jend(void)
{
    jput("}\n", 2);
    if (out_fd >= 0) {
        size_t off = 0;
        while (off < jlen) {
            ssize_t w = R(write)(out_fd, jb + off, jlen - off);
            if (w <= 0) {
                break;
            }
            off += (size_t) w;
        }
    }
}

static void die_shim(const char *msg)
{
    jbegin("shim_error");
    jstr("msg", msg);
    jend();
    R(_exit)(125);
}

static void hang(const char *msg)
{
    jbegin("hang");
    jstr("msg", msg);
    jend();
    R(_exit)(124);
}

static void unvirt(const char *call, const char *what)
{
    jbegin("unvirtualized");
    jstr("call", call);
    jstr("what", what);
    jend();
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static unsigned char *unhex(const char *s, size_t *outlen)
{
    size_t n = strcmp(s, "-") == 0 ? 0 : strlen(s);
    if (n % 2) {
        die_shim("odd hex length in script");
    }
    unsigned char *b = malloc(n / 2 + 1);
    for (size_t i = 0; i < n / 2; i++) {
        int h = hexval(s[2 * i]), l = hexval(s[2 * i + 1]);
        if (h < 0 || l < 0) {
            die_shim("bad hex in script");
        }
        b[i] = (unsigned char) (h * 16 + l);
    }
    *outlen = n / 2;
    b[n / 2] = 0;
    return b;
}

static char *unhex_str(const char *s)
{
    size_t n;
    return (char *) unhex(s, &n);
}

static int kind_of(const char *s)
{
    if (strcmp(s, "tun") == 0) {
        return K_TUN;
    }
    if (strcmp(s, "udp") == 0) {
        return K_UDP;
    }
    if (strcmp(s, "urandom") == 0) {
        return K_URANDOM;
    }
    return K_NONE;
}

static const char *kind_name(int k)
{
    switch (k) {
    case K_TUN:
        return "tun";
    case K_UDP:
        return "udp";
    case K_URANDOM:
        return "urandom";
    default:
        return "none";
    }
}

static int parse_addr(const char *s, struct sockaddr_storage *ss, socklen_t *len)
{
    char        host[96];
    const char *port;
    memset(ss, 0, sizeof *ss);
    if (s[0] == '[') {
        const char *e = strchr(s, ']');
        if (e == NULL || e[1] != ':') {
            return -1;
        }
        snprintf(host, sizeof host, "%.*s", (int) (e - s - 1), s + 1);
        port = e + 2;
        struct sockaddr_in6 *a = (struct sockaddr_in6 *) ss;
        a->sin6_family         = AF_INET6;
        a->sin6_port           = htons((uint16_t) atoi(port));
        if (inet_pton(AF_INET6, host, &a->sin6_addr) != 1) {
            return -1;
        }
        *len = sizeof *a;
        return 0;
    }
    const char *c = strrchr(s, ':');
    if (c == NULL) {
        return -1;
    }
    snprintf(host, sizeof host, "%.*s", (int) (c - s), s);
    struct sockaddr_in *a = (struct sockaddr_in *) ss;
    a->sin_family         = AF_INET;
    a->sin_port           = htons((uint16_t) atoi(c + 1));
    if (inet_pton(AF_INET, host, &a->sin_addr) != 1) {
        return -1;
    }
    *len = sizeof *a;
    return 0;
}

static void fmt_addr(const struct sockaddr *sa, socklen_t len, char *out, size_t cap)
{
    char host[96];
    if (sa == NULL || len == 0) {
        snprintf(out, cap, "-");
    } else if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *) sa;
        inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
        snprintf(out, cap, "%s:%u", host, ntohs(a->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *) sa;
        inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
        snprintf(out, cap, "[%s]:%u", host, ntohs(a->sin6_port));
    } else {
        snprintf(out, cap, "family-%d", sa->sa_family);
    }
}

static int addr_eq(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family) {
        return 0;
    }
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const void *) a, *y = (const void *) b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const void *) a, *y = (const void *) b;
        return x->sin6_port == y->sin6_port && memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0;
    }
    return 0;
}

static long long next_ev_ns(void)
{
    return evi < nev ? evs[evi].t_ms * 1000000LL : -1;
}

static void set_now(long long n)
{
    if (n > now_ns) {
        now_ns = n;
    }
    if (hang_ns >= 0 && now_ns > hang_ns) {
        hang("virtual time limit exceeded");
    }
}

static int is_vsig(int s)
{
    return s == SIGHUP || s == SIGINT || s == SIGQUIT || s == SIGUSR1 || s == SIGUSR2 ||
           s == SIGTERM;
}

static void die_by_signal(int sig)
{
    sigset_t set;
    R(signal)(sig, SIG_DFL);
    sigemptyset(&set);
    sigaddset(&set, sig);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
    raise(sig);
    R(_exit)(128 + sig);
}

static int deliver_signal(int sig)
{
    struct sigdisp d = disp[sig];
    jbegin("signal_delivered");
    jint("sig", sig);
    jstr("disp", d.handler == SIG_DFL ? "default" : d.handler == SIG_IGN ? "ignore" : "handler");
    jend();
    if (d.handler == SIG_IGN) {
        return 0;
    }
    if (d.handler == SIG_DFL) {
        die_by_signal(sig);
    }
    if (d.siginfo) {
        siginfo_t si;
        memset(&si, 0, sizeof si);
        si.si_signo = sig;
        ((void (*)(int, siginfo_t *, void *)) d.handler)(sig, &si, NULL);
    } else {
        ((void (*)(int)) d.handler)(sig);
    }
    return 1;
}

static void q_push(struct dgram **q, size_t *n, size_t *cap, struct dgram d)
{
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 64;
        *q   = realloc(*q, *cap * sizeof **q);
    }
    (*q)[(*n)++] = d;
}

static int udp_alive(void)
{
    return active_udp >= 0 && vfds[active_udp].kind == K_UDP;
}

static int tun_alive(void)
{
    for (int i = 0; i < MAXFD; i++) {
        if (vfds[i].kind == K_TUN) {
            return 1;
        }
    }
    return 0;
}

static void build_udp_in(struct ev *e)
{
    struct dgram d;
    memset(&d, 0, sizeof d);
    if (parse_addr(e->from, &d.from, &d.fl) != 0) {
        die_shim("bad udp_in source address");
    }
    if (e->auth == A_RAW) {
        d.p = malloc(e->len + 1);
        memcpy(d.p, e->data, e->len);
        d.n = e->len;
    } else {
        uint8_t nonce[16], tag[16];
        memcpy(nonce, e->rnd, 8);
        for (int i = 0; i < 8; i++) {
            nonce[8 + i] = (uint8_t) (e->counter >> (8 * i));
        }
        size_t L = e->len;
        d.p      = malloc(32 + L + 1);
        memcpy(d.p, nonce, 16);
        const uint8_t zero[32] = { 0 };
        if (key_set) {
            if (HiAE_encrypt(key, nonce, e->data, d.p + 16, L, NULL, 0, tag) != 0) {
                die_shim("HiAE_encrypt failed");
            }
        } else {
            memcpy(d.p + 16, e->data, L);
            if (HiAE_mac(zero, nonce, e->data, L, tag) != 0) {
                die_shim("HiAE_mac failed");
            }
        }
        if (e->auth == A_BADTAG) {
            tag[0] ^= 1;
        }
        memcpy(d.p + 16 + L, tag, 16);
        d.n = 32 + L;
        if (e->auth == A_TRUNC && (size_t) e->authn < d.n) {
            d.n = (size_t) e->authn;
        }
        if (e->auth == A_FLIP && (size_t) e->authn < d.n) {
            d.p[e->authn] ^= 1;
        }
    }
    if (!udp_alive()) {
        jbegin("udp_drop");
        jstr("reason", "no_socket");
        jstr("from", e->from);
        jend();
        free(d.p);
        return;
    }
    q_push(&udp_q, &udp_qn, &udp_qcap, d);
}

static int pump(void)
{
    int signalled = 0;
    while (evi < nev && evs[evi].t_ms * 1000000LL <= now_ns) {
        struct ev *e = &evs[evi++];
        switch (e->type) {
        case E_UDP:
            build_udp_in(e);
            break;
        case E_TUN:
            if (tun_alive()) {
                struct dgram d;
                memset(&d, 0, sizeof d);
                d.p = malloc(e->len + 1);
                memcpy(d.p, e->data, e->len);
                d.n = e->len;
                q_push(&tun_q, &tun_qn, &tun_qcap, d);
            } else {
                jbegin("tun_drop");
                jstr("reason", "no_device");
                jend();
            }
            break;
        case E_PERR:
            pending_err[e->fdkind] |= e->revents;
            break;
        case E_SIG:
            if (deliver_signal(e->sig)) {
                signalled = 1;
            }
            break;
        }
    }
    return signalled;
}

static int udp_peek(void)
{
    while (udp_qh < udp_qn) {
        struct dgram *d = &udp_q[udp_qh];
        if (udp_alive() && vfds[active_udp].connected &&
            !addr_eq(&d->from, &vfds[active_udp].peer)) {
            char from[128];
            fmt_addr((struct sockaddr *) &d->from, d->fl, from, sizeof from);
            jbegin("udp_drop");
            jstr("reason", "peer_mismatch");
            jstr("from", from);
            jend();
            free(d->p);
            udp_qh++;
            continue;
        }
        return 1;
    }
    return 0;
}

static int tun_peek(void)
{
    return tun_qh < tun_qn;
}

static int wait_ready(int kind)
{
    for (;;) {
        if (pump()) {
            return EINTR;
        }
        if (kind == K_UDP ? udp_peek() : tun_peek()) {
            return 0;
        }
        long long n = next_ev_ns();
        if (n < 0) {
            hang("blocking read with no future events");
        }
        set_now(n);
    }
}

struct inj {
    int  hit;
    int  err;
    long shortn;
};

static struct inj inject(const char *call, int kind, const char *path)
{
    struct inj r = { 0, 0, -1 };
    for (int i = 0; i < nerules; i++) {
        struct erule *e = &erules[i];
        if (strcmp(e->call, call) != 0) {
            continue;
        }
        if (e->kind != K_NONE && e->kind != kind) {
            continue;
        }
        if (e->path != NULL && (path == NULL || strcmp(e->path, path) != 0)) {
            continue;
        }
        int seen = ++shm->err_seen[i];
        if (seen >= e->nth && (e->count == 0 || seen < e->nth + e->count)) {
            r.hit    = 1;
            r.err    = e->err;
            r.shortn = e->shortn;
            return r;
        }
    }
    return r;
}

static int vk(int fd)
{
    return (inited && fd >= 0 && fd < MAXFD) ? vfds[fd].kind : K_NONE;
}

static int alloc_vfd(int kind, int flags)
{
    int fd = R(open)("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (fd >= MAXFD) {
        R(close)(fd);
        errno = EMFILE;
        return -1;
    }
    memset(&vfds[fd], 0, sizeof vfds[fd]);
    vfds[fd].kind  = kind;
    vfds[fd].flags = O_RDWR | flags;
    return fd;
}

static unsigned long long splitmix_block(unsigned long long k)
{
    unsigned long long z = seed + (k + 1) * 0x9E3779B97F4A7C15ULL;
    z                    = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z                    = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void urandom_fill(unsigned char *b, size_t n)
{
    for (size_t i = 0; i < n; i++, ur_pos++) {
        if (ur_pos < ur_prefix_len) {
            b[i] = ur_prefix[ur_pos];
        } else {
            unsigned long long p = ur_pos - ur_prefix_len;
            b[i] = (unsigned char) (splitmix_block(p / 8) >> (8 * (p % 8)));
        }
    }
}

static const char *signame(int s)
{
    switch (s) {
    case SIGHUP:
        return "SIGHUP";
    case SIGINT:
        return "SIGINT";
    case SIGQUIT:
        return "SIGQUIT";
    case SIGUSR1:
        return "SIGUSR1";
    case SIGUSR2:
        return "SIGUSR2";
    case SIGTERM:
        return "SIGTERM";
    default:
        return "SIG?";
    }
}

static const char *disp_name(void *h)
{
    return h == SIG_DFL ? "SIG_DFL" : h == SIG_IGN ? "SIG_IGN" : "handler";
}

static unsigned char *flatten(const struct iovec *iov, size_t cnt, size_t *len)
{
    size_t n = 0;
    for (size_t i = 0; i < cnt; i++) {
        n += iov[i].iov_len;
    }
    unsigned char *b = malloc(n + 1);
    size_t         o = 0;
    for (size_t i = 0; i < cnt; i++) {
        memcpy(b + o, iov[i].iov_base, iov[i].iov_len);
        o += iov[i].iov_len;
    }
    *len = n;
    return b;
}

static size_t scatter(const struct iovec *iov, size_t cnt, const unsigned char *src, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < cnt && o < n; i++) {
        size_t c = iov[i].iov_len < n - o ? iov[i].iov_len : n - o;
        memcpy(iov[i].iov_base, src + o, c);
        o += c;
    }
    return o;
}

static void emit_udp_out(const char *via, const unsigned char *raw, size_t n, const char *to)
{
    jbegin("udp_out");
    jstr("via", via);
    jstr("to", to);
    jhex("raw", raw, n);
    if (n >= 32) {
        size_t        L  = n - 32;
        unsigned char *pt = malloc(L + 1);
        int           ok;
        unsigned long long counter = 0;
        for (int i = 0; i < 8; i++) {
            counter |= (unsigned long long) raw[8 + i] << (8 * i);
        }
        if (key_set) {
            ok = HiAE_decrypt(key, raw, pt, raw + 16, L, NULL, 0, raw + 16 + L) == 0;
        } else {
            const uint8_t zero[32] = { 0 };
            uint8_t       tag[16];
            HiAE_mac(zero, raw, raw + 16, L, tag);
            ok = memcmp(tag, raw + 16 + L, 16) == 0;
            memcpy(pt, raw + 16, L);
        }
        unsigned char ff[16];
        memset(ff, 0xff, sizeof ff);
        jhex("random", raw, 8);
        juint("counter", counter);
        jbool("probe", memcmp(raw, ff, 16) == 0);
        jbool("tag_ok", ok);
        juint("payload_len", L);
        if (memcmp(raw, ff, 16) != 0) {
            jhex("payload", ok ? pt : raw + 16, L);
        }
        free(pt);
    } else {
        jbool("short", 1);
    }
    jend();
}

static long udp_send(int fd, const unsigned char *buf, size_t n, const struct sockaddr *to,
                     socklen_t tolen, const char *via)
{
    struct vfd *v = &vfds[fd];
    char        dest[128];
    struct inj  in = inject(via, K_UDP, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    if (in.hit && in.shortn >= 0 && (size_t) in.shortn < n) {
        n = (size_t) in.shortn;
    }
    if (to != NULL && tolen > 0) {
        if (v->connected && !addr_eq((const struct sockaddr_storage *) to, &v->peer)) {
            errno = EISCONN;
            return -1;
        }
        fmt_addr(to, tolen, dest, sizeof dest);
    } else if (v->connected) {
        fmt_addr((struct sockaddr *) &v->peer, v->peerlen, dest, sizeof dest);
    } else {
        errno = EDESTADDRREQ;
        return -1;
    }
    emit_udp_out(via, buf, n, dest);
    return (long) n;
}

static long udp_recv(int fd, unsigned char *buf, size_t cap, int nonblock, struct sockaddr *from,
                     socklen_t *fromlen, int *eno)
{
    (void) fd;
    if (!udp_peek()) {
        if (nonblock) {
            *eno = EAGAIN;
            return -1;
        }
        int e = wait_ready(K_UDP);
        if (e) {
            *eno = e;
            return -1;
        }
        udp_peek();
        if (udp_qh >= udp_qn) {
            *eno = EAGAIN;
            return -1;
        }
    }
    struct dgram *d = &udp_q[udp_qh++];
    size_t        c = d->n < cap ? d->n : cap;
    memcpy(buf, d->p, c);
    if (from != NULL && fromlen != NULL) {
        socklen_t l = *fromlen < d->fl ? *fromlen : d->fl;
        memcpy(from, &d->from, l);
        *fromlen = d->fl;
    }
    free(d->p);
    return (long) c;
}

static long tun_recv(unsigned char *buf, size_t cap, int nonblock, int *eno)
{
    if (!tun_peek()) {
        if (nonblock) {
            *eno = EAGAIN;
            return -1;
        }
        int e = wait_ready(K_TUN);
        if (e) {
            *eno = e;
            return -1;
        }
    }
    struct dgram *d = &tun_q[tun_qh++];
    size_t        c = d->n < cap ? d->n : cap;
    memcpy(buf, d->p, c);
    free(d->p);
    return (long) c;
}

static long tun_send(const unsigned char *buf, size_t n, const char *via)
{
    struct inj in = inject(via, K_TUN, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    if (in.hit && in.shortn >= 0 && (size_t) in.shortn < n) {
        n = (size_t) in.shortn;
    }
    jbegin("tun_out");
    jstr("via", via);
    juint("len", n);
    jhex("data", buf, n);
    jend();
    return (long) n;
}

static long do_read_like(int fd, void *buf, size_t n, const char *call, int nonblock)
{
    int kind = vk(fd);
    struct inj in = inject(call, kind, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    if (in.hit && in.shortn >= 0 && (size_t) in.shortn < n) {
        n = (size_t) in.shortn;
    }
    int  eno = 0;
    long r;
    switch (kind) {
    case K_TUN:
        r = tun_recv(buf, n, nonblock || (vfds[fd].flags & O_NONBLOCK), &eno);
        break;
    case K_UDP:
        r = udp_recv(fd, buf, n, nonblock || (vfds[fd].flags & O_NONBLOCK), NULL, NULL, &eno);
        break;
    default:
        urandom_fill(buf, n);
        return (long) n;
    }
    if (r < 0) {
        errno = eno;
    }
    return r;
}

X int clock_gettime(clockid_t id, struct timespec *ts)
{
    if (!inited || id == CLOCK_PROCESS_CPUTIME_ID || id == CLOCK_THREAD_CPUTIME_ID) {
        return R(clock_gettime)(id, ts);
    }
    long long base = (id == CLOCK_REALTIME || id == CLOCK_REALTIME_COARSE) ? real_base : mono_base;
    long long ns   = base * 1000000000LL + now_ns;
    ts->tv_sec     = ns / 1000000000LL;
    ts->tv_nsec    = ns % 1000000000LL;
    return 0;
}

X int gettimeofday(struct timeval *tv, void *tz)
{
    if (!inited) {
        return R(gettimeofday)(tv, tz);
    }
    long long ns = real_base * 1000000000LL + now_ns;
    tv->tv_sec   = ns / 1000000000LL;
    tv->tv_usec  = (ns % 1000000000LL) / 1000;
    return 0;
}

X time_t time(time_t *t)
{
    if (!inited) {
        return R(time)(t);
    }
    time_t v = (time_t) ((real_base * 1000000000LL + now_ns) / 1000000000LL);
    if (t != NULL) {
        *t = v;
    }
    return v;
}

static int sleep_ns(long long ns, long long *remain)
{
    long long deadline = now_ns + ns;
    for (;;) {
        if (pump()) {
            *remain = deadline > now_ns ? deadline - now_ns : 0;
            return EINTR;
        }
        long long nx = next_ev_ns();
        if (nx < 0 || nx > deadline) {
            set_now(deadline);
            *remain = 0;
            return 0;
        }
        set_now(nx);
    }
}

X unsigned int sleep(unsigned int sec)
{
    if (!inited) {
        return R(sleep)(sec);
    }
    jbegin("sleep");
    jint("ms", (long long) sec * 1000);
    jend();
    long long rem;
    int       e = sleep_ns((long long) sec * 1000000000LL, &rem);
    return e ? (unsigned int) ((rem + 999999999LL) / 1000000000LL) : 0;
}

X int usleep(useconds_t us)
{
    if (!inited) {
        return R(usleep)(us);
    }
    jbegin("sleep");
    jint("ms", (long long) us / 1000);
    jend();
    long long rem;
    int       e = sleep_ns((long long) us * 1000LL, &rem);
    if (e) {
        errno = e;
        return -1;
    }
    return 0;
}

X int nanosleep(const struct timespec *req, struct timespec *rem)
{
    if (!inited) {
        return R(nanosleep)(req, rem);
    }
    long long ns = (long long) req->tv_sec * 1000000000LL + req->tv_nsec;
    jbegin("sleep");
    jint("ms", ns / 1000000);
    jend();
    long long left;
    int       e = sleep_ns(ns, &left);
    if (e) {
        if (rem != NULL) {
            rem->tv_sec  = left / 1000000000LL;
            rem->tv_nsec = left % 1000000000LL;
        }
        errno = e;
        return -1;
    }
    return 0;
}

X int clock_nanosleep(clockid_t id, int flags, const struct timespec *req, struct timespec *rem)
{
    if (!inited) {
        return R(clock_nanosleep)(id, flags, req, rem);
    }
    long long ns = (long long) req->tv_sec * 1000000000LL + req->tv_nsec;
    if (flags & TIMER_ABSTIME) {
        long long base = (id == CLOCK_REALTIME) ? real_base : mono_base;
        ns -= base * 1000000000LL + now_ns;
        if (ns < 0) {
            ns = 0;
        }
    }
    jbegin("sleep");
    jint("ms", ns / 1000000);
    jend();
    long long left;
    int       e = sleep_ns(ns, &left);
    if (e) {
        if (rem != NULL && !(flags & TIMER_ABSTIME)) {
            rem->tv_sec  = left / 1000000000LL;
            rem->tv_nsec = left % 1000000000LL;
        }
        return e;
    }
    return 0;
}

static int poll_compute(struct pollfd *fds, nfds_t n)
{
    int cnt = 0;
    for (nfds_t i = 0; i < n; i++) {
        struct pollfd *p = &fds[i];
        p->revents       = 0;
        if (p->fd < 0) {
            continue;
        }
        int k = vk(p->fd);
        if (k == K_NONE) {
            struct pollfd t = *p;
            R(poll)(&t, 1, 0);
            p->revents = t.revents;
        } else {
            short rv = 0;
            if ((p->events & POLLIN) && ((k == K_UDP && udp_peek()) || (k == K_TUN && tun_peek()) ||
                                         k == K_URANDOM)) {
                rv |= POLLIN;
            }
            if (p->events & POLLOUT) {
                rv |= POLLOUT;
            }
            if (pending_err[k]) {
                rv |= (short) pending_err[k];
                pending_err[k] = 0;
            }
            p->revents = rv;
        }
        if (p->revents) {
            cnt++;
        }
    }
    return cnt;
}

static int do_poll(struct pollfd *fds, nfds_t n, long long timeout_ms)
{
    struct inj in = inject("poll", K_NONE, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    long long deadline = timeout_ms < 0 ? -1 : now_ns + timeout_ms * 1000000LL;
    for (;;) {
        if (pump()) {
            errno = EINTR;
            return -1;
        }
        int cnt = poll_compute(fds, n);
        if (cnt > 0 || timeout_ms == 0) {
            if (verbose) {
                jbegin("poll");
                jint("timeout_ms", timeout_ms);
                jint("ret", cnt);
                jend();
            }
            return cnt;
        }
        long long nx = next_ev_ns();
        if (nx < 0 || (deadline >= 0 && nx > deadline)) {
            if (deadline < 0) {
                hang("poll blocks forever with no future events");
            }
            set_now(deadline);
            if (verbose) {
                jbegin("poll");
                jint("timeout_ms", timeout_ms);
                jint("ret", 0);
                jend();
            }
            return 0;
        }
        set_now(nx);
    }
}

static int has_virtual(const struct pollfd *fds, nfds_t n)
{
    for (nfds_t i = 0; i < n; i++) {
        if (vk(fds[i].fd) != K_NONE) {
            return 1;
        }
    }
    return 0;
}

X int poll(struct pollfd *fds, nfds_t n, int timeout)
{
    if (!inited || !has_virtual(fds, n)) {
        return R(poll)(fds, n, timeout);
    }
    return do_poll(fds, n, timeout);
}

X int ppoll(struct pollfd *fds, nfds_t n, const struct timespec *ts, const sigset_t *mask)
{
    if (!inited || !has_virtual(fds, n)) {
        return R(ppoll)(fds, n, ts, mask);
    }
    long long ms = ts == NULL ? -1 : (long long) ts->tv_sec * 1000 + (ts->tv_nsec + 999999) / 1000000;
    return do_poll(fds, n, ms);
}

X ssize_t read(int fd, void *buf, size_t n)
{
    if (vk(fd) == K_NONE) {
        return R(read)(fd, buf, n);
    }
    return do_read_like(fd, buf, n, "read", 0);
}

X ssize_t readv(int fd, const struct iovec *iov, int cnt)
{
    if (vk(fd) == K_NONE) {
        return R(readv)(fd, iov, cnt);
    }
    size_t cap = 0;
    for (int i = 0; i < cnt; i++) {
        cap += iov[i].iov_len;
    }
    unsigned char *b = malloc(cap + 1);
    long           r = do_read_like(fd, b, cap, "readv", 0);
    if (r > 0) {
        scatter(iov, (size_t) cnt, b, (size_t) r);
    }
    free(b);
    return r;
}

X ssize_t write(int fd, const void *buf, size_t n)
{
    int k = vk(fd);
    if (k == K_NONE) {
        return R(write)(fd, buf, n);
    }
    if (k == K_TUN) {
        return tun_send(buf, n, "write");
    }
    if (k == K_UDP) {
        return udp_send(fd, buf, n, NULL, 0, "write");
    }
    errno = EBADF;
    return -1;
}

X ssize_t writev(int fd, const struct iovec *iov, int cnt)
{
    int k = vk(fd);
    if (k == K_NONE) {
        return R(writev)(fd, iov, cnt);
    }
    size_t         n;
    unsigned char *b = flatten(iov, (size_t) cnt, &n);
    long           r;
    if (k == K_TUN) {
        r = tun_send(b, n, "writev");
    } else if (k == K_UDP) {
        r = udp_send(fd, b, n, NULL, 0, "writev");
    } else {
        errno = EBADF;
        r     = -1;
    }
    free(b);
    return r;
}

X ssize_t recv(int fd, void *buf, size_t n, int flags)
{
    if (vk(fd) != K_UDP) {
        return R(recv)(fd, buf, n, flags);
    }
    struct inj in = inject("recv", K_UDP, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    int  eno = 0;
    long r   = udp_recv(fd, buf, n, (flags & MSG_DONTWAIT) || (vfds[fd].flags & O_NONBLOCK), NULL,
                        NULL, &eno);
    if (r < 0) {
        errno = eno;
    }
    return r;
}

X ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *from, socklen_t *fl)
{
    if (vk(fd) != K_UDP) {
        return R(recvfrom)(fd, buf, n, flags, from, fl);
    }
    struct inj in = inject("recvfrom", K_UDP, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    int  eno = 0;
    long r   = udp_recv(fd, buf, n, (flags & MSG_DONTWAIT) || (vfds[fd].flags & O_NONBLOCK), from,
                        fl, &eno);
    if (r < 0) {
        errno = eno;
    }
    return r;
}

X ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
    if (vk(fd) != K_UDP) {
        return R(recvmsg)(fd, msg, flags);
    }
    struct inj in = inject("recvmsg", K_UDP, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    size_t cap = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        cap += msg->msg_iov[i].iov_len;
    }
    unsigned char *b   = malloc(cap + 1);
    int            eno = 0;
    socklen_t      fl  = msg->msg_namelen;
    long           r   = udp_recv(fd, b, cap, (flags & MSG_DONTWAIT) || (vfds[fd].flags & O_NONBLOCK),
                                  msg->msg_name, msg->msg_name ? &fl : NULL, &eno);
    if (r >= 0) {
        scatter(msg->msg_iov, msg->msg_iovlen, b, (size_t) r);
        if (msg->msg_name) {
            msg->msg_namelen = fl;
        }
        msg->msg_controllen = 0;
        msg->msg_flags      = 0;
    } else {
        errno = eno;
    }
    free(b);
    return r;
}

X ssize_t send(int fd, const void *buf, size_t n, int flags)
{
    if (vk(fd) != K_UDP) {
        return R(send)(fd, buf, n, flags);
    }
    return udp_send(fd, buf, n, NULL, 0, "send");
}

X ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *to,
                 socklen_t tolen)
{
    if (vk(fd) != K_UDP) {
        return R(sendto)(fd, buf, n, flags, to, tolen);
    }
    return udp_send(fd, buf, n, to, tolen, "sendto");
}

X ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
    if (vk(fd) != K_UDP) {
        return R(sendmsg)(fd, msg, flags);
    }
    size_t         n;
    unsigned char *b = flatten(msg->msg_iov, msg->msg_iovlen, &n);
    long           r = udp_send(fd, b, n, msg->msg_name, msg->msg_namelen, "sendmsg");
    free(b);
    return r;
}

X int close(int fd)
{
    int k = vk(fd);
    if (k != K_NONE) {
        if (verbose) {
            jbegin("close");
            jstr("role", kind_name(k));
            jend();
        }
        memset(&vfds[fd], 0, sizeof vfds[fd]);
        if (active_udp == fd) {
            active_udp = -1;
        }
    }
    return R(close)(fd);
}

X int socket(int domain, int type, int proto)
{
    if (!inited) {
        return R(socket)(domain, type, proto);
    }
    int base = type & 0xff;
    int fl   = 0;
    if (type & SOCK_NONBLOCK) {
        fl |= O_NONBLOCK;
    }
    jbegin("socket");
    jstr("domain", domain == AF_INET ? "AF_INET" : domain == AF_INET6 ? "AF_INET6" : "AF_OTHER");
    jint("domain_num", domain);
    jstr("type", base == SOCK_DGRAM ? "SOCK_DGRAM" : base == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_OTHER");
    jint("protocol", proto);
    jend();
    struct inj in = inject("socket", K_UDP, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    if ((domain != AF_INET && domain != AF_INET6) || base != SOCK_DGRAM) {
        unvirt("socket", "only AF_INET/AF_INET6 SOCK_DGRAM is virtualized");
        errno = EAFNOSUPPORT;
        return -1;
    }
    return alloc_vfd(K_UDP, fl);
}

X int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (vk(fd) != K_UDP) {
        return R(connect)(fd, addr, len);
    }
    char a[128];
    fmt_addr(addr, len, a, sizeof a);
    jbegin("connect");
    jstr("addr", a);
    jend();
    struct inj in = inject("connect", K_UDP, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    memset(&vfds[fd].peer, 0, sizeof vfds[fd].peer);
    memcpy(&vfds[fd].peer, addr, len < sizeof vfds[fd].peer ? len : sizeof vfds[fd].peer);
    vfds[fd].peerlen   = len;
    vfds[fd].connected = 1;
    active_udp         = fd;
    return 0;
}

X int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    if (vk(fd) != K_UDP) {
        return R(bind)(fd, addr, len);
    }
    char a[128];
    fmt_addr(addr, len, a, sizeof a);
    jbegin("bind");
    jstr("addr", a);
    jend();
    struct inj in = inject("bind", K_UDP, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    vfds[fd].bound = 1;
    active_udp     = fd;
    return 0;
}

X int setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
    if (vk(fd) != K_UDP) {
        return R(setsockopt)(fd, level, name, val, len);
    }
    jbegin("setsockopt");
    jint("level", level);
    jint("name", name);
    jhex("value", val, len < 64 ? len : 64);
    jend();
    struct inj in = inject("setsockopt", K_UDP, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    return 0;
}

X int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);
    int k = vk(fd);
    if (k == K_NONE) {
        return R(fcntl)(fd, cmd, arg);
    }
    const char *name = cmd == F_GETFL ? "F_GETFL" : cmd == F_SETFL ? "F_SETFL"
                     : cmd == F_GETFD ? "F_GETFD" : cmd == F_SETFD ? "F_SETFD" : NULL;
    if (name == NULL) {
        unvirt("fcntl", "unsupported command on virtual fd");
        errno = EINVAL;
        return -1;
    }
    jbegin("fcntl");
    jstr("role", kind_name(k));
    jstr("cmd", name);
    if (cmd == F_SETFL || cmd == F_SETFD) {
        jint("arg", arg);
    }
    jend();
    struct inj in = inject("fcntl", k, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    switch (cmd) {
    case F_GETFL:
        return vfds[fd].flags;
    case F_SETFL:
        vfds[fd].flags = (int) arg;
        return 0;
    case F_GETFD:
        return vfds[fd].fdflags;
    default:
        vfds[fd].fdflags = (int) arg;
        return 0;
    }
}

X int ioctl(int fd, unsigned long req, ...)
{
    va_list ap;
    va_start(ap, req);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    int k = vk(fd);
    if (k == K_NONE) {
        return R(ioctl)(fd, req, arg);
    }
    struct inj in = inject("ioctl", k, NULL);
    struct ifreq *ifr = arg;
    if (req == TUNSETIFF) {
        char wanted[IFNAMSIZ + 1];
        snprintf(wanted, sizeof wanted, "%.*s", IFNAMSIZ, ifr->ifr_name);
        jbegin("ioctl");
        jstr("role", kind_name(k));
        jstr("req", "TUNSETIFF");
        jstr("ifname", wanted);
        jint("flags", ifr->ifr_flags);
        jend();
        if (in.hit && in.err > 0) {
            errno = in.err;
            return -1;
        }
        if (wanted[0] == 0 || strstr(wanted, "%d") != NULL) {
            snprintf(ifr->ifr_name, IFNAMSIZ, "%s", tun_name);
        }
        return 0;
    }
    if (req == SIOCSIFMTU) {
        char name[IFNAMSIZ + 1];
        snprintf(name, sizeof name, "%.*s", IFNAMSIZ, ifr->ifr_name);
        jbegin("ioctl");
        jstr("role", kind_name(k));
        jstr("req", "SIOCSIFMTU");
        jstr("ifname", name);
        jint("mtu", ifr->ifr_mtu);
        jend();
        if (in.hit && in.err > 0) {
            errno = in.err;
            return -1;
        }
        return 0;
    }
    if (req == FIONBIO) {
        int on = *(int *) arg;
        jbegin("ioctl");
        jstr("role", kind_name(k));
        jstr("req", "FIONBIO");
        jint("arg", on);
        jend();
        if (on) {
            vfds[fd].flags |= O_NONBLOCK;
        } else {
            vfds[fd].flags &= ~O_NONBLOCK;
        }
        return 0;
    }
    char rb[32];
    snprintf(rb, sizeof rb, "0x%lx", req);
    unvirt("ioctl", rb);
    errno = ENOTTY;
    return -1;
}

static int open_virtual(const char *path, int flags)
{
    if (!inited || path == NULL) {
        return -2;
    }
    int kind;
    if (strcmp(path, "/dev/net/tun") == 0) {
        kind = K_TUN;
    } else if (strcmp(path, "/dev/urandom") == 0 || strcmp(path, "/dev/random") == 0) {
        kind = K_URANDOM;
    } else {
        return -2;
    }
    jbegin("open");
    jstr("path", path);
    jint("flags", flags);
    jend();
    struct inj in = inject("open", kind, path);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    return alloc_vfd(kind, flags & O_NONBLOCK);
}

X int open(const char *path, int flags, ...)
{
    mode_t  mode = 0;
    va_list ap;
    va_start(ap, flags);
    if (flags & (O_CREAT | O_TMPFILE)) {
        mode = va_arg(ap, mode_t);
    }
    va_end(ap);
    int v = open_virtual(path, flags);
    return v != -2 ? v : R(open)(path, flags, mode);
}

X int open64(const char *path, int flags, ...)
{
    mode_t  mode = 0;
    va_list ap;
    va_start(ap, flags);
    if (flags & (O_CREAT | O_TMPFILE)) {
        mode = va_arg(ap, mode_t);
    }
    va_end(ap);
    int v = open_virtual(path, flags);
    return v != -2 ? v : R(open64)(path, flags, mode);
}

X int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t  mode = 0;
    va_list ap;
    va_start(ap, flags);
    if (flags & (O_CREAT | O_TMPFILE)) {
        mode = va_arg(ap, mode_t);
    }
    va_end(ap);
    int v = open_virtual(path, flags);
    return v != -2 ? v : R(openat)(dirfd, path, flags, mode);
}

X int openat64(int dirfd, const char *path, int flags, ...)
{
    mode_t  mode = 0;
    va_list ap;
    va_start(ap, flags);
    if (flags & (O_CREAT | O_TMPFILE)) {
        mode = va_arg(ap, mode_t);
    }
    va_end(ap);
    int v = open_virtual(path, flags);
    return v != -2 ? v : R(openat64)(dirfd, path, flags, mode);
}

X int __open_2(const char *path, int flags)
{
    int v = open_virtual(path, flags);
    return v != -2 ? v : R(__open_2)(path, flags);
}

X int __open64_2(const char *path, int flags)
{
    int v = open_virtual(path, flags);
    return v != -2 ? v : R(__open64_2)(path, flags);
}

X int __openat_2(int dirfd, const char *path, int flags)
{
    int v = open_virtual(path, flags);
    return v != -2 ? v : R(__openat_2)(dirfd, path, flags);
}

X int __openat64_2(int dirfd, const char *path, int flags)
{
    int v = open_virtual(path, flags);
    return v != -2 ? v : R(__openat64_2)(dirfd, path, flags);
}

static struct crule *find_rule(const char *kind, const char *text)
{
    for (int i = 0; i < ncrules; i++) {
        struct crule *r = &crules[i];
        if (strcmp(r->kind, "any") != 0 && strcmp(r->kind, kind) != 0) {
            continue;
        }
        if (r->match != NULL && strstr(text, r->match) == NULL) {
            continue;
        }
        int seen = ++shm->rule_seen[i];
        if (seen >= r->from && (r->to == 0 || seen <= r->to)) {
            return r;
        }
    }
    return NULL;
}

static char *join_argv(char *const argv[])
{
    size_t n = 1;
    for (int i = 0; argv && argv[i]; i++) {
        n += strlen(argv[i]) + 1;
    }
    char *s = malloc(n);
    s[0]    = 0;
    for (int i = 0; argv && argv[i]; i++) {
        if (i) {
            strcat(s, " ");
        }
        strcat(s, argv[i]);
    }
    return s;
}

static void jargv(char *const argv[])
{
    jput(",\"argv\":[", 9);
    for (int i = 0; argv && argv[i]; i++) {
        if (i) {
            jput(",", 1);
        }
        jesc(argv[i], strlen(argv[i]));
    }
    jput("]", 1);
}

static int fd_is_null(int fd)
{
    char    p[64], t[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(p, t, sizeof t - 1);
    if (n < 0) {
        return 0;
    }
    t[n] = 0;
    return strcmp(t, "/dev/null") == 0;
}

static int wait_status_of(struct crule *r)
{
    if (r == NULL) {
        return 0;
    }
    return r->term_sig ? r->term_sig : (r->exit_code & 0xff) << 8;
}

__attribute__((noreturn)) static void child_exit(struct crule *r)
{
    if (r != NULL && r->term_sig) {
        die_by_signal(r->term_sig);
    }
    R(_exit)(r == NULL ? 0 : r->exit_code);
    abort();
}

static int exec_common(const char *via, const char *file, char *const argv[])
{
    struct inj in = inject(via, K_NONE, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    char         *joined = join_argv(argv);
    struct crule *r      = find_rule("exec", joined);
    free(joined);
    jbegin("cmd");
    jstr("via", via);
    jstr("file", file);
    jargv(argv);
    jbool("stdout_null", fd_is_null(1));
    jbool("stderr_null", fd_is_null(2));
    jend();
    child_exit(r);
}

X int execvp(const char *file, char *const argv[])
{
    if (!inited) {
        return R(execvp)(file, argv);
    }
    return exec_common("execvp", file, argv);
}

X int execv(const char *file, char *const argv[])
{
    if (!inited) {
        return R(execv)(file, argv);
    }
    return exec_common("execv", file, argv);
}

X int execve(const char *file, char *const argv[], char *const envp[])
{
    if (!inited) {
        return R(execve)(file, argv, envp);
    }
    return exec_common("execve", file, argv);
}

X int execvpe(const char *file, char *const argv[], char *const envp[])
{
    if (!inited) {
        return R(execvpe)(file, argv, envp);
    }
    return exec_common("execvpe", file, argv);
}

X pid_t fork(void)
{
    if (!inited) {
        return R(fork)();
    }
    struct inj in = inject("fork", K_NONE, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    if (verbose) {
        jbegin("fork");
        jend();
    }
    return R(fork)();
}

X pid_t waitpid(pid_t pid, int *status, int options)
{
    if (!inited) {
        return R(waitpid)(pid, status, options);
    }
    struct inj in = inject("waitpid", K_NONE, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    return R(waitpid)(pid, status, options);
}

X int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa,
                  const posix_spawnattr_t *attr, char *const argv[], char *const envp[])
{
    (void) fa;
    (void) attr;
    (void) envp;
    if (!inited) {
        return R(posix_spawn)(pid, path, fa, attr, argv, envp);
    }
    pid_t c = 0;
    int   e = 0;
    {
        struct inj in = inject("posix_spawn", K_NONE, NULL);
        if (in.hit && in.err > 0) {
            return in.err;
        }
        c = R(fork)();
        if (c == 0) {
            struct crule *r = find_rule("exec", join_argv(argv));
            jbegin("cmd");
            jstr("via", "posix_spawn");
            jstr("file", path);
            jargv(argv);
            jend();
            child_exit(r);
        }
        if (c < 0) {
            e = errno;
        }
    }
    if (e == 0 && pid != NULL) {
        *pid = c;
    }
    return e;
}

X int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *fa,
                   const posix_spawnattr_t *attr, char *const argv[], char *const envp[])
{
    if (!inited) {
        return R(posix_spawnp)(pid, file, fa, attr, argv, envp);
    }
    pid_t c = 0;
    struct inj in = inject("posix_spawnp", K_NONE, NULL);
    if (in.hit && in.err > 0) {
        return in.err;
    }
    c = R(fork)();
    if (c == 0) {
        struct crule *r = find_rule("exec", join_argv(argv));
        jbegin("cmd");
        jstr("via", "posix_spawnp");
        jstr("file", file);
        jargv(argv);
        jend();
        child_exit(r);
    }
    if (c < 0) {
        return errno;
    }
    if (pid != NULL) {
        *pid = c;
    }
    return 0;
}

X int system(const char *cmd)
{
    if (!inited) {
        return R(system)(cmd);
    }
    if (cmd == NULL) {
        return 1;
    }
    struct inj in = inject("system", K_NONE, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return -1;
    }
    struct crule *r = find_rule("system", cmd);
    jbegin("cmd");
    jstr("via", "system");
    jstr("command", cmd);
    jend();
    return wait_status_of(r);
}

X FILE *popen(const char *cmd, const char *mode)
{
    if (!inited) {
        return R(popen)(cmd, mode);
    }
    struct inj in = inject("popen", K_NONE, NULL);
    if (in.hit && in.err > 0) {
        errno = in.err;
        return NULL;
    }
    struct crule *r = find_rule("popen", cmd);
    jbegin("cmd");
    jstr("via", "popen");
    jstr("command", cmd);
    jstr("mode", mode);
    jend();
    FILE *fp;
    if (mode[0] == 'r') {
        int p[2];
        if (pipe(p) != 0) {
            return NULL;
        }
        size_t n = r != NULL ? r->outlen : 0;
        if (n > 60000) {
            n = 60000;
        }
        if (n > 0) {
            ssize_t w = R(write)(p[1], r->out, n);
            (void) w;
        }
        R(close)(p[1]);
        fp = fdopen(p[0], "r");
    } else {
        int fd = R(open)("/dev/null", O_WRONLY);
        fp     = fd < 0 ? NULL : fdopen(fd, "w");
    }
    if (fp == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof popens / sizeof popens[0]; i++) {
        if (popens[i].fp == NULL) {
            popens[i].fp     = fp;
            popens[i].status = wait_status_of(r);
            return fp;
        }
    }
    fclose(fp);
    errno = EMFILE;
    return NULL;
}

X int pclose(FILE *fp)
{
    if (!inited) {
        return R(pclose)(fp);
    }
    for (size_t i = 0; i < sizeof popens / sizeof popens[0]; i++) {
        if (popens[i].fp == fp) {
            int st = popens[i].status;
            popens[i].fp = NULL;
            fclose(fp);
            return st;
        }
    }
    return R(pclose)(fp);
}

static struct addrinfo *mk_ai(const struct sockaddr_storage *ss, socklen_t len, int socktype,
                              int proto)
{
    struct addrinfo *ai = calloc(1, sizeof *ai);
    ai->ai_family       = ss->ss_family;
    ai->ai_socktype     = socktype;
    ai->ai_protocol     = proto;
    ai->ai_addrlen      = len;
    ai->ai_addr         = malloc(len);
    memcpy(ai->ai_addr, ss, len);
    return ai;
}

static void set_port(struct sockaddr_storage *ss, uint16_t port)
{
    if (ss->ss_family == AF_INET) {
        ((struct sockaddr_in *) ss)->sin_port = htons(port);
    } else {
        ((struct sockaddr_in6 *) ss)->sin6_port = htons(port);
    }
}

static int lit_addr(const char *s, struct sockaddr_storage *ss, socklen_t *len)
{
    memset(ss, 0, sizeof *ss);
    struct sockaddr_in  *a4 = (struct sockaddr_in *) ss;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) ss;
    if (inet_pton(AF_INET, s, &a4->sin_addr) == 1) {
        ss->ss_family = AF_INET;
        *len          = sizeof *a4;
        return 0;
    }
    if (inet_pton(AF_INET6, s, &a6->sin6_addr) == 1) {
        ss->ss_family = AF_INET6;
        *len          = sizeof *a6;
        return 0;
    }
    return -1;
}

X int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                  struct addrinfo **res)
{
    int family = hints ? hints->ai_family : AF_UNSPEC;
    int stype  = hints ? hints->ai_socktype : 0;
    int flags  = hints ? hints->ai_flags : 0;
    jbegin("getaddrinfo");
    jstr("node", node);
    jstr("service", service);
    jint("flags", flags);
    jint("family", family);
    jint("socktype", stype);
    jend();
    struct inj in = inject("getaddrinfo", K_NONE, NULL);
    if (in.hit) {
        return in.err;
    }
    long port = 0;
    if (service != NULL) {
        char *e;
        port = strtol(service, &e, 10);
        if (*service == 0 || *e != 0 || port < 0 || port > 65535) {
            return EAI_SERVICE;
        }
    }
    char *list = NULL;
    char  lit[96];
    if (node == NULL) {
        list = strdup((flags & AI_PASSIVE) ? passive_addr : "127.0.0.1");
    } else {
        struct sockaddr_storage tmp;
        socklen_t               tl;
        if (lit_addr(node, &tmp, &tl) == 0) {
            list = strdup(node);
        } else if (!(flags & AI_NUMERICHOST)) {
            for (int i = 0; i < ndns; i++) {
                if (strcmp(dns[i].name, node) == 0) {
                    if (strncmp(dns[i].value, "EAI_", 4) == 0) {
                        return strcmp(dns[i].value, "EAI_AGAIN") == 0 ? EAI_AGAIN
                               : strcmp(dns[i].value, "EAI_FAIL") == 0 ? EAI_FAIL : EAI_NONAME;
                    }
                    list = strdup(dns[i].value);
                    break;
                }
            }
        }
    }
    if (list == NULL) {
        return EAI_NONAME;
    }
    struct addrinfo *head = NULL, **tail = &head;
    char            *save = NULL;
    for (char *tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        struct sockaddr_storage ss;
        socklen_t               sl;
        snprintf(lit, sizeof lit, "%s", tok);
        if (lit_addr(lit, &ss, &sl) != 0) {
            continue;
        }
        if (family != AF_UNSPEC && ss.ss_family != family) {
            continue;
        }
        set_port(&ss, (uint16_t) port);
        int st = stype ? stype : SOCK_DGRAM;
        struct addrinfo *ai = mk_ai(&ss, sl, st, st == SOCK_DGRAM ? IPPROTO_UDP : 0);
        *tail = ai;
        tail  = &ai->ai_next;
    }
    free(list);
    if (head == NULL) {
        return EAI_NONAME;
    }
    *res = head;
    return 0;
}

X void freeaddrinfo(struct addrinfo *ai)
{
    while (ai != NULL) {
        struct addrinfo *n = ai->ai_next;
        free(ai->ai_addr);
        free(ai->ai_canonname);
        free(ai);
        ai = n;
    }
}

X int getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen,
                  char *serv, socklen_t servlen, int flags)
{
    char h[96] = "", s[16] = "";
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const void *) sa;
        inet_ntop(AF_INET, &a->sin_addr, h, sizeof h);
        snprintf(s, sizeof s, "%u", ntohs(a->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const void *) sa;
        inet_ntop(AF_INET6, &a->sin6_addr, h, sizeof h);
        snprintf(s, sizeof s, "%u", ntohs(a->sin6_port));
    } else {
        return EAI_FAMILY;
    }
    jbegin("getnameinfo");
    jint("flags", flags);
    jstr("addr", h);
    jend();
    struct inj in = inject("getnameinfo", K_NONE, NULL);
    if (in.hit) {
        return in.err;
    }
    const char *name = h;
    if (!(flags & NI_NUMERICHOST)) {
        for (int i = 0; i < ndns; i++) {
            if (strstr(dns[i].value, h) != NULL && strncmp(dns[i].value, "EAI_", 4) != 0) {
                name = dns[i].name;
                break;
            }
        }
    }
    (void) salen;
    if (host != NULL && hostlen > 0) {
        if (strlen(name) >= hostlen) {
            return EAI_OVERFLOW;
        }
        strcpy(host, name);
    }
    if (serv != NULL && servlen > 0) {
        if (strlen(s) >= servlen) {
            return EAI_OVERFLOW;
        }
        strcpy(serv, s);
    }
    return 0;
}

X sighandler_t signal(int sig, sighandler_t h)
{
    if (!inited || !is_vsig(sig)) {
        return R(signal)(sig, h);
    }
    jbegin("signal");
    jint("sig", sig);
    jstr("name", signame(sig));
    jstr("disp", disp_name(h));
    jend();
    void *prev      = disp[sig].handler;
    disp[sig].handler = h;
    disp[sig].siginfo = 0;
    return prev;
}

X int sigaction(int sig, const struct sigaction *act, struct sigaction *old)
{
    if (!inited || !is_vsig(sig)) {
        return R(sigaction)(sig, act, old);
    }
    if (old != NULL) {
        memset(old, 0, sizeof *old);
        old->sa_handler = disp[sig].handler;
        if (disp[sig].siginfo) {
            old->sa_flags |= SA_SIGINFO;
        }
    }
    if (act != NULL) {
        void *h = (act->sa_flags & SA_SIGINFO) ? (void *) act->sa_sigaction : (void *) act->sa_handler;
        jbegin("signal");
        jint("sig", sig);
        jstr("name", signame(sig));
        jstr("disp", disp_name(h));
        jend();
        disp[sig].handler = h;
        disp[sig].siginfo = (act->sa_flags & SA_SIGINFO) != 0;
    }
    return 0;
}

static void parse_script(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        die_shim("cannot open script");
    }
    char *line = NULL;
    size_t cap = 0;
    size_t evcap = 0;
    while (getline(&line, &cap, f) > 0) {
        char *tok[16];
        int   nt = 0;
        line[strcspn(line, "\r\n")] = 0;
        for (char *p = strtok(line, " "); p && nt < 16; p = strtok(NULL, " ")) {
            tok[nt++] = p;
        }
        if (nt == 0) {
            continue;
        }
        if (strcmp(tok[0], "seed") == 0 && nt == 2) {
            seed = strtoull(tok[1], NULL, 10);
        } else if (strcmp(tok[0], "urandom_prefix") == 0 && nt == 2) {
            ur_prefix = unhex(tok[1], &ur_prefix_len);
        } else if (strcmp(tok[0], "key") == 0 && nt == 2) {
            size_t n;
            unsigned char *k = unhex(tok[1], &n);
            if (n == 32) {
                memcpy(key, k, 32);
                key_set = 1;
            } else if (n != 0) {
                die_shim("key must be 32 bytes");
            }
        } else if (strcmp(tok[0], "tun_name") == 0 && nt == 2) {
            snprintf(tun_name, sizeof tun_name, "%s", unhex_str(tok[1]));
        } else if (strcmp(tok[0], "passive") == 0 && nt == 2) {
            snprintf(passive_addr, sizeof passive_addr, "%s", unhex_str(tok[1]));
        } else if (strcmp(tok[0], "clock") == 0 && nt == 3) {
            mono_base = atoll(tok[1]);
            real_base = atoll(tok[2]);
        } else if (strcmp(tok[0], "verbose") == 0 && nt == 2) {
            verbose = atoi(tok[1]);
        } else if (strcmp(tok[0], "hang_ms") == 0 && nt == 2) {
            hang_ns = atoll(tok[1]) * 1000000LL;
        } else if (strcmp(tok[0], "dns") == 0 && nt == 3 && ndns < 256) {
            dns[ndns].name  = unhex_str(tok[1]);
            dns[ndns].value = unhex_str(tok[2]);
            ndns++;
        } else if (strcmp(tok[0], "err") == 0 && nt == 8 && nerules < MAXRULE) {
            struct erule *e = &erules[nerules++];
            snprintf(e->call, sizeof e->call, "%s", tok[1]);
            e->kind   = kind_of(tok[2]);
            e->path   = strcmp(tok[3], "-") == 0 ? NULL : unhex_str(tok[3]);
            e->nth    = atoi(tok[4]);
            e->count  = atoi(tok[5]);
            e->err    = atoi(tok[6]);
            e->shortn = atol(tok[7]);
        } else if (strcmp(tok[0], "rule") == 0 && nt == 7 && ncrules < MAXRULE) {
            struct crule *r = &crules[ncrules++];
            snprintf(r->kind, sizeof r->kind, "%s", tok[1]);
            r->match     = strcmp(tok[2], "-") == 0 ? NULL : unhex_str(tok[2]);
            r->from      = atoi(tok[3]);
            r->to        = atoi(tok[4]);
            r->exit_code = atoi(tok[5]);
            size_t on;
            char *sg = strchr(tok[6], ':');
            if (sg == NULL) {
                die_shim("bad rule line");
            }
            *sg        = 0;
            r->term_sig = atoi(tok[6]);
            r->out     = (char *) unhex(sg + 1, &on);
            r->outlen  = on;
        } else if (strcmp(tok[0], "ev") == 0 && nt >= 4) {
            if (nev == evcap) {
                evcap = evcap ? evcap * 2 : 64;
                evs   = realloc(evs, evcap * sizeof *evs);
            }
            struct ev *e = &evs[nev++];
            memset(e, 0, sizeof *e);
            e->t_ms = atoll(tok[1]);
            if (strcmp(tok[2], "udp_in") == 0 && nt == 9) {
                e->type = E_UDP;
                snprintf(e->from, sizeof e->from, "%s", unhex_str(tok[3]));
                size_t n;
                unsigned char *r = unhex(tok[4], &n);
                if (n != 8) {
                    die_shim("udp_in random must be 8 bytes");
                }
                memcpy(e->rnd, r, 8);
                e->counter = strtoull(tok[5], NULL, 10);
                const char *a = tok[6];
                e->authn      = atol(tok[7]);
                e->auth       = strcmp(a, "valid") == 0 ? A_VALID : strcmp(a, "bad_tag") == 0 ? A_BADTAG
                              : strcmp(a, "truncate") == 0 ? A_TRUNC : strcmp(a, "raw") == 0 ? A_RAW
                              : strcmp(a, "flip") == 0 ? A_FLIP : -1;
                if (e->auth < 0) {
                    die_shim("unknown auth mode");
                }
                e->data = unhex(tok[8], &e->len);
            } else if (strcmp(tok[2], "tun_in") == 0 && nt == 4) {
                e->type = E_TUN;
                e->data = unhex(tok[3], &e->len);
            } else if (strcmp(tok[2], "signal") == 0 && nt == 4) {
                e->type = E_SIG;
                e->sig  = atoi(tok[3]);
            } else if (strcmp(tok[2], "poll_err") == 0 && nt == 5) {
                e->type    = E_PERR;
                e->fdkind  = kind_of(tok[3]);
                e->revents = atoi(tok[4]);
            } else {
                die_shim("bad ev line");
            }
        } else {
            die_shim("unknown script line");
        }
    }
    free(line);
    fclose(f);
}

__attribute__((constructor)) static void shim_init(void)
{
    const char *script = getenv("TWICE_SHIM_SCRIPT");
    const char *out    = getenv("TWICE_SHIM_OUT");
    if (script == NULL || out == NULL) {
        return;
    }
    root_pid = getpid();
    int fd   = R(open)(out, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) {
        return;
    }
    out_fd = R(fcntl)(fd, F_DUPFD_CLOEXEC, 900);
    R(close)(fd);
    shm = mmap(NULL, sizeof *shm, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shm == MAP_FAILED) {
        return;
    }
    for (int i = 0; i < 65; i++) {
        disp[i].handler = SIG_DFL;
    }
    inited = 1;
    parse_script(script);
}
