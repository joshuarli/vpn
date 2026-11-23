#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int HiAE_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *msg, uint8_t *ct,
                 size_t msg_len, const uint8_t *ad, size_t ad_len, uint8_t *tag);
int HiAE_decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *msg, const uint8_t *ct,
                 size_t ct_len, const uint8_t *ad, size_t ad_len, const uint8_t *tag);
int HiAE_mac(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
             uint8_t *tag);
int HiAE_verify_tag(const uint8_t *expected_tag, const uint8_t *actual_tag);
const char *HiAE_get_implementation_name(void);

enum Op { ENCRYPT, DECRYPT, DECRYPT_FAIL, MAC, MAC_VERIFY };

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

static const char *op_names[] = { "encrypt", "decrypt", "decrypt_fail", "mac", "mac_verify" };

int main(int argc, char **argv)
{
    int      op = -1;
    size_t   size = 1420;
    uint64_t ms = 100, warm_ms = 50, seed = 1;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--op")) {
            for (int k = 0; k < 5; k++) {
                if (!strcmp(argv[i + 1], op_names[k])) {
                    op = k;
                }
            }
        } else if (!strcmp(argv[i], "--size")) {
            size = strtoull(argv[i + 1], NULL, 10);
        } else if (!strcmp(argv[i], "--ms")) {
            ms = strtoull(argv[i + 1], NULL, 10);
        } else if (!strcmp(argv[i], "--warmup-ms")) {
            warm_ms = strtoull(argv[i + 1], NULL, 10);
        } else if (!strcmp(argv[i], "--seed")) {
            seed = strtoull(argv[i + 1], NULL, 10);
        }
    }
    if (op < 0) {
        fprintf(stderr, "usage: crypto_bench --op encrypt|decrypt|decrypt_fail|mac|mac_verify "
                        "--size N [--ms M] [--warmup-ms W] [--seed S]\n");
        return 2;
    }

    uint8_t key[32], nonce[16], tag[16], bad_tag[16], good_tag[16];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t) splitmix(&seed);
    }
    for (int i = 0; i < 16; i++) {
        nonce[i] = (uint8_t) splitmix(&seed);
    }
    uint8_t *src = aligned_alloc(64, size + 64);
    uint8_t *dst = aligned_alloc(64, size + 64);
    uint8_t *ct  = aligned_alloc(64, size + 64);
    for (size_t i = 0; i < size; i++) {
        src[i] = (uint8_t) splitmix(&seed);
    }
    HiAE_encrypt(key, nonce, src, ct, size, NULL, 0, good_tag);
    memcpy(bad_tag, good_tag, 16);
    bad_tag[0] ^= 1;

    size_t   batch = 1 + (65536 / (size ? size : 1));
    uint64_t ctr = 0, ops = 0, sink = 0;
    uint64_t start = now_ns(), end_warm = start + warm_ms * 1000000ULL, t0 = 0, t_end = 0;
    int      measuring = 0;
    for (;;) {
        uint64_t t = now_ns();
        if (!measuring) {
            if (t >= end_warm) {
                measuring = 1;
                t0        = t;
                t_end     = t0 + ms * 1000000ULL;
                ops       = 0;
            }
        } else if (t >= t_end) {
            break;
        }
        for (size_t b = 0; b < batch; b++) {
            switch (op) {
            case ENCRYPT:
                memcpy(nonce, &ctr, 8);
                ctr++;
                HiAE_encrypt(key, nonce, src, dst, size, NULL, 0, tag);
                sink += tag[0];
                break;
            case DECRYPT:
                sink += (uint64_t) HiAE_decrypt(key, nonce, dst, ct, size, NULL, 0, good_tag);
                break;
            case DECRYPT_FAIL:
                sink += (uint64_t) (HiAE_decrypt(key, nonce, dst, ct, size, NULL, 0, bad_tag) != 0);
                break;
            case MAC:
                memcpy(nonce, &ctr, 8);
                ctr++;
                HiAE_mac(key, nonce, src, size, tag);
                sink += tag[0];
                break;
            case MAC_VERIFY:
                HiAE_mac(key, nonce, src, size, tag);
                sink += (uint64_t) HiAE_verify_tag(tag, tag);
                break;
            }
        }
        ops += batch;
    }
    uint64_t elapsed = now_ns() - t0;
    double   ns_op   = (double) elapsed / (double) ops;
    printf("{\"tool\":\"crypto_bench\",\"lang\":\"c\",\"backend\":\"%s\",\"op\":\"%s\",\"size\":%zu,"
           "\"ops\":%llu,\"elapsed_ns\":%llu,\"ns_per_op\":%.4f,\"mib_per_s\":%.3f,\"sink\":%llu}\n",
           HiAE_get_implementation_name(), op_names[op], size, (unsigned long long) ops,
           (unsigned long long) elapsed, ns_op, (double) size / ns_op * 1e9 / 1048576.0,
           (unsigned long long) sink);
    return 0;
}
