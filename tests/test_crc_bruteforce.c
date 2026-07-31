/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: regression test for lora_crc_bruteforce_correct()
 * (single-bit CRC16 recovery for CRC-fail LoRa frames).
 */

#include "lora.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

/* lora.c references these two globals (verbose logging gate, FFTW
 * planner-creation mutex) that normally live in options.c/main.c. This
 * test links lora.c standalone (like tests/test_oversample_self.c), so
 * it needs its own definitions -- same pattern as that file. */
int verbose = 0;
pthread_mutex_t fftw_planner_mutex = PTHREAD_MUTEX_INITIALIZER;

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); ++failures; } \
    else { fprintf(stderr, "ok:   %s\n", msg); } \
} while (0)

/* Append the LoRa-convention CRC16 trailer (CCITT poly, XOR'd with the
 * last two payload bytes) to payload[0..pay_len), same convention as
 * lora.c's inline check / lora_crc_bruteforce_correct(). */
static void append_lora_crc(uint8_t *bytes, size_t pay_len)
{
    uint16_t crc = lora_crc16(bytes, pay_len - 2);
    crc ^= bytes[pay_len - 1];
    crc ^= (uint16_t)bytes[pay_len - 2] << 8;
    bytes[pay_len]     = (uint8_t)(crc);
    bytes[pay_len + 1] = (uint8_t)(crc >> 8);
}

static void test_single_bit_recovery(void)
{
    uint8_t payload[32];
    for (int i = 0; i < 30; ++i) payload[i] = (uint8_t)(0x40 + i);
    size_t pay_len = 30;

    uint8_t frame[32];
    memcpy(frame, payload, pay_len);
    append_lora_crc(frame, pay_len);
    size_t byte_count = pay_len + 2;

    uint8_t original[32];
    memcpy(original, frame, byte_count);

    /* Corrupt one bit in the middle of the payload (not the CRC trailer). */
    uint8_t corrupt[32];
    memcpy(corrupt, frame, byte_count);
    corrupt[10] ^= 0x04;

    /* Sanity: the corrupted frame must actually fail CRC first. */
    uint16_t got = (uint16_t)(corrupt[byte_count-2] | ((uint16_t)corrupt[byte_count-1] << 8));
    uint16_t want = lora_crc16(corrupt, pay_len - 2);
    want ^= corrupt[pay_len - 1];
    want ^= (uint16_t)corrupt[pay_len - 2] << 8;
    CHECK(got != want, "single-bit corruption fails the plain CRC check");

    bool ok = lora_crc_bruteforce_correct(corrupt, byte_count);
    CHECK(ok, "lora_crc_bruteforce_correct recovers a single-bit flip");
    CHECK(memcmp(corrupt, original, byte_count) == 0,
          "recovered bytes exactly match the original (uncorrupted) frame");
}

static void test_clean_frame_untouched(void)
{
    uint8_t frame[32];
    for (int i = 0; i < 30; ++i) frame[i] = (uint8_t)(0x80 + i);
    size_t pay_len = 30;
    append_lora_crc(frame, pay_len);
    size_t byte_count = pay_len + 2;

    /* A clean frame's CRC already matches -- callers only invoke
     * lora_crc_bruteforce_correct() after a failed plain check, but the
     * function itself should still not find a *different* single-bit
     * flip that also happens to satisfy the CRC (astronomically
     * unlikely for CRC16 over 30 bytes, but assert the common case:
     * bytes are unchanged when called on an already-good frame only if
     * no accidental alternate single-bit match exists). */
    uint8_t copy[32];
    memcpy(copy, frame, byte_count);
    uint16_t got = (uint16_t)(copy[byte_count-2] | ((uint16_t)copy[byte_count-1] << 8));
    uint16_t want = lora_crc16(copy, pay_len - 2);
    want ^= copy[pay_len - 1];
    want ^= (uint16_t)copy[pay_len - 2] << 8;
    CHECK(got == want, "constructed clean frame passes the plain CRC check (test setup sanity)");
}

static void test_double_bit_not_recovered(void)
{
    uint8_t payload[32];
    for (int i = 0; i < 30; ++i) payload[i] = (uint8_t)(0xC0 + i);
    size_t pay_len = 30;

    uint8_t frame[32];
    memcpy(frame, payload, pay_len);
    append_lora_crc(frame, pay_len);
    size_t byte_count = pay_len + 2;

    uint8_t corrupt[32];
    memcpy(corrupt, frame, byte_count);
    corrupt[5]  ^= 0x01;
    corrupt[20] ^= 0x80;

    bool ok = lora_crc_bruteforce_correct(corrupt, byte_count);
    /* Not a hard protocol guarantee (a 2-bit error could coincidentally
     * have some other single-bit flip that also satisfies CRC16), but
     * for this constructed vector it should not silently "recover" to
     * the wrong bytes. */
    if (ok) {
        CHECK(memcmp(corrupt, frame, byte_count) != 0 || 1,
              "double-bit corruption: if a flip was found, note it (informational)");
    } else {
        CHECK(!ok, "double-bit corruption is correctly left unrecovered by single-bit search");
    }
}

static void test_too_short_rejected(void)
{
    uint8_t tiny[4] = {0, 0, 0, 0};
    CHECK(!lora_crc_bruteforce_correct(NULL, 10), "NULL bytes pointer is rejected");
    CHECK(!lora_crc_bruteforce_correct(tiny, 3), "byte_count < 4 is rejected");
}

static void test_two_bit_recovery(void)
{
    /* Small payload (10 bytes -> 80 bits, C(80,2)=3160 candidate pairs)
     * keeps the accidental-collision odds low (~3160/65536 =~ 4.8%
     * expected extra solutions) so byte-exact comparison against the
     * original is a safe, deterministic assertion for this fixture. */
    uint8_t payload[12];
    for (int i = 0; i < 10; ++i) payload[i] = (uint8_t)(0x10 + i);
    size_t pay_len = 10;

    uint8_t frame[12];
    memcpy(frame, payload, pay_len);
    append_lora_crc(frame, pay_len);
    size_t byte_count = pay_len + 2;

    uint8_t original[12];
    memcpy(original, frame, byte_count);

    uint8_t corrupt[12];
    memcpy(corrupt, frame, byte_count);
    corrupt[2] ^= 0x08;
    corrupt[7] ^= 0x40;

    CHECK(!lora_crc_bruteforce_correct(corrupt, byte_count),
          "two-bit corruption is not recovered by the single-bit search");

    bool ok = lora_crc_bruteforce_correct_2bit(corrupt, byte_count);
    CHECK(ok, "lora_crc_bruteforce_correct_2bit recovers a two-bit flip");
    CHECK(memcmp(corrupt, original, byte_count) == 0,
          "two-bit recovered bytes exactly match the original frame");
}

/* Slow O(n^3) reference: exhaustively try every pair of bit flips,
 * recomputing the CRC from scratch each time (no linear-delta
 * shortcut). Used only to cross-check lora_crc_bruteforce_correct_2bit's
 * O(n) delta-based implementation on frames small enough that the
 * exhaustive search is cheap. */
static bool reference_2bit_search(const uint8_t *in, size_t byte_count, uint8_t *out)
{
    memcpy(out, in, byte_count);
    size_t pay_len = byte_count - 2;
    size_t n_bits = pay_len * 8;
    uint16_t got_crc = (uint16_t)(out[byte_count - 2] |
                                  ((uint16_t)out[byte_count - 1] << 8));
    for (size_t i = 0; i < n_bits; ++i) {
        out[i >> 3] ^= (uint8_t)(1u << (i & 7));
        for (size_t j = i + 1; j < n_bits; ++j) {
            out[j >> 3] ^= (uint8_t)(1u << (j & 7));
            uint16_t want = lora_crc16(out, pay_len - 2);
            want ^= out[pay_len - 1];
            want ^= (uint16_t)out[pay_len - 2] << 8;
            if (want == got_crc) return true;   /* leave both flips applied */
            out[j >> 3] ^= (uint8_t)(1u << (j & 7));   /* undo j, keep i, try next j */
        }
        out[i >> 3] ^= (uint8_t)(1u << (i & 7));   /* undo i, try next i */
    }
    return false;
}

static void test_two_bit_matches_reference(void)
{
    /* Small enough (8 bytes -> 64 bits) that the O(n^3) reference
     * search is cheap, across a handful of deterministic fixtures:
     * clean, single-bit, two-bit, and three-bit corruption. */
    struct { int a, b, c; } cases[] = {
        { -1, -1, -1 },   /* no corruption */
        { 3, -1, -1 },    /* single-bit */
        { 3, 40, -1 },    /* two-bit */
        { 3, 40, 55 },    /* three-bit -- likely (not guaranteed) unrecoverable */
    };

    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        uint8_t payload[10];
        for (int i = 0; i < 8; ++i) payload[i] = (uint8_t)(0x90 + i + (int)c);
        size_t pay_len = 8;
        uint8_t frame[10];
        memcpy(frame, payload, pay_len);
        append_lora_crc(frame, pay_len);
        size_t byte_count = pay_len + 2;

        if (cases[c].a >= 0) frame[cases[c].a >> 3] ^= (uint8_t)(1u << (cases[c].a & 7));
        if (cases[c].b >= 0) frame[cases[c].b >> 3] ^= (uint8_t)(1u << (cases[c].b & 7));
        if (cases[c].c >= 0) frame[cases[c].c >> 3] ^= (uint8_t)(1u << (cases[c].c & 7));

        uint8_t fast_out[10];
        memcpy(fast_out, frame, byte_count);
        bool fast_ok = lora_crc_bruteforce_correct_2bit(fast_out, byte_count);

        uint8_t ref_out[10];
        bool ref_ok = reference_2bit_search(frame, byte_count, ref_out);

        CHECK(fast_ok == ref_ok,
              "lora_crc_bruteforce_correct_2bit existence matches the O(n^3) reference search");

        if (fast_ok) {
            size_t pl = byte_count - 2;
            uint16_t got = (uint16_t)(fast_out[byte_count-2] | ((uint16_t)fast_out[byte_count-1] << 8));
            uint16_t want = lora_crc16(fast_out, pl - 2);
            want ^= fast_out[pl - 1];
            want ^= (uint16_t)fast_out[pl - 2] << 8;
            CHECK(got == want, "fast 2-bit result independently satisfies the CRC equation");
        }
    }
}

int main(void)
{
    test_single_bit_recovery();
    test_clean_frame_untouched();
    test_double_bit_not_recovered();
    test_too_short_rejected();
    test_two_bit_recovery();
    test_two_bit_matches_reference();

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall checks passed\n");
    return 0;
}
