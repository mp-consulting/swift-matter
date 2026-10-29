#include "cp256.h"
#include <string.h>

typedef unsigned __int128 u128;

static const uint64_t P[4] = {0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, 0x0000000000000000ull, 0xFFFFFFFF00000001ull};
/* -p^-1 mod 2^64 */
static const uint64_t P_INV = 0x0000000000000001ull;
/* b * R mod p: the curve's b in Montgomery form. */
static const uint64_t B_MONT[4] = {0xD89CDF6229C4BDDFull, 0xACF005CD78843090ull, 0xE5A220ABF7212ED6ull, 0xDC30061D04874834ull};

/* r = a (if mask = all ones) or b (if mask = 0). */
static void select4(uint64_t r[4], uint64_t mask, const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 0; i < 4; i++) r[i] = (a[i] & mask) | (b[i] & ~mask);
}

void cp256_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4], uint64_t m_inv) {
    uint64_t t[6] = {0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 product = (u128)a[j] * b[i] + t[j] + carry;
            t[j] = (uint64_t)product;
            carry = (uint64_t)(product >> 64);
        }
        u128 sum = (u128)t[4] + carry;
        t[4] = (uint64_t)sum;
        t[5] = (uint64_t)(sum >> 64);

        uint64_t k = t[0] * m_inv;
        u128 product = (u128)k * m[0] + t[0];
        carry = (uint64_t)(product >> 64);
        for (int j = 1; j < 4; j++) {
            product = (u128)k * m[j] + t[j] + carry;
            t[j - 1] = (uint64_t)product;
            carry = (uint64_t)(product >> 64);
        }
        sum = (u128)t[4] + carry;
        t[3] = (uint64_t)sum;
        t[4] = t[5] + (uint64_t)(sum >> 64);
    }
    uint64_t reduced[4];
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        u128 difference = (u128)t[i] - m[i] - borrow;
        reduced[i] = (uint64_t)difference;
        borrow = (uint64_t)(difference >> 64) & 1;
    }
    /* Keep the reduced value when t overflowed 256 bits or t >= m. */
    uint64_t keep = (0 - t[4]) | (0 - (1 - borrow));
    select4(r, keep, reduced, t);
}

static void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) { cp256_mont_mul(r, a, b, P, P_INV); }

static void fe_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t sum[4], reduced[4], carry = 0, borrow = 0;
    for (int i = 0; i < 4; i++) {
        u128 s = (u128)a[i] + b[i] + carry;
        sum[i] = (uint64_t)s;
        carry = (uint64_t)(s >> 64);
    }
    for (int i = 0; i < 4; i++) {
        u128 d = (u128)sum[i] - P[i] - borrow;
        reduced[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
    uint64_t keep = (0 - carry) | (0 - (1 - borrow));
    select4(r, keep, reduced, sum);
}

static void fe_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t difference[4], corrected[4], borrow = 0, carry = 0;
    for (int i = 0; i < 4; i++) {
        u128 d = (u128)a[i] - b[i] - borrow;
        difference[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
    for (int i = 0; i < 4; i++) {
        u128 s = (u128)difference[i] + P[i] + carry;
        corrected[i] = (uint64_t)s;
        carry = (uint64_t)(s >> 64);
    }
    select4(r, 0 - borrow, corrected, difference);
}

void cp256_fe_pow(uint64_t r[4], const uint64_t base[4], const uint64_t exponent[4]) {
    /* R mod p is the Montgomery form of 1. */
    uint64_t result[4] = {1, 0xFFFFFFFF00000000ull, 0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFEull};
    for (int index = 255; index >= 0; index--) {
        fe_mul(result, result, result);
        if ((exponent[index / 64] >> (index % 64)) & 1) fe_mul(result, result, base);
    }
    memcpy(r, result, sizeof(result));
}

void cp256_point_add(uint64_t r[12], const uint64_t p[12], const uint64_t q[12]) {
    const uint64_t *x1 = p, *y1 = p + 4, *z1 = p + 8, *x2 = q, *y2 = q + 4, *z2 = q + 8;
    uint64_t t0[4], t1[4], t2[4], t3[4], t4[4], x3[4], y3[4], z3[4];
    fe_mul(t0, x1, x2); fe_mul(t1, y1, y2); fe_mul(t2, z1, z2);
    fe_add(t3, x1, y1); fe_add(t4, x2, y2); fe_mul(t3, t3, t4);
    fe_add(t4, t0, t1); fe_sub(t3, t3, t4); fe_add(t4, y1, z1);
    fe_add(x3, y2, z2); fe_mul(t4, t4, x3); fe_add(x3, t1, t2);
    fe_sub(t4, t4, x3); fe_add(x3, x1, z1); fe_add(y3, x2, z2);
    fe_mul(x3, x3, y3); fe_add(y3, t0, t2); fe_sub(y3, x3, y3);
    fe_mul(z3, B_MONT, t2); fe_sub(x3, y3, z3); fe_add(z3, x3, x3);
    fe_add(x3, x3, z3); fe_sub(z3, t1, x3); fe_add(x3, t1, x3);
    fe_mul(y3, B_MONT, y3); fe_add(t1, t2, t2); fe_add(t2, t1, t2);
    fe_sub(y3, y3, t2); fe_sub(y3, y3, t0); fe_add(t1, y3, y3);
    fe_add(y3, t1, y3); fe_add(t1, t0, t0); fe_add(t0, t1, t0);
    fe_sub(t0, t0, t2); fe_mul(t1, t4, y3); fe_mul(t2, t0, y3);
    fe_mul(y3, x3, z3); fe_add(y3, y3, t2); fe_mul(x3, t3, x3);
    fe_sub(x3, x3, t1); fe_mul(z3, t4, z3); fe_mul(t1, t3, t0);
    fe_add(z3, z3, t1);
    memcpy(r, x3, 32); memcpy(r + 4, y3, 32); memcpy(r + 8, z3, 32);
}

static void cswap(uint64_t a[12], uint64_t b[12], uint64_t mask) {
    for (int i = 0; i < 12; i++) {
        uint64_t t = (a[i] ^ b[i]) & mask;
        a[i] ^= t;
        b[i] ^= t;
    }
}

void cp256_point_mul(uint64_t r[12], const uint64_t scalar[4], const uint64_t p[12]) {
    uint64_t r0[12] = {0, 0, 0, 0, 1, 0xFFFFFFFF00000000ull, 0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFEull, 0, 0, 0, 0};
    uint64_t r1[12];
    memcpy(r1, p, sizeof(r1));
    for (int index = 255; index >= 0; index--) {
        uint64_t mask = 0 - ((scalar[index / 64] >> (index % 64)) & 1);
        cswap(r0, r1, mask);
        cp256_point_add(r1, r0, r1);
        cp256_point_add(r0, r0, r0);
        cswap(r0, r1, mask);
    }
    memcpy(r, r0, sizeof(r0));
}
