#ifndef CP256_H
#define CP256_H

#include <stdint.h>

/// P-256 field and point arithmetic for SPAKE2+ (Swift wraps it in P256.swift).
/// Field elements are 4 little-endian 64-bit limbs in Montgomery form (R = 2^256).
/// Points are projective (X, Y, Z) as 12 limbs; the identity is (0, R, 0).

/// r = a * b * R^-1 mod m, m odd, m_inv = -m^-1 mod 2^64. Inputs below m; r may alias an input.
void cp256_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4], uint64_t m_inv);

/// r = base^exponent mod p in Montgomery form; the exponent is public (the loop branches on its bits).
void cp256_fe_pow(uint64_t r[4], const uint64_t base[4], const uint64_t exponent[4]);

/// r = p + q with the complete formulas of Renes, Costello and Batina (a = -3); r may alias p or q.
void cp256_point_add(uint64_t r[12], const uint64_t p[12], const uint64_t q[12]);

/// r = scalar * p by a Montgomery ladder over all 256 bits, with constant-time swaps.
void cp256_point_mul(uint64_t r[12], const uint64_t scalar[4], const uint64_t p[12]);

#endif
