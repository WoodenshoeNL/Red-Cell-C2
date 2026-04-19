/*
 * X25519.h — Minimal Curve25519 Diffie-Hellman for Archon ECDH key exchange.
 *
 * Self-contained, no dependencies.  Field arithmetic uses 10 signed 32-bit
 * limbs (alternating 26/25-bit widths) to represent GF(2^255-19) elements.
 * The Montgomery ladder is constant-time (no secret-dependent branches).
 */
#ifndef ARCHON_X25519_H
#define ARCHON_X25519_H

#ifdef _WIN32
#   include <windows.h>
    typedef UINT8  x25519_u8;
    typedef UINT32 x25519_u32;
    typedef INT32  x25519_i32;
    typedef UINT64 x25519_u64;
    typedef INT64  x25519_i64;
#else
#   include <stdint.h>
    typedef uint8_t  x25519_u8;
    typedef uint32_t x25519_u32;
    typedef int32_t  x25519_i32;
    typedef uint64_t x25519_u64;
    typedef int64_t  x25519_i64;
#endif

/*
 * Compute the X25519 public key from a 32-byte secret key.
 * Equivalent to scalar multiplication of the base point by `secret_key`.
 *
 * out_public_key  — 32 bytes output (u-coordinate on Curve25519)
 * secret_key      — 32 bytes input  (will be clamped internally)
 */
void x25519_public_key(
    x25519_u8 out_public_key[32],
    const x25519_u8 secret_key[32]
);

/*
 * Perform X25519 Diffie-Hellman key agreement.
 * Computes scalar(secret_key) · peer_public_key → shared_secret.
 *
 * out_shared_secret — 32 bytes output
 * secret_key        — 32 bytes input  (will be clamped internally)
 * peer_public_key   — 32 bytes input  (u-coordinate of peer's public key)
 */
void x25519_diffie_hellman(
    x25519_u8 out_shared_secret[32],
    const x25519_u8 secret_key[32],
    const x25519_u8 peer_public_key[32]
);

#endif /* ARCHON_X25519_H */
