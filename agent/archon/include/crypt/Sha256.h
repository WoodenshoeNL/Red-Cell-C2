/*
 * Sha256.h — SHA-256, HMAC-SHA256, and HKDF-SHA256 for Archon ECDH.
 *
 * Self-contained, no external dependencies.
 */
#ifndef ARCHON_SHA256_H
#define ARCHON_SHA256_H

#ifdef _WIN32
#   include <windows.h>
    typedef UINT8  sha_u8;
    typedef UINT32 sha_u32;
    typedef UINT64 sha_u64;
    typedef SIZE_T sha_size_t;
#else
#   include <stdint.h>
#   include <stddef.h>
    typedef uint8_t  sha_u8;
    typedef uint32_t sha_u32;
    typedef uint64_t sha_u64;
    typedef size_t   sha_size_t;
#endif

#define SHA256_DIGEST_LEN   32
#define SHA256_BLOCK_LEN    64

typedef struct {
    sha_u32 state[8];
    sha_u64 count;
    sha_u8  buf[SHA256_BLOCK_LEN];
} sha256_ctx;

/* Compute SHA-256 digest */
void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const sha_u8 *data, sha_size_t len);
void sha256_final(sha256_ctx *ctx, sha_u8 digest[SHA256_DIGEST_LEN]);
void sha256(const sha_u8 *data, sha_size_t len, sha_u8 digest[SHA256_DIGEST_LEN]);

/* Compute HMAC-SHA256: out must be SHA256_DIGEST_LEN bytes */
void hmac_sha256(
    const sha_u8 *key,  sha_size_t key_len,
    const sha_u8 *data, sha_size_t data_len,
    sha_u8 out[SHA256_DIGEST_LEN]
);

/*
 * HKDF-SHA256 expand (RFC 5869 §2.3).
 * `prk`  — 32-byte pseudo-random key (output of HMAC-SHA256 extract, or raw DH secret)
 * `info` / `info_len` — context string
 * `out`  / `out_len`  — output key material (max 32*255 = 8160 bytes)
 *
 * When prk is the raw ECDH shared secret (no salt), this is equivalent to
 * HKDF with an empty salt — matching x25519-dalek + hkdf::Hkdf::<Sha256>::new(None, …).
 */
void hkdf_sha256_expand(
    const sha_u8 *prk,  sha_size_t prk_len,
    const sha_u8 *info, sha_size_t info_len,
    sha_u8 *out,        sha_size_t out_len
);

#endif /* ARCHON_SHA256_H */
