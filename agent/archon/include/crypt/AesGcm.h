/*
 * AesGcm.h — AES-256-GCM authenticated encryption for Archon ECDH sessions.
 *
 * Implements AES-256 in GCM mode (RFC 5116).  Self-contained pure C:
 * the AES key schedule is taken from AesCrypt.c; GHASH is implemented here.
 *
 * Wire format for sealed buffers: nonce(12) | ciphertext | tag(16).
 * This matches the layout in common/src/crypto/ecdh.rs.
 */
#ifndef ARCHON_AESGCM_H
#define ARCHON_AESGCM_H

#ifdef _WIN32
#   include <windows.h>
    typedef UINT8  gcm_u8;
    typedef UINT32 gcm_u32;
    typedef UINT64 gcm_u64;
    typedef SIZE_T gcm_size_t;
    typedef BOOL   gcm_bool;
#   define GCM_TRUE  TRUE
#   define GCM_FALSE FALSE
#else
#   include <stdint.h>
#   include <stddef.h>
    typedef uint8_t  gcm_u8;
    typedef uint32_t gcm_u32;
    typedef uint64_t gcm_u64;
    typedef size_t   gcm_size_t;
    typedef int      gcm_bool;
#   define GCM_TRUE  1
#   define GCM_FALSE 0
#endif

#define AESGCM_KEY_LEN   32   /* AES-256 */
#define AESGCM_NONCE_LEN 12   /* 96-bit nonce (GCM standard) */
#define AESGCM_TAG_LEN   16   /* 128-bit authentication tag */

/*
 * Seal plaintext with AES-256-GCM.
 *
 * key        — 32-byte AES-256 key
 * nonce      — 12-byte nonce (must be unique per (key, message) pair)
 * plaintext  — input bytes
 * pt_len     — length of plaintext
 * out        — output buffer; must be at least (pt_len + AESGCM_TAG_LEN) bytes
 *
 * Returns GCM_TRUE on success.
 * out = ciphertext(pt_len bytes) | tag(16 bytes)
 */
gcm_bool aes256gcm_encrypt(
    const gcm_u8 *key,
    const gcm_u8  nonce[AESGCM_NONCE_LEN],
    const gcm_u8 *plaintext,
    gcm_size_t    pt_len,
    gcm_u8       *out
);

/*
 * Open an AES-256-GCM sealed buffer.
 *
 * key       — 32-byte AES-256 key
 * nonce     — 12-byte nonce used during encryption
 * ctext     — ciphertext bytes followed by the 16-byte authentication tag
 * ct_len    — total length of ctext (ciphertext + tag)
 * out       — output buffer; must be at least (ct_len - AESGCM_TAG_LEN) bytes
 *
 * Returns GCM_TRUE on success (tag verified).  Returns GCM_FALSE if the tag
 * does not match — callers must discard the output in that case.
 */
gcm_bool aes256gcm_decrypt(
    const gcm_u8 *key,
    const gcm_u8  nonce[AESGCM_NONCE_LEN],
    const gcm_u8 *ctext,
    gcm_size_t    ct_len,
    gcm_u8       *out
);

/*
 * Seal plaintext with a random 12-byte nonce prepended.
 *
 * Writes nonce(12) | ciphertext | tag(16) to `out`.
 * `out` must be at least (AESGCM_NONCE_LEN + pt_len + AESGCM_TAG_LEN) bytes.
 * `rng_fill` is a callback that fills a buffer with cryptographically secure
 * random bytes; returns GCM_TRUE on success.
 *
 * Returns total written length on success, or 0 on failure.
 */
gcm_size_t aes256gcm_seal(
    const gcm_u8 *key,
    const gcm_u8 *plaintext,
    gcm_size_t    pt_len,
    gcm_u8       *out,
    gcm_bool    (*rng_fill)(gcm_u8 *buf, gcm_size_t len)
);

/*
 * Open a sealed buffer of the form nonce(12) | ciphertext | tag(16).
 *
 * `in_len` = total sealed length including nonce and tag.
 * `out`    = output plaintext buffer; must be >= (in_len - 12 - 16) bytes.
 *
 * Returns plaintext length on success, or 0 on failure.
 */
gcm_size_t aes256gcm_open(
    const gcm_u8 *key,
    const gcm_u8 *in,
    gcm_size_t    in_len,
    gcm_u8       *out
);

#endif /* ARCHON_AESGCM_H */
