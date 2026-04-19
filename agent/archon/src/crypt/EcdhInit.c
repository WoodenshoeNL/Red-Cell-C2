/*
 * EcdhInit.c — Archon ECDH key exchange protocol implementation.
 *
 * Wire format matches common/src/crypto/ecdh.rs exactly so the existing
 * teamserver ECDH dispatch path handles Archon registration without changes.
 *
 * HKDF-SHA256 matches: Hkdf::<Sha256>::new(None, shared_secret).expand(info, &mut key)
 * with info = "red-cell-ecdh-session-key-v1".
 */

#include <crypt/EcdhInit.h>
#include <crypt/X25519.h>
#include <crypt/Sha256.h>
#include <crypt/AesGcm.h>

/* HKDF info string matching the Rust constant in common/src/crypto/ecdh.rs */
static const ei_u8 HKDF_INFO[] = "red-cell-ecdh-session-key-v1";
#define HKDF_INFO_LEN  28  /* strlen("red-cell-ecdh-session-key-v1") */

/* ── Session key derivation ──────────────────────────────────────────────── */

static void derive_session_key(
    const ei_u8 shared_secret[32],
    ei_u8       session_key[32]
) {
    /* HKDF-SHA256 with no salt and info = HKDF_INFO.
     * Matches Rust: Hkdf::<Sha256>::new(None, prk).expand(info, &mut okm).
     * "No salt" means the PRK equals HMAC-SHA256(0^32, ikm) = hmac(0..0, shared_secret).
     * We apply HKDF extract first (salt = 0^32), then expand. */
    ei_u8 prk[SHA256_DIGEST_LEN];
    ei_u8 zero_salt[SHA256_DIGEST_LEN];
    ei_size_t i;

    for (i = 0; i < SHA256_DIGEST_LEN; i++) zero_salt[i] = 0;

    /* Extract: PRK = HMAC-SHA256(salt=0^32, IKM=shared_secret) */
    hmac_sha256(zero_salt, SHA256_DIGEST_LEN,
                shared_secret, 32,
                prk);

    /* Expand: OKM = HKDF-expand(PRK, info, 32) */
    hkdf_sha256_expand(prk, SHA256_DIGEST_LEN,
                       HKDF_INFO, HKDF_INFO_LEN,
                       session_key, 32);
}

/* ── RNG bridge ──────────────────────────────────────────────────────────── */

/*
 * Adapter: the RNG callback signature in EcdhInit uses (ei_u8*, ei_size_t),
 * while AesGcm uses (gcm_u8*, gcm_size_t).  They are the same types, so a
 * simple cast works.
 */
typedef ei_bool (*ei_rng_fn)(ei_u8 *, ei_size_t);

static gcm_bool gcm_rng_bridge(gcm_u8 *buf, gcm_size_t len) {
    /* This is filled in per-call via a function pointer stored in a static;
     * the seal helpers are called directly from the function bodies below,
     * so we avoid needing a global. */
    (void)buf; (void)len;
    return GCM_FALSE;  /* unused; see local wrappers */
}

/* ── Public API ──────────────────────────────────────────────────────────── */

ei_bool ecdh_build_registration_packet(
    const ei_u8 *listener_pubkey,
    const ei_u8 *metadata,
    ei_size_t    metadata_len,
    ei_u8       *out_packet,
    ei_size_t   *out_packet_len,
    ei_u8        out_session_key[32],
    ei_bool    (*rng_fill)(ei_u8 *buf, ei_size_t len),
    ei_u64       unix_now
) {
    ei_u8 eph_secret[32];
    ei_u8 eph_public[32];
    ei_u8 shared[32];
    ei_u8 plaintext[8 + 4096];  /* timestamp + up to ~4K metadata */
    ei_size_t pt_len;
    ei_size_t i;

    if (metadata_len > 4088) return EI_FALSE;

    /* 1. Generate ephemeral X25519 keypair */
    if (!rng_fill(eph_secret, 32)) return EI_FALSE;

    x25519_public_key(eph_public, eph_secret);

    /* 2. ECDH: shared_secret = eph_secret × listener_pubkey */
    x25519_diffie_hellman(shared, eph_secret, listener_pubkey);

    /* 3. Derive session key via HKDF-SHA256 */
    derive_session_key(shared, out_session_key);

    /* Wipe the ephemeral secret and shared secret immediately */
    for (i = 0; i < 32; i++) { eph_secret[i] = 0; shared[i] = 0; }

    /* 4. Build plaintext: timestamp(8 BE) | metadata */
    plaintext[0] = (ei_u8)(unix_now >> 56);
    plaintext[1] = (ei_u8)(unix_now >> 48);
    plaintext[2] = (ei_u8)(unix_now >> 40);
    plaintext[3] = (ei_u8)(unix_now >> 32);
    plaintext[4] = (ei_u8)(unix_now >> 24);
    plaintext[5] = (ei_u8)(unix_now >> 16);
    plaintext[6] = (ei_u8)(unix_now >>  8);
    plaintext[7] = (ei_u8)(unix_now      );
    for (i = 0; i < metadata_len; i++) plaintext[8 + i] = metadata[i];
    pt_len = 8 + metadata_len;

    /* 5. Seal with AES-256-GCM: output = nonce(12) | ciphertext | tag(16) */
    gcm_u8 gcm_nonce[AESGCM_NONCE_LEN];
    if (!rng_fill(gcm_nonce, AESGCM_NONCE_LEN)) return EI_FALSE;

    /* out_packet = ephemeral_pubkey(32) | nonce(12) | ciphertext | tag(16) */
    for (i = 0; i < 32; i++) out_packet[i] = eph_public[i];

    if (!aes256gcm_encrypt(
            (const gcm_u8 *)out_session_key,
            gcm_nonce,
            (const gcm_u8 *)plaintext,
            (gcm_size_t)pt_len,
            (gcm_u8 *)(out_packet + 32 + AESGCM_NONCE_LEN)
        )) return EI_FALSE;

    /* Write nonce into packet at bytes [32..44) */
    for (i = 0; i < AESGCM_NONCE_LEN; i++) out_packet[32 + i] = gcm_nonce[i];

    *out_packet_len = 32 + AESGCM_NONCE_LEN + pt_len + AESGCM_TAG_LEN;
    return EI_TRUE;
}

ei_bool ecdh_parse_registration_response(
    const ei_u8 *session_key,
    const ei_u8 *response,
    ei_size_t    response_len,
    ei_u8        out_connection_id[16],
    ei_u32      *out_agent_id
) {
    ei_u8 plaintext[4];
    gcm_size_t pt_len;
    ei_size_t i;

    /* Response: connection_id(16) | nonce(12) | ciphertext | tag(16) */
    if (response_len < (ei_size_t)ECDH_REG_RESP_MIN) return EI_FALSE;

    for (i = 0; i < 16; i++) out_connection_id[i] = response[i];

    /* Decrypt the sealed portion: nonce(12) | ciphertext | tag(16) */
    pt_len = aes256gcm_open(
        (const gcm_u8 *)session_key,
        (const gcm_u8 *)(response + 16),  /* nonce starts at byte 16 */
        (gcm_size_t)(response_len - 16),
        (gcm_u8 *)plaintext
    );

    /* Plaintext must be exactly 4 bytes (agent_id, little-endian) */
    if (pt_len != 4) return EI_FALSE;

    *out_agent_id = (ei_u32)plaintext[0]
                 | ((ei_u32)plaintext[1] << 8)
                 | ((ei_u32)plaintext[2] << 16)
                 | ((ei_u32)plaintext[3] << 24);
    return EI_TRUE;
}

ei_bool ecdh_build_session_packet(
    const ei_u8 *connection_id,
    const ei_u8 *session_key,
    const ei_u8 *payload,
    ei_size_t    payload_len,
    ei_u8       *out,
    ei_size_t   *out_len,
    ei_bool    (*rng_fill)(ei_u8 *buf, ei_size_t len)
) {
    gcm_u8 nonce[AESGCM_NONCE_LEN];
    ei_size_t i;

    /* out = connection_id(16) | nonce(12) | ciphertext | tag(16) */
    for (i = 0; i < 16; i++) out[i] = connection_id[i];

    if (!rng_fill(nonce, AESGCM_NONCE_LEN)) return EI_FALSE;
    for (i = 0; i < AESGCM_NONCE_LEN; i++) out[16 + i] = nonce[i];

    if (!aes256gcm_encrypt(
            (const gcm_u8 *)session_key,
            nonce,
            (const gcm_u8 *)payload,
            (gcm_size_t)payload_len,
            (gcm_u8 *)(out + 16 + AESGCM_NONCE_LEN)
        )) return EI_FALSE;

    *out_len = 16 + AESGCM_NONCE_LEN + payload_len + AESGCM_TAG_LEN;
    return EI_TRUE;
}

ei_bool ecdh_open_session_response(
    const ei_u8 *session_key,
    const ei_u8 *response,
    ei_size_t    response_len,
    ei_u8       *out,
    ei_size_t   *out_len
) {
    gcm_size_t n;

    if (response_len < (ei_size_t)ECDH_SESS_RESP_MIN) return EI_FALSE;

    /* Response: nonce(12) | ciphertext | tag(16) */
    n = aes256gcm_open(
        (const gcm_u8 *)session_key,
        (const gcm_u8 *)response,
        (gcm_size_t)response_len,
        (gcm_u8 *)out
    );

    if (n == 0 && response_len > (ei_size_t)(AESGCM_NONCE_LEN + AESGCM_TAG_LEN))
        return EI_FALSE;

    *out_len = (ei_size_t)n;
    return EI_TRUE;
}
