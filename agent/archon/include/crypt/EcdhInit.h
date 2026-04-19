/*
 * EcdhInit.h — Archon ECDH session key exchange protocol.
 *
 * Implements the same wire format as common/src/crypto/ecdh.rs so that the
 * Red-Cell teamserver can handle Archon registration identically to Phantom
 * and Specter without any special-casing.
 *
 * Registration packet (agent → teamserver):
 *   ephemeral_pubkey(32) | nonce(12) | AES-GCM(timestamp_be8 | metadata) | tag(16)
 *
 * Registration response (teamserver → agent):
 *   connection_id(16) | nonce(12) | AES-GCM(agent_id_le4) | tag(16)
 *
 * Session packet (agent → teamserver):
 *   connection_id(16) | nonce(12) | AES-GCM(payload) | tag(16)
 *
 * Session response (teamserver → agent):
 *   nonce(12) | AES-GCM(payload) | tag(16)
 */
#ifndef ARCHON_ECDH_INIT_H
#define ARCHON_ECDH_INIT_H

#ifdef _WIN32
#   include <windows.h>
    typedef UINT8  ei_u8;
    typedef UINT32 ei_u32;
    typedef UINT64 ei_u64;
    typedef SIZE_T ei_size_t;
    typedef BOOL   ei_bool;
#   define EI_TRUE  TRUE
#   define EI_FALSE FALSE
#else
#   include <stdint.h>
#   include <stddef.h>
    typedef uint8_t  ei_u8;
    typedef uint32_t ei_u32;
    typedef uint64_t ei_u64;
    typedef size_t   ei_size_t;
    typedef int      ei_bool;
#   define EI_TRUE  1
#   define EI_FALSE 0
#endif

/* Minimum bytes for a valid registration response */
#define ECDH_REG_RESP_MIN  (16 + 12 + 4 + 16)   /* conn_id+nonce+agent_id+tag */

/* Minimum bytes for a valid session response */
#define ECDH_SESS_RESP_MIN (12 + 16)             /* nonce + tag */

/*
 * Build an ECDH registration packet.
 *
 * listener_pubkey  — 32-byte X25519 public key compiled into the binary
 * metadata         — raw agent metadata bytes (output of BuildEcdhMetadata)
 * metadata_len     — length of metadata
 * out_packet       — output buffer; caller must provide at least
 *                    (32 + 12 + 8 + metadata_len + 16) bytes
 * out_packet_len   — [out] bytes written to out_packet
 * out_session_key  — [out] 32-byte session key (store for session packets)
 * rng_fill         — callback that fills buf with len random bytes; TRUE=ok
 * unix_now         — current UTC Unix timestamp (seconds); for replay protection
 *
 * Returns EI_TRUE on success.
 */
ei_bool ecdh_build_registration_packet(
    const ei_u8 *listener_pubkey,
    const ei_u8 *metadata,
    ei_size_t    metadata_len,
    ei_u8       *out_packet,
    ei_size_t   *out_packet_len,
    ei_u8        out_session_key[32],
    ei_bool    (*rng_fill)(ei_u8 *buf, ei_size_t len),
    ei_u64       unix_now
);

/*
 * Parse a registration response from the teamserver.
 *
 * session_key     — 32-byte key returned by ecdh_build_registration_packet
 * response        — raw response bytes
 * response_len    — length of response
 * out_connection_id — [out] 16-byte connection ID for subsequent session packets
 * out_agent_id    — [out] agent ID assigned by the teamserver (little-endian)
 *
 * Returns EI_TRUE on success.
 */
ei_bool ecdh_parse_registration_response(
    const ei_u8 *session_key,
    const ei_u8 *response,
    ei_size_t    response_len,
    ei_u8        out_connection_id[16],
    ei_u32      *out_agent_id
);

/*
 * Build an ECDH session packet.
 *
 * connection_id — 16 bytes received in the registration response
 * session_key   — 32-byte session key
 * payload       — packet payload bytes
 * payload_len   — length of payload
 * out           — output buffer; at least (16 + 12 + payload_len + 16) bytes
 * out_len       — [out] total bytes written
 * rng_fill      — RNG callback
 *
 * Returns EI_TRUE on success.
 */
ei_bool ecdh_build_session_packet(
    const ei_u8 *connection_id,
    const ei_u8 *session_key,
    const ei_u8 *payload,
    ei_size_t    payload_len,
    ei_u8       *out,
    ei_size_t   *out_len,
    ei_bool    (*rng_fill)(ei_u8 *buf, ei_size_t len)
);

/*
 * Decrypt a session response (teamserver → agent).
 *
 * session_key   — 32-byte session key
 * response      — nonce(12) | ciphertext | tag(16)
 * response_len  — total length
 * out           — output buffer; at least (response_len - 12 - 16) bytes
 * out_len       — [out] plaintext bytes written
 *
 * Returns EI_TRUE on success.
 */
ei_bool ecdh_open_session_response(
    const ei_u8 *session_key,
    const ei_u8 *response,
    ei_size_t    response_len,
    ei_u8       *out,
    ei_size_t   *out_len
);

#endif /* ARCHON_ECDH_INIT_H */
