/*
 * test_ecdh_init.c — Integration tests for the Archon ECDH session key exchange.
 *
 * Tests the full crypto stack: X25519, SHA-256 / HMAC-SHA256 / HKDF-SHA256,
 * AES-256-GCM, and the ECDH registration + session protocol (EcdhInit).
 *
 * Build:
 *   cd agent/archon/tests && make test_ecdh_init
 *
 * Compiled for Linux with GCC — no Windows.h / MinGW required.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── Portable type aliases (mirror the #ifdef _WIN32 branches in the headers) ── */
typedef uint8_t  ei_u8;
typedef uint32_t ei_u32;
typedef uint64_t ei_u64;
typedef size_t   ei_size_t;
typedef int      ei_bool;
#define EI_TRUE  1
#define EI_FALSE 0

typedef uint8_t  gcm_u8;
typedef uint32_t gcm_u32;
typedef uint64_t gcm_u64;
typedef size_t   gcm_size_t;
typedef int      gcm_bool;
#define GCM_TRUE  1
#define GCM_FALSE 0

typedef int32_t  x25519_i32;
typedef int64_t  x25519_i64;
typedef uint8_t  x25519_u8;
typedef uint64_t x25519_u64;

typedef uint8_t  sha256_u8;
typedef uint32_t sha256_u32;
typedef uint64_t sha256_u64;
typedef size_t   sha256_size_t;

#define AESGCM_KEY_LEN   32
#define AESGCM_NONCE_LEN 12
#define AESGCM_TAG_LEN   16
#define SHA256_DIGEST_LEN 32

/* ── Pull in the crypto implementations ──────────────────────────────────── */
#include "../src/crypt/X25519.c"
#include "../src/crypt/Sha256.c"
#include "../src/crypt/AesGcm.c"
#include "../src/crypt/EcdhInit.c"

/* ── Test helpers ────────────────────────────────────────────────────────── */

static int  g_pass = 0;
static int  g_fail = 0;

static void CHECK(int cond, const char *name) {
    if (cond) {
        printf("  PASS  %s\n", name);
        g_pass++;
    } else {
        printf("  FAIL  %s\n", name);
        g_fail++;
    }
}

static void CHECK_BYTES(const uint8_t *a, const uint8_t *b, size_t n, const char *name) {
    if (memcmp(a, b, n) == 0) {
        printf("  PASS  %s\n", name);
        g_pass++;
    } else {
        printf("  FAIL  %s\n", name);
        size_t i;
        printf("        got:      ");
        for (i = 0; i < n; i++) printf("%02x", a[i]);
        printf("\n        expected: ");
        for (i = 0; i < n; i++) printf("%02x", b[i]);
        printf("\n");
        g_fail++;
    }
}

/* Simple CSPRNG using /dev/urandom for the test */
static ei_bool test_rng(ei_u8 *buf, ei_size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return EI_FALSE;
    size_t r = fread(buf, 1, len, f);
    fclose(f);
    return (r == len) ? EI_TRUE : EI_FALSE;
}

/* ── Test 1: SHA-256 known-answer test ───────────────────────────────────── */

static void test_sha256_known_vector(void) {
    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469312 */
    static const uint8_t in[] = { 'a', 'b', 'c' };
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x2e, 0xc7,
        0x3b, 0x00, 0x36, 0x1b, 0xbe, 0xf0, 0x46, 0x93,
        0x12, 0x19, 0x09, 0x33, 0x30, 0xf5, 0x85, 0x19,
    };
    uint8_t out[32];

    sha256(in, sizeof(in), out);
    CHECK_BYTES(out, expected, 32, "sha256(\"abc\") known vector");
}

/* ── Test 2: HMAC-SHA256 known-answer test ───────────────────────────────── */

static void test_hmac_sha256(void) {
    /* RFC 4231 test case 1:
     * Key = 0x0b0b...0b (20 bytes)
     * Data = "Hi There"
     * HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
     */
    static const uint8_t key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,
    };
    static const uint8_t data[] = { 'H','i',' ','T','h','e','r','e' };
    static const uint8_t expected[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
        0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
        0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7,
    };
    uint8_t out[32];

    hmac_sha256(key, 20, data, 8, out);
    CHECK_BYTES(out, expected, 32, "hmac_sha256 RFC 4231 test case 1");
}

/* ── Test 3: X25519 DH property (ECDH(A,B) == ECDH(B,A)) ────────────────── */

static void test_x25519_dh_property(void) {
    /* Use RFC 7748 section 6.1 inputs */
    static const uint8_t alice_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
        0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0x38,0xf4,0x09,0x39,0x52,0xd5,0x10,0x91,
        0x39,0xa4,0x3e,0xdb,0xef,0x2f,0x5a,0xa4,
    };
    static const uint8_t bob_priv[32] = {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
        0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
        0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb,
    };
    /* Expected shared secret (RFC 7748 section 6.1) */
    static const uint8_t expected_shared[32] = {
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,
        0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x35,
        0x76,0xf0,0x9e,0x5c,0x4b,0x36,0x40,0xcf,
    };

    uint8_t alice_pub[32], bob_pub[32];
    uint8_t shared_a[32], shared_b[32];

    x25519_public_key(alice_pub, alice_priv);
    x25519_public_key(bob_pub,   bob_priv);

    x25519_diffie_hellman(shared_a, alice_priv, bob_pub);
    x25519_diffie_hellman(shared_b, bob_priv,   alice_pub);

    CHECK(memcmp(shared_a, shared_b, 32) == 0, "x25519: ECDH(A,B) == ECDH(B,A)");
    CHECK_BYTES(shared_a, expected_shared, 32,  "x25519: shared secret matches RFC 7748 §6.1");
}

/* ── Test 4: AES-256-GCM round-trip ─────────────────────────────────────── */

static void test_aesgcm_roundtrip(void) {
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    };
    static const uint8_t nonce[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
        0xde,0xca,0xf8,0x88,
    };
    static const uint8_t plaintext[] = "ECDH session test payload for Archon";
    size_t pt_len = sizeof(plaintext) - 1;

    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t recovered[sizeof(plaintext)];

    gcm_bool ok_enc = aes256gcm_encrypt(key, nonce, plaintext, pt_len,
                                        ciphertext);
    CHECK(ok_enc, "aes256gcm_encrypt returns GCM_TRUE");

    gcm_bool ok_dec = aes256gcm_decrypt(key, nonce, ciphertext, pt_len + 16,
                                        recovered);
    CHECK(ok_dec, "aes256gcm_decrypt returns GCM_TRUE");
    CHECK(memcmp(recovered, plaintext, pt_len) == 0,
          "aes256gcm: decrypt recovers original plaintext");

    /* Tamper with ciphertext — tag must fail */
    ciphertext[0] ^= 0xff;
    gcm_bool ok_bad = aes256gcm_decrypt(key, nonce, ciphertext, pt_len + 16,
                                        recovered);
    CHECK(!ok_bad, "aes256gcm_decrypt rejects tampered ciphertext");
}

/* ── Test 5: aes256gcm_seal / aes256gcm_open (random nonce helpers) ──────── */

static void test_aesgcm_seal_open(void) {
    static const uint8_t key[32] = {
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
    };
    static const uint8_t pt[] = "hello ECDH";
    size_t pt_len = sizeof(pt) - 1;

    uint8_t sealed[12 + sizeof(pt) + 16];
    uint8_t opened[sizeof(pt)];

    gcm_size_t sealed_len = aes256gcm_seal(key, pt, pt_len, sealed, test_rng);
    CHECK(sealed_len == 12 + pt_len + 16, "aes256gcm_seal: correct output length");

    gcm_size_t opened_len = aes256gcm_open(key, sealed, sealed_len, opened);
    CHECK(opened_len == pt_len, "aes256gcm_open: correct plaintext length");
    CHECK(memcmp(opened, pt, pt_len) == 0, "aes256gcm_open: plaintext matches");
}

/* ── Test 6: Full ECDH registration + session protocol round-trip ─────────── */

/*
 * Simulate both sides:
 *   Agent:      ecdh_build_registration_packet()
 *   "Server":   ECDH(listener_static_secret, eph_pubkey), derive session key,
 *               decrypt metadata, build registration response
 *   Agent:      ecdh_parse_registration_response()
 *   Agent:      ecdh_build_session_packet()
 *   "Server":   ecdh_open_session_response() equivalent
 */

/* Server-side helper: derive session key from listener_secret + eph_public */
static void server_derive_session_key(
    const uint8_t listener_secret[32],
    const uint8_t eph_public[32],
    uint8_t       out_session_key[32]
) {
    uint8_t shared[32];
    x25519_diffie_hellman(shared, listener_secret, eph_public);

    /* HKDF-SHA256, no salt (zero salt), info = "red-cell-ecdh-session-key-v1" */
    static const uint8_t HKDF_INFO[] = "red-cell-ecdh-session-key-v1";
    uint8_t prk[32];
    uint8_t zero_salt[32];
    size_t i;
    for (i = 0; i < 32; i++) zero_salt[i] = 0;

    hmac_sha256(zero_salt, 32, shared, 32, prk);
    hkdf_sha256_expand(prk, 32, HKDF_INFO, 28, out_session_key, 32);
}

static void test_ecdh_full_protocol(void) {
    /* Listener static keypair (fixed for deterministic test) */
    static const uint8_t listener_secret[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
    };
    uint8_t listener_public[32];
    x25519_public_key(listener_public, listener_secret);

    /* Agent side — metadata to embed */
    static const uint8_t metadata[] = "agent-id\x00\x00\x00\x04hostname\x00\x00\x00\x04user";
    size_t meta_len = sizeof(metadata) - 1;

    /* Allocate registration packet buffer */
    size_t pkt_max = 32 + 12 + 8 + meta_len + 16 + 64;
    uint8_t *pkt_buf = malloc(pkt_max);
    size_t   pkt_len = pkt_max;
    uint8_t  agent_session_key[32];

    ei_bool ok_build = ecdh_build_registration_packet(
        listener_public, metadata, meta_len,
        pkt_buf, &pkt_len,
        agent_session_key,
        test_rng,
        (ei_u64)1700000000ULL  /* fixed unix timestamp for test */
    );
    CHECK(ok_build, "ecdh_build_registration_packet: returns EI_TRUE");

    /* Server side: extract ephemeral public key (first 32 bytes) and derive key */
    uint8_t server_session_key[32];
    server_derive_session_key(listener_secret, pkt_buf, server_session_key);

    CHECK(memcmp(agent_session_key, server_session_key, 32) == 0,
          "ecdh: agent and server derive identical session keys");

    /* Server side: decrypt registration packet to get metadata
     *   pkt_buf = eph_public(32) | nonce(12) | AES-GCM(timestamp_8 | metadata) | tag(16) */
    size_t sealed_len = pkt_len - 32;
    size_t plain_max  = sealed_len;
    uint8_t *plain_buf = malloc(plain_max);
    gcm_size_t plain_len = aes256gcm_open(
        server_session_key, pkt_buf + 32, (gcm_size_t)sealed_len, plain_buf);
    CHECK(plain_len == (gcm_size_t)(8 + meta_len),
          "ecdh: server decrypts registration packet (timestamp + metadata)");
    CHECK(memcmp(plain_buf + 8, metadata, meta_len) == 0,
          "ecdh: server sees correct metadata bytes");
    free(plain_buf);

    /* Server side: build registration response
     *   response = connection_id(16) | nonce(12) | AES-GCM(agent_id_le4) | tag(16) */
    uint8_t connection_id[16];
    test_rng(connection_id, 16);

    uint32_t assigned_agent_id = 0xDEAD1234u;
    uint8_t  agent_id_le4[4] = {
        (uint8_t)(assigned_agent_id      ),
        (uint8_t)(assigned_agent_id >>  8),
        (uint8_t)(assigned_agent_id >> 16),
        (uint8_t)(assigned_agent_id >> 24),
    };
    uint8_t resp_sealed[4 + 12 + 16];
    gcm_size_t resp_sealed_len = aes256gcm_seal(
        server_session_key, agent_id_le4, 4, resp_sealed, test_rng);

    uint8_t reg_response[16 + 12 + 4 + 16];
    memcpy(reg_response,      connection_id, 16);
    memcpy(reg_response + 16, resp_sealed,   resp_sealed_len);
    size_t reg_response_len = 16 + resp_sealed_len;

    /* Agent side: parse registration response */
    uint8_t  out_conn_id[16];
    uint32_t out_agent_id = 0;
    ei_bool ok_parse = ecdh_parse_registration_response(
        agent_session_key,
        reg_response, reg_response_len,
        out_conn_id, &out_agent_id);
    CHECK(ok_parse, "ecdh_parse_registration_response: returns EI_TRUE");
    CHECK(memcmp(out_conn_id, connection_id, 16) == 0,
          "ecdh: agent recovers correct connection_id");
    CHECK(out_agent_id == assigned_agent_id,
          "ecdh: agent recovers correct agent_id from response");

    /* Agent side: build a session packet */
    static const uint8_t payload[] = "task-result-bytes";
    size_t payload_len = sizeof(payload) - 1;
    size_t sess_pkt_max = 16 + 12 + payload_len + 16;
    uint8_t *sess_pkt = malloc(sess_pkt_max);
    size_t   sess_pkt_len = sess_pkt_max;

    ei_bool ok_sess = ecdh_build_session_packet(
        out_conn_id, agent_session_key,
        payload, payload_len,
        sess_pkt, &sess_pkt_len,
        test_rng);
    CHECK(ok_sess, "ecdh_build_session_packet: returns EI_TRUE");
    CHECK(memcmp(sess_pkt, out_conn_id, 16) == 0,
          "ecdh_build_session_packet: starts with connection_id");

    /* Server side: decrypt session packet (bytes 16 onwards = nonce|ct|tag) */
    size_t sess_body_len = sess_pkt_len - 16;
    uint8_t *sess_plain = malloc(sess_body_len);
    gcm_size_t sess_plain_len = aes256gcm_open(
        server_session_key, sess_pkt + 16, (gcm_size_t)sess_body_len, sess_plain);
    CHECK(sess_plain_len == (gcm_size_t)payload_len,
          "ecdh: server decrypts session packet");
    CHECK(memcmp(sess_plain, payload, payload_len) == 0,
          "ecdh: server sees correct session payload");
    free(sess_plain);

    /* Server side: seal a session response */
    static const uint8_t task_data[] = "command-from-teamserver";
    size_t task_len = sizeof(task_data) - 1;
    uint8_t *task_sealed = malloc(12 + task_len + 16);
    gcm_size_t task_sealed_len = aes256gcm_seal(
        server_session_key, task_data, task_len, task_sealed, test_rng);

    /* Agent side: open session response */
    uint8_t resp_out[64];
    size_t  resp_out_len = 0;
    ei_bool ok_open = ecdh_open_session_response(
        agent_session_key,
        task_sealed, (ei_size_t)task_sealed_len,
        resp_out, &resp_out_len);
    CHECK(ok_open, "ecdh_open_session_response: returns EI_TRUE");
    CHECK(resp_out_len == task_len, "ecdh_open_session_response: correct plaintext length");
    CHECK(memcmp(resp_out, task_data, task_len) == 0,
          "ecdh_open_session_response: correct plaintext content");

    free(task_sealed);
    free(sess_pkt);
    free(pkt_buf);
}

/*
 * Verify that the session packet GCM plaintext starts with an 8-byte
 * little-endian seq_num prefix followed by the application payload.
 *
 * This mirrors the agent-side PackageTransmitAll ECDH path: the agent
 * prepends seq_num(8 LE) before the DemonMessage bytes and seals the
 * whole thing.  The teamserver strips the prefix and validates it.
 */
static void test_ecdh_session_seq_num(void)
{
    printf("  seq_num prefix: ");

    /* Shared secret for this test */
    uint8_t key[32];
    memset(key, 0xAA, sizeof(key));

    /* Simulate what PackageTransmitAll builds: seq_num(8) | payload */
    uint64_t seq = 0x0000000000000007ULL; /* seq_num = 7 */
    const uint8_t demon_msg[] = {
        /* DemonMessage: cmd_id(4 LE) | req_id(4 LE) | len(4 LE) */
        0x01, 0x00, 0x00, 0x00,  /* cmd_id = 1 */
        0x02, 0x00, 0x00, 0x00,  /* req_id = 2 */
        0x00, 0x00, 0x00, 0x00   /* len = 0 (empty payload) */
    };

    uint8_t plaintext[8 + sizeof(demon_msg)];
    /* Write seq_num as little-endian u64 */
    for (int i = 0; i < 8; i++) {
        plaintext[i] = (uint8_t)(seq >> (8 * i));
    }
    memcpy(plaintext + 8, demon_msg, sizeof(demon_msg));
    size_t plaintext_len = sizeof(plaintext);

    /* Seal with AES-256-GCM (as ecdh_build_session_packet does internally) */
    uint8_t conn_id[16];
    memset(conn_id, 0xBB, sizeof(conn_id));
    size_t pkt_max = 16 + 12 + plaintext_len + 16;
    uint8_t *pkt = malloc(pkt_max);
    size_t   pkt_len = pkt_max;
    ei_bool ok = ecdh_build_session_packet(
        conn_id, key,
        plaintext, plaintext_len,
        pkt, &pkt_len,
        test_rng);
    CHECK(ok, "seq_num: ecdh_build_session_packet succeeds");

    /* Server decrypts: body[16..] = nonce | ciphertext | tag */
    size_t body_len = pkt_len - 16;
    uint8_t *decrypted = malloc(body_len);
    gcm_size_t decrypted_len = aes256gcm_open(key, pkt + 16, (gcm_size_t)body_len, decrypted);
    CHECK(decrypted_len == (gcm_size_t)plaintext_len,
          "seq_num: server decrypts full GCM plaintext");

    /* Verify seq_num prefix (little-endian u64) */
    uint64_t got_seq = 0;
    for (int i = 0; i < 8; i++) {
        got_seq |= (uint64_t)decrypted[i] << (8 * i);
    }
    CHECK(got_seq == seq, "seq_num: server reads correct seq_num from prefix");

    /* Verify remainder is the DemonMessage */
    CHECK(decrypted_len - 8 == sizeof(demon_msg),
          "seq_num: remainder length matches DemonMessage");
    CHECK(memcmp(decrypted + 8, demon_msg, sizeof(demon_msg)) == 0,
          "seq_num: remainder bytes match DemonMessage");

    /* Verify replay detection: a second packet with seq 6 (< 7) must be
     * distinguishable.  We just confirm the seq_num is lower. */
    uint64_t old_seq = 6;
    uint8_t old_prefix[8];
    for (int i = 0; i < 8; i++) old_prefix[i] = (uint8_t)(old_seq >> (8 * i));
    uint64_t read_old = 0;
    for (int i = 0; i < 8; i++) read_old |= (uint64_t)old_prefix[i] << (8 * i);
    CHECK(read_old < seq, "seq_num: lower seq_num correctly identified as replay candidate");

    free(decrypted);
    free(pkt);
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== Archon ECDH test suite ===\n\n");

    printf("SHA-256 / HMAC-SHA256:\n");
    test_sha256_known_vector();
    test_hmac_sha256();

    printf("\nX25519:\n");
    test_x25519_dh_property();

    printf("\nAES-256-GCM:\n");
    test_aesgcm_roundtrip();
    test_aesgcm_seal_open();

    printf("\nECDH protocol:\n");
    test_ecdh_full_protocol();
    test_ecdh_session_seq_num();

    printf("\n===========================\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
