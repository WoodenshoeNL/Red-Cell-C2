/*
 * replay_harness.c — Demon packet-header replay test.
 *
 * Reads a `.bin` corpus file captured from the teamserver's Demon protocol
 * and verifies the packet header fields without running the full agent
 * process.  Checks:
 *   - wire size field is consistent with the file length
 *   - magic bytes == 0xDEADBEEF
 *   - agent_id matches session.keys.json
 *   - command_id == DemonInit (99)
 *   - embedded AES key and IV match session.keys.json
 *
 * Build:
 *   gcc -std=c11 -Wall -Wextra -Werror -O2 -o demon_replay_harness replay_harness.c
 *
 * Run:
 *   ./demon_replay_harness <corpus-dir>
 *   e.g.: ./demon_replay_harness ../../../tests/wire-corpus/demon/checkin
 *
 * Exit code: 0 = all assertions passed, 1 = at least one failed,
 *            2 = usage / I/O error.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Protocol constants (must stay in sync with common/src/demon/commands.rs)
 * ---------------------------------------------------------------------- */
#define DEMON_MAGIC_VALUE   0xDEADBEEFUL
#define DEMON_INIT_CMD      99U

/* Header field offsets (big-endian wire layout) */
#define HDR_OFF_SIZE        0
#define HDR_OFF_MAGIC       4
#define HDR_OFF_AGENT_ID    8
/* Payload field offsets (relative to start of payload = byte 12) */
#define PLD_OFF_COMMAND_ID  0
#define PLD_OFF_REQUEST_ID  4
#define PLD_OFF_KEY         8
#define PLD_OFF_IV          40  /* 8 + AES_KEY_LEN(32) */

#define AES_KEY_LEN         32
#define AES_IV_LEN          16

/* -------------------------------------------------------------------------
 * Portable test framework
 * ---------------------------------------------------------------------- */
static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond)
{
    if (cond) {
        printf("  PASS  %s\n", name);
        g_pass++;
    } else {
        printf("  FAIL  %s\n", name);
        g_fail++;
    }
}

/* -------------------------------------------------------------------------
 * File I/O helpers
 * ---------------------------------------------------------------------- */

/* Read the entire file at `path` into a heap buffer.  Sets *out_len.
 * Returns NULL on error (errno set). */
static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

/* -------------------------------------------------------------------------
 * Big-endian decode helpers
 * ---------------------------------------------------------------------- */
static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         | ((uint32_t)p[3]      );
}

/* -------------------------------------------------------------------------
 * Minimal JSON field extractors (no external library dependency)
 * ---------------------------------------------------------------------- */

/* Find the string value for `key` in a flat JSON object.
 * Writes up to `out_cap - 1` characters into `out` and NUL-terminates.
 * Returns 1 on success, 0 if the key is not found. */
static int json_get_string(const char *json, const char *key,
                            char *out, size_t out_cap)
{
    char needle[128];
    /* Build search string like `"agent_id_hex":` */
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *pos = strstr(json, needle);
    if (!pos) return 0;
    pos += strlen(needle);
    /* Skip whitespace and colon */
    while (*pos == ' ' || *pos == '\t' || *pos == ':' || *pos == ' ') pos++;
    if (*pos != '"') return 0;
    pos++; /* skip opening quote */
    size_t i = 0;
    while (*pos && *pos != '"' && i + 1 < out_cap)
        out[i++] = *pos++;
    out[i] = '\0';
    return 1;
}

/* Decode a lowercase hex string (no 0x prefix) of length `byte_count * 2`
 * into `out`.  Returns 1 on success, 0 on length/format error. */
static int hex_decode(const char *hex, uint8_t *out, size_t byte_count)
{
    if (strlen(hex) < byte_count * 2) return 0;
    for (size_t i = 0; i < byte_count; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) return 0;
        out[i] = (uint8_t)byte;
    }
    return 1;
}

/* Parse `agent_id_hex` from session.keys.json.
 * Accepts "0xDEADC0DE" or "deadc0de". */
static uint32_t parse_agent_id_hex(const char *json)
{
    char val[64] = {0};
    if (!json_get_string(json, "agent_id_hex", val, sizeof(val)))
        return 0;
    /* Strip optional 0x / 0X prefix */
    const char *hex = val;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        hex += 2;
    unsigned long n = 0;
    if (sscanf(hex, "%lx", &n) != 1) return 0;
    return (uint32_t)n;
}

/* -------------------------------------------------------------------------
 * Build path: base_dir + "/" + filename
 * ---------------------------------------------------------------------- */
static void make_path(char *buf, size_t cap,
                       const char *dir, const char *file)
{
    snprintf(buf, cap, "%s/%s", dir, file);
}

/* -------------------------------------------------------------------------
 * Main test body
 * ---------------------------------------------------------------------- */
static int run_tests(const char *corpus_dir)
{
    char bin_path[4096];
    char keys_path[4096];
    make_path(bin_path,  sizeof(bin_path),  corpus_dir, "0000.bin");
    make_path(keys_path, sizeof(keys_path), corpus_dir, "session.keys.json");

    /* ── Load corpus binary ── */
    size_t bin_len = 0;
    uint8_t *bin = read_file(bin_path, &bin_len);
    if (!bin) {
        fprintf(stderr, "ERROR: cannot open corpus file: %s\n", bin_path);
        return 2;
    }

    /* ── Load session keys ── */
    size_t keys_len = 0;
    uint8_t *keys_raw = read_file(keys_path, &keys_len);
    if (!keys_raw) {
        fprintf(stderr, "ERROR: cannot open session keys: %s\n", keys_path);
        free(bin);
        return 2;
    }
    /* NUL-terminate for string functions */
    char *keys_json = malloc(keys_len + 1);
    if (!keys_json) { free(bin); free(keys_raw); return 2; }
    memcpy(keys_json, keys_raw, keys_len);
    keys_json[keys_len] = '\0';
    free(keys_raw);

    printf("Demon replay harness — corpus: %s\n\n", corpus_dir);
    printf("=== Structural header checks ===\n");

    /* ── 1. Minimum file size (at least 68 bytes: 12-byte header + 56-byte cleartext payload) ── */
    check("file is at least 68 bytes (header + cleartext payload)",
          bin_len >= 68);

    if (bin_len < 12) {
        fprintf(stderr, "ERROR: file too short to parse header (%zu bytes)\n", bin_len);
        free(bin); free(keys_json);
        return 2;
    }

    /* ── 2. Wire size field consistency ── */
    uint32_t wire_size = be32(bin + HDR_OFF_SIZE);
    /* wire_size must equal file_len - 4 (size field does not count itself) */
    check("wire size field == file_len - 4",
          wire_size == (uint32_t)(bin_len - 4));

    /* ── 3. Magic value ── */
    uint32_t magic = be32(bin + HDR_OFF_MAGIC);
    check("magic == 0xDEADBEEF",
          magic == DEMON_MAGIC_VALUE);

    /* ── 4. AgentID from packet vs session.keys.json ── */
    uint32_t packet_agent_id = be32(bin + HDR_OFF_AGENT_ID);
    uint32_t keys_agent_id   = parse_agent_id_hex(keys_json);
    char agent_id_check[128];
    snprintf(agent_id_check, sizeof(agent_id_check),
             "agent_id in packet (0x%08X) == session.keys.json agent_id_hex (0x%08X)",
             packet_agent_id, keys_agent_id);
    check(agent_id_check,
          keys_agent_id != 0 && packet_agent_id == keys_agent_id);

    /* ── 5. CommandID == DemonInit (99) ── */
    uint32_t command_id = be32(bin + 12 + PLD_OFF_COMMAND_ID);
    check("command_id == DemonInit (99)",
          command_id == DEMON_INIT_CMD);

    /* ── 6. AES key embedded in packet matches session.keys.json ── */
    printf("\n=== Cryptographic material checks ===\n");

    char key_hex_str[128] = {0};
    uint8_t expected_key[AES_KEY_LEN] = {0};
    int key_ok = json_get_string(keys_json, "aes_key_hex",
                                 key_hex_str, sizeof(key_hex_str));
    if (key_ok) key_ok = hex_decode(key_hex_str, expected_key, AES_KEY_LEN);
    check("session.keys.json aes_key_hex decoded successfully", key_ok);

    if (key_ok && bin_len >= 12 + PLD_OFF_KEY + AES_KEY_LEN) {
        check("AES key embedded in packet matches session.keys.json",
              memcmp(bin + 12 + PLD_OFF_KEY, expected_key, AES_KEY_LEN) == 0);
    }

    /* ── 7. AES IV embedded in packet matches session.keys.json ── */
    char iv_hex_str[64] = {0};
    uint8_t expected_iv[AES_IV_LEN] = {0};
    int iv_ok = json_get_string(keys_json, "aes_iv_hex",
                                iv_hex_str, sizeof(iv_hex_str));
    if (iv_ok) iv_ok = hex_decode(iv_hex_str, expected_iv, AES_IV_LEN);
    check("session.keys.json aes_iv_hex decoded successfully", iv_ok);

    if (iv_ok && bin_len >= 12 + PLD_OFF_IV + AES_IV_LEN) {
        check("AES IV embedded in packet matches session.keys.json",
              memcmp(bin + 12 + PLD_OFF_IV, expected_iv, AES_IV_LEN) == 0);
    }

    free(bin);
    free(keys_json);

    printf("\n--- Results: %d passed, %d failed ---\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <corpus-dir>\n", argv[0]);
        fprintf(stderr, "  e.g. %s ../../../tests/wire-corpus/demon/checkin\n", argv[0]);
        return 2;
    }
    return run_tests(argv[1]);
}
