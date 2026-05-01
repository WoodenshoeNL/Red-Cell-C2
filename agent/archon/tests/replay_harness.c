/*
 * replay_harness.c — Archon packet-header replay test.
 *
 * Archon is wire-compatible with Demon: both use the same transport envelope
 * format (0xDEADBEEF magic, big-endian header, DemonInit command = 99).
 *
 * This harness reads the Demon checkin corpus (the only populated corpus as of
 * 2026-05-01; Archon will gain its own corpus once live capture is available)
 * and verifies the packet header fields.  Exits 0 when the corpus is absent
 * or could not be opened — absence is expected on machines that have not run
 * the corpus-capture step yet.
 *
 * Build:
 *   gcc -std=c11 -Wall -Wextra -Werror -O2 -o archon_replay_harness replay_harness.c
 *
 * Run:
 *   ./archon_replay_harness <corpus-dir>
 *   e.g.: ./archon_replay_harness ../../../tests/wire-corpus/demon/checkin
 *
 * Exit code: 0 = all assertions passed or corpus absent (graceful skip),
 *            1 = at least one assertion failed, 2 = I/O error on existing file.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* -------------------------------------------------------------------------
 * Protocol constants
 * ---------------------------------------------------------------------- */
#define DEMON_MAGIC_VALUE   0xDEADBEEFUL
#define DEMON_INIT_CMD      99U

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

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         | ((uint32_t)p[3]      );
}

/* -------------------------------------------------------------------------
 * Minimal JSON field extractors
 * ---------------------------------------------------------------------- */
static int json_get_string(const char *json, const char *key,
                            char *out, size_t out_cap)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *pos = strstr(json, needle);
    if (!pos) return 0;
    pos += strlen(needle);
    while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
    if (*pos != '"') return 0;
    pos++;
    size_t i = 0;
    while (*pos && *pos != '"' && i + 1 < out_cap)
        out[i++] = *pos++;
    out[i] = '\0';
    return 1;
}

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

static uint32_t parse_agent_id_hex(const char *json)
{
    char val[64] = {0};
    if (!json_get_string(json, "agent_id_hex", val, sizeof(val))) return 0;
    const char *hex = val;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    unsigned long n = 0;
    if (sscanf(hex, "%lx", &n) != 1) return 0;
    return (uint32_t)n;
}

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

    /* Graceful skip when corpus is absent */
    size_t bin_len = 0;
    uint8_t *bin = read_file(bin_path, &bin_len);
    if (!bin) {
        if (errno == ENOENT) {
            printf("NOTE: corpus not found (%s) — skipping (expected before capture)\n",
                   bin_path);
            return 0;
        }
        fprintf(stderr, "ERROR: cannot open corpus file: %s\n", bin_path);
        return 2;
    }

    size_t keys_len = 0;
    uint8_t *keys_raw = read_file(keys_path, &keys_len);
    if (!keys_raw) {
        if (errno == ENOENT) {
            printf("NOTE: session keys not found (%s) — skipping\n", keys_path);
            free(bin);
            return 0;
        }
        fprintf(stderr, "ERROR: cannot open session keys: %s\n", keys_path);
        free(bin);
        return 2;
    }
    char *keys_json = malloc(keys_len + 1);
    if (!keys_json) { free(bin); free(keys_raw); return 2; }
    memcpy(keys_json, keys_raw, keys_len);
    keys_json[keys_len] = '\0';
    free(keys_raw);

    printf("Archon replay harness (wire-compatible with Demon)\n");
    printf("Corpus: %s\n\n", corpus_dir);
    printf("=== Structural header checks ===\n");

    check("file is at least 68 bytes", bin_len >= 68);
    if (bin_len < 12) {
        fprintf(stderr, "ERROR: file too short (%zu bytes)\n", bin_len);
        free(bin); free(keys_json);
        return 2;
    }

    uint32_t wire_size = be32(bin);
    check("wire size field == file_len - 4",
          wire_size == (uint32_t)(bin_len - 4));

    uint32_t magic = be32(bin + 4);
    check("magic == 0xDEADBEEF", magic == DEMON_MAGIC_VALUE);

    uint32_t packet_agent_id = be32(bin + 8);
    uint32_t keys_agent_id   = parse_agent_id_hex(keys_json);
    char id_label[128];
    snprintf(id_label, sizeof(id_label),
             "agent_id in packet (0x%08X) == session.keys.json (0x%08X)",
             packet_agent_id, keys_agent_id);
    check(id_label, keys_agent_id != 0 && packet_agent_id == keys_agent_id);

    uint32_t command_id = be32(bin + 12);
    check("command_id == DemonInit (99)", command_id == DEMON_INIT_CMD);

    printf("\n=== Cryptographic material checks ===\n");

    char key_hex_str[128] = {0};
    uint8_t expected_key[AES_KEY_LEN] = {0};
    int key_ok = json_get_string(keys_json, "aes_key_hex",
                                 key_hex_str, sizeof(key_hex_str));
    if (key_ok) key_ok = hex_decode(key_hex_str, expected_key, AES_KEY_LEN);
    check("aes_key_hex decoded from session.keys.json", key_ok);
    if (key_ok && bin_len >= 12 + 8 + AES_KEY_LEN)
        check("AES key embedded in packet matches session.keys.json",
              memcmp(bin + 12 + 8, expected_key, AES_KEY_LEN) == 0);

    char iv_hex_str[64] = {0};
    uint8_t expected_iv[AES_IV_LEN] = {0};
    int iv_ok = json_get_string(keys_json, "aes_iv_hex",
                                iv_hex_str, sizeof(iv_hex_str));
    if (iv_ok) iv_ok = hex_decode(iv_hex_str, expected_iv, AES_IV_LEN);
    check("aes_iv_hex decoded from session.keys.json", iv_ok);
    if (iv_ok && bin_len >= 12 + 8 + AES_KEY_LEN + AES_IV_LEN)
        check("AES IV embedded in packet matches session.keys.json",
              memcmp(bin + 12 + 8 + AES_KEY_LEN, expected_iv, AES_IV_LEN) == 0);

    free(bin);
    free(keys_json);

    printf("\n--- Results: %d passed, %d failed ---\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <corpus-dir>\n", argv[0]);
        return 2;
    }
    return run_tests(argv[1]);
}
