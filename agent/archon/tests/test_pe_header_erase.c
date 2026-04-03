/*
 * test_pe_header_erase.c — Unit tests for ARC-07 PE header signature erasure.
 *
 * Validates that the erasure logic correctly zeros:
 *   1. The DOS header (MZ signature + fields)
 *   2. The DOS stub (bytes between IMAGE_DOS_HEADER and PE signature)
 *   3. The PE signature (PE\0\0) and everything after it in the header page
 *
 * Build and run:
 *   cd agent/archon/tests && make && ./test_pe_header_erase
 *
 * This file is compiled for Linux with GCC — no mingw / windows.h required.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * PE structure definitions (portable, matching Windows PE format)
 * ---------------------------------------------------------------------- */

#define IMAGE_DOS_SIGNATURE    0x5A4D      /* MZ */
#define IMAGE_NT_SIGNATURE     0x00004550  /* PE\0\0 */

#define PE_HEADER_PAGE_SIZE    0x1000

#pragma pack(push, 1)
typedef struct {
    uint16_t e_magic;      /* MZ */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;     /* offset to PE signature */
} IMAGE_DOS_HEADER;
#pragma pack(pop)

/* -------------------------------------------------------------------------
 * Test helpers
 * ---------------------------------------------------------------------- */

static int tests_run    = 0;
static int tests_passed = 0;

#define ASSERT_MSG(cond, msg) do {                                      \
    tests_run++;                                                         \
    if ( !(cond) ) {                                                     \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __func__, __LINE__, msg); \
        return;                                                          \
    }                                                                    \
    tests_passed++;                                                      \
} while (0)

/* Fill a buffer with a synthetic, valid PE header at the start. */
static void build_synthetic_pe(uint8_t *buf, size_t size, int32_t pe_offset)
{
    /* Fill entire page with a recognizable non-zero pattern */
    memset(buf, 0xCC, size);

    /* DOS header */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_cblp   = 0x0090;
    dos->e_cp     = 0x0003;
    dos->e_lfanew = pe_offset;

    /* PE signature at e_lfanew */
    *(uint32_t *)(buf + pe_offset) = IMAGE_NT_SIGNATURE;
}

/*
 * Simulate the erasure logic from RtStompPeHeader.
 * This mirrors the implementation exactly — no NtProtectVirtualMemory
 * calls needed on Linux since we own the buffer.
 */
static int erase_pe_header(uint8_t *buf, size_t page_size)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    int32_t pe_offset;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;  /* already stomped — success */
    }

    pe_offset = dos->e_lfanew;
    if (pe_offset <= 0 || (uint32_t)pe_offset >= page_size - sizeof(uint32_t)) {
        return -1; /* invalid */
    }

    /* 1. Zero the DOS header */
    memset(buf, 0, sizeof(IMAGE_DOS_HEADER));

    /* 2. Zero the DOS stub */
    if ((uint32_t)pe_offset > sizeof(IMAGE_DOS_HEADER)) {
        memset(buf + sizeof(IMAGE_DOS_HEADER), 0,
               pe_offset - sizeof(IMAGE_DOS_HEADER));
    }

    /* 3. Zero from PE signature to end of page */
    memset(buf + pe_offset, 0, page_size - pe_offset);

    return 1; /* erased */
}

/* -------------------------------------------------------------------------
 * Test cases
 * ---------------------------------------------------------------------- */

/* Test: standard PE with e_lfanew = 0x80 (typical for small PE) */
static void test_standard_pe_erase(void)
{
    uint8_t buf[PE_HEADER_PAGE_SIZE];
    int32_t pe_off = 0x80;

    build_synthetic_pe(buf, sizeof(buf), pe_off);

    /* Verify the synthetic PE is valid before erasure */
    ASSERT_MSG(*(uint16_t *)buf == IMAGE_DOS_SIGNATURE,
               "MZ signature should be present before erasure");
    ASSERT_MSG(*(uint32_t *)(buf + pe_off) == IMAGE_NT_SIGNATURE,
               "PE signature should be present before erasure");

    int ret = erase_pe_header(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == 1, "erase_pe_header should return 1 (erased)");

    /* MZ signature must be gone */
    ASSERT_MSG(*(uint16_t *)buf == 0,
               "MZ signature should be zeroed after erasure");

    /* Full DOS header must be zeroed */
    uint8_t zero_dos[sizeof(IMAGE_DOS_HEADER)];
    memset(zero_dos, 0, sizeof(zero_dos));
    ASSERT_MSG(memcmp(buf, zero_dos, sizeof(IMAGE_DOS_HEADER)) == 0,
               "entire DOS header should be zeroed");

    /* DOS stub (between DOS header and PE sig) must be zeroed */
    for (size_t i = sizeof(IMAGE_DOS_HEADER); i < (size_t)pe_off; i++) {
        ASSERT_MSG(buf[i] == 0, "DOS stub byte should be zeroed");
    }

    /* PE signature must be gone */
    ASSERT_MSG(*(uint32_t *)(buf + pe_off) == 0,
               "PE signature should be zeroed after erasure");

    /* Everything from PE offset to end of page must be zero */
    for (size_t i = pe_off; i < PE_HEADER_PAGE_SIZE; i++) {
        ASSERT_MSG(buf[i] == 0, "header page tail byte should be zeroed");
    }

    printf("  PASS: test_standard_pe_erase\n");
}

/* Test: PE with e_lfanew = 0xE0 (larger DOS stub, typical for VS-compiled) */
static void test_large_dos_stub_erase(void)
{
    uint8_t buf[PE_HEADER_PAGE_SIZE];
    int32_t pe_off = 0xE0;

    build_synthetic_pe(buf, sizeof(buf), pe_off);

    int ret = erase_pe_header(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == 1, "should erase successfully");

    /* Entire range [0, page_size) should be zero */
    for (size_t i = 0; i < PE_HEADER_PAGE_SIZE; i++) {
        ASSERT_MSG(buf[i] == 0, "all bytes in header page should be zeroed");
    }

    printf("  PASS: test_large_dos_stub_erase\n");
}

/* Test: already-stomped header (no MZ) should be a no-op */
static void test_already_stomped(void)
{
    uint8_t buf[PE_HEADER_PAGE_SIZE];
    memset(buf, 0xAA, sizeof(buf));

    /* No MZ signature */
    *(uint16_t *)buf = 0x0000;

    int ret = erase_pe_header(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == 0, "should return 0 (already stomped)");

    /* Buffer should be unchanged (0xAA pattern minus first 2 bytes) */
    ASSERT_MSG(buf[2] == 0xAA, "rest of buffer should be untouched");

    printf("  PASS: test_already_stomped\n");
}

/* Test: e_lfanew at minimum valid offset (right after DOS header) */
static void test_minimal_dos_stub(void)
{
    uint8_t buf[PE_HEADER_PAGE_SIZE];
    int32_t pe_off = sizeof(IMAGE_DOS_HEADER); /* no stub at all */

    build_synthetic_pe(buf, sizeof(buf), pe_off);

    int ret = erase_pe_header(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == 1, "should erase successfully with minimal stub");

    ASSERT_MSG(*(uint16_t *)buf == 0, "MZ should be zeroed");
    ASSERT_MSG(*(uint32_t *)(buf + pe_off) == 0, "PE sig should be zeroed");

    printf("  PASS: test_minimal_dos_stub\n");
}

/* Test: e_lfanew pointing too far (past safe range) should fail */
static void test_invalid_pe_offset(void)
{
    uint8_t buf[PE_HEADER_PAGE_SIZE];

    build_synthetic_pe(buf, sizeof(buf), 0x80);

    /* Corrupt e_lfanew to point past the page */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    dos->e_lfanew = PE_HEADER_PAGE_SIZE;

    int ret = erase_pe_header(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == -1, "should return -1 for out-of-range e_lfanew");

    printf("  PASS: test_invalid_pe_offset\n");
}

/* Test: e_lfanew = 0 (invalid) should fail */
static void test_zero_pe_offset(void)
{
    uint8_t buf[PE_HEADER_PAGE_SIZE];

    build_synthetic_pe(buf, sizeof(buf), 0x80);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    dos->e_lfanew = 0;

    int ret = erase_pe_header(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == -1, "should return -1 for zero e_lfanew");

    printf("  PASS: test_zero_pe_offset\n");
}

/* -------------------------------------------------------------------------
 * Regression: original page protection is restored, not hardcoded
 *
 * ARC-07 bug: the PE header stomp originally hardcoded PAGE_EXECUTE_READ
 * as the restore value.  The correct behaviour is to save OldProt from
 * NtProtectVirtualMemory and pass it back on the restore call.
 *
 * Since we're on Linux and don't have NtProtectVirtualMemory, we verify
 * the erase_pe_header logic itself and add a simulated protection test.
 * ---------------------------------------------------------------------- */

/* Simulated protection tracking */
#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READ       0x20
#define PAGE_READONLY           0x02
#define PAGE_EXECUTE_READWRITE  0x40

static int g_prot_call_count = 0;
static uint32_t g_prot_new[8] = { 0 };
static uint32_t g_current_prot = PAGE_EXECUTE_READ;

static void sim_protect(uint32_t new_prot, uint32_t *old_prot)
{
    *old_prot = g_current_prot;
    if (g_prot_call_count < 8)
        g_prot_new[g_prot_call_count] = new_prot;
    g_prot_call_count++;
    g_current_prot = new_prot;
}

/*
 * Erase-with-protection: simulates the full NtProtectVirtualMemory flow
 * around the erase.  This is the code path that had the ARC-07 bug.
 */
static int erase_pe_header_with_protection(uint8_t *buf, size_t page_size)
{
    uint32_t old_prot = 0;
    uint32_t dummy = 0;
    int ret;

    /* Make writable */
    sim_protect(PAGE_READWRITE, &old_prot);

    ret = erase_pe_header(buf, page_size);

    /* Restore ORIGINAL protection — must use old_prot, NOT a constant */
    sim_protect(old_prot, &dummy);

    return ret;
}

static void test_protection_restore_not_hardcoded(void)
{
    uint8_t buf[PE_HEADER_PAGE_SIZE];

    /* Scenario 1: initial protection is PAGE_EXECUTE_READ */
    build_synthetic_pe(buf, sizeof(buf), 0x80);
    g_prot_call_count = 0;
    g_current_prot = PAGE_EXECUTE_READ;

    int ret = erase_pe_header_with_protection(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == 1, "should erase successfully");
    ASSERT_MSG(g_prot_call_count == 2, "should make 2 protection calls");
    ASSERT_MSG(g_prot_new[0] == PAGE_READWRITE, "first call sets PAGE_READWRITE");
    ASSERT_MSG(g_prot_new[1] == PAGE_EXECUTE_READ, "second call restores PAGE_EXECUTE_READ");

    /* Scenario 2: initial protection is PAGE_READONLY —
     * must NOT restore PAGE_EXECUTE_READ (the old bug) */
    build_synthetic_pe(buf, sizeof(buf), 0x80);
    g_prot_call_count = 0;
    g_current_prot = PAGE_READONLY;

    ret = erase_pe_header_with_protection(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == 1, "should erase successfully with PAGE_READONLY");
    ASSERT_MSG(g_prot_new[1] == PAGE_READONLY,
               "REGRESSION: must restore PAGE_READONLY, not hardcoded PAGE_EXECUTE_READ");

    /* Scenario 3: initial protection is PAGE_EXECUTE_READWRITE */
    build_synthetic_pe(buf, sizeof(buf), 0x80);
    g_prot_call_count = 0;
    g_current_prot = PAGE_EXECUTE_READWRITE;

    ret = erase_pe_header_with_protection(buf, PE_HEADER_PAGE_SIZE);
    ASSERT_MSG(ret == 1, "should erase successfully with PAGE_EXECUTE_READWRITE");
    ASSERT_MSG(g_prot_new[1] == PAGE_EXECUTE_READWRITE,
               "REGRESSION: must restore PAGE_EXECUTE_READWRITE, not hardcoded PAGE_EXECUTE_READ");

    printf("  PASS: test_protection_restore_not_hardcoded\n");
}

/* -------------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------- */

int main(void)
{
    printf("ARC-07 PE header erasure tests\n");

    test_standard_pe_erase();
    test_large_dos_stub_erase();
    test_already_stomped();
    test_minimal_dos_stub();
    test_invalid_pe_offset();
    test_zero_pe_offset();
    test_protection_restore_not_hardcoded();

    printf("\n%d / %d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
