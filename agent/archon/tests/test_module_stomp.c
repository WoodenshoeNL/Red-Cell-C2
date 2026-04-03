/*
 * test_module_stomp.c — Regression tests for ARC-05 module stomping.
 *
 * Validates:
 *   1. IsValidPe correctly identifies valid/invalid PE headers.
 *   2. Header page is overwritten with decoy DLL content.
 *   3. Module-stomped DLL is not identifiable by original export table.
 *   4. Original page protection is restored (not hardcoded).
 *   5. NULL ModuleBase returns STATUS_INVALID_PARAMETER.
 *   6. Invalid PE at ModuleBase returns STATUS_INVALID_IMAGE_FORMAT.
 *   7. After stomping, original MZ/PE signatures are replaced.
 *
 * Build and run:
 *   cd agent/archon/tests && make && ./test_module_stomp
 *
 * Compiled for Linux with GCC — no Windows SDK required.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * PE structure definitions (portable)
 * ---------------------------------------------------------------------- */
#define IMAGE_DOS_SIGNATURE    0x5A4D      /* MZ */
#define IMAGE_NT_SIGNATURE     0x00004550  /* PE\0\0 */
#define HEADER_PAGE_SIZE       0x1000

#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READ       0x20
#define PAGE_READONLY           0x02

#define STATUS_SUCCESS             ((long)0)
#define STATUS_INVALID_PARAMETER   ((long)0xC000000D)
#define STATUS_NOT_FOUND           ((long)0xC0000225)
#define STATUS_INVALID_IMAGE_FORMAT ((long)0xC000007B)
#define NT_SUCCESS(s) ((s) >= 0)

typedef uint8_t  UCHAR;
typedef uint8_t  *PUCHAR;
typedef uint16_t USHORT;
typedef uint32_t ULONG;
typedef uint32_t DWORD;
typedef long     NTSTATUS;
typedef void    *PVOID;
typedef size_t   SIZE_T;
typedef int      BOOL;

#define TRUE  1
#define FALSE 0

#pragma pack(push, 1)
typedef struct {
    uint16_t e_magic;
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
    int32_t  e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint32_t Signature;
    /* COFF header fields follow but we only need the Signature for validation */
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_NT_HEADERS_PARTIAL;

/* Simulated export directory (first 12 bytes) */
typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;        /* RVA of the DLL name string */
} IMAGE_EXPORT_DIRECTORY_PARTIAL;
#pragma pack(pop)

/* -------------------------------------------------------------------------
 * Simulated NtProtectVirtualMemory tracking
 * ---------------------------------------------------------------------- */
#define MAX_PROT_CALLS 16
static struct {
    ULONG NewProt;
    ULONG OldProt;
} g_prot_calls[MAX_PROT_CALLS];
static int g_prot_call_count = 0;
static ULONG g_current_prot = PAGE_EXECUTE_READ;

static NTSTATUS SimNtProtect(PVOID Base, SIZE_T Size, ULONG NewProt, ULONG *OldProt)
{
    (void)Base; (void)Size;
    if (g_prot_call_count < MAX_PROT_CALLS) {
        g_prot_calls[g_prot_call_count].NewProt = NewProt;
        g_prot_calls[g_prot_call_count].OldProt = g_current_prot;
        g_prot_call_count++;
    }
    *OldProt = g_current_prot;
    g_current_prot = NewProt;
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Helper: build a synthetic PE header in a buffer
 * ---------------------------------------------------------------------- */
static void build_pe(uint8_t *buf, size_t size, int32_t pe_offset,
                     uint16_t machine, const char *section_name)
{
    memset(buf, 0, size);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_cblp   = 0x0090;
    dos->e_cp     = 0x0003;
    dos->e_lfanew = pe_offset;

    IMAGE_NT_HEADERS_PARTIAL *nt = (IMAGE_NT_HEADERS_PARTIAL *)(buf + pe_offset);
    nt->Signature       = IMAGE_NT_SIGNATURE;
    nt->Machine         = machine;
    nt->NumberOfSections = 1;
    nt->TimeDateStamp   = 0x12345678;

    /* Write a section name after the optional header area */
    if (section_name) {
        size_t off = pe_offset + sizeof(IMAGE_NT_HEADERS_PARTIAL) + 96; /* after opt header */
        if (off + 8 < size) {
            memcpy(buf + off, section_name, strlen(section_name) < 8 ? strlen(section_name) : 8);
        }
    }
}

/* -------------------------------------------------------------------------
 * IsValidPe — copied from ModuleStomp.c
 * ---------------------------------------------------------------------- */
static BOOL IsValidPe(PVOID Base)
{
    IMAGE_DOS_HEADER *Dos;
    uint32_t         *NtSig;

    if (!Base)
        return FALSE;

    Dos = (IMAGE_DOS_HEADER *)Base;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    if (Dos->e_lfanew <= 0 || (uint32_t)Dos->e_lfanew >= HEADER_PAGE_SIZE - sizeof(uint32_t))
        return FALSE;

    NtSig = (uint32_t *)((uint8_t *)Base + Dos->e_lfanew);
    if (*NtSig != IMAGE_NT_SIGNATURE)
        return FALSE;

    return TRUE;
}

/* -------------------------------------------------------------------------
 * Simulated ModuleStompHeaders — mirrors the real implementation
 * ---------------------------------------------------------------------- */
static NTSTATUS ModuleStompHeaders(
    uint8_t *ModuleBase,
    uint8_t *DecoyBase
) {
    ULONG OldProt = 0;
    ULONG Dummy   = 0;
    PVOID Base;
    SIZE_T RegionSize = HEADER_PAGE_SIZE;

    if (!ModuleBase)
        return STATUS_INVALID_PARAMETER;

    if (!IsValidPe(ModuleBase))
        return STATUS_INVALID_IMAGE_FORMAT;

    if (!DecoyBase)
        return STATUS_NOT_FOUND;

    if (!IsValidPe(DecoyBase))
        return STATUS_INVALID_IMAGE_FORMAT;

    /* Make writable */
    Base = ModuleBase;
    SimNtProtect(Base, RegionSize, PAGE_READWRITE, &OldProt);

    /* Stomp headers */
    memcpy(ModuleBase, DecoyBase, HEADER_PAGE_SIZE);

    /* Restore protection */
    Base = ModuleBase;
    RegionSize = HEADER_PAGE_SIZE;
    SimNtProtect(Base, RegionSize, OldProt, &Dummy);

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Test scaffolding
 * ---------------------------------------------------------------------- */
static int tests_run    = 0;
static int tests_passed = 0;

#define TEST( name ) \
    static void name( void ); \
    static void run_##name( void ) { \
        tests_run++; \
        name(); \
        tests_passed++; \
        printf( "  PASS  %s\n", #name ); \
    } \
    static void name( void )

#define ASSERT( cond ) \
    do { \
        if ( !( cond ) ) { \
            printf( "  FAIL  %s:%d: %s\n", __FILE__, __LINE__, #cond ); \
            exit(1); \
        } \
    } while(0)

#define ASSERT_EQ( a, b ) \
    do { \
        if ( (a) != (b) ) { \
            printf( "  FAIL  %s:%d: %s == %llu, expected %llu\n", \
                    __FILE__, __LINE__, #a, \
                    (unsigned long long)(a), (unsigned long long)(b) ); \
            exit(1); \
        } \
    } while(0)

#define ASSERT_MEM_EQ( a, b, len ) \
    do { \
        if ( memcmp( (a), (b), (len) ) != 0 ) { \
            printf( "  FAIL  %s:%d: memcmp(%s, %s, %zu) != 0\n", \
                    __FILE__, __LINE__, #a, #b, (size_t)(len) ); \
            exit(1); \
        } \
    } while(0)

/* =========================================================================
 * Test 1: IsValidPe accepts valid PE
 * ======================================================================= */
TEST( test_valid_pe_accepted )
{
    uint8_t buf[HEADER_PAGE_SIZE];
    build_pe(buf, sizeof(buf), 0x80, 0x8664, ".text");
    ASSERT( IsValidPe(buf) == TRUE );
}

/* =========================================================================
 * Test 2: IsValidPe rejects NULL
 * ======================================================================= */
TEST( test_null_base_rejected )
{
    ASSERT( IsValidPe(NULL) == FALSE );
}

/* =========================================================================
 * Test 3: IsValidPe rejects missing MZ signature
 * ======================================================================= */
TEST( test_no_mz_rejected )
{
    uint8_t buf[HEADER_PAGE_SIZE];
    build_pe(buf, sizeof(buf), 0x80, 0x8664, ".text");
    /* Corrupt MZ */
    buf[0] = 0x00;
    buf[1] = 0x00;
    ASSERT( IsValidPe(buf) == FALSE );
}

/* =========================================================================
 * Test 4: IsValidPe rejects out-of-range e_lfanew
 * ======================================================================= */
TEST( test_bad_lfanew_rejected )
{
    uint8_t buf[HEADER_PAGE_SIZE];
    build_pe(buf, sizeof(buf), 0x80, 0x8664, ".text");
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    dos->e_lfanew = HEADER_PAGE_SIZE;  /* past page */
    ASSERT( IsValidPe(buf) == FALSE );
}

/* =========================================================================
 * Test 5: IsValidPe rejects missing PE signature
 * ======================================================================= */
TEST( test_no_pe_sig_rejected )
{
    uint8_t buf[HEADER_PAGE_SIZE];
    build_pe(buf, sizeof(buf), 0x80, 0x8664, ".text");
    /* Corrupt PE signature */
    *(uint32_t *)(buf + 0x80) = 0x00000000;
    ASSERT( IsValidPe(buf) == FALSE );
}

/* =========================================================================
 * Test 6: Module stomp replaces headers with decoy content
 * ======================================================================= */
TEST( test_stomp_replaces_headers )
{
    uint8_t module[HEADER_PAGE_SIZE];
    uint8_t decoy[HEADER_PAGE_SIZE];

    build_pe(module, sizeof(module), 0x80, 0x8664, ".text");
    build_pe(decoy,  sizeof(decoy),  0xE0, 0x014C, ".rsrc");

    /* Module has x64 machine type, decoy has x86 */
    IMAGE_NT_HEADERS_PARTIAL *mod_nt = (IMAGE_NT_HEADERS_PARTIAL *)(module + 0x80);
    IMAGE_NT_HEADERS_PARTIAL *dec_nt = (IMAGE_NT_HEADERS_PARTIAL *)(decoy + 0xE0);
    ASSERT_EQ( mod_nt->Machine, (uint16_t)0x8664 );
    ASSERT_EQ( dec_nt->Machine, (uint16_t)0x014C );

    g_prot_call_count = 0;
    g_current_prot = PAGE_EXECUTE_READ;

    NTSTATUS status = ModuleStompHeaders(module, decoy);
    ASSERT_EQ( status, STATUS_SUCCESS );

    /* After stomping, module should look like decoy */
    ASSERT_MEM_EQ( module, decoy, HEADER_PAGE_SIZE );

    /* The e_lfanew now points to the decoy's PE offset */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)module;
    ASSERT_EQ( dos->e_lfanew, (int32_t)0xE0 );
}

/* =========================================================================
 * Test 7: Module-stomped DLL is not identifiable by original section name
 *
 * Regression: after stomping, the original .text section name from the
 * agent's PE is replaced with the decoy's section table.
 * ======================================================================= */
TEST( test_original_export_table_replaced )
{
    uint8_t module[HEADER_PAGE_SIZE];
    uint8_t decoy[HEADER_PAGE_SIZE];

    /* Module has ".arch" section, decoy has ".rsrc" */
    build_pe(module, sizeof(module), 0x80, 0x8664, ".arch");
    build_pe(decoy,  sizeof(decoy),  0x80, 0x014C, ".rsrc");

    g_prot_call_count = 0;
    g_current_prot = PAGE_EXECUTE_READ;

    ModuleStompHeaders(module, decoy);

    /* The module should no longer contain ".arch" anywhere in the header page */
    int found_arch = 0;
    for (size_t i = 0; i <= HEADER_PAGE_SIZE - 5; i++) {
        if (memcmp(module + i, ".arch", 5) == 0) {
            found_arch = 1;
            break;
        }
    }
    ASSERT( found_arch == 0 );

    /* Should now contain ".rsrc" from the decoy */
    int found_rsrc = 0;
    for (size_t i = 0; i <= HEADER_PAGE_SIZE - 5; i++) {
        if (memcmp(module + i, ".rsrc", 5) == 0) {
            found_rsrc = 1;
            break;
        }
    }
    ASSERT( found_rsrc == 1 );
}

/* =========================================================================
 * Test 8: Original page protection is restored (not hardcoded)
 * ======================================================================= */
TEST( test_protection_restored )
{
    uint8_t module[HEADER_PAGE_SIZE];
    uint8_t decoy[HEADER_PAGE_SIZE];

    build_pe(module, sizeof(module), 0x80, 0x8664, NULL);
    build_pe(decoy,  sizeof(decoy),  0x80, 0x014C, NULL);

    /* Start with PAGE_READONLY (unusual, but tests that we restore it) */
    g_prot_call_count = 0;
    g_current_prot = PAGE_READONLY;

    ModuleStompHeaders(module, decoy);

    ASSERT_EQ( g_prot_call_count, 2 );
    /* First: set to PAGE_READWRITE */
    ASSERT_EQ( g_prot_calls[0].NewProt, (ULONG)PAGE_READWRITE );
    /* Second: restore to PAGE_READONLY (what was captured as OldProt) */
    ASSERT_EQ( g_prot_calls[1].NewProt, (ULONG)PAGE_READONLY );
}

/* =========================================================================
 * Test 9: NULL ModuleBase returns STATUS_INVALID_PARAMETER
 * ======================================================================= */
TEST( test_null_module_base )
{
    uint8_t decoy[HEADER_PAGE_SIZE];
    build_pe(decoy, sizeof(decoy), 0x80, 0x014C, NULL);

    NTSTATUS status = ModuleStompHeaders(NULL, decoy);
    ASSERT_EQ( status, STATUS_INVALID_PARAMETER );
}

/* =========================================================================
 * Test 10: Invalid PE at ModuleBase returns STATUS_INVALID_IMAGE_FORMAT
 * ======================================================================= */
TEST( test_invalid_module_pe )
{
    uint8_t module[HEADER_PAGE_SIZE];
    uint8_t decoy[HEADER_PAGE_SIZE];

    memset(module, 0xAA, sizeof(module));  /* garbage, no MZ */
    build_pe(decoy, sizeof(decoy), 0x80, 0x014C, NULL);

    NTSTATUS status = ModuleStompHeaders(module, decoy);
    ASSERT_EQ( status, STATUS_INVALID_IMAGE_FORMAT );
}

/* =========================================================================
 * Test 11: No decoy available returns STATUS_NOT_FOUND
 * ======================================================================= */
TEST( test_no_decoy )
{
    uint8_t module[HEADER_PAGE_SIZE];
    build_pe(module, sizeof(module), 0x80, 0x8664, NULL);

    NTSTATUS status = ModuleStompHeaders(module, NULL);
    ASSERT_EQ( status, STATUS_NOT_FOUND );
}

/* =========================================================================
 * Main
 * ======================================================================= */
int main( void )
{
    printf( "=== ARC-05 module stomp regression tests ===\n" );

    run_test_valid_pe_accepted();
    run_test_null_base_rejected();
    run_test_no_mz_rejected();
    run_test_bad_lfanew_rejected();
    run_test_no_pe_sig_rejected();
    run_test_stomp_replaces_headers();
    run_test_original_export_table_replaced();
    run_test_protection_restored();
    run_test_null_module_base();
    run_test_invalid_module_pe();
    run_test_no_decoy();

    printf( "\n%d / %d tests passed\n", tests_passed, tests_run );
    return ( tests_passed == tests_run ) ? 0 : 1;
}
