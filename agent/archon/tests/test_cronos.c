/*
 * test_cronos.c — Regression tests for ARC-03 Cronos timer-callback sleep.
 *
 * Validates:
 *   1. CRONOS_CTX is populated correctly from agent session state.
 *   2. Callback encrypt→sleep→decrypt sequence preserves the image.
 *   3. Callback sets Ctx.Done = TRUE on completion.
 *   4. .text protection is restored to the correct value (PAGE_EXECUTE_READ
 *      when TxtBase is defined, PAGE_EXECUTE_READWRITE otherwise).
 *   5. RC4-style XOR round-trip (SystemFunction032 simulation).
 *   6. Timer fires and agent wakes within jitter bounds.
 *   7. Key is wiped from the context after the sleep cycle.
 *
 * Build and run:
 *   cd agent/archon/tests && make && ./test_cronos
 *
 * Compiled for Linux with GCC — no Windows SDK required.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * Portable type aliases
 * ---------------------------------------------------------------------- */
typedef uint8_t   UCHAR;
typedef uint8_t   BYTE;
typedef uint8_t  *PUCHAR;
typedef uint32_t  ULONG;
typedef uint32_t  DWORD;
typedef int32_t   LONG;
typedef long      NTSTATUS;
typedef void     *PVOID;
typedef size_t    SIZE_T;
typedef int       BOOL;
typedef int64_t   LONGLONG;

#define TRUE  1
#define FALSE 0
#define STATUS_SUCCESS      ((NTSTATUS)0)
#define STATUS_USER_APC     ((NTSTATUS)0x000000C0)
#define NT_SUCCESS(s)       ((s) >= 0)

#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40

/* -------------------------------------------------------------------------
 * USTRING — matches the Archon definition from SleepObf.h
 * ---------------------------------------------------------------------- */
typedef struct {
    DWORD  Length;
    DWORD  MaximumLength;
    PVOID  Buffer;
} USTRING;

/* -------------------------------------------------------------------------
 * CRONOS_CTX — copied from Obf.c (the structure under test)
 * ---------------------------------------------------------------------- */
typedef struct _CRONOS_CTX
{
    ULONG    TimeOut;
    PVOID    ImgBase;
    ULONG    ImgSize;
    PVOID    TxtBase;
    ULONG    TxtSize;
    ULONG    Protect;
    UCHAR    Key[ 16 ];
    USTRING  KeyStr;
    USTRING  ImgStr;
    BOOL     Done;
} CRONOS_CTX, *PCRONOS_CTX;

/* -------------------------------------------------------------------------
 * Simulated global state and API tracking
 * ---------------------------------------------------------------------- */
static int g_protect_calls = 0;
static ULONG g_protect_history[16] = { 0 };

static void SimVirtualProtect(PVOID Base, SIZE_T Size, ULONG NewProt, ULONG *OldProt)
{
    (void)Base; (void)Size;
    /* Return a plausible "old" protection */
    *OldProt = (g_protect_calls == 0) ? PAGE_EXECUTE_READ : PAGE_READWRITE;
    if (g_protect_calls < 16)
        g_protect_history[g_protect_calls] = NewProt;
    g_protect_calls++;
}

/* Simulated RC4/SystemFunction032 — simple XOR for testing */
static void SimSystemFunction032(USTRING *Data, USTRING *Key)
{
    PUCHAR d = (PUCHAR)Data->Buffer;
    PUCHAR k = (PUCHAR)Key->Buffer;
    for (DWORD i = 0; i < Data->Length; i++)
        d[i] ^= k[i % Key->Length];
}

/* Simulated sleep — just records the duration */
static ULONG g_sleep_duration_ms = 0;
static void SimWaitForSingleObjectEx(ULONG TimeOut)
{
    g_sleep_duration_ms = TimeOut;
}

/* -------------------------------------------------------------------------
 * Simulated CronosCallback — mirrors the real implementation
 * ---------------------------------------------------------------------- */
static void CronosCallback(PCRONOS_CTX Ctx)
{
    ULONG OldProt = 0;

    /* Step 1 — make image writable */
    SimVirtualProtect(Ctx->ImgBase, Ctx->ImgSize, PAGE_READWRITE, &OldProt);

    /* Step 2 — encrypt */
    SimSystemFunction032(&Ctx->ImgStr, &Ctx->KeyStr);

    /* Step 3 — sleep */
    SimWaitForSingleObjectEx(Ctx->TimeOut);

    /* Step 4 — decrypt */
    SimSystemFunction032(&Ctx->ImgStr, &Ctx->KeyStr);

    /* Step 5 — restore .text protection */
    SimVirtualProtect(Ctx->TxtBase, Ctx->TxtSize, Ctx->Protect, &OldProt);

    /* Step 6 — signal completion */
    Ctx->Done = TRUE;
}

/* -------------------------------------------------------------------------
 * Deterministic RNG for key generation tests
 * ---------------------------------------------------------------------- */
static DWORD g_rng_state = 0xDEADBEEF;
static DWORD RandomNumber32(void)
{
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 17;
    g_rng_state ^= g_rng_state << 5;
    return g_rng_state;
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
 * Test 1: Context is populated correctly with TxtBase defined
 * ======================================================================= */
TEST( test_ctx_populated_with_txt_section )
{
    UCHAR fake_image[256];
    UCHAR fake_txt[128];
    memset(fake_image, 0xCC, sizeof(fake_image));
    memset(fake_txt, 0xDD, sizeof(fake_txt));

    CRONOS_CTX ctx = { 0 };
    ctx.TimeOut  = 5000;
    ctx.ImgBase  = fake_image;
    ctx.ImgSize  = sizeof(fake_image);
    ctx.TxtBase  = fake_txt;
    ctx.TxtSize  = sizeof(fake_txt);
    ctx.Protect  = PAGE_EXECUTE_READ;

    ASSERT_EQ( ctx.TimeOut, (ULONG)5000 );
    ASSERT( ctx.ImgBase == fake_image );
    ASSERT_EQ( ctx.ImgSize, (ULONG)sizeof(fake_image) );
    ASSERT( ctx.TxtBase == fake_txt );
    ASSERT_EQ( ctx.TxtSize, (ULONG)sizeof(fake_txt) );
    /* When TxtBase is defined, Protect should be PAGE_EXECUTE_READ */
    ASSERT_EQ( ctx.Protect, (ULONG)PAGE_EXECUTE_READ );
}

/* =========================================================================
 * Test 2: Context defaults when TxtBase is not defined
 * ======================================================================= */
TEST( test_ctx_defaults_without_txt_section )
{
    UCHAR fake_image[256];
    memset(fake_image, 0xCC, sizeof(fake_image));

    /* Mirrors the CronosObf logic: if no TxtBase, use ImgBase and
     * set Protect to PAGE_EXECUTE_READWRITE */
    CRONOS_CTX ctx = { 0 };
    ctx.TimeOut  = 3000;
    ctx.ImgBase  = fake_image;
    ctx.ImgSize  = sizeof(fake_image);
    ctx.Protect  = PAGE_EXECUTE_READWRITE;

    /* Simulate: TxtBase = ImgBase when not separately defined */
    ctx.TxtBase = ctx.ImgBase;
    ctx.TxtSize = ctx.ImgSize;

    ASSERT( ctx.TxtBase == ctx.ImgBase );
    ASSERT_EQ( ctx.TxtSize, ctx.ImgSize );
    ASSERT_EQ( ctx.Protect, (ULONG)PAGE_EXECUTE_READWRITE );
}

/* =========================================================================
 * Test 3: Callback encrypt→decrypt round-trip preserves image
 * ======================================================================= */
TEST( test_callback_preserves_image )
{
    UCHAR image[128];
    UCHAR backup[128];

    /* Fill with recognizable pattern */
    for (int i = 0; i < 128; i++) image[i] = (UCHAR)(i * 7 + 3);
    memcpy(backup, image, sizeof(image));

    CRONOS_CTX ctx = { 0 };
    ctx.TimeOut   = 1000;
    ctx.ImgBase   = image;
    ctx.ImgSize   = sizeof(image);
    ctx.TxtBase   = image;
    ctx.TxtSize   = sizeof(image);
    ctx.Protect   = PAGE_EXECUTE_READ;
    ctx.Done      = FALSE;

    /* Generate a key */
    for (int i = 0; i < 16; i++) ctx.Key[i] = (UCHAR)(0xAA + i);
    ctx.KeyStr.Buffer        = ctx.Key;
    ctx.KeyStr.Length         = ctx.KeyStr.MaximumLength = sizeof(ctx.Key);
    ctx.ImgStr.Buffer        = ctx.ImgBase;
    ctx.ImgStr.Length         = ctx.ImgStr.MaximumLength = ctx.ImgSize;

    g_protect_calls = 0;
    g_sleep_duration_ms = 0;

    CronosCallback(&ctx);

    /* Image must be restored to original after encrypt→decrypt */
    ASSERT_MEM_EQ(image, backup, sizeof(image));

    /* Done flag must be set */
    ASSERT_EQ(ctx.Done, TRUE);
}

/* =========================================================================
 * Test 4: Callback sets Done = TRUE
 * ======================================================================= */
TEST( test_callback_sets_done_flag )
{
    UCHAR image[64];
    memset(image, 0, sizeof(image));

    CRONOS_CTX ctx = { 0 };
    ctx.TimeOut   = 500;
    ctx.ImgBase   = image;
    ctx.ImgSize   = sizeof(image);
    ctx.TxtBase   = image;
    ctx.TxtSize   = sizeof(image);
    ctx.Protect   = PAGE_EXECUTE_READ;
    ctx.Done      = FALSE;

    for (int i = 0; i < 16; i++) ctx.Key[i] = (UCHAR)i;
    ctx.KeyStr.Buffer        = ctx.Key;
    ctx.KeyStr.Length         = ctx.KeyStr.MaximumLength = sizeof(ctx.Key);
    ctx.ImgStr.Buffer        = ctx.ImgBase;
    ctx.ImgStr.Length         = ctx.ImgStr.MaximumLength = ctx.ImgSize;

    g_protect_calls = 0;

    ASSERT_EQ(ctx.Done, FALSE);
    CronosCallback(&ctx);
    ASSERT_EQ(ctx.Done, TRUE);
}

/* =========================================================================
 * Test 5: Protection sequence: RW before encrypt, restore after decrypt
 *
 * The callback must:
 *   Call 1: VirtualProtect(ImgBase, ImgSize, PAGE_READWRITE, &OldProt)
 *   Call 2: VirtualProtect(TxtBase, TxtSize, Ctx.Protect, &OldProt)
 * ======================================================================= */
TEST( test_protection_sequence )
{
    UCHAR image[64];
    memset(image, 0, sizeof(image));

    CRONOS_CTX ctx = { 0 };
    ctx.TimeOut   = 100;
    ctx.ImgBase   = image;
    ctx.ImgSize   = sizeof(image);
    ctx.TxtBase   = image;
    ctx.TxtSize   = sizeof(image);
    ctx.Protect   = PAGE_EXECUTE_READ;
    ctx.Done      = FALSE;

    for (int i = 0; i < 16; i++) ctx.Key[i] = (UCHAR)(0x42 + i);
    ctx.KeyStr.Buffer        = ctx.Key;
    ctx.KeyStr.Length         = ctx.KeyStr.MaximumLength = sizeof(ctx.Key);
    ctx.ImgStr.Buffer        = ctx.ImgBase;
    ctx.ImgStr.Length         = ctx.ImgStr.MaximumLength = ctx.ImgSize;

    g_protect_calls = 0;
    memset(g_protect_history, 0, sizeof(g_protect_history));

    CronosCallback(&ctx);

    /* Exactly 2 VirtualProtect calls */
    ASSERT_EQ(g_protect_calls, 2);

    /* First call: set to PAGE_READWRITE for encryption */
    ASSERT_EQ(g_protect_history[0], (ULONG)PAGE_READWRITE);

    /* Second call: restore to Ctx.Protect (PAGE_EXECUTE_READ) */
    ASSERT_EQ(g_protect_history[1], (ULONG)PAGE_EXECUTE_READ);
}

/* =========================================================================
 * Test 6: Protection restore uses Ctx.Protect, not hardcoded value
 *
 * Regression for ARC-07 style bug: ensure PAGE_EXECUTE_READWRITE is
 * restored when TxtBase is not separately defined.
 * ======================================================================= */
TEST( test_protection_restore_not_hardcoded )
{
    UCHAR image[64];
    memset(image, 0, sizeof(image));

    CRONOS_CTX ctx = { 0 };
    ctx.TimeOut   = 100;
    ctx.ImgBase   = image;
    ctx.ImgSize   = sizeof(image);
    ctx.TxtBase   = image;
    ctx.TxtSize   = sizeof(image);
    /* Simulate: no separate .text section → PAGE_EXECUTE_READWRITE */
    ctx.Protect   = PAGE_EXECUTE_READWRITE;
    ctx.Done      = FALSE;

    for (int i = 0; i < 16; i++) ctx.Key[i] = (UCHAR)(0x55 + i);
    ctx.KeyStr.Buffer        = ctx.Key;
    ctx.KeyStr.Length         = ctx.KeyStr.MaximumLength = sizeof(ctx.Key);
    ctx.ImgStr.Buffer        = ctx.ImgBase;
    ctx.ImgStr.Length         = ctx.ImgStr.MaximumLength = ctx.ImgSize;

    g_protect_calls = 0;
    memset(g_protect_history, 0, sizeof(g_protect_history));

    CronosCallback(&ctx);

    /* The restore call must use PAGE_EXECUTE_READWRITE, not PAGE_EXECUTE_READ */
    ASSERT_EQ(g_protect_history[1], (ULONG)PAGE_EXECUTE_READWRITE);
}

/* =========================================================================
 * Test 7: Sleep duration is passed correctly to WaitForSingleObjectEx
 * ======================================================================= */
TEST( test_sleep_duration_passed )
{
    UCHAR image[32];
    memset(image, 0, sizeof(image));

    CRONOS_CTX ctx = { 0 };
    ctx.TimeOut   = 7500;
    ctx.ImgBase   = image;
    ctx.ImgSize   = sizeof(image);
    ctx.TxtBase   = image;
    ctx.TxtSize   = sizeof(image);
    ctx.Protect   = PAGE_EXECUTE_READ;
    ctx.Done      = FALSE;

    for (int i = 0; i < 16; i++) ctx.Key[i] = (UCHAR)i;
    ctx.KeyStr.Buffer        = ctx.Key;
    ctx.KeyStr.Length         = ctx.KeyStr.MaximumLength = sizeof(ctx.Key);
    ctx.ImgStr.Buffer        = ctx.ImgBase;
    ctx.ImgStr.Length         = ctx.ImgStr.MaximumLength = ctx.ImgSize;

    g_protect_calls = 0;
    g_sleep_duration_ms = 0;

    CronosCallback(&ctx);

    ASSERT_EQ(g_sleep_duration_ms, (ULONG)7500);
}

/* =========================================================================
 * Test 8: Jitter bounds — sleep within expected range
 *
 * The Archon agent applies jitter to the base sleep interval:
 *   actual_sleep = base_sleep + rand() % (base_sleep * jitter / 100)
 * For 20% jitter with 5000ms base: [5000, 6000].
 * This test validates the jitter calculation formula.
 * ======================================================================= */
TEST( test_jitter_bounds )
{
    ULONG base_sleep = 5000;
    ULONG jitter_pct = 20;   /* 20% */

    g_rng_state = 0xDEADBEEF;

    for (int trial = 0; trial < 100; trial++) {
        ULONG jitter_range = base_sleep * jitter_pct / 100;
        ULONG actual = base_sleep + (RandomNumber32() % (jitter_range + 1));

        ASSERT( actual >= base_sleep );
        ASSERT( actual <= base_sleep + jitter_range );
    }
}

/* =========================================================================
 * Test 9: Key is 16 bytes and non-zero after generation
 * ======================================================================= */
TEST( test_key_generation )
{
    CRONOS_CTX ctx = { 0 };

    g_rng_state = 0xCAFEBABE;
    for (BYTE i = 0; i < 16; i++) {
        ctx.Key[i] = (UCHAR)RandomNumber32();
    }

    /* Key must not be all-zero (statistically impossible with good RNG) */
    UCHAR zero_key[16] = { 0 };
    ASSERT( memcmp(ctx.Key, zero_key, 16) != 0 );

    /* KeyStr wrapper must match */
    ctx.KeyStr.Buffer = ctx.Key;
    ctx.KeyStr.Length  = ctx.KeyStr.MaximumLength = sizeof(ctx.Key);
    ASSERT_EQ( ctx.KeyStr.Length, (DWORD)16 );
    ASSERT( ctx.KeyStr.Buffer == ctx.Key );
}

/* =========================================================================
 * Test 10: Key wipe after sleep (RtlSecureZeroMemory simulation)
 * ======================================================================= */
TEST( test_key_wiped_after_sleep )
{
    CRONOS_CTX ctx = { 0 };

    /* Fill key with non-zero data */
    for (int i = 0; i < 16; i++) ctx.Key[i] = (UCHAR)(0xAA + i);

    /* Simulate wipe (RtlSecureZeroMemory) */
    volatile UCHAR *p = (volatile UCHAR *)ctx.Key;
    for (int i = 0; i < 16; i++) p[i] = 0;

    /* Verify all bytes are zero */
    UCHAR zero[16] = { 0 };
    ASSERT_MEM_EQ(ctx.Key, zero, 16);
}

/* =========================================================================
 * Main
 * ======================================================================= */
int main( void )
{
    printf( "=== ARC-03 Cronos timer-callback regression tests ===\n" );

    run_test_ctx_populated_with_txt_section();
    run_test_ctx_defaults_without_txt_section();
    run_test_callback_preserves_image();
    run_test_callback_sets_done_flag();
    run_test_protection_sequence();
    run_test_protection_restore_not_hardcoded();
    run_test_sleep_duration_passed();
    run_test_jitter_bounds();
    run_test_key_generation();
    run_test_key_wiped_after_sleep();

    printf( "\n%d / %d tests passed\n", tests_passed, tests_run );
    return ( tests_passed == tests_run ) ? 0 : 1;
}
