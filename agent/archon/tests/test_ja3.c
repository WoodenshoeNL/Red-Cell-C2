/*
 * test_ja3.c — Regression tests for ARC-06 JA3 fingerprint randomization.
 *
 * Validates:
 *   1. All protocol sets include TLS 1.2 (baseline compatibility).
 *   2. There are at least 2 distinct protocol sets (fingerprint diversity).
 *   3. Random selection produces different choices across calls.
 *   4. Selected set is stored in Ja3ProtoSet config field.
 *   5. Schannel cache flush is triggered (SslEmptyCache called).
 *   6. WinHTTP session is torn down to force new ClientHello.
 *
 * Build and run:
 *   cd agent/archon/tests && make && ./test_ja3
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
typedef uint32_t DWORD;
typedef int      BOOL;
typedef void    *PVOID;

#define TRUE  1
#define FALSE 0

/* -------------------------------------------------------------------------
 * WinHTTP protocol flag constants (from winhttp.h)
 * ---------------------------------------------------------------------- */
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1    0x00000080
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1  0x00000200
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2  0x00000800
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3  0x00002000

/* -------------------------------------------------------------------------
 * Protocol sets — copied verbatim from TransportHttp.c
 * ---------------------------------------------------------------------- */
static const DWORD ProtoSets[] = {
    /* 0: TLS 1.2 only */
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
    /* 1: TLS 1.2 + TLS 1.3 */
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
    /* 2: TLS 1.1 + TLS 1.2 */
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
    /* 3: TLS 1.1 + TLS 1.2 + TLS 1.3 */
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
    /* 4: TLS 1.0 + TLS 1.1 + TLS 1.2 */
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1   | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
    /* 5: TLS 1.0 + TLS 1.1 + TLS 1.2 + TLS 1.3 */
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1   | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
};
static const DWORD ProtoCount = sizeof(ProtoSets) / sizeof(ProtoSets[0]);

/* -------------------------------------------------------------------------
 * Deterministic RNG (same XOR-shift as the agent)
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
 * Simulated config state
 * ---------------------------------------------------------------------- */
static DWORD g_ja3_proto_set = 0;
static int   g_ssl_empty_cache_calls = 0;
static int   g_session_close_calls   = 0;
static PVOID g_http_session          = NULL;

static void SimSslEmptyCache(void)
{
    g_ssl_empty_cache_calls++;
}

static void SimWinHttpCloseHandle(PVOID h)
{
    (void)h;
    g_session_close_calls++;
}

/* -------------------------------------------------------------------------
 * Simulated HttpJa3Randomize — mirrors TransportHttp.c
 * ---------------------------------------------------------------------- */
static void HttpJa3Randomize(void)
{
    g_ja3_proto_set = ProtoSets[RandomNumber32() % ProtoCount];

    /* Flush Schannel cache */
    SimSslEmptyCache();

    /* Tear down WinHTTP session */
    if (g_http_session) {
        SimWinHttpCloseHandle(g_http_session);
        g_http_session = NULL;
    }
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

/* =========================================================================
 * Test 1: All protocol sets include TLS 1.2
 *
 * Every set must include TLS 1.2 for baseline server compatibility.
 * This is the core invariant that prevents broken connections.
 * ======================================================================= */
TEST( test_all_sets_include_tls12 )
{
    for (DWORD i = 0; i < ProtoCount; i++) {
        ASSERT( (ProtoSets[i] & WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2) != 0 );
    }
}

/* =========================================================================
 * Test 2: At least 2 distinct protocol sets exist
 *
 * Without at least 2 sets, there is no fingerprint diversity.
 * ======================================================================= */
TEST( test_sufficient_set_diversity )
{
    ASSERT( ProtoCount >= 2 );

    /* Verify they are actually distinct */
    int distinct = 0;
    for (DWORD i = 1; i < ProtoCount; i++) {
        if (ProtoSets[i] != ProtoSets[0]) {
            distinct = 1;
            break;
        }
    }
    ASSERT( distinct == 1 );
}

/* =========================================================================
 * Test 3: Sets cover a range of protocol combinations
 * ======================================================================= */
TEST( test_protocol_set_coverage )
{
    /* Count how many sets include TLS 1.3 */
    int with_13 = 0;
    int without_13 = 0;
    for (DWORD i = 0; i < ProtoCount; i++) {
        if (ProtoSets[i] & WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
            with_13++;
        else
            without_13++;
    }
    /* Should have both TLS 1.3 and non-TLS 1.3 variants */
    ASSERT( with_13 > 0 );
    ASSERT( without_13 > 0 );
}

/* =========================================================================
 * Test 4: Random selection produces different values across calls
 *
 * Regression: ensures the JA3 fingerprint actually differs between
 * connections rather than always selecting the same protocol set.
 * ======================================================================= */
TEST( test_random_selection_differs )
{
    g_rng_state = 0xDEADBEEF;

    DWORD selections[100];
    for (int i = 0; i < 100; i++) {
        selections[i] = ProtoSets[RandomNumber32() % ProtoCount];
    }

    /* At least 2 distinct values in 100 selections */
    int distinct = 0;
    for (int i = 1; i < 100; i++) {
        if (selections[i] != selections[0]) {
            distinct = 1;
            break;
        }
    }
    ASSERT( distinct == 1 );
}

/* =========================================================================
 * Test 5: Selected set is always one of the predefined sets
 * ======================================================================= */
TEST( test_selection_in_valid_set )
{
    g_rng_state = 0xCAFEBABE;

    for (int trial = 0; trial < 200; trial++) {
        DWORD selected = ProtoSets[RandomNumber32() % ProtoCount];

        /* Must be one of the known sets */
        int found = 0;
        for (DWORD i = 0; i < ProtoCount; i++) {
            if (selected == ProtoSets[i]) {
                found = 1;
                break;
            }
        }
        ASSERT( found == 1 );

        /* Must include TLS 1.2 */
        ASSERT( (selected & WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2) != 0 );
    }
}

/* =========================================================================
 * Test 6: HttpJa3Randomize stores result in config
 * ======================================================================= */
TEST( test_ja3_randomize_stores_result )
{
    g_rng_state = 0x12345678;
    g_ja3_proto_set = 0;
    g_ssl_empty_cache_calls = 0;
    g_session_close_calls = 0;
    g_http_session = (PVOID)0xBEEF;  /* simulate active session */

    HttpJa3Randomize();

    /* Result stored */
    ASSERT( g_ja3_proto_set != 0 );

    /* Must be one of the known sets */
    int found = 0;
    for (DWORD i = 0; i < ProtoCount; i++) {
        if (g_ja3_proto_set == ProtoSets[i]) {
            found = 1;
            break;
        }
    }
    ASSERT( found == 1 );
}

/* =========================================================================
 * Test 7: SslEmptyCache is called to flush Schannel session cache
 * ======================================================================= */
TEST( test_schannel_cache_flushed )
{
    g_rng_state = 0xAAAAAAAA;
    g_ssl_empty_cache_calls = 0;
    g_http_session = (PVOID)0xDEAD;

    HttpJa3Randomize();

    ASSERT_EQ( g_ssl_empty_cache_calls, 1 );
}

/* =========================================================================
 * Test 8: WinHTTP session is torn down when active
 * ======================================================================= */
TEST( test_http_session_closed )
{
    g_rng_state = 0xBBBBBBBB;
    g_session_close_calls = 0;
    g_http_session = (PVOID)0xCAFE;

    HttpJa3Randomize();

    ASSERT_EQ( g_session_close_calls, 1 );
    ASSERT( g_http_session == NULL );
}

/* =========================================================================
 * Test 9: No session close when no session is active
 * ======================================================================= */
TEST( test_no_close_when_no_session )
{
    g_rng_state = 0xCCCCCCCC;
    g_session_close_calls = 0;
    g_http_session = NULL;

    HttpJa3Randomize();

    /* Should NOT call close when session is already NULL */
    ASSERT_EQ( g_session_close_calls, 0 );
}

/* =========================================================================
 * Test 10: Consecutive calls produce different JA3 configs
 *
 * Over 10 consecutive randomizations, at least 2 should differ.
 * ======================================================================= */
TEST( test_consecutive_calls_differ )
{
    g_rng_state = 0xDEADBEEF;
    g_http_session = (PVOID)0x1;

    DWORD results[10];
    for (int i = 0; i < 10; i++) {
        g_http_session = (PVOID)(uintptr_t)(i + 1);
        HttpJa3Randomize();
        results[i] = g_ja3_proto_set;
    }

    int differ = 0;
    for (int i = 1; i < 10; i++) {
        if (results[i] != results[0]) {
            differ = 1;
            break;
        }
    }
    ASSERT( differ == 1 );
}

/* =========================================================================
 * Main
 * ======================================================================= */
int main( void )
{
    printf( "=== ARC-06 JA3 fingerprint randomization regression tests ===\n" );

    run_test_all_sets_include_tls12();
    run_test_sufficient_set_diversity();
    run_test_protocol_set_coverage();
    run_test_random_selection_differs();
    run_test_selection_in_valid_set();
    run_test_ja3_randomize_stores_result();
    run_test_schannel_cache_flushed();
    run_test_http_session_closed();
    run_test_no_close_when_no_session();
    run_test_consecutive_calls_differ();

    printf( "\n%d / %d tests passed\n", tests_passed, tests_run );
    return ( tests_passed == tests_run ) ? 0 : 1;
}
