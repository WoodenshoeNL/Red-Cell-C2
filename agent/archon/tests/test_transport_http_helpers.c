/*
 * test_transport_http_helpers.c — Regression tests for ARC-09 HTTP transport
 * IPv6/proxy helper edge cases.
 *
 * Covers:
 *   1. Explicit IPv6 literal detection for bracketed, zoned, and IPv4-mapped text.
 *   2. Rejection of malformed bracketed hosts and colon-bearing non-literals.
 *   3. Auto-proxy bypass for literal IPv4 and IPv6 hosts.
 *   4. Proxy lookup URL composition for IPv6 hosts, including zone stripping.
 *   5. Fallback to the relative path when the host is malformed or too long.
 *
 * Build and run:
 *   cd agent/archon/tests && make test_transport_http_helpers && ./test_transport_http_helpers
 *
 * Compiled for Linux with GCC — no Windows SDK required.
 * Helper implementations live in agent/archon/src/core/TransportHttpHelpers.inc.h;
 * this file exercises the production code directly via textual inclusion.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <locale.h>

typedef uint32_t DWORD;
typedef unsigned long ULONG;
typedef int BOOL;
typedef int INT;
typedef wchar_t WCHAR;
typedef const WCHAR *LPCWSTR;
typedef WCHAR *LPWSTR;
typedef size_t SIZE_T;

#define TRUE  1
#define FALSE 0

#include "../src/core/TransportHttpHelpers.inc.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void run_##name(void) { \
        tests_run++; \
        name(); \
        tests_passed++; \
        printf("  PASS  %s\n", #name); \
    } \
    static void name(void)

#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            printf("  FAIL  %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define ASSERT_WSTR_EQ(actual, expected) \
    do { \
        if (wcscmp((actual), (expected)) != 0) { \
            printf("  FAIL  %s:%d: wide strings differ\n", __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

TEST(test_ipv6_literal_detection_accepts_expected_forms)
{
    ASSERT( HttpIsLiteralIpv6Host( L"[2001:db8::1]" ) );
    ASSERT( HttpIsLiteralIpv6Host( L"fe80::1%eth0" ) );
    ASSERT( HttpIsLiteralIpv6Host( L"::ffff:192.0.2.1" ) );
    ASSERT( HttpIsLiteralIpv6Host( L"::1" ) );
}

TEST(test_ipv6_literal_detection_rejects_malformed_hosts)
{
    ASSERT( !HttpIsLiteralIpv6Host( L"[2001:db8::1" ) );
    ASSERT( !HttpIsLiteralIpv6Host( L"[2001:db8::1]extra" ) );
    ASSERT( !HttpIsLiteralIpv6Host( L"example:proxy" ) );
    ASSERT( !HttpIsLiteralIpv6Host( L"host:name" ) );
    ASSERT( !HttpIsLiteralIpv6Host( L"fe80::1%bad!zone" ) );
}

TEST(test_skip_autoproxy_treats_ipv4_mapped_ipv6_as_literal)
{
    ASSERT( HttpHostSkipsWinHttpAutoproxy( L"192.0.2.10" ) );
    ASSERT( HttpHostSkipsWinHttpAutoproxy( L"[2001:db8::1]" ) );
    ASSERT( HttpHostSkipsWinHttpAutoproxy( L"::ffff:192.0.2.1" ) );
    ASSERT( !HttpHostSkipsWinHttpAutoproxy( L"teamserver.example" ) );
}

TEST(test_compose_url_brackets_unbracketed_ipv6_and_strips_zone)
{
    WCHAR  Buf[ 256 ];
    LPWSTR Out = HttpBuildProxyUrl( Buf, 256, L"fe80::1%eth0", 8443, TRUE, L"/checkin" );

    ASSERT( Out == Buf );
    ASSERT_WSTR_EQ( Buf, L"https://[fe80::1]:8443/checkin" );
}

TEST(test_compose_url_keeps_valid_bracketed_ipv6)
{
    WCHAR  Buf[ 256 ];
    LPWSTR Out = HttpBuildProxyUrl( Buf, 256, L"[2001:db8::5]", 80, FALSE, L"/stage" );

    ASSERT( Out == Buf );
    ASSERT_WSTR_EQ( Buf, L"http://[2001:db8::5]:80/stage" );
}

TEST(test_compose_url_falls_back_for_invalid_bracketed_host)
{
    WCHAR  Buf[ 256 ];
    WCHAR  Rel[] = L"/stage";
    LPWSTR Out = HttpBuildProxyUrl( Buf, 256, L"[2001:db8::5", 80, FALSE, Rel );

    ASSERT( Out == Rel );
}

TEST(test_compose_url_falls_back_for_overlong_ipv6_literal)
{
    WCHAR  LongHost[ 256 ];
    WCHAR  Buf[ 256 ];
    WCHAR  Rel[] = L"/x";
    SIZE_T Pos = 0;

    for (int i = 0; i < 26; i++) {
        const WCHAR *Chunk = L"2001:";
        for (int j = 0; Chunk[j]; j++) {
            LongHost[Pos++] = Chunk[j];
        }
    }
    LongHost[Pos++] = L':';
    LongHost[Pos++] = L'1';
    LongHost[Pos] = L'\0';

    /* The overlong form (26+ groups) is now correctly rejected as an IPv6 literal. */
    ASSERT( ! HttpIsLiteralIpv6Host( LongHost ) );
    /* compose treats it as a plain host and produces a URL rather than falling back */
    ASSERT( HttpBuildProxyUrl( Buf, 256, LongHost, 443, TRUE, Rel ) == Buf );
}

TEST(test_ipv6_reject_triple_colon)
{
    ASSERT( ! HttpIsLiteralIpv6Host( L"2001:::1" ) );
    ASSERT( ! HttpIsLiteralIpv6Host( L":::1" ) );
    ASSERT( ! HttpIsLiteralIpv6Host( L"fe80:::1%eth0" ) );
}

TEST(test_ipv6_reject_overlong_hextet)
{
    ASSERT( ! HttpIsLiteralIpv6Host( L"12345::1" ) );
    ASSERT( ! HttpIsLiteralIpv6Host( L"2001:db8:00000::1" ) );
    ASSERT( ! HttpIsLiteralIpv6Host( L"[fffff::1]" ) );
}

TEST(test_ipv6_reject_too_many_groups)
{
    /* 9 explicit groups, no :: */
    ASSERT( ! HttpIsLiteralIpv6Host( L"1:2:3:4:5:6:7:8:9" ) );
    /* 8 explicit groups with a :: — total would exceed 8 */
    ASSERT( ! HttpIsLiteralIpv6Host( L"1:2:3:4::5:6:7:8" ) );
}

TEST(test_ipv6_reject_duplicate_double_colon)
{
    ASSERT( ! HttpIsLiteralIpv6Host( L"1::2::3" ) );
    ASSERT( ! HttpIsLiteralIpv6Host( L"::1::2" ) );
}

TEST(test_ipv6_reject_ipv4_suffix_overflow)
{
    /* HexLen overflows (5 hex digits) before the first dot — must be rejected */
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:12345.0.0.1" ) );
    /* Five IPv4 octets (DotCount == 4, not 3) — must be rejected */
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:1.2.3.4.5" ) );
}

TEST(test_ipv6_reject_non_decimal_ipv4_suffix)
{
    /* Hex letters in the dotted tail are not valid decimal octets */
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:a.b.c.d" ) );
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:1a.2.3.4" ) );
    /* Octet value out of range 0-255 */
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:256.0.0.1" ) );
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:192.300.2.1" ) );
    /* Too few octets: only three dot-separated groups (DotCount==2 at group close) */
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:1.2.3" ) );
    /* Empty middle octet: consecutive dots with no digits between them */
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:1..2.3" ) );
    /* Hex letter immediately after a valid last octet (HasDot==TRUE path) */
    ASSERT( ! HttpIsLiteralIpv6Host( L"::ffff:1.2.3.4f" ) );
    /* Valid IPv4-mapped address must still be accepted */
    ASSERT(   HttpIsLiteralIpv6Host( L"::ffff:192.0.2.1" ) );
    ASSERT(   HttpIsLiteralIpv6Host( L"::ffff:0.0.0.0" ) );
    ASSERT(   HttpIsLiteralIpv6Host( L"::ffff:255.255.255.255" ) );
}

int main(void)
{
    setlocale(LC_ALL, "C.UTF-8");

    printf("Running TransportHttp helper regression tests...\n");

    run_test_ipv6_literal_detection_accepts_expected_forms();
    run_test_ipv6_literal_detection_rejects_malformed_hosts();
    run_test_skip_autoproxy_treats_ipv4_mapped_ipv6_as_literal();
    run_test_compose_url_brackets_unbracketed_ipv6_and_strips_zone();
    run_test_compose_url_keeps_valid_bracketed_ipv6();
    run_test_compose_url_falls_back_for_invalid_bracketed_host();
    run_test_compose_url_falls_back_for_overlong_ipv6_literal();
    run_test_ipv6_reject_triple_colon();
    run_test_ipv6_reject_overlong_hextet();
    run_test_ipv6_reject_too_many_groups();
    run_test_ipv6_reject_duplicate_double_colon();
    run_test_ipv6_reject_ipv4_suffix_overflow();
    run_test_ipv6_reject_non_decimal_ipv4_suffix();

    printf("\nSummary: %d/%d tests passed\n", tests_passed, tests_run);
    return 0;
}
