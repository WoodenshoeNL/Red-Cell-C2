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
 * The pure helper logic is copied from agent/archon/src/core/TransportHttp.c.
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

typedef struct _HOST_DATA {
    LPCWSTR Host;
    DWORD   Port;
} HOST_DATA, *PHOST_DATA;

static SIZE_T StringLengthW(LPCWSTR String)
{
    SIZE_T Len = 0;
    while (String && String[Len]) {
        Len++;
    }
    return Len;
}

static BOOL HttpIsHexDigitW(
    WCHAR Ch
)
{
    return ( Ch >= L'0' && Ch <= L'9' )
        || ( Ch >= L'a' && Ch <= L'f' )
        || ( Ch >= L'A' && Ch <= L'F' );
}

static BOOL HttpIsLiteralIpv6Host(
    LPCWSTR Host
)
{
    LPCWSTR Scan;
    SIZE_T  Len;
    DWORD   ColonCount = 0;
    BOOL    InZone     = FALSE;

    if ( ! Host || ! Host[ 0 ] ) {
        return FALSE;
    }

    Scan = Host;
    Len  = StringLengthW( Host );

    if ( Host[ 0 ] == L'[' ) {
        SIZE_T End = 1;

        while ( Host[ End ] && Host[ End ] != L']' ) {
            End++;
        }

        if ( End == 1 || Host[ End ] != L']' || Host[ End + 1 ] != L'\0' ) {
            return FALSE;
        }

        Scan = Host + 1;
        Len  = End - 1;
    }

    for ( SIZE_T i = 0; i < Len; i++ ) {
        WCHAR Ch = Scan[ i ];

        if ( Ch == L':' ) {
            if ( InZone ) {
                return FALSE;
            }
            ColonCount++;
            continue;
        }

        if ( Ch == L'%' ) {
            if ( InZone || i == 0 || i + 1 >= Len ) {
                return FALSE;
            }
            InZone = TRUE;
            continue;
        }

        if ( InZone ) {
            if (
                ( Ch >= L'0' && Ch <= L'9' )
                || ( Ch >= L'a' && Ch <= L'z' )
                || ( Ch >= L'A' && Ch <= L'Z' )
                || Ch == L'.'
                || Ch == L'-'
                || Ch == L'_'
            ) {
                continue;
            }
            return FALSE;
        }

        if ( HttpIsHexDigitW( Ch ) || Ch == L'.' ) {
            continue;
        }

        return FALSE;
    }

    return ColonCount >= 2;
}

static BOOL HttpIsLiteralIpv4Host(
    LPCWSTR Host
)
{
    DWORD Parts   = 0;
    DWORD Val     = 0;
    BOOL  HasDigs = FALSE;

    if ( ! Host || ! Host[ 0 ] ) {
        return FALSE;
    }

    for ( SIZE_T i = 0; ; i++ ) {
        WCHAR Ch = Host[ i ];

        if ( Ch >= L'0' && Ch <= L'9' ) {
            Val = Val * 10 + ( DWORD )( Ch - L'0' );
            if ( Val > 255 ) {
                return FALSE;
            }
            HasDigs = TRUE;
        } else if ( Ch == L'.' || Ch == L'\0' ) {
            if ( ! HasDigs ) {
                return FALSE;
            }
            Parts++;
            Val     = 0;
            HasDigs = FALSE;
            if ( Ch == L'\0' ) {
                break;
            }
            if ( Parts >= 4 ) {
                if ( Host[ i + 1 ] != L'\0' ) {
                    return FALSE;
                }
            }
        } else {
            return FALSE;
        }
    }

    return Parts == 4;
}

static BOOL HttpHostSkipsWinHttpAutoproxy(
    LPCWSTR Host
)
{
    if ( ! Host || ! Host[ 0 ] ) {
        return FALSE;
    }

    if ( HttpIsLiteralIpv4Host( Host ) ) {
        return TRUE;
    }

    if ( HttpIsLiteralIpv6Host( Host ) ) {
        return TRUE;
    }

    return FALSE;
}

static LPWSTR HttpComposeUrlForProxyLookup(
    WCHAR *    Buf,
    SIZE_T     CchBuf,
    PHOST_DATA H,
    BOOL       Secure,
    LPWSTR     RelativePath
)
{
    LPCWSTR scheme;
    LPCWSTR hostUse;
    INT     nw;
    WCHAR   HostNz[ 128 ] = { 0 };
    SIZE_T  zi;

    if ( ! Buf || CchBuf < 16 || ! RelativePath || ! H || ! H->Host ) {
        return RelativePath;
    }

    scheme  = Secure ? L"https://" : L"http://";
    hostUse = H->Host;

    if ( hostUse[ 0 ] == L'[' && HttpIsLiteralIpv6Host( hostUse ) ) {
        nw = swprintf(
            Buf,
            CchBuf,
            L"%ls%ls:%lu%ls",
            scheme,
            hostUse,
            ( ULONG ) H->Port,
            RelativePath
        );
    } else if ( hostUse[ 0 ] == L'[' ) {
        return RelativePath;
    } else if ( HttpIsLiteralIpv6Host( H->Host ) ) {
        zi = 0;
        while (
            zi < ( sizeof( HostNz ) / sizeof( HostNz[ 0 ] ) ) - 1
            && hostUse[ zi ]
        ) {
            if ( hostUse[ zi ] == L'%' ) {
                break;
            }
            HostNz[ zi ] = hostUse[ zi ];
            zi++;
        }
        if ( hostUse[ zi ] != L'\0' && hostUse[ zi ] != L'%' ) {
            return RelativePath;
        }
        HostNz[ zi ] = L'\0';

        nw = swprintf(
            Buf,
            CchBuf,
            L"%ls[%ls]:%lu%ls",
            scheme,
            HostNz,
            ( ULONG ) H->Port,
            RelativePath
        );
    } else {
        nw = swprintf(
            Buf,
            CchBuf,
            L"%ls%ls:%lu%ls",
            scheme,
            hostUse,
            ( ULONG ) H->Port,
            RelativePath
        );
    }

    if ( nw < 0 || ( SIZE_T ) nw >= CchBuf ) {
        return RelativePath;
    }

    return Buf;
}

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
    HOST_DATA Host = { L"fe80::1%eth0", 8443 };
    WCHAR     Buf[ 256 ];
    LPWSTR    Out = HttpComposeUrlForProxyLookup( Buf, 256, &Host, TRUE, L"/checkin" );

    ASSERT( Out == Buf );
    ASSERT_WSTR_EQ( Buf, L"https://[fe80::1]:8443/checkin" );
}

TEST(test_compose_url_keeps_valid_bracketed_ipv6)
{
    HOST_DATA Host = { L"[2001:db8::5]", 80 };
    WCHAR     Buf[ 256 ];
    LPWSTR    Out = HttpComposeUrlForProxyLookup( Buf, 256, &Host, FALSE, L"/stage" );

    ASSERT( Out == Buf );
    ASSERT_WSTR_EQ( Buf, L"http://[2001:db8::5]:80/stage" );
}

TEST(test_compose_url_falls_back_for_invalid_bracketed_host)
{
    HOST_DATA Host = { L"[2001:db8::5", 80 };
    WCHAR     Buf[ 256 ];
    WCHAR     Rel[] = L"/stage";
    LPWSTR    Out = HttpComposeUrlForProxyLookup( Buf, 256, &Host, FALSE, Rel );

    ASSERT( Out == Rel );
}

TEST(test_compose_url_falls_back_for_overlong_ipv6_literal)
{
    WCHAR     LongHost[ 256 ];
    HOST_DATA Host;
    WCHAR     Buf[ 256 ];
    WCHAR     Rel[] = L"/x";
    SIZE_T    Pos = 0;

    for (int i = 0; i < 26; i++) {
        const WCHAR *Chunk = L"2001:";
        for (int j = 0; Chunk[j]; j++) {
            LongHost[Pos++] = Chunk[j];
        }
    }
    LongHost[Pos++] = L':';
    LongHost[Pos++] = L'1';
    LongHost[Pos] = L'\0';

    Host.Host = LongHost;
    Host.Port = 443;

    ASSERT( HttpIsLiteralIpv6Host( LongHost ) );
    ASSERT( HttpComposeUrlForProxyLookup( Buf, 256, &Host, TRUE, Rel ) == Rel );
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

    printf("\nSummary: %d/%d tests passed\n", tests_passed, tests_run);
    return 0;
}
