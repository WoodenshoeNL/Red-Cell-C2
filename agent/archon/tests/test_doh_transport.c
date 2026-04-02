/*
 * test_doh_transport.c — Unit tests for ARC-08 DoH transport helpers.
 *
 * Covers:
 *   1. B32Encode / B32Decode round-trip (empty, 1 byte, 5 bytes, varied lengths).
 *   2. B32Encode output is lowercase and DNS-safe (only [a-z2-7]).
 *   3. B32Decode rejects invalid characters (returns 0).
 *   4. Hex04: zero, small, large values.
 *   5. BuildUplinkName: format "<b32>.<seq><tot>.<session>.u.<domain>".
 *   6. BuildReadyName: format "rdy.<session>.d.<domain>".
 *   7. BuildChunkFetchName: format "<seq>.<session>.d.<domain>".
 *   8. JsonGetU64: found, not found, zero, non-zero values.
 *   9. JsonExtractTxtData: TXT found, none found, escaped-quote handling.
 *  10. GenerateSessionHex: 16 chars, all lowercase hex, consecutive calls differ.
 *
 * Build and run:
 *   cd agent/archon/tests && make
 *
 * Compiled for Linux (x86_64) with GCC — no Windows SDK required.
 * The static helpers are copied verbatim from agent/archon/src/core/TransportDoH.c
 * with Windows type aliases provided below (same approach as test_crypto.c).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Portable type aliases (mirror windows.h names used by Archon source)
 * ---------------------------------------------------------------------- */
typedef uint8_t   BYTE;
typedef uint8_t  *PBYTE;
typedef char      CHAR;
typedef char     *PCHAR;
typedef uint32_t  DWORD;
typedef uint64_t  UINT64;
typedef uint32_t  UINT32;
typedef size_t    SIZE_T;
typedef int       BOOL;
typedef void      VOID;

#define TRUE  1
#define FALSE 0

/* StringLengthA replacement */
static SIZE_T StringLengthA(const CHAR *s)
{
    SIZE_T n = 0;
    while (s[n]) n++;
    return n;
}

/* Chunk-sizing constants (copied from TransportDoH.h). */
#define DOH_CHUNK_B32_LEN  60
#define DOH_CHUNK_BYTES    37   /* floor(60 * 5 / 8) */
#define DOH_MAX_CHUNKS     1000

/* RandomNumber32 stub — deterministic XOR-shift so GenerateSessionHex
 * produces valid (non-random) output for tests. */
static DWORD g_rng_state = 0xDEADBEEF;
static DWORD RandomNumber32(void)
{
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 17;
    g_rng_state ^= g_rng_state << 5;
    return g_rng_state;
}

/* -------------------------------------------------------------------------
 * Static helpers copied verbatim from agent/archon/src/core/TransportDoH.c.
 * Only these pure-C encoding/parsing helpers are exercised; the WinHTTP
 * send/receive functions (DoHTxtQuery, DoHSend) are not compiled here.
 * ---------------------------------------------------------------------- */

static const CHAR B32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

static SIZE_T B32Encode( const BYTE* Src, SIZE_T SrcLen, PCHAR Dst )
{
    UINT64 Buf  = 0;
    UINT32 Bits = 0;
    SIZE_T Out  = 0;

    for ( SIZE_T i = 0; i < SrcLen; i++ )
    {
        Buf = ( Buf << 8 ) | (UINT64) Src[ i ];
        Bits += 8;
        while ( Bits >= 5 )
        {
            Bits -= 5;
            Dst[ Out++ ] = B32_ALPHABET[ ( Buf >> Bits ) & 0x1F ];
        }
    }
    if ( Bits > 0 )
    {
        Dst[ Out++ ] = B32_ALPHABET[ ( Buf << ( 5 - Bits ) ) & 0x1F ];
    }
    Dst[ Out ] = '\0';
    return Out;
}

static SIZE_T B32Decode( const CHAR* Src, SIZE_T StrLen, BYTE* Dst )
{
    UINT64 Buf  = 0;
    UINT32 Bits = 0;
    SIZE_T Out  = 0;

    for ( SIZE_T i = 0; i < StrLen; i++ )
    {
        CHAR ch = Src[ i ];
        UINT64 Val;
        if ( ch >= 'a' && ch <= 'z' )
            Val = (UINT64)( ch - 'a' );
        else if ( ch >= '2' && ch <= '7' )
            Val = (UINT64)( ch - '2' + 26 );
        else
            return 0; /* invalid character */

        Buf = ( Buf << 5 ) | Val;
        Bits += 5;
        if ( Bits >= 8 )
        {
            Bits -= 8;
            Dst[ Out++ ] = (BYTE)( Buf >> Bits );
            Buf &= ( (UINT64)1 << Bits ) - 1;
        }
    }
    return Out;
}

static const CHAR HexChars[] = "0123456789abcdef";

static VOID GenerateSessionHex( CHAR Dst[ 17 ] )
{
    for ( DWORD i = 0; i < 4; i++ )
    {
        DWORD Rnd = RandomNumber32();
        Dst[ i * 4 + 0 ] = HexChars[ ( Rnd >> 28 ) & 0x0F ];
        Dst[ i * 4 + 1 ] = HexChars[ ( Rnd >> 24 ) & 0x0F ];
        Dst[ i * 4 + 2 ] = HexChars[ ( Rnd >> 20 ) & 0x0F ];
        Dst[ i * 4 + 3 ] = HexChars[ ( Rnd >> 16 ) & 0x0F ];
    }
    Dst[ 16 ] = '\0';
}

static VOID Hex04( DWORD Val, CHAR Dst[ 5 ] )
{
    Dst[ 0 ] = HexChars[ ( Val >> 12 ) & 0x0F ];
    Dst[ 1 ] = HexChars[ ( Val >>  8 ) & 0x0F ];
    Dst[ 2 ] = HexChars[ ( Val >>  4 ) & 0x0F ];
    Dst[ 3 ] = HexChars[ ( Val >>  0 ) & 0x0F ];
    Dst[ 4 ] = '\0';
}

static BOOL JsonGetU64( const CHAR* Body, const CHAR* Key, UINT64* Out )
{
    SIZE_T KeyLen = StringLengthA( Key );
    const CHAR* Pos = Body;

    for ( ;; )
    {
        const CHAR* Quote = NULL;
        for ( const CHAR* p = Pos; *p; p++ )
        {
            if ( *p == '"' )
            {
                BOOL Match = TRUE;
                for ( SIZE_T k = 0; k < KeyLen; k++ )
                {
                    if ( p[ 1 + k ] != Key[ k ] )
                    {
                        Match = FALSE;
                        break;
                    }
                }
                if ( Match && p[ 1 + KeyLen ] == '"' )
                {
                    Quote = p + 1 + KeyLen + 1;
                    break;
                }
            }
        }
        if ( !Quote )
            return FALSE;

        while ( *Quote == ' ' || *Quote == '\t' || *Quote == '\n' || *Quote == '\r' )
            Quote++;
        if ( *Quote != ':' )
        {
            Pos = Quote;
            continue;
        }
        Quote++;
        while ( *Quote == ' ' || *Quote == '\t' || *Quote == '\n' || *Quote == '\r' )
            Quote++;

        UINT64 Val = 0;
        BOOL   Found = FALSE;
        while ( *Quote >= '0' && *Quote <= '9' )
        {
            Val = Val * 10 + ( *Quote - '0' );
            Quote++;
            Found = TRUE;
        }
        if ( Found )
        {
            *Out = Val;
            return TRUE;
        }
        Pos = Quote;
    }
}

static BOOL JsonExtractTxtData( const CHAR* Body, PCHAR Dst, SIZE_T DstSize )
{
    const CHAR* Search = Body;
    const CHAR* TypePos = NULL;

    for ( ;; )
    {
        for ( const CHAR* s = Search; *s; s++ )
        {
            if ( s[0] == '"' && s[1] == 't' && s[2] == 'y' && s[3] == 'p' &&
                 s[4] == 'e' && s[5] == '"' )
            {
                const CHAR* t = s + 6;
                while ( *t == ' ' || *t == '\t' ) t++;
                if ( *t == ':' )
                {
                    t++;
                    while ( *t == ' ' || *t == '\t' ) t++;
                    if ( t[0] == '1' && t[1] == '6' &&
                         ( t[2] < '0' || t[2] > '9' ) )
                    {
                        TypePos = s;
                        break;
                    }
                }
            }
        }

        if ( !TypePos )
            return FALSE;

        const CHAR* ObjEnd = TypePos;
        while ( *ObjEnd && *ObjEnd != '}' )
            ObjEnd++;

        const CHAR* d = TypePos;
        while ( d < ObjEnd )
        {
            if ( d[0] == '"' && d[1] == 'd' && d[2] == 'a' && d[3] == 't' &&
                 d[4] == 'a' && d[5] == '"' )
            {
                const CHAR* v = d + 6;
                while ( *v == ' ' || *v == '\t' ) v++;
                if ( *v == ':' )
                {
                    v++;
                    while ( *v == ' ' || *v == '\t' ) v++;
                    if ( *v == '"' )
                    {
                        v++;
                        SIZE_T idx = 0;
                        while ( *v && *v != '"' && idx < DstSize - 1 )
                        {
                            if ( *v == '\\' && v[1] == '"' )
                            {
                                v++; /* skip backslash */
                                v++; /* skip the escaped '"' (delimiter, not content) */
                                continue;
                            }
                            Dst[ idx++ ] = *v;
                            v++;
                        }
                        Dst[ idx ] = '\0';
                        return TRUE;
                    }
                }
            }
            d++;
        }

        Search = ObjEnd;
        if ( !*Search )
            return FALSE;
        TypePos = NULL;
    }
}

static SIZE_T BuildUplinkName(
    PCHAR       Dst,
    SIZE_T      DstSize,
    const CHAR* B32Chunk,
    DWORD       Seq,
    DWORD       Total,
    const CHAR* Session,
    const CHAR* C2Domain
)
{
    CHAR SeqHex[ 5 ];
    CHAR TotHex[ 5 ];
    Hex04( Seq, SeqHex );
    Hex04( Total, TotHex );

    SIZE_T Off = 0;
    const CHAR* Src;

    Src = B32Chunk;
    while ( *Src && Off < DstSize - 1 ) Dst[ Off++ ] = *Src++;
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    for ( int i = 0; i < 4 && Off < DstSize - 1; i++ ) Dst[ Off++ ] = SeqHex[ i ];
    for ( int i = 0; i < 4 && Off < DstSize - 1; i++ ) Dst[ Off++ ] = TotHex[ i ];
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    Src = Session;
    while ( *Src && Off < DstSize - 1 ) Dst[ Off++ ] = *Src++;
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    if ( Off < DstSize - 1 ) Dst[ Off++ ] = 'u';
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    Src = C2Domain;
    while ( *Src && Off < DstSize - 1 ) Dst[ Off++ ] = *Src++;

    Dst[ Off ] = '\0';
    return Off;
}

static SIZE_T BuildReadyName(
    PCHAR       Dst,
    SIZE_T      DstSize,
    const CHAR* Session,
    const CHAR* C2Domain
)
{
    SIZE_T Off = 0;
    const CHAR* Src;

    Dst[ Off++ ] = 'r'; Dst[ Off++ ] = 'd'; Dst[ Off++ ] = 'y';
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    Src = Session;
    while ( *Src && Off < DstSize - 1 ) Dst[ Off++ ] = *Src++;
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    if ( Off < DstSize - 1 ) Dst[ Off++ ] = 'd';
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    Src = C2Domain;
    while ( *Src && Off < DstSize - 1 ) Dst[ Off++ ] = *Src++;

    Dst[ Off ] = '\0';
    return Off;
}

static SIZE_T BuildChunkFetchName(
    PCHAR       Dst,
    SIZE_T      DstSize,
    DWORD       Seq,
    const CHAR* Session,
    const CHAR* C2Domain
)
{
    SIZE_T Off = 0;
    CHAR SeqHex[ 5 ];
    const CHAR* Src;

    Hex04( Seq, SeqHex );
    for ( int i = 0; i < 4 && Off < DstSize - 1; i++ ) Dst[ Off++ ] = SeqHex[ i ];
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    Src = Session;
    while ( *Src && Off < DstSize - 1 ) Dst[ Off++ ] = *Src++;
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    if ( Off < DstSize - 1 ) Dst[ Off++ ] = 'd';
    if ( Off < DstSize - 1 ) Dst[ Off++ ] = '.';

    Src = C2Domain;
    while ( *Src && Off < DstSize - 1 ) Dst[ Off++ ] = *Src++;

    Dst[ Off ] = '\0';
    return Off;
}

/* -------------------------------------------------------------------------
 * Test framework
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
 * Section 1: B32Encode / B32Decode round-trip
 * ---------------------------------------------------------------------- */
static void test_b32_round_trip(void)
{
    printf("\n=== B32Encode / B32Decode ===\n");

    /* 1a. Empty input */
    {
        CHAR out[16] = { 0 };
        SIZE_T n = B32Encode(NULL, 0, out);
        check("empty: B32Encode length == 0", n == 0);
        check("empty: B32Encode output is NUL", out[0] == '\0');
    }

    /* 1b. Single byte: 0xFF */
    {
        BYTE  src[1]  = { 0xFF };
        CHAR  enc[16] = { 0 };
        BYTE  dec[16] = { 0 };
        SIZE_T enc_n = B32Encode(src, 1, enc);
        check("1-byte: encoded length > 0", enc_n > 0);
        SIZE_T dec_n = B32Decode(enc, enc_n, dec);
        check("1-byte: decoded length == 1", dec_n == 1);
        check("1-byte: round-trip matches", dec[0] == 0xFF);
    }

    /* 1c. 5 bytes — exactly 8 base32 chars (no trailing partial group) */
    {
        BYTE  src[5]  = { 0xDE, 0xAD, 0xBE, 0xEF, 0x42 };
        CHAR  enc[16] = { 0 };
        BYTE  dec[16] = { 0 };
        SIZE_T enc_n = B32Encode(src, 5, enc);
        check("5-bytes: encoded length == 8", enc_n == 8);
        SIZE_T dec_n = B32Decode(enc, enc_n, dec);
        check("5-bytes: decoded length == 5", dec_n == 5);
        check("5-bytes: round-trip matches", memcmp(dec, src, 5) == 0);
    }

    /* 1d. Varied lengths 1..40 */
    {
        int all_ok = 1;
        for (SIZE_T len = 1; len <= 40; len++) {
            BYTE src[40];
            CHAR enc[128] = { 0 };
            BYTE dec[40]  = { 0 };
            for (SIZE_T i = 0; i < len; i++) src[i] = (BYTE)(i * 7 + 13);
            SIZE_T enc_n = B32Encode(src, len, enc);
            SIZE_T dec_n = B32Decode(enc, enc_n, dec);
            if (dec_n != len || memcmp(dec, src, len) != 0) {
                printf("        FAIL at len=%zu\n", len);
                all_ok = 0;
            }
        }
        check("varied lengths 1..40: all round-trip correctly", all_ok);
    }

    /* 1e. Output contains only lowercase [a-z2-7] */
    {
        BYTE  src[256];
        CHAR  enc[512] = { 0 };
        for (int i = 0; i < 256; i++) src[i] = (BYTE)i;
        SIZE_T enc_n = B32Encode(src, 256, enc);
        int dns_safe = 1;
        for (SIZE_T i = 0; i < enc_n; i++) {
            char ch = enc[i];
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '2' && ch <= '7'))) {
                dns_safe = 0;
                break;
            }
        }
        check("all-bytes: output only contains [a-z2-7]", dns_safe);
    }

    /* 1f. B32Decode rejects '+' */
    {
        const CHAR bad[] = "abcde+fg";
        BYTE dec[16] = { 0 };
        SIZE_T n = B32Decode(bad, StringLengthA(bad), dec);
        check("invalid char '+': B32Decode returns 0", n == 0);
    }

    /* 1g. B32Decode rejects uppercase */
    {
        const CHAR bad[] = "ABCDE";
        BYTE dec[16] = { 0 };
        SIZE_T n = B32Decode(bad, StringLengthA(bad), dec);
        check("uppercase input: B32Decode returns 0", n == 0);
    }

    /* 1h. B32Decode rejects '0' and '1' (not in RFC 4648 base32 alphabet) */
    {
        const CHAR bad[] = "abcde0fg";
        BYTE dec[16] = { 0 };
        SIZE_T n = B32Decode(bad, StringLengthA(bad), dec);
        check("digit '0' (not in alphabet): B32Decode returns 0", n == 0);
    }
}

/* -------------------------------------------------------------------------
 * Section 2: Hex04
 * ---------------------------------------------------------------------- */
static void test_hex04(void)
{
    printf("\n=== Hex04 ===\n");

    { CHAR buf[5] = { 0 }; Hex04(0, buf);
      check("0x0000 -> \"0000\"", strcmp(buf, "0000") == 0); }

    { CHAR buf[5] = { 0 }; Hex04(0x000F, buf);
      check("0x000F -> \"000f\"", strcmp(buf, "000f") == 0); }

    { CHAR buf[5] = { 0 }; Hex04(0xABCD, buf);
      check("0xABCD -> \"abcd\"", strcmp(buf, "abcd") == 0); }

    { CHAR buf[5] = { 0 }; Hex04(0xFFFF, buf);
      check("0xFFFF -> \"ffff\"", strcmp(buf, "ffff") == 0); }

    { CHAR buf[5] = { 0x42, 0x42, 0x42, 0x42, 0x42 };
      Hex04(0x1234, buf);
      check("Hex04 NUL-terminates at buf[4]", buf[4] == '\0'); }

    /* Only the low 16 bits matter: 0x10000 & 0xFFFF == 0 → "0000" */
    { CHAR buf[5] = { 0 }; Hex04(0x10000, buf);
      check("Hex04 uses low 16 bits only", strcmp(buf, "0000") == 0); }
}

/* -------------------------------------------------------------------------
 * Section 3: BuildUplinkName
 * ---------------------------------------------------------------------- */
static void test_build_uplink_name(void)
{
    printf("\n=== BuildUplinkName ===\n");

    /* 3a. Basic format */
    {
        CHAR out[256] = { 0 };
        BuildUplinkName(out, sizeof(out),
                        "abcde", 0, 3,
                        "aabb1122ccdd3344",
                        "c2.example.com");

        check("uplink: starts with b32 chunk 'abcde.'",
              strncmp(out, "abcde.", 6) == 0);
        check("uplink: seq+total hex '00000003' present",
              strstr(out, "00000003") != NULL);
        check("uplink: session present",
              strstr(out, "aabb1122ccdd3344") != NULL);
        check("uplink: '.u.' direction sentinel present",
              strstr(out, ".u.") != NULL);
        check("uplink: domain present",
              strstr(out, "c2.example.com") != NULL);
    }

    /* 3b. seq=5, total=10 */
    {
        CHAR out[256] = { 0 };
        BuildUplinkName(out, sizeof(out),
                        "zzzz", 5, 10,
                        "0000000000000000",
                        "test.domain");
        check("uplink: seq=5 hex is '0005'",  strstr(out, "0005") != NULL);
        check("uplink: total=10 hex is '000a'", strstr(out, "000a") != NULL);
    }

    /* 3c. Return value equals strlen */
    {
        CHAR out[256] = { 0 };
        SIZE_T ret = BuildUplinkName(out, sizeof(out),
                                     "aa", 0, 1,
                                     "abcdef1234567890",
                                     "x.test");
        check("uplink: return value matches strlen", ret == StringLengthA(out));
    }

    /* 3d. seq=0xFFFF (max 4-char hex label) */
    {
        CHAR out[256] = { 0 };
        BuildUplinkName(out, sizeof(out),
                        "a", 0xFFFF, 0xFFFF,
                        "1234567890abcdef",
                        "d.test");
        check("uplink: seq/total=0xFFFF both 'ffff'",
              strstr(out, "ffffffff") != NULL);
    }
}

/* -------------------------------------------------------------------------
 * Section 4: BuildReadyName
 * ---------------------------------------------------------------------- */
static void test_build_ready_name(void)
{
    printf("\n=== BuildReadyName ===\n");

    /* 4a. Exact format: rdy.<session>.d.<domain> */
    {
        const CHAR *session = "deadbeef01234567";
        const CHAR *domain  = "c2.red-cell.test";
        CHAR out[256]  = { 0 };
        CHAR expected[256] = { 0 };
        BuildReadyName(out, sizeof(out), session, domain);
        snprintf(expected, sizeof(expected), "rdy.%s.d.%s", session, domain);
        check("ready: full format matches", strcmp(out, expected) == 0);
    }

    /* 4b. Starts with 'rdy.' */
    {
        CHAR out[256] = { 0 };
        BuildReadyName(out, sizeof(out), "1234abcd5678ef90", "x.test");
        check("ready: starts with 'rdy.'", strncmp(out, "rdy.", 4) == 0);
    }

    /* 4c. Return value equals strlen */
    {
        CHAR out[256] = { 0 };
        SIZE_T ret = BuildReadyName(out, sizeof(out),
                                    "aaaaaaaaaaaaaaaa",
                                    "a.b.c.d");
        check("ready: return value matches strlen", ret == StringLengthA(out));
    }
}

/* -------------------------------------------------------------------------
 * Section 5: BuildChunkFetchName
 * ---------------------------------------------------------------------- */
static void test_build_chunk_fetch_name(void)
{
    printf("\n=== BuildChunkFetchName ===\n");

    /* 5a. Exact format: <seq:04x>.<session>.d.<domain> */
    {
        const CHAR *session = "aabbccddeeff0011";
        const CHAR *domain  = "c2.red-cell.test";
        CHAR out[256]  = { 0 };
        CHAR expected[256] = { 0 };
        BuildChunkFetchName(out, sizeof(out), 0xAB, session, domain);
        snprintf(expected, sizeof(expected), "00ab.%s.d.%s", session, domain);
        check("fetch: full format matches", strcmp(out, expected) == 0);
    }

    /* 5b. seq=0 */
    {
        CHAR out[256] = { 0 };
        BuildChunkFetchName(out, sizeof(out), 0, "0000000000000000", "x.test");
        check("fetch: seq=0 starts with '0000.'", strncmp(out, "0000.", 5) == 0);
    }

    /* 5c. seq=0xFFFF */
    {
        CHAR out[256] = { 0 };
        BuildChunkFetchName(out, sizeof(out), 0xFFFF, "0000000000000000", "x.test");
        check("fetch: seq=0xFFFF starts with 'ffff.'", strncmp(out, "ffff.", 5) == 0);
    }

    /* 5d. Return value equals strlen */
    {
        CHAR out[256] = { 0 };
        SIZE_T ret = BuildChunkFetchName(out, sizeof(out),
                                         7,
                                         "1234abcd5678ef90",
                                         "d.test");
        check("fetch: return value matches strlen", ret == StringLengthA(out));
    }
}

/* -------------------------------------------------------------------------
 * Section 6: JsonGetU64
 * ---------------------------------------------------------------------- */
static void test_json_get_u64(void)
{
    printf("\n=== JsonGetU64 ===\n");

    { UINT64 v = 99;
      BOOL ok = JsonGetU64("{\"Status\":0,\"TC\":false}", "Status", &v);
      check("Status=0: found", ok == TRUE);
      check("Status=0: value is 0", v == 0); }

    { UINT64 v = 0;
      BOOL ok = JsonGetU64("{\"Status\":3,\"TC\":false,\"RD\":true}", "Status", &v);
      check("Status=3: found", ok == TRUE);
      check("Status=3: value is 3", v == 3); }

    { UINT64 v = 0;
      BOOL ok = JsonGetU64("{\"Status\": 5}", "Status", &v);
      check("Status= 5 (space after colon): found", ok == TRUE);
      check("Status= 5 (space after colon): value is 5", v == 5); }

    { UINT64 v = 42;
      BOOL ok = JsonGetU64("{\"TC\":false}", "Status", &v);
      check("missing key: returns FALSE", ok == FALSE); }

    { UINT64 v = 0;
      BOOL ok = JsonGetU64("{\"Status\":1000}", "Status", &v);
      check("large value 1000: found", ok == TRUE);
      check("large value 1000: value correct", v == 1000); }

    /* Key prefix match must not collide: "StatusCode" != "Status" */
    { UINT64 v = 99;
      BOOL ok = JsonGetU64("{\"StatusCode\":200}", "Status", &v);
      /* "StatusCode" key has closing quote at a different position — should not match */
      check("'StatusCode' does not match 'Status'", ok == FALSE || v != 200); }
}

/* -------------------------------------------------------------------------
 * Section 7: JsonExtractTxtData
 * ---------------------------------------------------------------------- */
static void test_json_extract_txt_data(void)
{
    printf("\n=== JsonExtractTxtData ===\n");

    /* 7a. Single TXT record (Cloudflare-style escaped quotes around value) */
    {
        const CHAR *body =
            "{\"Status\":0,\"Answer\":["
            "{\"name\":\"rdy.abc.d.c2.test.\",\"type\":16,\"TTL\":1,"
            "\"data\":\"\\\"0003\\\"\"}]}";
        CHAR out[64] = { 0 };
        BOOL ok = JsonExtractTxtData(body, out, sizeof(out));
        check("single TXT: found", ok == TRUE);
        check("single TXT: escaped quotes stripped, data is '0003'",
              strcmp(out, "0003") == 0);
    }

    /* 7b. No TXT record (type=1 A record only) */
    {
        const CHAR *body =
            "{\"Status\":0,\"Answer\":["
            "{\"name\":\"example.\",\"type\":1,\"TTL\":60,\"data\":\"1.2.3.4\"}]}";
        CHAR out[64] = { 0 };
        BOOL ok = JsonExtractTxtData(body, out, sizeof(out));
        check("no TXT record: returns FALSE", ok == FALSE);
    }

    /* 7c. type=16 with plain (unescaped) data string */
    {
        const CHAR *body =
            "{\"Status\":0,\"Answer\":["
            "{\"type\":16,\"data\":\"hello\"}]}";
        CHAR out[64] = { 0 };
        BOOL ok = JsonExtractTxtData(body, out, sizeof(out));
        check("plain data: found", ok == TRUE);
        check("plain data: value is 'hello'", strcmp(out, "hello") == 0);
    }

    /* 7d. NXDOMAIN response (no Answer section) */
    {
        const CHAR *body = "{\"Status\":3,\"TC\":false,\"RD\":true}";
        CHAR out[64] = { 0 };
        BOOL ok = JsonExtractTxtData(body, out, sizeof(out));
        check("NXDOMAIN (no Answer): returns FALSE", ok == FALSE);
    }

    /* 7e. Multiple records — first TXT is returned */
    {
        const CHAR *body =
            "{\"Status\":0,\"Answer\":["
            "{\"type\":1,\"data\":\"10.0.0.1\"},"
            "{\"type\":16,\"data\":\"first\"},"
            "{\"type\":16,\"data\":\"second\"}]}";
        CHAR out[64] = { 0 };
        BOOL ok = JsonExtractTxtData(body, out, sizeof(out));
        check("multi-record: found", ok == TRUE);
        check("multi-record: first TXT value returned",
              strcmp(out, "first") == 0);
    }

    /* 7f. type=16 record with no data field — no crash */
    {
        const CHAR *body =
            "{\"Status\":0,\"Answer\":["
            "{\"type\":16,\"TTL\":1}]}";
        CHAR out[64] = "sentinel";
        JsonExtractTxtData(body, out, sizeof(out)); /* result irrelevant */
        check("type=16 without data field: no crash", 1);
    }
}

/* -------------------------------------------------------------------------
 * Section 8: GenerateSessionHex
 * ---------------------------------------------------------------------- */
static void test_generate_session_hex(void)
{
    printf("\n=== GenerateSessionHex ===\n");

    /* Reset RNG to known state for reproducibility */
    g_rng_state = 0xDEADBEEF;

    /* 8a. Length is 16 */
    {
        CHAR buf[17] = { 0x42 };
        GenerateSessionHex(buf);
        check("session hex: length is 16", StringLengthA(buf) == 16);
    }

    /* 8b. All chars are lowercase hex [0-9a-f] */
    {
        CHAR buf[17] = { 0 };
        GenerateSessionHex(buf);
        int all_hex = 1;
        for (int i = 0; i < 16; i++) {
            char ch = buf[i];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
                all_hex = 0;
                break;
            }
        }
        check("session hex: all chars are [0-9a-f]", all_hex);
    }

    /* 8c. NUL at position 16 */
    {
        CHAR buf[17];
        memset(buf, 0x42, sizeof(buf));
        GenerateSessionHex(buf);
        check("session hex: NUL-terminated at buf[16]", buf[16] == '\0');
    }

    /* 8d. Consecutive calls produce different values */
    {
        CHAR a[17] = { 0 };
        CHAR b[17] = { 0 };
        GenerateSessionHex(a);
        GenerateSessionHex(b);
        check("session hex: consecutive calls differ", strcmp(a, b) != 0);
    }
}

/* -------------------------------------------------------------------------
 * Section 9: Wire format consistency (Specter-compatible)
 * ---------------------------------------------------------------------- */
static void test_wire_format_consistency(void)
{
    printf("\n=== Wire format consistency (Specter-compatible) ===\n");

    const CHAR *session = "deadbeef01234567";
    const CHAR *domain  = "c2.red-cell.test";
    const CHAR *chunk   = "abcdefghijklmnop";

    /* 9a. Uplink second label is seqhex+totalhex (8 hex chars, no separator) */
    {
        CHAR out[256] = { 0 };
        BuildUplinkName(out, sizeof(out), chunk, 2, 5, session, domain);
        const CHAR *dot1 = strchr(out, '.');
        check("uplink: first dot exists", dot1 != NULL);
        if (dot1)
            check("uplink: second label is '00020005'",
                  strncmp(dot1 + 1, "00020005", 8) == 0);
    }

    /* 9b. Ready name exactly matches Specter format */
    {
        CHAR out[256]  = { 0 };
        CHAR expected[256] = { 0 };
        BuildReadyName(out, sizeof(out), session, domain);
        snprintf(expected, sizeof(expected), "rdy.%s.d.%s", session, domain);
        check("ready: exact Specter format", strcmp(out, expected) == 0);
    }

    /* 9c. Fetch name exactly matches Specter format */
    {
        CHAR out[256]  = { 0 };
        CHAR expected[256] = { 0 };
        BuildChunkFetchName(out, sizeof(out), 0xAB, session, domain);
        snprintf(expected, sizeof(expected), "00ab.%s.d.%s", session, domain);
        check("fetch: exact Specter format", strcmp(out, expected) == 0);
    }

    /* 9d. Chunk-bytes constant: floor(60 * 5 / 8) == 37 */
    check("DOH_CHUNK_BYTES == 37", DOH_CHUNK_BYTES == 37);

    /* 9e. B32 label fits in a DNS label (≤ 63 octets) */
    check("DOH_CHUNK_B32_LEN == 60 (≤ 63)", DOH_CHUNK_B32_LEN == 60);

    /* 9f. A full-size chunk encodes to exactly DOH_CHUNK_B32_LEN chars */
    {
        BYTE  src[DOH_CHUNK_BYTES];
        CHAR  enc[DOH_CHUNK_B32_LEN + 4];
        for (SIZE_T i = 0; i < DOH_CHUNK_BYTES; i++) src[i] = (BYTE)(i);
        SIZE_T n = B32Encode(src, DOH_CHUNK_BYTES, enc);
        check("full-chunk: encoded length == DOH_CHUNK_B32_LEN", n == DOH_CHUNK_B32_LEN);
    }

    /* 9g. Uplink and downlink use different direction sentinels */
    {
        CHAR up[256] = { 0 };
        CHAR rd[256] = { 0 };
        BuildUplinkName(up, sizeof(up), "aa", 0, 1, session, domain);
        BuildReadyName(rd, sizeof(rd), session, domain);
        check("uplink uses '.u.' sentinel", strstr(up, ".u.") != NULL);
        check("ready uses '.d.' sentinel",  strstr(rd, ".d.") != NULL);
        check("uplink does not contain '.d.'", strstr(up, ".d.") == NULL);
        check("ready does not contain '.u.'",  strstr(rd, ".u.") == NULL);
    }
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(void)
{
    printf("Archon DoH transport unit tests\n");

    test_b32_round_trip();
    test_hex04();
    test_build_uplink_name();
    test_build_ready_name();
    test_build_chunk_fetch_name();
    test_json_get_u64();
    test_json_extract_txt_data();
    test_generate_session_hex();
    test_wire_format_consistency();

    printf("\n--- Results: %d passed, %d failed ---\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
