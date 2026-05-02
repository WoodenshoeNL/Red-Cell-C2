/*
 * TransportHttpHelpers.inc.h — pure IPv6/IPv4/proxy-URL helper logic.
 *
 * Included via textual inclusion by TransportHttp.c (production) and
 * test_transport_http_helpers.c (Linux unit-test harness).  All functions are
 * declared static so each translation unit gets its own copy; the file must
 * not be included more than once per TU.
 *
 * Required before including this file:
 *   - BOOL, DWORD, WCHAR, LPCWSTR, LPWSTR, INT, SIZE_T, ULONG, TRUE, FALSE
 *
 * Optional overrides:
 *   - HTTP_HELPER_SWPRINTF  — defaults to swprintf (C99).  Override to
 *     Instance->Win32.swprintf_s in production TUs that want the custom
 *     function-pointer dispatch table.
 */

#ifndef HTTP_HELPER_SWPRINTF
#  define HTTP_HELPER_SWPRINTF swprintf
#endif

static SIZE_T HttpStrLen( LPCWSTR s )
{
    SIZE_T n = 0;
    while ( s && s[ n ] ) {
        n++;
    }
    return n;
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
    SIZE_T  i;
    DWORD   HexLen;
    DWORD   GroupCount;
    BOOL    HasDc;
    BOOL    InGroup;
    BOOL    HasDot;
    DWORD   DotCount;

    if ( ! Host || ! Host[ 0 ] ) {
        return FALSE;
    }

    Scan = Host;
    Len  = HttpStrLen( Host );

    /* Strip optional bracket wrapping: [addr] */
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

    /* Strip and validate zone ID (%...) */
    for ( i = 0; i < Len; i++ ) {
        if ( Scan[ i ] == L'%' ) {
            if ( i == 0 || i + 1 >= Len ) {
                return FALSE;
            }
            for ( SIZE_T j = i + 1; j < Len; j++ ) {
                WCHAR ZoneCh = Scan[ j ];
                if ( ! (
                    ( ZoneCh >= L'0' && ZoneCh <= L'9' )
                    || ( ZoneCh >= L'a' && ZoneCh <= L'z' )
                    || ( ZoneCh >= L'A' && ZoneCh <= L'Z' )
                    || ZoneCh == L'.'
                    || ZoneCh == L'-'
                    || ZoneCh == L'_'
                ) ) {
                    return FALSE;
                }
            }
            Len = i; /* trim to IPv6 portion only */
            break;
        }
    }

    if ( Len == 0 ) {
        return FALSE;
    }

    /* Reject a leading lone colon (single ':', not '::') */
    if ( Scan[ 0 ] == L':' && ( Len < 2 || Scan[ 1 ] != L':' ) ) {
        return FALSE;
    }

    /* Reject a trailing lone colon */
    if ( Scan[ Len - 1 ] == L':' && ( Len < 2 || Scan[ Len - 2 ] != L':' ) ) {
        return FALSE;
    }

    /* Reject triple or more consecutive colons (:::) */
    for ( i = 0; i + 2 < Len; i++ ) {
        if ( Scan[ i ] == L':' && Scan[ i + 1 ] == L':' && Scan[ i + 2 ] == L':' ) {
            return FALSE;
        }
    }

    /* Parse groups — each hextet must be 1–4 hex digits; an embedded
     * IPv4 suffix (dots present) counts as two groups toward the total. */
    HexLen     = 0;
    GroupCount = 0;
    HasDc      = FALSE;
    InGroup    = FALSE;
    HasDot     = FALSE;
    DotCount   = 0;

    /* Per-octet state for the IPv4-mapped dotted tail. */
    DWORD OctetVal         = 0;    /* decimal value of the current octet or pre-dot portion */
    BOOL  OctetHasDig      = FALSE;/* final octet has at least one digit */
    BOOL  GroupOnlyDecimal = TRUE; /* no hex-only chars seen in current group */

    for ( i = 0; i <= Len; i++ ) {
        WCHAR Ch = ( i < Len ) ? Scan[ i ] : L'\0';

        if ( Ch == L':' || Ch == L'\0' ) {
            /* Close the current group */
            if ( InGroup ) {
                if ( HexLen > 4 ) { return FALSE; }
                if ( HasDot ) {
                    if ( DotCount != 3 )  { return FALSE; }
                    if ( ! OctetHasDig )  { return FALSE; } /* last octet must have digits */
                    GroupCount++; /* IPv4 suffix counts as two groups */
                }
                GroupCount++;
                InGroup          = FALSE;
                HexLen           = 0;
                HasDot           = FALSE;
                DotCount         = 0;
                OctetVal         = 0;
                OctetHasDig      = FALSE;
                GroupOnlyDecimal = TRUE;
            }

            if ( Ch == L'\0' ) {
                break;
            }

            /* Detect '::' (triple-colon already rejected above) */
            if ( i + 1 < Len && Scan[ i + 1 ] == L':' ) {
                if ( HasDc ) {
                    return FALSE; /* a second '::' is not valid */
                }
                HasDc = TRUE;
                i++;
            }

        } else if ( Ch == L'.' ) {
            if ( ! InGroup ) { return FALSE; }
            if ( HasDot ) {
                /* Subsequent dots: each octet needs at least one digit. */
                if ( ! OctetHasDig ) { return FALSE; }
                OctetVal    = 0;
                OctetHasDig = FALSE;
            } else {
                /* First dot: the pre-dot portion must be decimal-only and 0-255. */
                if ( ! GroupOnlyDecimal ) { return FALSE; }
                if ( OctetVal > 255 )     { return FALSE; }
                OctetVal    = 0;
                OctetHasDig = FALSE;
            }
            HasDot = TRUE;
            DotCount++;

        } else if ( Ch >= L'0' && Ch <= L'9' ) {
            /* Decimal digit — valid in both hex hextets and dotted IPv4 tails. */
            InGroup = TRUE;
            if ( HasDot ) {
                OctetVal = OctetVal * 10 + (DWORD)( Ch - L'0' );
                if ( OctetVal > 255 ) { return FALSE; }
                OctetHasDig = TRUE;
            } else {
                HexLen++;
                /* Accumulate for range check at the first dot, if one follows. */
                OctetVal = OctetVal * 10 + (DWORD)( Ch - L'0' );
            }

        } else if ( HttpIsHexDigitW( Ch ) ) {
            /* Hex-only digit (a-f / A-F) — not allowed inside a dotted IPv4 tail. */
            if ( HasDot ) { return FALSE; }
            InGroup          = TRUE;
            HexLen++;
            GroupOnlyDecimal = FALSE;

        } else {
            return FALSE;
        }
    }

    /* Validate total group count:
     *   with    '::' — explicit groups must be ≤ 7 (one or more implicit zeros)
     *   without '::' — must have exactly 8 groups */
    if ( HasDc ) {
        return GroupCount <= 7;
    }

    return GroupCount == 8;
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
                /* Only four octets allowed; reject 1.2.3.4.trailing */
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

/*!
 * Build a full http(s)://host[:port]/path URL for proxy-discovery APIs.
 *
 * Pure function: no global state.  The production TU wraps this with
 * HttpComposeUrlForProxyLookup() which reads Host/Port/Secure from the
 * Instance config and supplies Instance->Win32.swprintf_s via the
 * HTTP_HELPER_SWPRINTF macro.
 *
 * Returns Buf on success, RelativePath on any error or overflow.
 */
static LPWSTR HttpBuildProxyUrl(
    WCHAR *  Buf,
    SIZE_T   CchBuf,
    LPCWSTR  Host,
    DWORD    Port,
    BOOL     Secure,
    LPWSTR   RelativePath
)
{
    LPCWSTR scheme;
    LPCWSTR hostUse;
    INT     nw;
    WCHAR   HostNz[ 128 ] = { 0 };
    SIZE_T  zi;

    if ( ! Buf || CchBuf < 16 || ! RelativePath || ! Host ) {
        return RelativePath;
    }

    scheme  = Secure ? L"https://" : L"http://";
    hostUse = Host;

    /* RFC 3986 / WinHTTP: accept bracketed IPv6 only when closing ']' present. */
    if ( hostUse[ 0 ] == L'[' && HttpIsLiteralIpv6Host( hostUse ) ) {
        nw = HTTP_HELPER_SWPRINTF(
            Buf,
            CchBuf,
            L"%ls%ls:%lu%ls",
            scheme,
            hostUse,
            ( ULONG ) Port,
            RelativePath
        );
    } else if ( hostUse[ 0 ] == L'[' ) {
        return RelativePath;
    } else if ( HttpIsLiteralIpv6Host( Host ) ) {
        /* Unbracketed IPv6: strip zone id (%scope) so the proxy API sees a valid host. */
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

        nw = HTTP_HELPER_SWPRINTF(
            Buf,
            CchBuf,
            L"%ls[%ls]:%lu%ls",
            scheme,
            HostNz,
            ( ULONG ) Port,
            RelativePath
        );
    } else {
        nw = HTTP_HELPER_SWPRINTF(
            Buf,
            CchBuf,
            L"%ls%ls:%lu%ls",
            scheme,
            hostUse,
            ( ULONG ) Port,
            RelativePath
        );
    }

    if ( nw < 0 || ( SIZE_T ) nw >= CchBuf ) {
        return RelativePath;
    }

    return Buf;
}
