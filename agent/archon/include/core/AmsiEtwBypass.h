#ifndef ARCHON_AMSIETWBYPASS_H
#define ARCHON_AMSIETWBYPASS_H

#include <windows.h>
#include <ntstatus.h>

/*!
 * Apply a persistent process-wide in-memory patch to AmsiScanBuffer and
 * NtTraceEvent.  Overwrites the function preambles with a minimal stub that
 * returns E_INVALIDARG / STATUS_SUCCESS so that every thread — including
 * those created after the patch — skips AMSI scanning and ETW tracing.
 *
 * The patch is idempotent: calling it a second time is a no-op if both
 * functions have already been patched.
 *
 * @return STATUS_SUCCESS on success.
 *         STATUS_UNSUCCESSFUL if the required function address is unavailable.
 *         An NTSTATUS error from NtProtectVirtualMemory on write failure.
 */
NTSTATUS AmsiEtwBypassPatch( VOID );

#endif /* ARCHON_AMSIETWBYPASS_H */
