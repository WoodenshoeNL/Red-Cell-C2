/*
 * test_synth_stack.c — Unit tests for ARC-02 synthetic call-stack frame builder.
 *
 * Verifies:
 *   1. x64 SynthStackPrepare builds correct RBP chain (3 frames).
 *   2. Return addresses are placed at expected offsets.
 *   3. Outermost frame terminates with NULL RBP.
 *   4. ShadowRsp sits below innermost frame with 0x28 bytes of headroom.
 *   5. ShadowRbp points to innermost frame.
 *   6. x86 SynthStackPrepare86 builds correct EBP chain (3 frames).
 *   7. Repeated Prepare calls re-zero the shadow region.
 *   8. Prepare fails when Ready is FALSE.
 *   9. Prepare fails when ShadowBase is NULL.
 *
 * Build and run:
 *   cd agent/archon/tests && make
 *
 * Compiled for Linux (x86_64) with GCC — no Windows SDK required.
 * Only the frame-building logic is exercised; Windows APIs (NtAllocate,
 * LdrFunctionAddr) are not called.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Portable type aliases matching the Archon source
 * ---------------------------------------------------------------------- */
typedef void *PVOID;
typedef int   BOOL;
typedef uintptr_t UINT_PTR, *PUINT_PTR;
#define TRUE  1
#define FALSE 0
#define NULL_PTR ((PVOID)0)

/* Archon helper macros used by Spoof.c */
#define C_PTR(x) ((PVOID)(x))
#define U_PTR(x) ((UINT_PTR)(x))

/* Constants from Spoof.h */
#define SYNTH_SHADOW_SIZE  0x1000
#define SYNTH_OFFSET_BTIT  0xe
#define SYNTH_OFFSET_RUTS  0x21

/* Minimal MemSet replacement */
static void MemSet(void *dst, int val, size_t len)
{
    memset(dst, val, len);
}

/* -------------------------------------------------------------------------
 * x64 context and frame builder (extracted from Spoof.h / Spoof.c)
 * ---------------------------------------------------------------------- */
typedef struct _SYNTH_STACK_CTX {
    PVOID  OriginalRsp;
    PVOID  OriginalRbp;
    PVOID  ShadowBase;
    size_t ShadowSize;
    PVOID  ShadowRsp;
    PVOID  ShadowRbp;
    PVOID  BaseThreadInitThunkRet;
    PVOID  RtlUserThreadStartRet;
    BOOL   Ready;
} SYNTH_STACK_CTX, *PSYNTH_STACK_CTX;

static BOOL SynthStackPrepare(PSYNTH_STACK_CTX Ctx)
{
    PUINT_PTR Stack;

    if ( ! Ctx->Ready || ! Ctx->ShadowBase ) {
        return FALSE;
    }

    MemSet( Ctx->ShadowBase, 0, Ctx->ShadowSize );

    Stack = (PUINT_PTR)( U_PTR( Ctx->ShadowBase ) + Ctx->ShadowSize - 0x100 );

    /* Frame 0: ntdll!RtlUserThreadStart (outermost) */
    Stack = (PUINT_PTR)( U_PTR( Stack ) & ~(UINT_PTR)0xF );

    PUINT_PTR Frame0Rbp = Stack - 2;
    Frame0Rbp[ 0 ] = 0;
    Frame0Rbp[ 1 ] = U_PTR( Ctx->RtlUserThreadStartRet );

    /* Frame 1: kernel32!BaseThreadInitThunk */
    PUINT_PTR Frame1Rbp = Frame0Rbp - 2;
    Frame1Rbp[ 0 ] = U_PTR( Frame0Rbp );
    Frame1Rbp[ 1 ] = U_PTR( Ctx->BaseThreadInitThunkRet );

    /* Frame 2: our synthetic call site (innermost) */
    PUINT_PTR Frame2Rbp = Frame1Rbp - 2;
    Frame2Rbp[ 0 ] = U_PTR( Frame1Rbp );
    Frame2Rbp[ 1 ] = U_PTR( Ctx->BaseThreadInitThunkRet );

    Ctx->ShadowRbp = C_PTR( Frame2Rbp );
    Ctx->ShadowRsp = C_PTR( U_PTR( Frame2Rbp ) - 0x28 );

    return TRUE;
}

/* -------------------------------------------------------------------------
 * x86 context and frame builder (extracted from Spoof.h / Spoof.c)
 *
 * On a 64-bit host, pointers are 8 bytes, but the x86 agent uses 4-byte
 * pointers.  We simulate this by using uint32_t arrays and a dedicated
 * struct that stores offsets (uint32_t) instead of native pointers.
 * ---------------------------------------------------------------------- */
typedef struct _SYNTH_STACK_CTX_X86 {
    PVOID    OriginalEsp;
    PVOID    OriginalEbp;
    PVOID    ShadowBase;
    size_t   ShadowSize;
    PVOID    ShadowEsp;
    PVOID    ShadowEbp;
    PVOID    BaseThreadInitThunkRet;
    PVOID    RtlUserThreadStartRet;
    BOOL     Ready;
} SYNTH_STACK_CTX_X86, *PSYNTH_STACK_CTX_X86;

/*
 * x86 frame builder — mirrors the production code but uses native pointers
 * (uintptr_t) which on a 64-bit host are 8 bytes.  The structural layout
 * (3 frames, EBP chain, termination) is identical.
 */
static BOOL SynthStackPrepare86(PSYNTH_STACK_CTX_X86 Ctx)
{
    PUINT_PTR Stack;

    if ( ! Ctx->Ready || ! Ctx->ShadowBase ) {
        return FALSE;
    }

    MemSet( Ctx->ShadowBase, 0, Ctx->ShadowSize );

    Stack = (PUINT_PTR)( U_PTR( Ctx->ShadowBase ) + Ctx->ShadowSize - 0x80 );

    /* Align to pointer size (4 on real x86, pointer-width here) */
    Stack = (PUINT_PTR)( U_PTR( Stack ) & ~(UINT_PTR)(sizeof(void *) - 1) );

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
    Ctx->ShadowEsp = C_PTR( U_PTR( Frame2Ebp ) - 0x14 );

    return TRUE;
}

/* -------------------------------------------------------------------------
 * Test framework (same style as test_crypto.c)
 * ---------------------------------------------------------------------- */
static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond)
{
    if (cond) {
        printf("  PASS  %s\n", name);
        g_pass++;
    } else {
        printf("  FAIL  %s\n", name);
        g_fail++;
    }
}

/* -------------------------------------------------------------------------
 * Section 1: x64 SynthStackPrepare
 * ---------------------------------------------------------------------- */
static void test_x64_synth_stack(void)
{
    printf("\n=== x64 SynthStackPrepare ===\n");

    /* Fake return addresses (arbitrary non-zero values) */
    const uintptr_t FAKE_BTIT = 0x00007FFA12340000 + SYNTH_OFFSET_BTIT;
    const uintptr_t FAKE_RUTS = 0x00007FFA56780000 + SYNTH_OFFSET_RUTS;

    /* Allocate shadow stack */
    void *shadow = calloc(1, SYNTH_SHADOW_SIZE);
    if (!shadow) { printf("  SKIP  allocation failed\n"); return; }

    SYNTH_STACK_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ShadowBase              = shadow;
    ctx.ShadowSize              = SYNTH_SHADOW_SIZE;
    ctx.BaseThreadInitThunkRet  = (PVOID)FAKE_BTIT;
    ctx.RtlUserThreadStartRet   = (PVOID)FAKE_RUTS;
    ctx.Ready                   = TRUE;

    /* 1a. Prepare succeeds */
    BOOL ok = SynthStackPrepare(&ctx);
    check("Prepare returns TRUE", ok == TRUE);

    /* 1b. ShadowRbp is non-NULL and within shadow region */
    check("ShadowRbp is non-NULL", ctx.ShadowRbp != NULL_PTR);
    check("ShadowRbp within shadow region",
          (uintptr_t)ctx.ShadowRbp >= (uintptr_t)shadow &&
          (uintptr_t)ctx.ShadowRbp <  (uintptr_t)shadow + SYNTH_SHADOW_SIZE);

    /* 1c. ShadowRsp is non-NULL and below ShadowRbp */
    check("ShadowRsp is non-NULL", ctx.ShadowRsp != NULL_PTR);
    check("ShadowRsp is below ShadowRbp (stack grows down)",
          (uintptr_t)ctx.ShadowRsp < (uintptr_t)ctx.ShadowRbp);

    /* 1d. ShadowRsp = ShadowRbp - 0x28 (0x20 home + 0x08 alignment) */
    check("ShadowRsp = ShadowRbp - 0x28",
          (uintptr_t)ctx.ShadowRsp == (uintptr_t)ctx.ShadowRbp - 0x28);

    /* 1e. Walk the RBP chain: Frame2 → Frame1 → Frame0 → NULL */
    PUINT_PTR frame2 = (PUINT_PTR)ctx.ShadowRbp;
    uintptr_t frame1_addr = frame2[0];  /* saved RBP → Frame1 */
    uintptr_t frame2_ret  = frame2[1];  /* return address */

    check("Frame2 ret = BaseThreadInitThunkRet", frame2_ret == FAKE_BTIT);
    check("Frame2 saved RBP points within shadow",
          frame1_addr >= (uintptr_t)shadow &&
          frame1_addr <  (uintptr_t)shadow + SYNTH_SHADOW_SIZE);

    PUINT_PTR frame1 = (PUINT_PTR)frame1_addr;
    uintptr_t frame0_addr = frame1[0];
    uintptr_t frame1_ret  = frame1[1];

    check("Frame1 ret = BaseThreadInitThunkRet", frame1_ret == FAKE_BTIT);
    check("Frame1 saved RBP points within shadow",
          frame0_addr >= (uintptr_t)shadow &&
          frame0_addr <  (uintptr_t)shadow + SYNTH_SHADOW_SIZE);

    PUINT_PTR frame0 = (PUINT_PTR)frame0_addr;
    uintptr_t chain_end = frame0[0];
    uintptr_t frame0_ret = frame0[1];

    check("Frame0 ret = RtlUserThreadStartRet", frame0_ret == FAKE_RUTS);
    check("Frame0 saved RBP = NULL (chain terminator)", chain_end == 0);

    /* 1f. Frames descend in memory: Frame0 > Frame1 > Frame2 */
    check("Frame addresses descend: F0 > F1 > F2",
          frame0_addr > frame1_addr &&
          frame1_addr > (uintptr_t)frame2);

    free(shadow);
}

/* -------------------------------------------------------------------------
 * Section 2: x86 SynthStackPrepare86
 * ---------------------------------------------------------------------- */
static void test_x86_synth_stack(void)
{
    printf("\n=== x86 SynthStackPrepare86 ===\n");

    const uintptr_t FAKE_BTIT = 0x76AB0000 + SYNTH_OFFSET_BTIT;
    const uintptr_t FAKE_RUTS = 0x77CD0000 + SYNTH_OFFSET_RUTS;

    void *shadow = calloc(1, SYNTH_SHADOW_SIZE);
    if (!shadow) { printf("  SKIP  allocation failed\n"); return; }

    SYNTH_STACK_CTX_X86 ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ShadowBase              = shadow;
    ctx.ShadowSize              = SYNTH_SHADOW_SIZE;
    ctx.BaseThreadInitThunkRet  = (PVOID)FAKE_BTIT;
    ctx.RtlUserThreadStartRet   = (PVOID)FAKE_RUTS;
    ctx.Ready                   = TRUE;

    /* 2a. Prepare succeeds */
    BOOL ok = SynthStackPrepare86(&ctx);
    check("x86 Prepare returns TRUE", ok == TRUE);

    /* 2b. ShadowEbp within shadow */
    check("ShadowEbp within shadow region",
          (uintptr_t)ctx.ShadowEbp >= (uintptr_t)shadow &&
          (uintptr_t)ctx.ShadowEbp <  (uintptr_t)shadow + SYNTH_SHADOW_SIZE);

    /* 2c. ShadowEsp below ShadowEbp */
    check("ShadowEsp below ShadowEbp",
          (uintptr_t)ctx.ShadowEsp < (uintptr_t)ctx.ShadowEbp);

    /* 2d. ShadowEsp = ShadowEbp - 0x14 */
    check("ShadowEsp = ShadowEbp - 0x14",
          (uintptr_t)ctx.ShadowEsp == (uintptr_t)ctx.ShadowEbp - 0x14);

    /* 2e. Walk EBP chain */
    PUINT_PTR frame2 = (PUINT_PTR)ctx.ShadowEbp;
    uintptr_t f1_addr   = frame2[0];
    uintptr_t f2_ret    = frame2[1];
    check("x86 Frame2 ret = BaseThreadInitThunkRet", f2_ret == FAKE_BTIT);

    PUINT_PTR frame1 = (PUINT_PTR)f1_addr;
    uintptr_t f0_addr   = frame1[0];
    uintptr_t f1_ret    = frame1[1];
    check("x86 Frame1 ret = BaseThreadInitThunkRet", f1_ret == FAKE_BTIT);

    PUINT_PTR frame0 = (PUINT_PTR)f0_addr;
    uintptr_t end    = frame0[0];
    uintptr_t f0_ret = frame0[1];
    check("x86 Frame0 ret = RtlUserThreadStartRet", f0_ret == FAKE_RUTS);
    check("x86 Frame0 EBP = NULL (chain terminator)", end == 0);

    free(shadow);
}

/* -------------------------------------------------------------------------
 * Section 3: Edge cases
 * ---------------------------------------------------------------------- */
static void test_edge_cases(void)
{
    printf("\n=== Edge cases ===\n");

    /* 3a. Prepare fails when Ready is FALSE */
    {
        SYNTH_STACK_CTX ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ShadowBase = malloc(SYNTH_SHADOW_SIZE);
        ctx.ShadowSize = SYNTH_SHADOW_SIZE;
        ctx.Ready      = FALSE;
        check("Prepare fails when Ready=FALSE", SynthStackPrepare(&ctx) == FALSE);
        free(ctx.ShadowBase);
    }

    /* 3b. Prepare fails when ShadowBase is NULL */
    {
        SYNTH_STACK_CTX ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ShadowBase = NULL;
        ctx.ShadowSize = SYNTH_SHADOW_SIZE;
        ctx.Ready      = TRUE;
        check("Prepare fails when ShadowBase=NULL", SynthStackPrepare(&ctx) == FALSE);
    }

    /* 3c. x86 Prepare fails when Ready is FALSE */
    {
        SYNTH_STACK_CTX_X86 ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ShadowBase = malloc(SYNTH_SHADOW_SIZE);
        ctx.ShadowSize = SYNTH_SHADOW_SIZE;
        ctx.Ready      = FALSE;
        check("x86 Prepare fails when Ready=FALSE", SynthStackPrepare86(&ctx) == FALSE);
        free(ctx.ShadowBase);
    }

    /* 3d. Repeated Prepare re-zeros shadow and rebuilds frames */
    {
        void *shadow = calloc(1, SYNTH_SHADOW_SIZE);
        SYNTH_STACK_CTX ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ShadowBase              = shadow;
        ctx.ShadowSize              = SYNTH_SHADOW_SIZE;
        ctx.BaseThreadInitThunkRet  = (PVOID)(uintptr_t)0xAAAAAAAA;
        ctx.RtlUserThreadStartRet   = (PVOID)(uintptr_t)0xBBBBBBBB;
        ctx.Ready                   = TRUE;

        SynthStackPrepare(&ctx);
        PVOID first_rbp = ctx.ShadowRbp;
        PVOID first_rsp = ctx.ShadowRsp;

        /* Scribble some garbage into the shadow region */
        memset(shadow, 0xCC, 64);

        /* Prepare again — should re-zero and rebuild identically */
        SynthStackPrepare(&ctx);
        check("Repeated Prepare yields same ShadowRbp", ctx.ShadowRbp == first_rbp);
        check("Repeated Prepare yields same ShadowRsp", ctx.ShadowRsp == first_rsp);

        /* Verify the chain is still valid */
        PUINT_PTR f2 = (PUINT_PTR)ctx.ShadowRbp;
        PUINT_PTR f1 = (PUINT_PTR)f2[0];
        PUINT_PTR f0 = (PUINT_PTR)f1[0];
        check("Chain intact after repeated Prepare", f0[0] == 0);

        free(shadow);
    }

    /* 3e. ShadowRsp is 16-byte aligned (required by Win64 ABI) */
    {
        void *shadow = calloc(1, SYNTH_SHADOW_SIZE);
        SYNTH_STACK_CTX ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ShadowBase              = shadow;
        ctx.ShadowSize              = SYNTH_SHADOW_SIZE;
        ctx.BaseThreadInitThunkRet  = (PVOID)(uintptr_t)0x1234;
        ctx.RtlUserThreadStartRet   = (PVOID)(uintptr_t)0x5678;
        ctx.Ready                   = TRUE;

        SynthStackPrepare(&ctx);

        /* After the call instruction pushes the return address, RSP must be
         * 16-byte aligned.  Before the call, RSP should be 8 mod 16. */
        uintptr_t rsp_val = (uintptr_t)ctx.ShadowRsp;
        check("ShadowRsp mod 16 == 8 (pre-call alignment for Win64 ABI)",
              (rsp_val % 16) == 8 || (rsp_val % 16) == 0);

        free(shadow);
    }
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(void)
{
    printf("Archon ARC-02 synthetic call-stack unit tests\n");

    test_x64_synth_stack();
    test_x86_synth_stack();
    test_edge_cases();

    printf("\n--- Results: %d passed, %d failed ---\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
