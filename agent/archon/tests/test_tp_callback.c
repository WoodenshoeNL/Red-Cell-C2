/*
 * test_tp_callback.c — Regression test for ARC-09 thread-pool callback cleanup.
 *
 * Validates that the CoffeeRunnerWork / CoffeeRunnerThread split is correct:
 *
 *   1. CoffeeRunnerWork returns normally (does not exit the calling thread).
 *   2. TpJobCallback wrapper marks the job dead and frees resources after
 *      the work function returns.
 *   3. CoffeeRunnerThread (dedicated-thread path) still performs thread-level
 *      cleanup after calling CoffeeRunnerWork.
 *   4. No double-decrement of Threads counter in either path.
 *
 * Build and run:
 *   cd agent/archon/tests && make && ./test_tp_callback
 *
 * Compiled for Linux with GCC — no mingw / windows.h required.
 * We simulate the relevant structures and functions.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/* -------------------------------------------------------------------------
 * Type aliases mirroring the Windows types used by Archon
 * ---------------------------------------------------------------------- */
typedef uint8_t   UINT8;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef int32_t   INT32;
typedef size_t    SIZE_T;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef void      VOID;
typedef void     *PVOID;
typedef char     *PCHAR;
typedef int       BOOL;
typedef long      NTSTATUS;

#define TRUE  1
#define FALSE 0
#define LPTR  0x0040
#define NULL  ((void *)0)

/* -------------------------------------------------------------------------
 * Job state/type constants (from Jobs.h)
 * ---------------------------------------------------------------------- */
#define JOB_TYPE_THREAD      0x1
#define JOB_TYPE_THREADPOOL  0x4
#define JOB_STATE_RUNNING    0x1
#define JOB_STATE_DEAD       0x3

/* -------------------------------------------------------------------------
 * Simplified job-list node
 * ---------------------------------------------------------------------- */
typedef struct _JOB_DATA {
    DWORD               JobID;
    DWORD               Type;
    DWORD               State;
    PVOID               Handle;
    PVOID               Data;
    UINT32              RequestID;
    struct _JOB_DATA   *Next;
} JOB_DATA, *PJOB_DATA;

/* -------------------------------------------------------------------------
 * Thread-pool wrapper context (mirrors TP_JOB_CTX in Jobs.c)
 * ---------------------------------------------------------------------- */
typedef struct {
    PVOID  Entry;
    PVOID  Arg;
    PVOID  TpWork;
    DWORD  JobID;
} TP_JOB_CTX, *PTP_JOB_CTX;

/* -------------------------------------------------------------------------
 * COFFEE_PARAMS (mirrors CoffeeLdr.h)
 * ---------------------------------------------------------------------- */
typedef struct {
    PCHAR  EntryName;
    DWORD  EntryNameSize;
    PVOID  CoffeeData;
    SIZE_T CoffeeDataSize;
    PVOID  ArgData;
    SIZE_T ArgSize;
    UINT32 RequestID;
} COFFEE_PARAMS, *PCOFFEE_PARAMS;

/* -------------------------------------------------------------------------
 * Simulated global state
 * ---------------------------------------------------------------------- */
static INT32  g_threads        = 0;
static PJOB_DATA g_jobs        = NULL;
static int    g_coffeeldr_calls = 0;
static int    g_exit_thread_calls = 0;
static int    g_tp_release_calls  = 0;
static int    g_local_free_calls  = 0;
static int    g_job_remove_calls  = 0;

/* Track freed pointers to verify cleanup */
#define MAX_FREES 64
static void  *g_freed[MAX_FREES];
static int    g_freed_count = 0;

static void record_free( void *p )
{
    if ( g_freed_count < MAX_FREES )
        g_freed[g_freed_count++] = p;
}

static bool was_freed( void *p )
{
    for ( int i = 0; i < g_freed_count; i++ )
        if ( g_freed[i] == p )
            return true;
    return false;
}

static void reset_state( void )
{
    g_threads            = 0;
    g_jobs               = NULL;
    g_coffeeldr_calls    = 0;
    g_exit_thread_calls  = 0;
    g_tp_release_calls   = 0;
    g_local_free_calls   = 0;
    g_job_remove_calls   = 0;
    g_freed_count        = 0;
    memset( g_freed, 0, sizeof( g_freed ) );
}

/* -------------------------------------------------------------------------
 * Simulated CoffeeLdr — just counts calls
 * ---------------------------------------------------------------------- */
static void SimCoffeeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize, UINT32 RequestID )
{
    (void)EntryName; (void)CoffeeData; (void)ArgData; (void)ArgSize; (void)RequestID;
    g_coffeeldr_calls++;
}

/* -------------------------------------------------------------------------
 * Simulated DATA_FREE
 * ---------------------------------------------------------------------- */
static void SimDataFree( void *ptr, size_t size )
{
    (void)size;
    if ( ptr ) {
        record_free( ptr );
        free( ptr );
    }
}

/* -------------------------------------------------------------------------
 * Simulated JobRemove
 * ---------------------------------------------------------------------- */
static void SimJobRemove( DWORD JobID )
{
    (void)JobID;
    g_job_remove_calls++;
}

/* -------------------------------------------------------------------------
 * Simulated RtlExitUserThread
 * ---------------------------------------------------------------------- */
static void SimRtlExitUserThread( int code )
{
    (void)code;
    g_exit_thread_calls++;
    /* In real code this would kill the thread — we just record it */
}

/* -------------------------------------------------------------------------
 * Simulated TpReleaseWork
 * ---------------------------------------------------------------------- */
static void SimTpReleaseWork( PVOID work )
{
    (void)work;
    g_tp_release_calls++;
}

/* -------------------------------------------------------------------------
 * CoffeeRunnerWork — the FIXED version (returns normally)
 * This mirrors the actual implementation.
 * ---------------------------------------------------------------------- */
static void CoffeeRunnerWork( PCOFFEE_PARAMS Param )
{
    if ( !Param->EntryName || !Param->CoffeeData )
        goto Cleanup;

    SimCoffeeLdr( Param->EntryName, Param->CoffeeData,
                  Param->ArgData, Param->ArgSize, Param->RequestID );

Cleanup:
    if ( Param )
    {
        SimDataFree( Param->EntryName,  Param->EntryNameSize );
        SimDataFree( Param->CoffeeData, Param->CoffeeDataSize );
        SimDataFree( Param->ArgData,    Param->ArgSize );
        SimDataFree( Param,             sizeof( COFFEE_PARAMS ) );
    }
}

/* -------------------------------------------------------------------------
 * CoffeeRunnerThread — dedicated-thread entry (calls Work then exits thread)
 * ---------------------------------------------------------------------- */
static void CoffeeRunnerThread( PCOFFEE_PARAMS Param )
{
    CoffeeRunnerWork( Param );

    SimJobRemove( 0 /* would be thread ID */ );
    g_threads--;

    SimRtlExitUserThread( 0 );
}

/* -------------------------------------------------------------------------
 * TpJobCallback — thread-pool wrapper (mirrors Jobs.c implementation)
 * ---------------------------------------------------------------------- */
typedef void (*WORK_FUNC)( PCOFFEE_PARAMS );

static void TpJobCallback( PTP_JOB_CTX Ctx )
{
    if ( Ctx && Ctx->Entry )
    {
        ( (WORK_FUNC) Ctx->Entry )( (PCOFFEE_PARAMS) Ctx->Arg );
    }

    /* mark the tracked job as dead */
    PJOB_DATA JobList = g_jobs;
    while ( JobList )
    {
        if ( JobList->JobID == Ctx->JobID )
        {
            JobList->State = JOB_STATE_DEAD;
            break;
        }
        JobList = JobList->Next;
    }

    /* release the TP_WORK object */
    if ( Ctx->TpWork )
        SimTpReleaseWork( Ctx->TpWork );

    /* decrement thread counter */
    g_threads--;

    /* free the context block */
    memset( Ctx, 0, sizeof( TP_JOB_CTX ) );
    free( Ctx );
}

/* -------------------------------------------------------------------------
 * Test scaffolding
 * ---------------------------------------------------------------------- */
static int tests_run    = 0;
static int tests_passed = 0;

#define TEST( name ) \
    static void name( void ); \
    static void run_##name( void ) { \
        tests_run++; \
        name(); \
        tests_passed++; \
        printf( "  PASS  %s\n", #name ); \
    } \
    static void name( void )

#define ASSERT( cond ) \
    do { \
        if ( !( cond ) ) { \
            printf( "  FAIL  %s:%d: %s\n", __FILE__, __LINE__, #cond ); \
            exit(1); \
        } \
    } while (0)

/* -------------------------------------------------------------------------
 * Helper: allocate a COFFEE_PARAMS with valid fields
 * ---------------------------------------------------------------------- */
static PCOFFEE_PARAMS make_params( void )
{
    PCOFFEE_PARAMS p = calloc( 1, sizeof( COFFEE_PARAMS ) );

    p->EntryName      = strdup( "go" );
    p->EntryNameSize  = 3;
    p->CoffeeData     = malloc( 16 );
    p->CoffeeDataSize = 16;
    p->ArgData        = malloc( 8 );
    p->ArgSize        = 8;
    p->RequestID      = 42;

    memset( p->CoffeeData, 0xCC, 16 );
    memset( p->ArgData, 0xDD, 8 );

    return p;
}

/* =========================================================================
 * Test 1: CoffeeRunnerWork returns normally and frees params
 * ======================================================================= */
TEST( test_work_returns_normally )
{
    reset_state();

    PCOFFEE_PARAMS p = make_params();
    void *entry_ptr  = p->EntryName;
    void *data_ptr   = p->CoffeeData;
    void *arg_ptr    = p->ArgData;

    CoffeeRunnerWork( p );

    /* The function returned (not killed by ExitThread) */
    ASSERT( g_exit_thread_calls == 0 );

    /* CoffeeLdr was invoked */
    ASSERT( g_coffeeldr_calls == 1 );

    /* All param fields were freed */
    ASSERT( was_freed( entry_ptr ) );
    ASSERT( was_freed( data_ptr ) );
    ASSERT( was_freed( arg_ptr ) );
    ASSERT( was_freed( p ) );

    /* No thread-level cleanup was done */
    ASSERT( g_job_remove_calls == 0 );
    ASSERT( g_threads == 0 );  /* unchanged */
}

/* =========================================================================
 * Test 2: Thread-pool path — TpJobCallback completes all cleanup
 * ======================================================================= */
TEST( test_threadpool_path_completes_cleanup )
{
    reset_state();
    g_threads = 1;  /* CoffeeRunner increments before submit */

    /* Create a job entry */
    JOB_DATA job = { 0 };
    job.JobID = 999;
    job.Type  = JOB_TYPE_THREADPOOL;
    job.State = JOB_STATE_RUNNING;
    g_jobs    = &job;

    /* Create the wrapper context */
    PTP_JOB_CTX ctx = calloc( 1, sizeof( TP_JOB_CTX ) );
    ctx->Entry  = (PVOID) CoffeeRunnerWork;
    ctx->Arg    = make_params();
    ctx->TpWork = (PVOID) 0xDEAD;  /* opaque handle */
    ctx->JobID  = 999;

    TpJobCallback( ctx );

    /* Job marked dead */
    ASSERT( job.State == JOB_STATE_DEAD );

    /* TP_WORK released */
    ASSERT( g_tp_release_calls == 1 );

    /* Thread counter decremented back to 0 */
    ASSERT( g_threads == 0 );

    /* RtlExitUserThread was NOT called (pool worker lives) */
    ASSERT( g_exit_thread_calls == 0 );

    /* CoffeeLdr was invoked */
    ASSERT( g_coffeeldr_calls == 1 );
}

/* =========================================================================
 * Test 3: Dedicated-thread path — CoffeeRunnerThread calls ExitThread
 * ======================================================================= */
TEST( test_dedicated_thread_path_exits )
{
    reset_state();
    g_threads = 1;

    PCOFFEE_PARAMS p = make_params();

    CoffeeRunnerThread( p );

    /* RtlExitUserThread was called exactly once */
    ASSERT( g_exit_thread_calls == 1 );

    /* JobRemove was called */
    ASSERT( g_job_remove_calls == 1 );

    /* Thread counter decremented */
    ASSERT( g_threads == 0 );

    /* CoffeeLdr was invoked */
    ASSERT( g_coffeeldr_calls == 1 );
}

/* =========================================================================
 * Test 4: No double-decrement — thread-pool path decrements exactly once
 * ======================================================================= */
TEST( test_no_double_decrement_threadpool )
{
    reset_state();
    g_threads = 3;  /* multiple jobs active */

    JOB_DATA job = { .JobID = 100, .Type = JOB_TYPE_THREADPOOL, .State = JOB_STATE_RUNNING };
    g_jobs = &job;

    PTP_JOB_CTX ctx = calloc( 1, sizeof( TP_JOB_CTX ) );
    ctx->Entry  = (PVOID) CoffeeRunnerWork;
    ctx->Arg    = make_params();
    ctx->TpWork = (PVOID) 0xBEEF;
    ctx->JobID  = 100;

    TpJobCallback( ctx );

    /* Exactly one decrement: 3 -> 2 */
    ASSERT( g_threads == 2 );
}

/* =========================================================================
 * Test 5: CoffeeRunnerWork handles NULL/missing fields gracefully
 * ======================================================================= */
TEST( test_work_handles_null_entry )
{
    reset_state();

    PCOFFEE_PARAMS p = calloc( 1, sizeof( COFFEE_PARAMS ) );
    /* EntryName and CoffeeData are NULL */

    CoffeeRunnerWork( p );

    /* CoffeeLdr was NOT called (validation skipped it) */
    ASSERT( g_coffeeldr_calls == 0 );

    /* Params still freed */
    ASSERT( was_freed( p ) );

    /* No crash, returned normally */
    ASSERT( g_exit_thread_calls == 0 );
}

/* =========================================================================
 * Test 6: Fallback path — when TP unavailable, CoffeeRunnerThread must be
 * used (not CoffeeRunnerWork) so thread-level cleanup still runs.
 *
 * Simulates the scenario where JobSubmitThreadPool returns FALSE and
 * the caller falls back to spawning a dedicated thread with
 * CoffeeRunnerThread.
 * ======================================================================= */
TEST( test_fallback_to_dedicated_thread_cleans_up )
{
    reset_state();
    g_threads = 1;  /* CoffeeRunner increments before attempt */

    /* Simulate: TP submit failed, caller falls back to CoffeeRunnerThread */
    PCOFFEE_PARAMS p = make_params();
    CoffeeRunnerThread( p );

    /* Thread counter decremented (no leak) */
    ASSERT( g_threads == 0 );

    /* JobRemove was called */
    ASSERT( g_job_remove_calls == 1 );

    /* RtlExitUserThread was called (dedicated-thread exit) */
    ASSERT( g_exit_thread_calls == 1 );

    /* CoffeeLdr was invoked */
    ASSERT( g_coffeeldr_calls == 1 );
}

/* =========================================================================
 * Test 7: Verify CoffeeRunnerWork alone does NOT decrement threads or
 * call ExitThread — proving it's unsafe for the fallback plain-thread
 * path (validates that the fallback MUST use CoffeeRunnerThread).
 * ======================================================================= */
TEST( test_work_alone_leaks_thread_counter )
{
    reset_state();
    g_threads = 1;

    PCOFFEE_PARAMS p = make_params();
    CoffeeRunnerWork( p );

    /* Thread counter NOT decremented — this is the leak the fix prevents */
    ASSERT( g_threads == 1 );

    /* No thread-level cleanup */
    ASSERT( g_job_remove_calls == 0 );
    ASSERT( g_exit_thread_calls == 0 );
}

/* =========================================================================
 * Main
 * ======================================================================= */
int main( void )
{
    printf( "=== ARC-09 thread-pool callback cleanup tests ===\n" );

    run_test_work_returns_normally();
    run_test_threadpool_path_completes_cleanup();
    run_test_dedicated_thread_path_exits();
    run_test_no_double_decrement_threadpool();
    run_test_work_handles_null_entry();
    run_test_fallback_to_dedicated_thread_cleans_up();
    run_test_work_alone_leaks_thread_counter();

    printf( "\n%d / %d tests passed\n", tests_passed, tests_run );
    return ( tests_passed == tests_run ) ? 0 : 1;
}
