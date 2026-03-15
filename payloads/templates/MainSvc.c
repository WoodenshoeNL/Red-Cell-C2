/**
 * @file MainSvc.c
 * @brief Windows Service EXE entry point template for the Demon agent.
 *
 * This template is compiled as the Windows Service Exe payload format.
 * It registers a service control dispatcher, then starts the Demon agent
 * inside the service's main function via DemonMain().
 *
 * The builder injects the following preprocessor defines at compile time:
 *   MAIN_THREADED  - Demon is started on the current thread (not a new one)
 *   SVC_EXE        - Activates service-specific code paths inside the agent
 *   SERVICE_NAME   - Wide string name passed to the SCM dispatcher table
 *
 * Compile flags (MinGW cross-compiler):
 *   -mwindows -ladvapi32 -lntdll
 *   -e WinMain  (x64)  or  -e _WinMain  (x86)
 */

#include <Demon.h>

/* Service handle and status shared between SvcMain and SrvCtrlHandler. */
SERVICE_STATUS_HANDLE StatusHandle = { 0 };
SERVICE_STATUS        SvcStatus    = {
    .dwServiceType      = SERVICE_WIN32,
    .dwCurrentState     = SERVICE_START_PENDING,
    .dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
};

/* Forward declarations. */
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR* Argv );
VOID WINAPI SrvCtrlHandler( DWORD CtrlCode );

/**
 * WinMain — entry point called by the Windows loader.
 *
 * Registers the service dispatch table with the SCM so that the process can
 * run as a Windows service.  The SCM then calls SvcMain on its own thread.
 */
INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    SERVICE_TABLE_ENTRY DispatchTable[] = {
        { SERVICE_NAME, SvcMain },
        { NULL,         NULL    },
    };

    StartServiceCtrlDispatcherA( DispatchTable );
    return 0;
}

/**
 * SvcMain — called by the SCM after the dispatcher table is registered.
 *
 * Registers the control handler so that stop/shutdown signals can be
 * processed, then calls DemonMain() to start the agent on this thread.
 */
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR* Argv )
{
    StatusHandle = RegisterServiceCtrlHandlerA( SERVICE_NAME, SrvCtrlHandler );
    if ( !StatusHandle )
        return;

    DemonMain( NULL, NULL );
}

/**
 * SrvCtrlHandler — handles SERVICE_CONTROL_STOP and SERVICE_CONTROL_SHUTDOWN.
 *
 * Any stop/shutdown code causes the service to report itself as stopped so
 * that the SCM can clean up the process.
 */
VOID WINAPI SrvCtrlHandler( DWORD CtrlCode )
{
    if ( CtrlCode == SERVICE_CONTROL_STOP || CtrlCode == SERVICE_CONTROL_SHUTDOWN )
    {
        SvcStatus.dwWin32ExitCode = 0;
        SvcStatus.dwCurrentState  = SERVICE_STOPPED;
        SetServiceStatus( StatusHandle, &SvcStatus );
    }
}
