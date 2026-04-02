#ifndef DEMON_DSTDIO_H
#define DEMON_DSTDIO_H

#include <Demon.h>

#define MemCopy         __builtin_memcpy
#define MemSet          __stosb
#define MemZero( p, l ) __stosb( p, 0, l )
#define NO_INLINE       __attribute__ ((noinline))

/* ARC-04: Sentinel header prepended to every MmHeapAlloc allocation.
 * During sleep the heap walk checks for this magic to selectively
 * encrypt only agent-owned blocks, leaving system/library allocations
 * (and the heap manager's own metadata) intact. */
#define HEAP_SENTINEL_MAGIC  ((UINT32)0xA4C4DE4D)
#define HEAP_SENTINEL_SIZE   8  /* sizeof(UINT32 magic) + 4 bytes padding for 8-byte alignment */

/// Check whether a heap block starts with the sentinel magic.
#define HEAP_HAS_SENTINEL( p ) \
    ( (p) != NULL && *( (UINT32*)(p) ) == HEAP_SENTINEL_MAGIC )

INT     StringCompareA( LPCSTR String1, LPCSTR String2 );
INT     StringCompareW( LPWSTR String1, LPWSTR String2 );
INT     StringNCompareW( LPWSTR String1, LPWSTR String2, INT Length );
INT     StringNCompareIW( LPWSTR String1, LPWSTR String2, INT Length );
PCHAR   StringCopyA( PCHAR String1, PCHAR String2 );
PWCHAR  StringCopyW(PWCHAR String1, PWCHAR String2);
SIZE_T  StringLengthA( LPCSTR String );
SIZE_T  StringLengthW( LPCWSTR String );
PCHAR   StringConcatA(PCHAR String, PCHAR String2);
PWCHAR  StringConcatW(PWCHAR String, PWCHAR String2);
PCHAR   StringTokenA(PCHAR String, CONST PCHAR Delim);
LPWSTR  WcsStr( PWCHAR String, PWCHAR String2 );
LPWSTR  WcsIStr( PWCHAR String, PWCHAR String2 );
INT     MemCompare( PVOID s1, PVOID s2, INT len );
UINT64  GetSystemFileTime( );
BYTE    HideChar( BYTE C );

SIZE_T  WCharStringToCharString( PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed );
SIZE_T  CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );

#endif
