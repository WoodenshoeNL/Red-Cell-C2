/*
 * test_heap_enc.c — Unit tests for ARC-04 heap encryption primitives.
 *
 * Covers:
 *   1. Sentinel header constants and alignment.
 *   2. HEAP_HAS_SENTINEL macro correctness.
 *   3. HeapXorBlock round-trip (encrypt → decrypt recovers plaintext).
 *   4. HeapXorBlock with varying key lengths.
 *   5. Sentinel-filtered XOR: tagged blocks are encrypted, untagged are not.
 *   6. Zero-length and edge-case blocks.
 *
 * Build and run:
 *   cd agent/archon/tests && make && ./test_heap_enc
 *
 * Compiled for Linux with GCC — no mingw / windows.h required.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Portable type aliases (mirror windows.h names used by Archon source)
 * ---------------------------------------------------------------------- */
typedef uint8_t   UINT8;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef size_t    SIZE_T;
typedef unsigned long ULONG;
typedef uint8_t  *PUCHAR;
typedef void      VOID;

/* -------------------------------------------------------------------------
 * Reproduce the sentinel constants from MiniStd.h
 * ---------------------------------------------------------------------- */
#define HEAP_SENTINEL_MAGIC  ((UINT32)0xA4C4DE4D)
#define HEAP_SENTINEL_SIZE   8

#define HEAP_HAS_SENTINEL( p ) \
    ( (p) != NULL && *( (UINT32*)(p) ) == HEAP_SENTINEL_MAGIC )

/* -------------------------------------------------------------------------
 * HeapXorBlock — copied from Obf.c (portable, no Instance dependency)
 * ---------------------------------------------------------------------- */
static VOID HeapXorBlock(
    PUCHAR Data,
    SIZE_T Size,
    PUCHAR Key,
    ULONG  KeyLen
) {
    for ( SIZE_T i = 0; i < Size; i++ ) {
        Data[ i ] ^= Key[ i % KeyLen ];
    }
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
    } while(0)

#define ASSERT_EQ( a, b ) \
    do { \
        if ( (a) != (b) ) { \
            printf( "  FAIL  %s:%d: %s == %llu, expected %llu\n", \
                    __FILE__, __LINE__, #a, \
                    (unsigned long long)(a), (unsigned long long)(b) ); \
            exit(1); \
        } \
    } while(0)

#define ASSERT_MEM_EQ( a, b, len ) \
    do { \
        if ( memcmp( (a), (b), (len) ) != 0 ) { \
            printf( "  FAIL  %s:%d: memcmp(%s, %s, %zu) != 0\n", \
                    __FILE__, __LINE__, #a, #b, (size_t)(len) ); \
            exit(1); \
        } \
    } while(0)

/* =========================================================================
 * Tests
 * ====================================================================== */

TEST( sentinel_constants_alignment )
{
    /* Sentinel size must be a multiple of the maximum fundamental alignment
     * so that user data past the sentinel remains properly aligned. */
    ASSERT( HEAP_SENTINEL_SIZE >= sizeof( UINT32 ) );
    ASSERT_EQ( HEAP_SENTINEL_SIZE % 4, 0 );
    ASSERT_EQ( HEAP_SENTINEL_SIZE, 8 );
}

TEST( heap_has_sentinel_positive )
{
    /* A buffer starting with the sentinel magic should match. */
    UINT8 buf[ 16 ];
    memset( buf, 0, sizeof( buf ) );
    *( (UINT32*) buf ) = HEAP_SENTINEL_MAGIC;
    ASSERT( HEAP_HAS_SENTINEL( buf ) );
}

TEST( heap_has_sentinel_negative )
{
    /* A buffer that does NOT start with the sentinel should not match. */
    UINT8 buf[ 16 ];
    memset( buf, 0xFF, sizeof( buf ) );
    ASSERT( ! HEAP_HAS_SENTINEL( buf ) );
}

TEST( heap_has_sentinel_null )
{
    ASSERT( ! HEAP_HAS_SENTINEL( NULL ) );
}

TEST( xor_block_roundtrip )
{
    /* Encrypt then decrypt with the same key should recover the plaintext. */
    UINT8 plain[] = "Hello, heap encryption!";
    UINT8 backup[ sizeof( plain ) ];
    UINT8 key[]   = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                      0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };

    memcpy( backup, plain, sizeof( plain ) );

    /* encrypt */
    HeapXorBlock( plain, sizeof( plain ), key, sizeof( key ) );

    /* ciphertext must differ from plaintext (statistically guaranteed
     * for any non-zero key and non-trivial data). */
    ASSERT( memcmp( plain, backup, sizeof( plain ) ) != 0 );

    /* decrypt (XOR is its own inverse) */
    HeapXorBlock( plain, sizeof( plain ), key, sizeof( key ) );
    ASSERT_MEM_EQ( plain, backup, sizeof( plain ) );
}

TEST( xor_block_short_key )
{
    /* Test with a 1-byte key — exercises the modulo wrapping. */
    UINT8 data[] = { 0x41, 0x42, 0x43, 0x44 };
    UINT8 orig[ sizeof( data ) ];
    UINT8 key   = 0xFF;

    memcpy( orig, data, sizeof( data ) );
    HeapXorBlock( data, sizeof( data ), &key, 1 );

    /* Each byte should be XOR'd with 0xFF */
    ASSERT_EQ( data[0], 0x41 ^ 0xFF );
    ASSERT_EQ( data[1], 0x42 ^ 0xFF );
    ASSERT_EQ( data[2], 0x43 ^ 0xFF );
    ASSERT_EQ( data[3], 0x44 ^ 0xFF );

    /* Round-trip */
    HeapXorBlock( data, sizeof( data ), &key, 1 );
    ASSERT_MEM_EQ( data, orig, sizeof( data ) );
}

TEST( xor_block_zero_length )
{
    /* Zero-length encrypt should be a no-op. */
    UINT8 data[] = { 0xAA, 0xBB };
    UINT8 orig[ sizeof( data ) ];
    UINT8 key[]  = { 0xFF };

    memcpy( orig, data, sizeof( data ) );
    HeapXorBlock( data, 0, key, sizeof( key ) );
    ASSERT_MEM_EQ( data, orig, sizeof( data ) );
}

TEST( sentinel_tagged_block_encrypted )
{
    /* Simulate a sentinel-tagged heap block:
     *   [ SENTINEL_MAGIC (4 bytes) | padding (4 bytes) | user data ... ]
     *
     * The encrypt routine should only XOR the user-data portion. */
    const SIZE_T user_size = 32;
    const SIZE_T total_size = HEAP_SENTINEL_SIZE + user_size;
    UINT8 block[ HEAP_SENTINEL_SIZE + 32 ];
    UINT8 user_backup[ 32 ];
    UINT8 key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

    /* Set up the sentinel header */
    memset( block, 0, total_size );
    *( (UINT32*) block ) = HEAP_SENTINEL_MAGIC;

    /* Fill user data with recognizable pattern */
    for ( SIZE_T i = 0; i < user_size; i++ ) {
        block[ HEAP_SENTINEL_SIZE + i ] = (UINT8)( i + 1 );
    }
    memcpy( user_backup, block + HEAP_SENTINEL_SIZE, user_size );

    /* Verify sentinel is detected */
    ASSERT( HEAP_HAS_SENTINEL( block ) );

    /* Simulate what HeapEncryptDecrypt does: only encrypt past sentinel */
    HeapXorBlock(
        block + HEAP_SENTINEL_SIZE,
        user_size,
        key,
        sizeof( key )
    );

    /* Sentinel bytes must be unchanged */
    ASSERT_EQ( *( (UINT32*) block ), HEAP_SENTINEL_MAGIC );

    /* User data must be different (encrypted) */
    ASSERT( memcmp( block + HEAP_SENTINEL_SIZE, user_backup, user_size ) != 0 );

    /* Sentinel must still be detectable after encryption */
    ASSERT( HEAP_HAS_SENTINEL( block ) );

    /* Decrypt and verify round-trip */
    HeapXorBlock(
        block + HEAP_SENTINEL_SIZE,
        user_size,
        key,
        sizeof( key )
    );
    ASSERT_MEM_EQ( block + HEAP_SENTINEL_SIZE, user_backup, user_size );
}

TEST( untagged_block_not_encrypted )
{
    /* A block without the sentinel magic should be skipped by the
     * filtering logic.  Simulate the check. */
    UINT8 block[ 40 ];
    UINT8 backup[ 40 ];
    UINT8 key[] = { 0xAA, 0xBB, 0xCC, 0xDD };

    memset( block, 0x42, sizeof( block ) );
    memcpy( backup, block, sizeof( block ) );

    /* Simulate the sentinel check from HeapEncryptDecrypt */
    SIZE_T data_size = sizeof( block );
    if ( data_size > HEAP_SENTINEL_SIZE && HEAP_HAS_SENTINEL( block ) ) {
        HeapXorBlock(
            block + HEAP_SENTINEL_SIZE,
            data_size - HEAP_SENTINEL_SIZE,
            key,
            sizeof( key )
        );
    }

    /* Block should be unchanged — no sentinel, no encryption */
    ASSERT_MEM_EQ( block, backup, sizeof( block ) );
}

TEST( sentinel_alloc_layout )
{
    /* Verify the layout: raw alloc has sentinel at offset 0,
     * user pointer is at raw + HEAP_SENTINEL_SIZE. */
    UINT8 raw_block[ HEAP_SENTINEL_SIZE + 64 ];
    memset( raw_block, 0, sizeof( raw_block ) );

    /* Simulate MmHeapAlloc: write sentinel, return offset pointer */
    *( (UINT32*) raw_block ) = HEAP_SENTINEL_MAGIC;
    UINT8 *user_ptr = raw_block + HEAP_SENTINEL_SIZE;

    /* Write some data to user area */
    memset( user_ptr, 0xAB, 64 );

    /* Verify sentinel is intact */
    ASSERT( HEAP_HAS_SENTINEL( raw_block ) );

    /* Verify user pointer offset */
    ASSERT_EQ( (SIZE_T)( user_ptr - raw_block ), (SIZE_T) HEAP_SENTINEL_SIZE );

    /* Simulate MmHeapFree: recover raw pointer */
    UINT8 *recovered_raw = user_ptr - HEAP_SENTINEL_SIZE;
    ASSERT( recovered_raw == raw_block );
    ASSERT_EQ( *( (UINT32*) recovered_raw ), HEAP_SENTINEL_MAGIC );
}

TEST( xor_block_large_buffer )
{
    /* Stress test with a larger buffer to catch off-by-one errors. */
    const SIZE_T size = 4096;
    UINT8 *data = malloc( size );
    UINT8 *orig = malloc( size );
    UINT8 key[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };

    ASSERT( data != NULL );
    ASSERT( orig != NULL );

    for ( SIZE_T i = 0; i < size; i++ ) {
        data[i] = (UINT8)( i & 0xFF );
    }
    memcpy( orig, data, size );

    HeapXorBlock( data, size, key, sizeof( key ) );
    ASSERT( memcmp( data, orig, size ) != 0 );

    HeapXorBlock( data, size, key, sizeof( key ) );
    ASSERT_MEM_EQ( data, orig, size );

    free( data );
    free( orig );
}

/* =========================================================================
 * Runner
 * ====================================================================== */

int main( void )
{
    printf( "=== test_heap_enc ===\n" );

    run_sentinel_constants_alignment();
    run_heap_has_sentinel_positive();
    run_heap_has_sentinel_negative();
    run_heap_has_sentinel_null();
    run_xor_block_roundtrip();
    run_xor_block_short_key();
    run_xor_block_zero_length();
    run_sentinel_tagged_block_encrypted();
    run_untagged_block_not_encrypted();
    run_sentinel_alloc_layout();
    run_xor_block_large_buffer();

    printf( "\n%d/%d tests passed.\n", tests_passed, tests_run );
    return ( tests_passed == tests_run ) ? 0 : 1;
}
