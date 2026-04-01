/*
 * test_crypto.c — Unit tests for Archon crypto primitives.
 *
 * Covers:
 *   1. AdvanceIvByBlocks: zero-advance, single-block, multi-block (known
 *      vector), 64-bit low-half wraparound (carry propagation), full
 *      128-bit overflow.
 *   2. AES-256-CTR encrypt/decrypt round-trip at offset 0 and at offset N.
 *   3. Monotonic-CTR offset continuity: back-to-back packets produce
 *      non-overlapping keystream regions and plaintext is fully recovered.
 *
 * Build and run:
 *   cd agent/archon/tests && make
 *
 * This file is compiled for Linux with GCC using portable stdint types —
 * no mingw / windows.h required.
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
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef size_t    SIZE_T;
typedef uint8_t  *PUINT8;
typedef void      VOID;

/* -------------------------------------------------------------------------
 * Minimal AES-256-CTR implementation
 * Copied verbatim from agent/archon/src/crypt/AesCrypt.c with Windows
 * types replaced by the portable aliases defined above, and __builtin_memcpy
 * replaced by the standard memcpy.
 * ---------------------------------------------------------------------- */
#define AES_BLOCKLEN    16
#define AES_KEYLEN      32
#define AES_keyExpSize  240

#define CTR    1
#define AES256 1

typedef struct {
    UINT8 RoundKey[AES_keyExpSize];
    UINT8 Iv[AES_BLOCKLEN];
} AESCTX, *PAESCTX;

#define Nb 4

#if defined(AES256) && (AES256 == 1)
# define Nk 8
# define Nr 14
#endif

typedef UINT8 state_t[4][4];

static const UINT8 sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const UINT8 Rcon[11] = {
    0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

#define getSBoxValue(num) (sbox[(num)])

static void KeyExpansion(UINT8 *RoundKey, const UINT8 *Key)
{
    unsigned i, j, k;
    UINT8 tempa[4];

    for (i = 0; i < Nk; ++i) {
        RoundKey[(i*4)+0] = Key[(i*4)+0];
        RoundKey[(i*4)+1] = Key[(i*4)+1];
        RoundKey[(i*4)+2] = Key[(i*4)+2];
        RoundKey[(i*4)+3] = Key[(i*4)+3];
    }
    for (i = Nk; i < Nb*(Nr+1); ++i) {
        k = (i-1)*4;
        tempa[0]=RoundKey[k+0]; tempa[1]=RoundKey[k+1];
        tempa[2]=RoundKey[k+2]; tempa[3]=RoundKey[k+3];
        if (i % Nk == 0) {
            UINT8 u8tmp = tempa[0];
            tempa[0]=tempa[1]; tempa[1]=tempa[2];
            tempa[2]=tempa[3]; tempa[3]=u8tmp;
            tempa[0]=getSBoxValue(tempa[0]); tempa[1]=getSBoxValue(tempa[1]);
            tempa[2]=getSBoxValue(tempa[2]); tempa[3]=getSBoxValue(tempa[3]);
            tempa[0] ^= Rcon[i/Nk];
        }
        if (i % Nk == 4) {
            tempa[0]=getSBoxValue(tempa[0]); tempa[1]=getSBoxValue(tempa[1]);
            tempa[2]=getSBoxValue(tempa[2]); tempa[3]=getSBoxValue(tempa[3]);
        }
        j = i*4; k = (i-Nk)*4;
        RoundKey[j+0]=RoundKey[k+0]^tempa[0]; RoundKey[j+1]=RoundKey[k+1]^tempa[1];
        RoundKey[j+2]=RoundKey[k+2]^tempa[2]; RoundKey[j+3]=RoundKey[k+3]^tempa[3];
    }
}

static void AddRoundKey(UINT8 round, state_t *state, const UINT8 *RoundKey)
{
    UINT8 i, j;
    for (i=0; i<4; ++i)
        for (j=0; j<4; ++j)
            (*state)[i][j] ^= RoundKey[(round*Nb*4)+(i*Nb)+j];
}

static void SubBytes(state_t *state)
{
    UINT8 i, j;
    for (i=0; i<4; ++i)
        for (j=0; j<4; ++j)
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
}

static void ShiftRows(state_t *state)
{
    UINT8 temp;
    temp=(*state)[0][1]; (*state)[0][1]=(*state)[1][1]; (*state)[1][1]=(*state)[2][1];
    (*state)[2][1]=(*state)[3][1]; (*state)[3][1]=temp;
    temp=(*state)[0][2]; (*state)[0][2]=(*state)[2][2]; (*state)[2][2]=temp;
    temp=(*state)[1][2]; (*state)[1][2]=(*state)[3][2]; (*state)[3][2]=temp;
    temp=(*state)[0][3]; (*state)[0][3]=(*state)[3][3]; (*state)[3][3]=(*state)[2][3];
    (*state)[2][3]=(*state)[1][3]; (*state)[1][3]=temp;
}

static UINT8 xtime(UINT8 x) { return (UINT8)((x<<1)^(((x>>7)&1)*0x1b)); }

static void MixColumns(state_t *state)
{
    UINT8 i, Tmp, Tm, t;
    for (i=0; i<4; ++i) {
        t  =(*state)[i][0];
        Tmp=(*state)[i][0]^(*state)[i][1]^(*state)[i][2]^(*state)[i][3];
        Tm=(*state)[i][0]^(*state)[i][1]; Tm=xtime(Tm); (*state)[i][0]^=Tm^Tmp;
        Tm=(*state)[i][1]^(*state)[i][2]; Tm=xtime(Tm); (*state)[i][1]^=Tm^Tmp;
        Tm=(*state)[i][2]^(*state)[i][3]; Tm=xtime(Tm); (*state)[i][2]^=Tm^Tmp;
        Tm=(*state)[i][3]^t;              Tm=xtime(Tm); (*state)[i][3]^=Tm^Tmp;
    }
}

static void Cipher(state_t *state, const UINT8 *RoundKey)
{
    UINT8 round;
    AddRoundKey(0, state, RoundKey);
    for (round=1; ; ++round) {
        SubBytes(state); ShiftRows(state);
        if (round == Nr) break;
        MixColumns(state); AddRoundKey(round, state, RoundKey);
    }
    AddRoundKey(Nr, state, RoundKey);
}

static void AesInit(PAESCTX ctx, const PUINT8 key, const PUINT8 iv)
{
    KeyExpansion(ctx->RoundKey, key);
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

static void AesXCryptBuffer(PAESCTX ctx, PUINT8 buf, SIZE_T length)
{
    UINT8 buffer[AES_BLOCKLEN];
    size_t i;
    int bi;
    for (i=0, bi=AES_BLOCKLEN; i<length; ++i, ++bi) {
        if (bi == AES_BLOCKLEN) {
            memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((state_t *)buffer, ctx->RoundKey);
            for (bi=(AES_BLOCKLEN-1); bi>=0; --bi) {
                if (ctx->Iv[bi] == 255) { ctx->Iv[bi]=0; continue; }
                ctx->Iv[bi] += 1; break;
            }
            bi = 0;
        }
        buf[i] ^= buffer[bi];
    }
}

/* -------------------------------------------------------------------------
 * AdvanceIvByBlocks
 * Copied verbatim from agent/archon/src/core/Package.c (static function).
 * Adding this non-static wrapper here allows direct testing without
 * modifying the production source.
 * ---------------------------------------------------------------------- */
static void AdvanceIvByBlocks(PUINT8 Iv, UINT64 Blocks)
{
    UINT64 Lo, Hi, NewLo;

    if (Blocks == 0)
        return;

    Lo = ((UINT64)Iv[ 8]<<56)|((UINT64)Iv[ 9]<<48)|
         ((UINT64)Iv[10]<<40)|((UINT64)Iv[11]<<32)|
         ((UINT64)Iv[12]<<24)|((UINT64)Iv[13]<<16)|
         ((UINT64)Iv[14]<< 8)|((UINT64)Iv[15]    );
    Hi = ((UINT64)Iv[ 0]<<56)|((UINT64)Iv[ 1]<<48)|
         ((UINT64)Iv[ 2]<<40)|((UINT64)Iv[ 3]<<32)|
         ((UINT64)Iv[ 4]<<24)|((UINT64)Iv[ 5]<<16)|
         ((UINT64)Iv[ 6]<< 8)|((UINT64)Iv[ 7]    );

    NewLo = Lo + Blocks;
    if (NewLo < Lo)
        Hi++;

    Iv[ 0]=(UINT8)(Hi   >>56); Iv[ 1]=(UINT8)(Hi   >>48);
    Iv[ 2]=(UINT8)(Hi   >>40); Iv[ 3]=(UINT8)(Hi   >>32);
    Iv[ 4]=(UINT8)(Hi   >>24); Iv[ 5]=(UINT8)(Hi   >>16);
    Iv[ 6]=(UINT8)(Hi   >> 8); Iv[ 7]=(UINT8)(Hi       );
    Iv[ 8]=(UINT8)(NewLo>>56); Iv[ 9]=(UINT8)(NewLo>>48);
    Iv[10]=(UINT8)(NewLo>>40); Iv[11]=(UINT8)(NewLo>>32);
    Iv[12]=(UINT8)(NewLo>>24); Iv[13]=(UINT8)(NewLo>>16);
    Iv[14]=(UINT8)(NewLo>> 8); Iv[15]=(UINT8)(NewLo    );
}

/* -------------------------------------------------------------------------
 * Test framework
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

static void print_iv(const char *label, const UINT8 *iv)
{
    printf("        %s: ", label);
    for (int i = 0; i < 16; i++) printf("%02x", iv[i]);
    printf("\n");
}

/* -------------------------------------------------------------------------
 * Section 1: AdvanceIvByBlocks
 * ---------------------------------------------------------------------- */
static void test_advance_iv_by_blocks(void)
{
    printf("\n=== AdvanceIvByBlocks ===\n");

    /* 1a. Zero advance — IV must be unchanged */
    {
        UINT8 iv[16] = {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
        };
        UINT8 orig[16];
        memcpy(orig, iv, 16);
        AdvanceIvByBlocks(iv, 0);
        check("zero-advance is no-op", memcmp(iv, orig, 16) == 0);
    }

    /* 1b. Single-block advance (+1) on all-zero IV → bytes 8-15 become 0..001 */
    {
        UINT8 iv[16] = { 0 };
        UINT8 expect[16] = { 0 };
        expect[15] = 0x01;
        AdvanceIvByBlocks(iv, 1);
        check("single-block: all-zero IV becomes ...0001", memcmp(iv, expect, 16) == 0);
    }

    /* 1c. Multi-block known-vector: IV = 0, advance by 0x0102030405060708
     *     Expected Lo half = 0x0102030405060708, Hi half = 0 */
    {
        UINT8 iv[16] = { 0 };
        UINT8 expect[16] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  /* Hi */
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08   /* Lo */
        };
        AdvanceIvByBlocks(iv, (UINT64)0x0102030405060708ULL);
        check("multi-block known-vector", memcmp(iv, expect, 16) == 0);
    }

    /* 1d. Carry propagation: Lo = UINT64_MAX, advance by 1
     *     Lo wraps to 0, Hi increments by 1. */
    {
        /* Start: Hi=0x0000000000000001, Lo=0xffffffffffffffff */
        UINT8 iv[16] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,  /* Hi = 1 */
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff   /* Lo = UINT64_MAX */
        };
        /* After +1: Lo wraps to 0, Hi becomes 2 */
        UINT8 expect[16] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,  /* Hi = 2 */
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00   /* Lo = 0 */
        };
        AdvanceIvByBlocks(iv, 1);
        if (memcmp(iv, expect, 16) != 0) {
            print_iv("got   ", iv);
            print_iv("expect", expect);
        }
        check("carry: Lo=UINT64_MAX + 1 propagates to Hi", memcmp(iv, expect, 16) == 0);
    }

    /* 1e. Full 128-bit overflow: Hi=UINT64_MAX, Lo=UINT64_MAX, advance by 1 → all zeros */
    {
        UINT8 iv[16] = {
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
        };
        UINT8 expect[16] = { 0 };
        AdvanceIvByBlocks(iv, 1);
        check("full-128-bit overflow wraps to zero", memcmp(iv, expect, 16) == 0);
    }

    /* 1f. AdvanceIvByBlocks N times matches AesXCryptBuffer's IV advancement.
     *
     * AesXCryptBuffer increments ctx->Iv by 1 (big-endian, from byte 15) for
     * each block it processes.  Advancing by N via AdvanceIvByBlocks must put
     * the IV into the same state as processing N×16 zero bytes would. */
    {
        const UINT64 N = 5;
        /* Non-const: AesInit takes PUINT8 (uint8_t * const), not const uint8_t * */
        UINT8 key1f[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        UINT8 base_iv1f[16] = {
            0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
            0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
        };

        /* Advance via AesXCryptBuffer: encrypt N*16 bytes to consume N blocks */
        AESCTX ctx;
        UINT8 dummy[80] = { 0 };  /* N * AES_BLOCKLEN */
        AesInit(&ctx, key1f, base_iv1f);
        AesXCryptBuffer(&ctx, dummy, N * AES_BLOCKLEN);
        UINT8 iv_after_encrypt[16];
        memcpy(iv_after_encrypt, ctx.Iv, 16);

        /* Advance via AdvanceIvByBlocks */
        UINT8 iv_advanced[16];
        memcpy(iv_advanced, base_iv1f, 16);
        AdvanceIvByBlocks(iv_advanced, N);

        if (memcmp(iv_after_encrypt, iv_advanced, 16) != 0) {
            print_iv("encrypt-driven", iv_after_encrypt);
            print_iv("AdvanceIvByBlk ", iv_advanced);
        }
        check("AdvanceIvByBlocks(N) matches AesXCryptBuffer block advancement",
              memcmp(iv_after_encrypt, iv_advanced, 16) == 0);
    }
}

/* -------------------------------------------------------------------------
 * Section 2: AES-256-CTR encrypt / decrypt round-trip
 * ---------------------------------------------------------------------- */
static void test_aes_roundtrip(void)
{
    printf("\n=== AES-256-CTR round-trip ===\n");

    /* Non-const so they can be passed to AesInit (which takes PUINT8 = uint8_t * const) */
    UINT8 key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    UINT8 base_iv[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };

    /* 2a. Round-trip at offset 0 (17 bytes — crosses a block boundary) */
    {
        UINT8 plaintext[17] = "Hello, Red Cell!";
        UINT8 buf[17];
        UINT8 recovered[17];
        AESCTX enc, dec;

        memcpy(buf, plaintext, 17);
        AesInit(&enc, key, base_iv);
        AesXCryptBuffer(&enc, buf, 17);           /* encrypt */

        /* Must have changed at least one byte */
        check("offset-0: ciphertext differs from plaintext",
              memcmp(buf, plaintext, 17) != 0);

        memcpy(recovered, buf, 17);
        AesInit(&dec, key, base_iv);
        AesXCryptBuffer(&dec, recovered, 17);     /* decrypt */

        check("offset-0: decrypt recovers plaintext",
              memcmp(recovered, plaintext, 17) == 0);
    }

    /* 2b. Round-trip at offset N (skip first K blocks by seeking with
     *     AdvanceIvByBlocks before encrypting) */
    {
        const UINT64 skip_blocks = 7;
        UINT8 plaintext[32];
        for (size_t i = 0; i < 32; i++) plaintext[i] = (UINT8)(i * 3 + 0xab);

        UINT8 buf[32];
        UINT8 recovered[32];
        UINT8 enc_iv[16], dec_iv[16];
        AESCTX enc, dec;

        memcpy(enc_iv, base_iv, 16);
        AdvanceIvByBlocks(enc_iv, skip_blocks);
        AesInit(&enc, key, enc_iv);
        memcpy(buf, plaintext, 32);
        AesXCryptBuffer(&enc, buf, 32);

        check("offset-N: ciphertext differs from plaintext",
              memcmp(buf, plaintext, 32) != 0);

        memcpy(dec_iv, base_iv, 16);
        AdvanceIvByBlocks(dec_iv, skip_blocks);
        AesInit(&dec, key, dec_iv);
        memcpy(recovered, buf, 32);
        AesXCryptBuffer(&dec, recovered, 32);

        check("offset-N: decrypt at same offset recovers plaintext",
              memcmp(recovered, plaintext, 32) == 0);
    }

    /* 2c. Decrypt at wrong offset does NOT recover plaintext */
    {
        const UINT64 enc_offset = 3;
        const UINT64 dec_offset = 4;   /* deliberately off by one block */
        UINT8 plaintext[16] = { 0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe,
                                 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
        UINT8 buf[16];
        UINT8 bad_dec[16];
        UINT8 iv_enc[16], iv_dec[16];
        AESCTX enc, dec;

        memcpy(iv_enc, base_iv, 16);
        AdvanceIvByBlocks(iv_enc, enc_offset);
        AesInit(&enc, key, iv_enc);
        memcpy(buf, plaintext, 16);
        AesXCryptBuffer(&enc, buf, 16);

        memcpy(iv_dec, base_iv, 16);
        AdvanceIvByBlocks(iv_dec, dec_offset);
        AesInit(&dec, key, iv_dec);
        memcpy(bad_dec, buf, 16);
        AesXCryptBuffer(&dec, bad_dec, 16);

        check("wrong-offset decrypt does NOT recover plaintext",
              memcmp(bad_dec, plaintext, 16) != 0);
    }
}

/* -------------------------------------------------------------------------
 * Section 3: Monotonic CTR offset continuity
 * ---------------------------------------------------------------------- */
static void test_monotonic_ctr(void)
{
    printf("\n=== Monotonic CTR offset continuity ===\n");

    /* Non-const so they can be passed to AesInit (which takes PUINT8 = uint8_t * const) */
    UINT8 key[32] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
        0x76,0x2e,0x71,0x60,0xf3,0x8b,0x4d,0xa5,
        0x6a,0x78,0x4d,0x90,0x45,0x19,0x0c,0xfe
    };
    UINT8 base_iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    /* Simulate two sequential "packets":
     *   Packet 1: 48 bytes (3 blocks) at CtrBlockOffset = 0
     *   Packet 2: 32 bytes (2 blocks) at CtrBlockOffset = 3 */

    const SIZE_T pkt1_len = 48;
    const SIZE_T pkt2_len = 32;
    const UINT64 pkt1_blocks = (pkt1_len + AES_BLOCKLEN - 1) / AES_BLOCKLEN;  /* 3 */
    const UINT64 pkt2_offset = pkt1_blocks;                                    /* 3 */

    UINT8 pkt1_plain[48], pkt2_plain[32];
    for (size_t i = 0; i < 48; i++) pkt1_plain[i] = (UINT8)(i + 0x10);
    for (size_t i = 0; i < 32; i++) pkt2_plain[i] = (UINT8)(i + 0x40);

    /* --- Encrypt both packets --- */
    UINT8 pkt1_enc[48], pkt2_enc[32];
    memcpy(pkt1_enc, pkt1_plain, 48);
    memcpy(pkt2_enc, pkt2_plain, 32);

    UINT8 iv1[16], iv2[16];
    memcpy(iv1, base_iv, 16);
    AdvanceIvByBlocks(iv1, 0);              /* packet 1: offset 0 */
    AESCTX ctx1;
    AesInit(&ctx1, key, iv1);
    AesXCryptBuffer(&ctx1, pkt1_enc, pkt1_len);

    memcpy(iv2, base_iv, 16);
    AdvanceIvByBlocks(iv2, pkt2_offset);    /* packet 2: offset 3 */
    AESCTX ctx2;
    AesInit(&ctx2, key, iv2);
    AesXCryptBuffer(&ctx2, pkt2_enc, pkt2_len);

    /* 3a. Ciphertext regions are not identical to plaintext */
    check("pkt1: ciphertext differs from plaintext",
          memcmp(pkt1_enc, pkt1_plain, 48) != 0);
    check("pkt2: ciphertext differs from plaintext",
          memcmp(pkt2_enc, pkt2_plain, 32) != 0);

    /* 3b. Packets use non-overlapping keystream: XOR of the two ciphertexts
     *     does not equal the XOR of the two plaintexts (which would happen if
     *     the same keystream block were reused). */
    {
        /* Compare the first 32 bytes of pkt1 keystream vs all of pkt2 keystream.
         * keystream_pkt1[i] = pkt1_enc[i] ^ pkt1_plain[i]
         * keystream_pkt2[i] = pkt2_enc[i] ^ pkt2_plain[i]
         * They must differ (different keystream blocks were used). */
        UINT8 ks1[32], ks2[32];
        for (size_t i = 0; i < 32; i++) ks1[i] = pkt1_enc[i] ^ pkt1_plain[i];
        for (size_t i = 0; i < 32; i++) ks2[i] = pkt2_enc[i] ^ pkt2_plain[i];
        check("pkt1 and pkt2 use non-overlapping keystream regions",
              memcmp(ks1, ks2, 32) != 0);
    }

    /* 3c. Decrypt packet 1 at offset 0 recovers plaintext */
    {
        UINT8 iv_dec[16], buf[48];
        AESCTX dec;
        memcpy(iv_dec, base_iv, 16);
        AdvanceIvByBlocks(iv_dec, 0);
        AesInit(&dec, key, iv_dec);
        memcpy(buf, pkt1_enc, 48);
        AesXCryptBuffer(&dec, buf, 48);
        check("pkt1: decrypt at offset 0 recovers plaintext",
              memcmp(buf, pkt1_plain, 48) == 0);
    }

    /* 3d. Decrypt packet 2 at offset pkt2_offset recovers plaintext */
    {
        UINT8 iv_dec[16], buf[32];
        AESCTX dec;
        memcpy(iv_dec, base_iv, 16);
        AdvanceIvByBlocks(iv_dec, pkt2_offset);
        AesInit(&dec, key, iv_dec);
        memcpy(buf, pkt2_enc, 32);
        AesXCryptBuffer(&dec, buf, 32);
        check("pkt2: decrypt at offset 3 recovers plaintext",
              memcmp(buf, pkt2_plain, 32) == 0);
    }

    /* 3e. Block-offset arithmetic: pkt1_blocks == (pkt1_len + 15) / 16 */
    check("CtrBlockOffset advance is ceil(len/16)",
          pkt1_blocks == 3 && pkt2_offset == 3);

    /* 3f. Decrypting pkt2 at offset 0 (wrong) does NOT recover plaintext */
    {
        UINT8 iv_bad[16], buf[32];
        AESCTX dec;
        memcpy(iv_bad, base_iv, 16);
        /* intentionally use offset 0 instead of pkt2_offset */
        AesInit(&dec, key, iv_bad);
        memcpy(buf, pkt2_enc, 32);
        AesXCryptBuffer(&dec, buf, 32);
        check("pkt2: wrong-offset decrypt does NOT recover plaintext",
              memcmp(buf, pkt2_plain, 32) != 0);
    }
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(void)
{
    printf("Archon crypto unit tests\n");

    test_advance_iv_by_blocks();
    test_aes_roundtrip();
    test_monotonic_ctr();

    printf("\n--- Results: %d passed, %d failed ---\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
