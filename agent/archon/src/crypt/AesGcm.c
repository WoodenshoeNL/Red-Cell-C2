/*
 * AesGcm.c — AES-256-GCM authenticated encryption for Archon ECDH sessions.
 *
 * Self-contained: includes its own AES-256 key schedule and ECB block cipher.
 *
 * GCM follows NIST SP 800-38D.  GHASH uses a schoolbook 128-bit carry-less
 * multiplier (no lookup tables; correct but not timing-hardened for bulk use).
 * Archon only uses this for key-exchange packets, not bulk data transfer.
 *
 * Wire format: nonce(12) | ciphertext | tag(16) — matches ecdh.rs.
 */

#include <crypt/AesGcm.h>

/* ── AES-256 primitives ──────────────────────────────────────────────────── */

#define AES256_ROUNDS      14
#define AES256_EXPANDED_LEN  240  /* 15 * 16 */

static const gcm_u8 SBOX[256] = {
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

#define XTIME(a) (((a)<<1) ^ (((a)>>7)*0x1b))

static void aes256_key_expand(const gcm_u8 key[32], gcm_u8 rk[AES256_EXPANDED_LEN]) {
    static const gcm_u8 Rcon[11] = {
        0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
    };
    gcm_u8 t[4];
    int i, j, k;

    for (i = 0; i < 32; i++) rk[i] = key[i];
    for (i = 8; i < 60; i++) {
        t[0]=rk[(i-1)*4+0]; t[1]=rk[(i-1)*4+1];
        t[2]=rk[(i-1)*4+2]; t[3]=rk[(i-1)*4+3];
        if (i % 8 == 0) {
            gcm_u8 u=t[0]; t[0]=SBOX[t[1]]; t[1]=SBOX[t[2]];
            t[2]=SBOX[t[3]]; t[3]=SBOX[u];
            t[0] ^= Rcon[i/8];
        } else if (i % 8 == 4) {
            t[0]=SBOX[t[0]]; t[1]=SBOX[t[1]]; t[2]=SBOX[t[2]]; t[3]=SBOX[t[3]];
        }
        j=i*4; k=(i-8)*4;
        rk[j+0]=rk[k+0]^t[0]; rk[j+1]=rk[k+1]^t[1];
        rk[j+2]=rk[k+2]^t[2]; rk[j+3]=rk[k+3]^t[3];
    }
}

static void aes256_encrypt_block(const gcm_u8 rk[AES256_EXPANDED_LEN],
                                  const gcm_u8 in[16], gcm_u8 out[16]) {
    gcm_u8 s[16], t[16];
    int r, i;

    for (i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];

    for (r = 1; r <= AES256_ROUNDS; r++) {
        const gcm_u8 *rkr = rk + r*16;
        gcm_u8 tmp;

        /* SubBytes */
        for (i = 0; i < 16; i++) t[i] = SBOX[s[i]];

        /* ShiftRows */
        tmp=t[1]; t[1]=t[5]; t[5]=t[9];  t[9]=t[13]; t[13]=tmp;
        tmp=t[2]; t[2]=t[10]; t[10]=tmp;
        tmp=t[6]; t[6]=t[14]; t[14]=tmp;
        tmp=t[15]; t[15]=t[11]; t[11]=t[7]; t[7]=t[3]; t[3]=tmp;

        if (r < AES256_ROUNDS) {
            /* MixColumns */
            gcm_u8 a, b, c, d;
            for (i = 0; i < 4; i++) {
                a=t[i*4+0]; b=t[i*4+1]; c=t[i*4+2]; d=t[i*4+3];
                s[i*4+0] = XTIME(a)^XTIME(b)^b^c^d;
                s[i*4+1] = a^XTIME(b)^XTIME(c)^c^d;
                s[i*4+2] = a^b^XTIME(c)^XTIME(d)^d;
                s[i*4+3] = XTIME(a)^a^b^c^XTIME(d);
            }
        } else {
            for (i = 0; i < 16; i++) s[i] = t[i];
        }

        for (i = 0; i < 16; i++) s[i] ^= rkr[i];
    }
    for (i = 0; i < 16; i++) out[i] = s[i];
}

/* ── GHASH ───────────────────────────────────────────────────────────────── */

typedef struct { gcm_u64 hi, lo; } u128;

static u128 u128_xor(u128 a, u128 b) {
    u128 r; r.hi=a.hi^b.hi; r.lo=a.lo^b.lo; return r;
}

/* Carry-less multiply in GF(2^128), polynomial x^128+x^7+x^2+x+1 (big-endian bit order) */
static u128 gf_mul(u128 X, u128 H) {
    u128 Z = {0,0};
    int i;
    for (i = 0; i < 128; i++) {
        /* If MSB of X is set, Z ^= H */
        if (X.hi >> 63) Z = u128_xor(Z, H);
        /* X <<= 1 */
        X.hi = (X.hi<<1) | (X.lo>>63);
        X.lo <<= 1;
        /* H >>= 1 with reduction if bit 0 was set */
        gcm_u64 carry = H.lo & 1;
        H.lo = (H.hi<<63) | (H.lo>>1);
        H.hi >>= 1;
        if (carry) H.hi ^= 0xe100000000000000ULL;
    }
    return Z;
}

static u128 bytes_to_u128(const gcm_u8 b[16]) {
    u128 r; int i;
    r.hi=0; r.lo=0;
    for (i=0;i<8;i++) r.hi=(r.hi<<8)|b[i];
    for (i=8;i<16;i++) r.lo=(r.lo<<8)|b[i];
    return r;
}

static void u128_to_bytes(gcm_u8 b[16], u128 v) {
    int i;
    for (i=7;i>=0;i--) { b[i]=(gcm_u8)v.hi; v.hi>>=8; }
    for (i=15;i>=8;i--) { b[i]=(gcm_u8)v.lo; v.lo>>=8; }
}

/* Accumulate a 16-byte block into the GHASH running state */
static u128 ghash_block(u128 Y, u128 H, const gcm_u8 block[16]) {
    return gf_mul(u128_xor(Y, bytes_to_u128(block)), H);
}

/* ── AES-CTR encrypt/decrypt (for GCM) ──────────────────────────────────── */

static void gcm_ctr_xcrypt(
    const gcm_u8 rk[AES256_EXPANDED_LEN],
    const gcm_u8 J0[16],  /* base counter block (counter starts at 2) */
    const gcm_u8 *in,
    gcm_size_t    in_len,
    gcm_u8       *out
) {
    gcm_u8 ctr[16], ks[16];
    gcm_u32 cnt;
    gcm_size_t i, pos = 0;

    for (i = 0; i < 16; i++) ctr[i] = J0[i];
    /* Initial counter = inc(J0) = J0 with lower 32 bits = 2 */
    cnt = 2;
    ctr[12]=(gcm_u8)(cnt>>24); ctr[13]=(gcm_u8)(cnt>>16);
    ctr[14]=(gcm_u8)(cnt>>8);  ctr[15]=(gcm_u8)(cnt);

    while (in_len >= 16) {
        aes256_encrypt_block(rk, ctr, ks);
        for (i = 0; i < 16; i++) out[pos+i] = in[pos+i] ^ ks[i];
        cnt++;
        ctr[12]=(gcm_u8)(cnt>>24); ctr[13]=(gcm_u8)(cnt>>16);
        ctr[14]=(gcm_u8)(cnt>>8);  ctr[15]=(gcm_u8)(cnt);
        pos += 16; in_len -= 16;
    }
    if (in_len) {
        aes256_encrypt_block(rk, ctr, ks);
        for (i = 0; i < in_len; i++) out[pos+i] = in[pos+i] ^ ks[i];
    }
}

/* Compute GHASH(H, ciphertext) and return as u128 */
static u128 gcm_ghash_ciphertext(u128 H, const gcm_u8 *ct, gcm_size_t ct_len) {
    u128 Y = {0,0};
    gcm_u8 block[16];
    gcm_size_t i;

    while (ct_len >= 16) {
        Y = ghash_block(Y, H, ct);
        ct += 16; ct_len -= 16;
    }
    if (ct_len) {
        for (i = 0; i < 16; i++) block[i] = (i < ct_len) ? ct[i] : 0;
        Y = ghash_block(Y, H, block);
    }
    return Y;
}

/* Build GHASH length block and produce final tag */
static void gcm_finish_tag(
    const gcm_u8 rk[AES256_EXPANDED_LEN],
    const gcm_u8 J0[16],
    u128 Y_after_ciphertext,
    u128 H,
    gcm_size_t ct_len,
    gcm_u8 tag[AESGCM_TAG_LEN]
) {
    gcm_u8 len_block[16] = {0};
    gcm_u8 e_j0[16];
    gcm_u64 lc_bits = (gcm_u64)ct_len * 8;
    gcm_size_t i;

    /* Length block: [0 x 64 bits || len(C) x 64 bits], big-endian */
    len_block[ 8]=(gcm_u8)(lc_bits>>56); len_block[ 9]=(gcm_u8)(lc_bits>>48);
    len_block[10]=(gcm_u8)(lc_bits>>40); len_block[11]=(gcm_u8)(lc_bits>>32);
    len_block[12]=(gcm_u8)(lc_bits>>24); len_block[13]=(gcm_u8)(lc_bits>>16);
    len_block[14]=(gcm_u8)(lc_bits>> 8); len_block[15]=(gcm_u8)(lc_bits    );

    u128 Y_final = gf_mul(
        u128_xor(Y_after_ciphertext, bytes_to_u128(len_block)),
        H
    );
    gcm_u8 S[16];
    u128_to_bytes(S, Y_final);

    aes256_encrypt_block(rk, J0, e_j0);
    for (i = 0; i < AESGCM_TAG_LEN; i++) tag[i] = e_j0[i] ^ S[i];
}

/* ── Public API ──────────────────────────────────────────────────────────── */

gcm_bool aes256gcm_encrypt(
    const gcm_u8 *key,
    const gcm_u8  nonce[AESGCM_NONCE_LEN],
    const gcm_u8 *plaintext,
    gcm_size_t    pt_len,
    gcm_u8       *out       /* ciphertext(pt_len) | tag(16) */
) {
    gcm_u8 rk[AES256_EXPANDED_LEN];
    gcm_u8 H_block[16] = {0};
    gcm_u8 J0[16];
    u128 H;
    gcm_size_t i;

    aes256_key_expand(key, rk);
    aes256_encrypt_block(rk, H_block, H_block);
    H = bytes_to_u128(H_block);

    for (i = 0; i < 12; i++) J0[i] = nonce[i];
    J0[12]=0; J0[13]=0; J0[14]=0; J0[15]=1;

    /* CTR-encrypt plaintext → ciphertext */
    gcm_ctr_xcrypt(rk, J0, plaintext, pt_len, out);

    /* GHASH(H, ciphertext) then produce tag */
    u128 Y = gcm_ghash_ciphertext(H, out, pt_len);
    gcm_finish_tag(rk, J0, Y, H, pt_len, out + pt_len);

    return GCM_TRUE;
}

gcm_bool aes256gcm_decrypt(
    const gcm_u8 *key,
    const gcm_u8  nonce[AESGCM_NONCE_LEN],
    const gcm_u8 *ctext,    /* ciphertext | tag(16) */
    gcm_size_t    ct_len,   /* total = ciphertext + 16 */
    gcm_u8       *out       /* plaintext(ct_len - 16) */
) {
    gcm_u8 rk[AES256_EXPANDED_LEN];
    gcm_u8 H_block[16] = {0};
    gcm_u8 J0[16];
    gcm_u8 computed_tag[AESGCM_TAG_LEN];
    u128 H;
    gcm_size_t pt_len, i;
    gcm_u8 bad = 0;

    if (ct_len < AESGCM_TAG_LEN) return GCM_FALSE;
    pt_len = ct_len - AESGCM_TAG_LEN;

    aes256_key_expand(key, rk);
    aes256_encrypt_block(rk, H_block, H_block);
    H = bytes_to_u128(H_block);

    for (i = 0; i < 12; i++) J0[i] = nonce[i];
    J0[12]=0; J0[13]=0; J0[14]=0; J0[15]=1;

    /* GHASH over the ciphertext (NOT the plaintext) */
    u128 Y = gcm_ghash_ciphertext(H, ctext, pt_len);
    gcm_finish_tag(rk, J0, Y, H, pt_len, computed_tag);

    /* CTR-decrypt ciphertext → plaintext */
    gcm_ctr_xcrypt(rk, J0, ctext, pt_len, out);

    /* Constant-time tag comparison */
    for (i = 0; i < AESGCM_TAG_LEN; i++) bad |= computed_tag[i] ^ ctext[pt_len+i];
    if (bad) { for (i = 0; i < pt_len; i++) out[i] = 0; return GCM_FALSE; }
    return GCM_TRUE;
}

gcm_size_t aes256gcm_seal(
    const gcm_u8 *key,
    const gcm_u8 *plaintext,
    gcm_size_t    pt_len,
    gcm_u8       *out,
    gcm_bool    (*rng_fill)(gcm_u8 *buf, gcm_size_t len)
) {
    gcm_u8 nonce[AESGCM_NONCE_LEN];
    gcm_size_t i;

    if (!rng_fill(nonce, AESGCM_NONCE_LEN)) return 0;
    for (i = 0; i < AESGCM_NONCE_LEN; i++) out[i] = nonce[i];
    if (!aes256gcm_encrypt(key, nonce, plaintext, pt_len, out + AESGCM_NONCE_LEN))
        return 0;
    return AESGCM_NONCE_LEN + pt_len + AESGCM_TAG_LEN;
}

gcm_size_t aes256gcm_open(
    const gcm_u8 *key,
    const gcm_u8 *in,
    gcm_size_t    in_len,
    gcm_u8       *out
) {
    gcm_size_t ct_len;
    if (in_len < AESGCM_NONCE_LEN + AESGCM_TAG_LEN) return 0;
    ct_len = in_len - AESGCM_NONCE_LEN;
    if (!aes256gcm_decrypt(key, in, in + AESGCM_NONCE_LEN, ct_len, out)) return 0;
    return ct_len - AESGCM_TAG_LEN;
}
