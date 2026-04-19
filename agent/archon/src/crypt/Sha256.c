/*
 * Sha256.c — SHA-256 / HMAC-SHA256 / HKDF-SHA256 implementation.
 *
 * SHA-256 follows FIPS 180-4.  HMAC follows RFC 2104.  HKDF follows RFC 5869.
 * This file has no dependencies beyond the standard C runtime.
 */

#include <crypt/Sha256.h>

/* ── Big-endian helpers ──────────────────────────────────────────────────── */

#define BE32(b,w) \
    (b)[0]=(sha_u8)((w)>>24); (b)[1]=(sha_u8)((w)>>16); \
    (b)[2]=(sha_u8)((w)>> 8); (b)[3]=(sha_u8)((w)    )

static sha_u32 get_be32(const sha_u8 *b) {
    return ((sha_u32)b[0]<<24) | ((sha_u32)b[1]<<16)
         | ((sha_u32)b[2]<< 8) |  (sha_u32)b[3];
}

/* ── SHA-256 compression constants ──────────────────────────────────────── */

static const sha_u32 K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static const sha_u32 IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define CH(e,f,g)   (((e)&(f)) ^ (~(e)&(g)))
#define MAJ(a,b,c)  (((a)&(b)) ^ ((a)&(c)) ^ ((b)&(c)))
#define EP0(a)  (ROTR32(a, 2) ^ ROTR32(a,13) ^ ROTR32(a,22))
#define EP1(e)  (ROTR32(e, 6) ^ ROTR32(e,11) ^ ROTR32(e,25))
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x,18) ^ ((x)>>  3))
#define SIG1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x)>> 10))

static void sha256_compress(sha_u32 state[8], const sha_u8 block[64]) {
    sha_u32 W[64];
    sha_u32 a,b,c,d,e,f,g,h,t1,t2;
    int i;

    for (i = 0; i < 16; i++) W[i] = get_be32(block + 4*i);
    for (i = 16; i < 64; i++)
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];

    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }

    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

/* ── SHA-256 streaming API ───────────────────────────────────────────────── */

void sha256_init(sha256_ctx *ctx) {
    int i;
    ctx->count = 0;
    for (i = 0; i < 8; i++) ctx->state[i] = IV[i];
}

void sha256_update(sha256_ctx *ctx, const sha_u8 *data, sha_size_t len) {
    sha_size_t i;
    for (i = 0; i < len; ++i) {
        ctx->buf[ctx->count & 63u] = data[i];
        ctx->count++;
        if ((ctx->count & 63u) == 0)
            sha256_compress(ctx->state, ctx->buf);
    }
}

void sha256_final(sha256_ctx *ctx, sha_u8 digest[SHA256_DIGEST_LEN]) {
    sha_u64 bit_count = ctx->count * 8u;
    sha_size_t buf_used = (sha_size_t)(ctx->count & 63u);
    sha_size_t i;

    /* Append 0x80 padding byte */
    ctx->buf[buf_used++] = 0x80;

    /* If no room for the 8-byte length field, flush the partial block */
    if (buf_used > 56) {
        while (buf_used < 64) ctx->buf[buf_used++] = 0;
        sha256_compress(ctx->state, ctx->buf);
        buf_used = 0;
    }

    /* Zero-pad up to the length field position */
    while (buf_used < 56) ctx->buf[buf_used++] = 0;

    /* Append big-endian bit count */
    ctx->buf[56] = (sha_u8)(bit_count >> 56);
    ctx->buf[57] = (sha_u8)(bit_count >> 48);
    ctx->buf[58] = (sha_u8)(bit_count >> 40);
    ctx->buf[59] = (sha_u8)(bit_count >> 32);
    ctx->buf[60] = (sha_u8)(bit_count >> 24);
    ctx->buf[61] = (sha_u8)(bit_count >> 16);
    ctx->buf[62] = (sha_u8)(bit_count >>  8);
    ctx->buf[63] = (sha_u8)(bit_count      );
    sha256_compress(ctx->state, ctx->buf);

    for (i = 0; i < 8; i++) { BE32(digest + 4*i, ctx->state[i]); }
}

void sha256(const sha_u8 *data, sha_size_t len, sha_u8 digest[SHA256_DIGEST_LEN]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* ── HMAC-SHA256 ─────────────────────────────────────────────────────────── */

void hmac_sha256(
    const sha_u8 *key,  sha_size_t key_len,
    const sha_u8 *data, sha_size_t data_len,
    sha_u8 out[SHA256_DIGEST_LEN]
) {
    sha_u8 k_block[SHA256_BLOCK_LEN];
    sha_u8 inner[SHA256_DIGEST_LEN];
    sha256_ctx ctx;
    sha_size_t i;

    /* Derive block-length key */
    if (key_len > SHA256_BLOCK_LEN) {
        sha256(key, key_len, k_block);
        for (i = SHA256_DIGEST_LEN; i < SHA256_BLOCK_LEN; i++) k_block[i] = 0;
    } else {
        for (i = 0; i < key_len; i++) k_block[i] = key[i];
        for (; i < SHA256_BLOCK_LEN; i++) k_block[i] = 0;
    }

    /* Inner hash: H(k XOR ipad || data) */
    sha256_init(&ctx);
    {
        sha_u8 ipad[SHA256_BLOCK_LEN];
        for (i = 0; i < SHA256_BLOCK_LEN; i++) ipad[i] = k_block[i] ^ 0x36;
        sha256_update(&ctx, ipad, SHA256_BLOCK_LEN);
    }
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    /* Outer hash: H(k XOR opad || inner) */
    sha256_init(&ctx);
    {
        sha_u8 opad[SHA256_BLOCK_LEN];
        for (i = 0; i < SHA256_BLOCK_LEN; i++) opad[i] = k_block[i] ^ 0x5c;
        sha256_update(&ctx, opad, SHA256_BLOCK_LEN);
    }
    sha256_update(&ctx, inner, SHA256_DIGEST_LEN);
    sha256_final(&ctx, out);
}

/* ── HKDF-SHA256 expand (RFC 5869 §2.3) ─────────────────────────────────── */

void hkdf_sha256_expand(
    const sha_u8 *prk,  sha_size_t prk_len,
    const sha_u8 *info, sha_size_t info_len,
    sha_u8 *out,        sha_size_t out_len
) {
    sha_u8  t[SHA256_DIGEST_LEN];
    sha_u8  prev[SHA256_DIGEST_LEN];
    sha_size_t t_len = 0;
    sha_u8  counter = 1;
    sha_size_t out_pos = 0;

    while (out_pos < out_len) {
        sha_u8 tmp[SHA256_DIGEST_LEN + 256 + 1];
        sha_size_t tmp_len = 0;
        sha_size_t i, copy;

        for (i = 0; i < t_len; i++) tmp[tmp_len++] = prev[i];
        for (i = 0; i < info_len && tmp_len < sizeof(tmp)-1; i++)
            tmp[tmp_len++] = info[i];
        tmp[tmp_len++] = counter++;

        hmac_sha256(prk, prk_len, tmp, tmp_len, t);
        for (i = 0; i < SHA256_DIGEST_LEN; i++) prev[i] = t[i];
        t_len = SHA256_DIGEST_LEN;

        copy = out_len - out_pos;
        if (copy > SHA256_DIGEST_LEN) copy = SHA256_DIGEST_LEN;
        for (i = 0; i < copy; i++) out[out_pos++] = t[i];
    }
}
