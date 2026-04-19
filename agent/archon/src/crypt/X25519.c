/*
 * X25519.c — Curve25519 Diffie-Hellman implementation for Archon ECDH.
 *
 * Field elements are 10 signed 32-bit limbs with alternating 26/25-bit widths,
 * representing residues modulo 2^255-19.  The Montgomery ladder is
 * constant-time: swaps use arithmetic masks, no secret-dependent branches.
 *
 * Compatible with the x25519-dalek Rust crate used by the teamserver.
 */

#include <crypt/X25519.h>

typedef x25519_i32 fe[10];

/* ── Little-endian multi-byte loads ─────────────────────────────────────── */

static x25519_u64 load4(const x25519_u8 *s) {
    return (x25519_u64)s[0] | ((x25519_u64)s[1] << 8)
         | ((x25519_u64)s[2] << 16) | ((x25519_u64)s[3] << 24);
}

/* ── Load / Store ────────────────────────────────────────────────────────── */

static void fe_from_bytes(fe h, const x25519_u8 s[32]) {
    x25519_i64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    x25519_i64 carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;

    /* Extract 26/25-bit limbs from the 32-byte little-endian encoding */
    h0 = (x25519_i64)(load4(s)            & 0x3ffffffu);
    h1 = (x25519_i64)((load4(s+ 3) >> 2)  & 0x1ffffffu);
    h2 = (x25519_i64)((load4(s+ 6) >> 3)  & 0x3ffffffu);
    h3 = (x25519_i64)((load4(s+ 9) >> 5)  & 0x1ffffffu);
    h4 = (x25519_i64)((load4(s+12) >> 6)  & 0x3ffffffu);
    h5 = (x25519_i64)(load4(s+16)          & 0x1ffffffu);
    h6 = (x25519_i64)((load4(s+19) >> 1)  & 0x3ffffffu);
    h7 = (x25519_i64)((load4(s+22) >> 3)  & 0x1ffffffu);
    h8 = (x25519_i64)((load4(s+25) >> 4)  & 0x3ffffffu);
    h9 = (x25519_i64)((load4(s+28) >> 6)  & 0x1ffffffu);

    /* Carry chain to fully normalize */
    carry9 = (h9 + (x25519_i64)(1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
    carry1 = (h1 + (x25519_i64)(1<<24)) >> 25; h2 += carry1;       h1 -= carry1 << 25;
    carry3 = (h3 + (x25519_i64)(1<<24)) >> 25; h4 += carry3;       h3 -= carry3 << 25;
    carry5 = (h5 + (x25519_i64)(1<<24)) >> 25; h6 += carry5;       h5 -= carry5 << 25;
    carry7 = (h7 + (x25519_i64)(1<<24)) >> 25; h8 += carry7;       h7 -= carry7 << 25;
    carry0 = (h0 + (x25519_i64)(1<<25)) >> 26; h1 += carry0;       h0 -= carry0 << 26;
    carry2 = (h2 + (x25519_i64)(1<<25)) >> 26; h3 += carry2;       h2 -= carry2 << 26;
    carry4 = (h4 + (x25519_i64)(1<<25)) >> 26; h5 += carry4;       h4 -= carry4 << 26;
    carry6 = (h6 + (x25519_i64)(1<<25)) >> 26; h7 += carry6;       h6 -= carry6 << 26;
    carry8 = (h8 + (x25519_i64)(1<<25)) >> 26; h9 += carry8;       h8 -= carry8 << 26;

    h[0]=(x25519_i32)h0; h[1]=(x25519_i32)h1; h[2]=(x25519_i32)h2;
    h[3]=(x25519_i32)h3; h[4]=(x25519_i32)h4; h[5]=(x25519_i32)h5;
    h[6]=(x25519_i32)h6; h[7]=(x25519_i32)h7; h[8]=(x25519_i32)h8;
    h[9]=(x25519_i32)h9;
}

static void fe_to_bytes(x25519_u8 s[32], const fe h) {
    x25519_i32 carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;
    x25519_i32 h0=h[0],h1=h[1],h2=h[2],h3=h[3],h4=h[4],
               h5=h[5],h6=h[6],h7=h[7],h8=h[8],h9=h[9], q;

    /* Reduce to canonical [0, 2^255-19) */
    q = (19*h9 + (1<<24)) >> 25;
    q = (h0+q) >> 26; q = (h1+q) >> 25; q = (h2+q) >> 26; q = (h3+q) >> 25;
    q = (h4+q) >> 26; q = (h5+q) >> 25; q = (h6+q) >> 26; q = (h7+q) >> 25;
    q = (h8+q) >> 26; q = (h9+q) >> 25;

    h0 += 19*q;
    carry0=h0>>26; h1+=carry0; h0-=carry0<<26;
    carry1=h1>>25; h2+=carry1; h1-=carry1<<25;
    carry2=h2>>26; h3+=carry2; h2-=carry2<<26;
    carry3=h3>>25; h4+=carry3; h3-=carry3<<25;
    carry4=h4>>26; h5+=carry4; h4-=carry4<<26;
    carry5=h5>>25; h6+=carry5; h5-=carry5<<25;
    carry6=h6>>26; h7+=carry6; h6-=carry6<<26;
    carry7=h7>>25; h8+=carry7; h7-=carry7<<25;
    carry8=h8>>26; h9+=carry8; h8-=carry8<<26;
    carry9=h9>>25;             h9-=carry9<<25;

    /* Pack limbs into 32 bytes */
    s[ 0] = (x25519_u8)(h0 >>  0);
    s[ 1] = (x25519_u8)(h0 >>  8);
    s[ 2] = (x25519_u8)(h0 >> 16);
    s[ 3] = (x25519_u8)((h0 >> 24) | (h1 << 2));
    s[ 4] = (x25519_u8)(h1 >>  6);
    s[ 5] = (x25519_u8)(h1 >> 14);
    s[ 6] = (x25519_u8)((h1 >> 22) | (h2 << 3));
    s[ 7] = (x25519_u8)(h2 >>  5);
    s[ 8] = (x25519_u8)(h2 >> 13);
    s[ 9] = (x25519_u8)((h2 >> 21) | (h3 << 5));
    s[10] = (x25519_u8)(h3 >>  3);
    s[11] = (x25519_u8)(h3 >> 11);
    s[12] = (x25519_u8)((h3 >> 19) | (h4 << 6));
    s[13] = (x25519_u8)(h4 >>  2);
    s[14] = (x25519_u8)(h4 >> 10);
    s[15] = (x25519_u8)(h4 >> 18);
    s[16] = (x25519_u8)(h5 >>  0);
    s[17] = (x25519_u8)(h5 >>  8);
    s[18] = (x25519_u8)(h5 >> 16);
    s[19] = (x25519_u8)((h5 >> 24) | (h6 << 1));
    s[20] = (x25519_u8)(h6 >>  7);
    s[21] = (x25519_u8)(h6 >> 15);
    s[22] = (x25519_u8)((h6 >> 23) | (h7 << 3));
    s[23] = (x25519_u8)(h7 >>  5);
    s[24] = (x25519_u8)(h7 >> 13);
    s[25] = (x25519_u8)((h7 >> 21) | (h8 << 4));
    s[26] = (x25519_u8)(h8 >>  4);
    s[27] = (x25519_u8)(h8 >> 12);
    s[28] = (x25519_u8)((h8 >> 20) | (h9 << 6));
    s[29] = (x25519_u8)(h9 >>  2);
    s[30] = (x25519_u8)(h9 >> 10);
    s[31] = (x25519_u8)(h9 >> 18);
}

/* ── Field arithmetic ────────────────────────────────────────────────────── */

static void fe_copy(fe h, const fe f) {
    int i; for (i = 0; i < 10; i++) h[i] = f[i];
}

static void fe_zero(fe h) {
    h[0]=h[1]=h[2]=h[3]=h[4]=h[5]=h[6]=h[7]=h[8]=h[9]=0;
}

static void fe_add(fe h, const fe f, const fe g) {
    int i; for (i = 0; i < 10; i++) h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g) {
    int i; for (i = 0; i < 10; i++) h[i] = f[i] - g[i];
}

static void fe_mul(fe h, const fe f, const fe g) {
    x25519_i32 f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4],
               f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    x25519_i32 g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4],
               g5=g[5],g6=g[6],g7=g[7],g8=g[8],g9=g[9];
    x25519_i32 g1_19=(x25519_i32)(19*(x25519_i64)g1),
               g2_19=(x25519_i32)(19*(x25519_i64)g2),
               g3_19=(x25519_i32)(19*(x25519_i64)g3),
               g4_19=(x25519_i32)(19*(x25519_i64)g4),
               g5_19=(x25519_i32)(19*(x25519_i64)g5),
               g6_19=(x25519_i32)(19*(x25519_i64)g6),
               g7_19=(x25519_i32)(19*(x25519_i64)g7),
               g8_19=(x25519_i32)(19*(x25519_i64)g8),
               g9_19=(x25519_i32)(19*(x25519_i64)g9);
    x25519_i32 f1_2 =(x25519_i32)(2*(x25519_i64)f1),
               f3_2 =(x25519_i32)(2*(x25519_i64)f3),
               f5_2 =(x25519_i32)(2*(x25519_i64)f5),
               f7_2 =(x25519_i32)(2*(x25519_i64)f7),
               f9_2 =(x25519_i32)(2*(x25519_i64)f9);
    x25519_i64 carry0,carry1,carry2,carry3,carry4,
               carry5,carry6,carry7,carry8,carry9;
    x25519_i64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;

    h0 = (x25519_i64)f0*g0    + (x25519_i64)f1_2*g9_19 + (x25519_i64)f2*g8_19
       + (x25519_i64)f3_2*g7_19 + (x25519_i64)f4*g6_19 + (x25519_i64)f5_2*g5_19
       + (x25519_i64)f6*g4_19 + (x25519_i64)f7_2*g3_19 + (x25519_i64)f8*g2_19
       + (x25519_i64)f9_2*g1_19;
    h1 = (x25519_i64)f0*g1    + (x25519_i64)f1*g0      + (x25519_i64)f2*g9_19
       + (x25519_i64)f3*g8_19 + (x25519_i64)f4*g7_19   + (x25519_i64)f5*g6_19
       + (x25519_i64)f6*g5_19 + (x25519_i64)f7*g4_19   + (x25519_i64)f8*g3_19
       + (x25519_i64)f9*g2_19;
    h2 = (x25519_i64)f0*g2    + (x25519_i64)f1_2*g1    + (x25519_i64)f2*g0
       + (x25519_i64)f3_2*g9_19 + (x25519_i64)f4*g8_19 + (x25519_i64)f5_2*g7_19
       + (x25519_i64)f6*g6_19 + (x25519_i64)f7_2*g5_19 + (x25519_i64)f8*g4_19
       + (x25519_i64)f9_2*g3_19;
    h3 = (x25519_i64)f0*g3    + (x25519_i64)f1*g2      + (x25519_i64)f2*g1
       + (x25519_i64)f3*g0    + (x25519_i64)f4*g9_19   + (x25519_i64)f5*g8_19
       + (x25519_i64)f6*g7_19 + (x25519_i64)f7*g6_19   + (x25519_i64)f8*g5_19
       + (x25519_i64)f9*g4_19;
    h4 = (x25519_i64)f0*g4    + (x25519_i64)f1_2*g3    + (x25519_i64)f2*g2
       + (x25519_i64)f3_2*g1  + (x25519_i64)f4*g0      + (x25519_i64)f5_2*g9_19
       + (x25519_i64)f6*g8_19 + (x25519_i64)f7_2*g7_19 + (x25519_i64)f8*g6_19
       + (x25519_i64)f9_2*g5_19;
    h5 = (x25519_i64)f0*g5    + (x25519_i64)f1*g4      + (x25519_i64)f2*g3
       + (x25519_i64)f3*g2    + (x25519_i64)f4*g1      + (x25519_i64)f5*g0
       + (x25519_i64)f6*g9_19 + (x25519_i64)f7*g8_19   + (x25519_i64)f8*g7_19
       + (x25519_i64)f9*g6_19;
    h6 = (x25519_i64)f0*g6    + (x25519_i64)f1_2*g5    + (x25519_i64)f2*g4
       + (x25519_i64)f3_2*g3  + (x25519_i64)f4*g2      + (x25519_i64)f5_2*g1
       + (x25519_i64)f6*g0    + (x25519_i64)f7_2*g9_19 + (x25519_i64)f8*g8_19
       + (x25519_i64)f9_2*g7_19;
    h7 = (x25519_i64)f0*g7    + (x25519_i64)f1*g6      + (x25519_i64)f2*g5
       + (x25519_i64)f3*g4    + (x25519_i64)f4*g3      + (x25519_i64)f5*g2
       + (x25519_i64)f6*g1    + (x25519_i64)f7*g0      + (x25519_i64)f8*g9_19
       + (x25519_i64)f9*g8_19;
    h8 = (x25519_i64)f0*g8    + (x25519_i64)f1_2*g7    + (x25519_i64)f2*g6
       + (x25519_i64)f3_2*g5  + (x25519_i64)f4*g4      + (x25519_i64)f5_2*g3
       + (x25519_i64)f6*g2    + (x25519_i64)f7_2*g1    + (x25519_i64)f8*g0
       + (x25519_i64)f9_2*g9_19;
    h9 = (x25519_i64)f0*g9    + (x25519_i64)f1*g8      + (x25519_i64)f2*g7
       + (x25519_i64)f3*g6    + (x25519_i64)f4*g5      + (x25519_i64)f5*g4
       + (x25519_i64)f6*g3    + (x25519_i64)f7*g2      + (x25519_i64)f8*g1
       + (x25519_i64)f9*g0;

    carry0=(h0+(x25519_i64)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    carry4=(h4+(x25519_i64)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry1=(h1+(x25519_i64)(1<<24))>>25; h2+=carry1; h1-=carry1<<25;
    carry5=(h5+(x25519_i64)(1<<24))>>25; h6+=carry5; h5-=carry5<<25;
    carry2=(h2+(x25519_i64)(1<<25))>>26; h3+=carry2; h2-=carry2<<26;
    carry6=(h6+(x25519_i64)(1<<25))>>26; h7+=carry6; h6-=carry6<<26;
    carry3=(h3+(x25519_i64)(1<<24))>>25; h4+=carry3; h3-=carry3<<25;
    carry7=(h7+(x25519_i64)(1<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(x25519_i64)(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry8=(h8+(x25519_i64)(1<<25))>>26; h9+=carry8; h8-=carry8<<26;
    carry9=(h9+(x25519_i64)(1<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(x25519_i64)(1<<25))>>26; h1+=carry0; h0-=carry0<<26;

    h[0]=(x25519_i32)h0; h[1]=(x25519_i32)h1; h[2]=(x25519_i32)h2;
    h[3]=(x25519_i32)h3; h[4]=(x25519_i32)h4; h[5]=(x25519_i32)h5;
    h[6]=(x25519_i32)h6; h[7]=(x25519_i32)h7; h[8]=(x25519_i32)h8;
    h[9]=(x25519_i32)h9;
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

/* Multiply by the A24 constant 121666 */
static void fe_mul121666(fe h, const fe f) {
    x25519_i64 h0=(x25519_i64)f[0]*121666, h1=(x25519_i64)f[1]*121666,
               h2=(x25519_i64)f[2]*121666, h3=(x25519_i64)f[3]*121666,
               h4=(x25519_i64)f[4]*121666, h5=(x25519_i64)f[5]*121666,
               h6=(x25519_i64)f[6]*121666, h7=(x25519_i64)f[7]*121666,
               h8=(x25519_i64)f[8]*121666, h9=(x25519_i64)f[9]*121666;
    x25519_i64 c;
    c=(h9+(x25519_i64)(1<<24))>>25; h0+=c*19; h9-=c<<25;
    c=(h1+(x25519_i64)(1<<24))>>25; h2+=c; h1-=c<<25;
    c=(h3+(x25519_i64)(1<<24))>>25; h4+=c; h3-=c<<25;
    c=(h5+(x25519_i64)(1<<24))>>25; h6+=c; h5-=c<<25;
    c=(h7+(x25519_i64)(1<<24))>>25; h8+=c; h7-=c<<25;
    c=(h0+(x25519_i64)(1<<25))>>26; h1+=c; h0-=c<<26;
    c=(h2+(x25519_i64)(1<<25))>>26; h3+=c; h2-=c<<26;
    c=(h4+(x25519_i64)(1<<25))>>26; h5+=c; h4-=c<<26;
    c=(h6+(x25519_i64)(1<<25))>>26; h7+=c; h6-=c<<26;
    c=(h8+(x25519_i64)(1<<25))>>26; h9+=c; h8-=c<<26;
    h[0]=(x25519_i32)h0; h[1]=(x25519_i32)h1; h[2]=(x25519_i32)h2;
    h[3]=(x25519_i32)h3; h[4]=(x25519_i32)h4; h[5]=(x25519_i32)h5;
    h[6]=(x25519_i32)h6; h[7]=(x25519_i32)h7; h[8]=(x25519_i32)h8;
    h[9]=(x25519_i32)h9;
}

/* Constant-time conditional swap when swap=1 */
static void fe_cswap(fe f, fe g, unsigned int swap) {
    x25519_i32 mask = -(x25519_i32)swap;
    int i;
    for (i = 0; i < 10; i++) {
        x25519_i32 t = (f[i] ^ g[i]) & mask;
        f[i] ^= t; g[i] ^= t;
    }
}

/* Compute h = 1/z in GF(2^255-19) via z^(p-2) = z^(2^255-21) */
static void fe_invert(fe h, const fe z) {
    fe z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, tmp;
    int i;

    fe_sq(z2, z);
    fe_sq(tmp, z2); fe_sq(tmp, tmp);
    fe_mul(z9, tmp, z);
    fe_mul(z11, z9, z2);
    fe_sq(tmp, z11); fe_mul(z2_5_0, tmp, z9);

    fe_sq(tmp, z2_5_0);
    for (i = 1; i < 5; i++) fe_sq(tmp, tmp);
    fe_mul(z2_10_0, tmp, z2_5_0);

    fe_sq(tmp, z2_10_0);
    for (i = 1; i < 10; i++) fe_sq(tmp, tmp);
    fe_mul(z2_20_0, tmp, z2_10_0);

    fe_sq(tmp, z2_20_0);
    for (i = 1; i < 20; i++) fe_sq(tmp, tmp);
    fe_mul(tmp, tmp, z2_20_0);

    fe_sq(tmp, tmp);
    for (i = 1; i < 10; i++) fe_sq(tmp, tmp);
    fe_mul(z2_50_0, tmp, z2_10_0);

    fe_sq(tmp, z2_50_0);
    for (i = 1; i < 50; i++) fe_sq(tmp, tmp);
    fe_mul(z2_100_0, tmp, z2_50_0);

    fe_sq(tmp, z2_100_0);
    for (i = 1; i < 100; i++) fe_sq(tmp, tmp);
    fe_mul(tmp, tmp, z2_100_0);

    fe_sq(tmp, tmp);
    for (i = 1; i < 50; i++) fe_sq(tmp, tmp);
    fe_mul(tmp, tmp, z2_50_0);

    fe_sq(tmp, tmp); fe_sq(tmp, tmp); fe_sq(tmp, tmp);
    fe_sq(tmp, tmp); fe_sq(tmp, tmp);
    fe_mul(h, tmp, z11);
}

/* ── Montgomery ladder ───────────────────────────────────────────────────── */

static void x25519_ladder(fe result, const x25519_u8 scalar[32], const fe u) {
    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    unsigned int swap = 0, bit;
    int pos;

    fe_copy(x1, u);
    fe_zero(x2); x2[0] = 1;
    fe_zero(z2);
    fe_copy(x3, u);
    fe_zero(z3); z3[0] = 1;

    for (pos = 254; pos >= 0; pos--) {
        bit = (scalar[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(result, x2, z2);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void x25519_public_key(x25519_u8 out_public_key[32], const x25519_u8 secret_key[32]) {
    x25519_u8 clamped[32];
    fe base, result;
    int i;

    for (i = 0; i < 32; i++) clamped[i] = secret_key[i];
    clamped[ 0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    fe_zero(base); base[0] = 9;  /* Curve25519 base point u = 9 */
    x25519_ladder(result, clamped, base);
    fe_to_bytes(out_public_key, result);
}

void x25519_diffie_hellman(
    x25519_u8 out_shared_secret[32],
    const x25519_u8 secret_key[32],
    const x25519_u8 peer_public_key[32]
) {
    x25519_u8 clamped[32];
    fe u, result;
    int i;

    for (i = 0; i < 32; i++) clamped[i] = secret_key[i];
    clamped[ 0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    fe_from_bytes(u, peer_public_key);
    x25519_ladder(result, clamped, u);
    fe_to_bytes(out_shared_secret, result);
}
