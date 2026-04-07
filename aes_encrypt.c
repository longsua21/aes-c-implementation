#ifdef _WIN32
  #include <windows.h>
#else
  #define _POSIX_C_SOURCE 199309L
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ----------------------------------------------------------------
   Cross-platform high-resolution timer
   ---------------------------------------------------------------- */
#ifdef _WIN32
  typedef LARGE_INTEGER TimerVal;
  static double g_timer_freq = 0.0;
  static void timer_init(void) {
      LARGE_INTEGER f; QueryPerformanceFrequency(&f);
      g_timer_freq = (double)f.QuadPart / 1e6;
  }
  static void timer_get(TimerVal *t) { QueryPerformanceCounter(t); }
  static double timer_us(TimerVal *s, TimerVal *e) {
      return (double)(e->QuadPart - s->QuadPart) / g_timer_freq;
  }
#else
  #include <time.h>
  typedef struct timespec TimerVal;
  static void timer_init(void) {}
  static void timer_get(TimerVal *t) { clock_gettime(CLOCK_MONOTONIC, t); }
  static double timer_us(TimerVal *s, TimerVal *e) {
      return (double)(e->tv_sec  - s->tv_sec)  * 1e6
           + (double)(e->tv_nsec - s->tv_nsec) / 1e3;
  }
#endif

/* ================================================================
   AES CONSTANTS
   ================================================================ */

static const uint8_t SBOX[256] = {
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

static const uint8_t RSBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* RCON[1..14] — AES-256 key expansion can need up to index 7 but we store 15 */
static const uint8_t RCON[15] = {
    0x00,
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,
    0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d
};

/* ================================================================
   AES CONTEXT
   AES-128: Nk=4, Nr=10, round_key = 11*16 = 176 bytes
   AES-192: Nk=6, Nr=12, round_key = 13*16 = 208 bytes
   AES-256: Nk=8, Nr=14, round_key = 15*16 = 240 bytes
   ================================================================ */
typedef struct {
    int      Nk;             /* key words: 4/6/8             */
    int      Nr;             /* rounds:   10/12/14            */
    int      key_bits;       /* 128/192/256                   */
    uint8_t  round_key[240]; /* max needed: 15 * 16 = 240     */
} AES_CTX;

/* ================================================================
   KEY EXPANSION  (generic for Nk = 4, 6, 8)
   ================================================================ */
static void KeyExpansion(AES_CTX *ctx, const uint8_t *key)
{
    int Nk   = ctx->Nk;
    int Nr   = ctx->Nr;
    int total_words = (Nr + 1) * 4;  /* each round key = 4 words */

    /* W[i] stored as 4 consecutive bytes in round_key */
    uint8_t *W = ctx->round_key;

    /* Copy original key as first Nk words */
    memcpy(W, key, Nk * 4);

    for (int i = Nk; i < total_words; i++) {
        uint8_t temp[4];
        memcpy(temp, W + (i - 1) * 4, 4);

        if (i % Nk == 0) {
            /* RotWord */
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2];
            temp[2] = temp[3]; temp[3] = t;
            /* SubWord */
            temp[0] = SBOX[temp[0]]; temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]]; temp[3] = SBOX[temp[3]];
            /* XOR Rcon */
            temp[0] ^= RCON[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            /* Extra SubWord step only for AES-256 */
            temp[0] = SBOX[temp[0]]; temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]]; temp[3] = SBOX[temp[3]];
        }

        /* W[i] = W[i-Nk] XOR temp */
        W[i*4+0] = W[(i-Nk)*4+0] ^ temp[0];
        W[i*4+1] = W[(i-Nk)*4+1] ^ temp[1];
        W[i*4+2] = W[(i-Nk)*4+2] ^ temp[2];
        W[i*4+3] = W[(i-Nk)*4+3] ^ temp[3];
    }
}

/* ================================================================
   GF(2^8) MULTIPLY
   ================================================================ */
static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/* ================================================================
   ROUND FUNCTIONS
   ================================================================ */
static void AddRoundKey(AES_CTX *ctx, uint8_t state[4][4], int round)
{
    uint8_t *rk = ctx->round_key + round * 16;
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] ^= rk[c * 4 + r];
}

static void SubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = SBOX[state[r][c]];
}

static void InvSubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = RSBOX[state[r][c]];
}

static void ShiftRows(uint8_t state[4][4]) {
    uint8_t t;
    t = state[1][0]; state[1][0]=state[1][1]; state[1][1]=state[1][2]; state[1][2]=state[1][3]; state[1][3]=t;
    t = state[2][0]; state[2][0]=state[2][2]; state[2][2]=t;
    t = state[2][1]; state[2][1]=state[2][3]; state[2][3]=t;
    t = state[3][3]; state[3][3]=state[3][2]; state[3][2]=state[3][1]; state[3][1]=state[3][0]; state[3][0]=t;
}

static void InvShiftRows(uint8_t state[4][4]) {
    uint8_t t;
    t = state[1][3]; state[1][3]=state[1][2]; state[1][2]=state[1][1]; state[1][1]=state[1][0]; state[1][0]=t;
    t = state[2][0]; state[2][0]=state[2][2]; state[2][2]=t;
    t = state[2][1]; state[2][1]=state[2][3]; state[2][3]=t;
    t = state[3][0]; state[3][0]=state[3][1]; state[3][1]=state[3][2]; state[3][2]=state[3][3]; state[3][3]=t;
}

static void MixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0=state[0][c], s1=state[1][c], s2=state[2][c], s3=state[3][c];
        state[0][c] = gmul(2,s0)^gmul(3,s1)^s2^s3;
        state[1][c] = s0^gmul(2,s1)^gmul(3,s2)^s3;
        state[2][c] = s0^s1^gmul(2,s2)^gmul(3,s3);
        state[3][c] = gmul(3,s0)^s1^s2^gmul(2,s3);
    }
}

static void InvMixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0=state[0][c], s1=state[1][c], s2=state[2][c], s3=state[3][c];
        state[0][c] = gmul(0x0e,s0)^gmul(0x0b,s1)^gmul(0x0d,s2)^gmul(0x09,s3);
        state[1][c] = gmul(0x09,s0)^gmul(0x0e,s1)^gmul(0x0b,s2)^gmul(0x0d,s3);
        state[2][c] = gmul(0x0d,s0)^gmul(0x09,s1)^gmul(0x0e,s2)^gmul(0x0b,s3);
        state[3][c] = gmul(0x0b,s0)^gmul(0x0d,s1)^gmul(0x09,s2)^gmul(0x0e,s3);
    }
}

/* ================================================================
   AES ENCRYPT / DECRYPT  (single 16-byte block, generic Nr)
   ================================================================ */
static void AES_EncryptBlock(AES_CTX *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[4][4];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = in[c*4+r];

    AddRoundKey(ctx, state, 0);

    for (int round = 1; round <= ctx->Nr - 1; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(ctx, state, round);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(ctx, state, ctx->Nr);

    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[c*4+r] = state[r][c];
}

static void AES_DecryptBlock(AES_CTX *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[4][4];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = in[c*4+r];

    AddRoundKey(ctx, state, ctx->Nr);

    for (int round = ctx->Nr - 1; round >= 1; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(ctx, state, round);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(ctx, state, 0);

    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[c*4+r] = state[r][c];
}

/* ================================================================
   PKCS#7 PADDING
   ================================================================ */
static int pkcs7_pad(const uint8_t *in, int len, uint8_t *out)
{
    int pad_len = 16 - (len % 16);
    memcpy(out, in, len);
    for (int i = 0; i < pad_len; i++)
        out[len + i] = (uint8_t)pad_len;
    return len + pad_len;
}

static int pkcs7_unpad(const uint8_t *buf, int len)
{
    if (len <= 0) return 0;
    int pad = buf[len - 1];
    if (pad < 1 || pad > 16) return len;
    return len - pad;
}

/* ================================================================
   PRINT HELPERS
   ================================================================ */
static void print_separator(void) {
    printf("  +------------------------------------------------------+\n");
}

static void print_title(const char *title) {
    printf("\n");
    print_separator();
    printf("  |  %-52s|\n", title);
    print_separator();
    printf("\n");
}

static void print_hex(const char *label, const uint8_t *data, int len)
{
    printf("  %-24s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if (i + 1 < len) {
            if ((i + 1) % 16 == 0)       printf("\n  %24s  ", "");
            else if ((i + 1) % 4 == 0)   printf(" ");
        }
    }
    printf("\n");
}

/* ================================================================
   MAIN
   ================================================================ */
int main(void)
{
    timer_init();

    printf("\n");
    printf("  ======================================================\n");
    printf("  ||   AES-128 / 192 / 256 ENCRYPTION DEMO - C99     ||\n");
    printf("  ||       Khong dung thu vien ngoai                  ||\n");
    printf("  ======================================================\n");

    /* ----------------------------------------------------------
       Chon che do AES
       ---------------------------------------------------------- */
    int key_bits = 0;
    {
        char line[32];
        while (key_bits != 128 && key_bits != 192 && key_bits != 256) {
            printf("\n  Chon che do AES (128 / 192 / 256): ");
            fflush(stdout);
            if (!fgets(line, sizeof(line), stdin)) break;
            sscanf(line, "%d", &key_bits);
            if (key_bits != 128 && key_bits != 192 && key_bits != 256)
                printf("  [LOI] Chi chap nhan 128, 192 hoac 256!\n");
        }
    }

    /* ----------------------------------------------------------
       Thiet lap context theo key_bits
       ---------------------------------------------------------- */
    AES_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.key_bits = key_bits;
    if      (key_bits == 128) { ctx.Nk = 4; ctx.Nr = 10; }
    else if (key_bits == 192) { ctx.Nk = 6; ctx.Nr = 12; }
    else                      { ctx.Nk = 8; ctx.Nr = 14; }

    int key_bytes    = key_bits / 8;   /* 16 / 24 / 32 */
    int key_hex_len  = key_bytes * 2;  /* 32 / 48 / 64 */

    /* Default keys (NIST test vectors) */
    static const uint8_t DEFAULT_KEY128[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t DEFAULT_KEY192[24] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };
    static const uint8_t DEFAULT_KEY256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    /* ----------------------------------------------------------
       Nhap plaintext
       ---------------------------------------------------------- */
    char plaintext[224] = {0};
    printf("\n  Nhap plaintext (it nhat 15 ky tu, toi da 223):\n  > ");
    fflush(stdout);
    if (!fgets(plaintext, sizeof(plaintext), stdin)) {
        printf("  Loi nhap!\n"); return 1;
    }
    int pt_len = (int)strlen(plaintext);
    if (pt_len > 0 && plaintext[pt_len-1] == '\n') { plaintext[--pt_len] = '\0'; }
    if (pt_len < 15) {
        printf("\n  [LOI] Plaintext phai co it nhat 15 ky tu! (ban nhap %d)\n\n", pt_len);
        return 1;
    }

    /* ----------------------------------------------------------
       Nhap khoa
       ---------------------------------------------------------- */
    char key_str[130] = {0};
    uint8_t key[32]   = {0};

    printf("\n  Nhap khoa AES-%d (%d ky tu hex).\n", key_bits, key_hex_len);
    printf("  Nhan Enter de dung khoa mac dinh (NIST test vector).\n  > ");
    fflush(stdout);
    if (!fgets(key_str, sizeof(key_str), stdin)) {
        printf("  Loi nhap!\n"); return 1;
    }
    int ks_len = (int)strlen(key_str);
    if (ks_len > 0 && key_str[ks_len-1] == '\n') { key_str[--ks_len] = '\0'; }

    if (ks_len == 0) {
        const uint8_t *dk = (key_bits==128) ? DEFAULT_KEY128
                          : (key_bits==192) ? DEFAULT_KEY192
                                            : DEFAULT_KEY256;
        memcpy(key, dk, key_bytes);
        printf("  -> Dung khoa mac dinh AES-%d.\n", key_bits);
    } else if (ks_len != key_hex_len) {
        printf("\n  [LOI] Khoa AES-%d phai co dung %d ky tu hex! (ban nhap %d)\n\n",
               key_bits, key_hex_len, ks_len);
        return 1;
    } else {
        for (int i = 0; i < key_bytes; i++) {
            unsigned int bv = 0;
            if (sscanf(key_str + i*2, "%02x", &bv) != 1) {
                printf("\n  [LOI] Khoa chua ky tu hex khong hop le!\n\n");
                return 1;
            }
            key[i] = (uint8_t)bv;
        }
    }

    pt_len = (int)strlen(plaintext);

    /* ----------------------------------------------------------
       PKCS#7 padding + key expansion
       ---------------------------------------------------------- */
    uint8_t padded[240]     = {0};
    uint8_t ciphertext[240] = {0};
    uint8_t decrypted[240]  = {0};

    int padded_len = pkcs7_pad((const uint8_t *)plaintext, pt_len, padded);
    int num_blocks = padded_len / 16;

    KeyExpansion(&ctx, key);

    /* ----------------------------------------------------------
       In thong tin dau vao
       ---------------------------------------------------------- */
    print_title("THONG TIN DAU VAO");
    printf("  %-24s: AES-%d (%d rounds)\n", "Che do",  key_bits, ctx.Nr);
    printf("  %-24s: %s\n",                 "Plaintext goc", plaintext);
    printf("  %-24s: %d byte(s)\n",         "Do dai plaintext", pt_len);
    printf("  %-24s: %d block(s) x 16 byte\n","So block (sau pad)", num_blocks);
    print_hex("Khoa AES (HEX)", key, key_bytes);
    print_hex("Sau PKCS7 padding",  padded, padded_len);

    /* ----------------------------------------------------------
       MA HOA
       ---------------------------------------------------------- */
    print_title("MA HOA (ENCRYPT)");

    TimerVal t0, t1;
    timer_get(&t0);
    for (int i = 0; i < padded_len; i += 16)
        AES_EncryptBlock(&ctx, padded + i, ciphertext + i);
    timer_get(&t1);
    double enc_us = timer_us(&t0, &t1);

    print_hex("Ciphertext (HEX)", ciphertext, padded_len);
    printf("  %-24s: %.4f us (%.6f ms)\n", "Thoi gian ma hoa", enc_us, enc_us/1000.0);

    /* ----------------------------------------------------------
       GIAI MA
       ---------------------------------------------------------- */
    print_title("GIAI MA (DECRYPT)");

    timer_get(&t0);
    for (int i = 0; i < padded_len; i += 16)
        AES_DecryptBlock(&ctx, ciphertext + i, decrypted + i);
    timer_get(&t1);
    double dec_us = timer_us(&t0, &t1);

    int dec_len = pkcs7_unpad(decrypted, padded_len);
    decrypted[dec_len] = '\0';

    print_hex("Sau giai ma (HEX)", decrypted, dec_len);
    printf("  %-24s: %s\n",     "Plaintext phuc hoi", (char *)decrypted);
    printf("  %-24s: %.4f us (%.6f ms)\n", "Thoi gian giai ma", dec_us, dec_us/1000.0);

    /* ----------------------------------------------------------
       KET QUA KIEM TRA
       ---------------------------------------------------------- */
    print_title("KET QUA KIEM TRA");

    int match = (dec_len == pt_len) &&
                (memcmp(plaintext, decrypted, (size_t)pt_len) == 0);

    printf("  Plaintext goc   : %s\n", plaintext);
    printf("  Sau giai ma     : %s\n", (char *)decrypted);
    printf("  Ket qua         : %s\n",
           match ? "[PASS] Giai ma chinh xac!" : "[FAIL] Sai!");

    printf("\n");
    printf("  +------------------------------------------------------+\n");
    printf("  |  TONG KET THOI GIAN  (AES-%d, %d block)             |\n",
           key_bits, num_blocks);
    printf("  +------------------------------------------------------+\n");
    printf("  |  Ma hoa  : %10.4f us  (%10.6f ms)          |\n", enc_us, enc_us/1000.0);
    printf("  |  Giai ma : %10.4f us  (%10.6f ms)          |\n", dec_us, dec_us/1000.0);
    printf("  +------------------------------------------------------+\n\n");
    
    printf("  Nhan Enter de thoat chuong trinh...\n");
    // Dùng vòng lặp để xóa bộ nhớ đệm (phòng trường hợp phím Enter bị kẹt lại từ bước nhập Key)
    int c;
    while ((c = getchar()) != '\n' && c != EOF); 
    getchar();   

    return 0;
}
