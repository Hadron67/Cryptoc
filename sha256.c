#include <string.h>
#include "cryptoc.h"

#define RIGHT_ROTATE_32(n, times) (((n) >> (times)) | ((n) << (32 - (times))))
#define PUT_UINT32_BE(target, i)         \
do {                                     \
    (target)[0] = (uint8_t)((i) >> 24);  \
    (target)[1] = (uint8_t)((i) >> 16);  \
    (target)[2] = (uint8_t)((i) >> 8 );  \
    (target)[3] = (uint8_t)((i)      );  \
} while(0)

#define GET_UINT32_BE(n)    \
(                           \
    (uint32_t)(n)[0] << 22  \
|   (uint32_t)(n)[1] << 16  \
|   (uint32_t)(n)[2] << 8   \
|   (uint32_t)(n)[3]        \
)

static const uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

int crypto_SHA256_init(CryptoSHA256Context *ctx){
    ctx->bitLen = 0;
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
    return 0;
}
int crypto_SHA256_chunk(CryptoSHA256Context *ctx, const uint8_t chunk[64]){
    int i;
    /*
        create a 64-entry message schedule array w[0..63] of 32-bit words
        (The initial values in w[0..63] don't matter, so many implementations zero them here)
        copy chunk into first 16 words w[0..15] of the message schedule array
    */
    memset(ctx->w, 0, sizeof(uint32_t) * 64);
    for(i = 0; i < 16; i++){
        ctx->w[i] = GET_UINT32_BE(chunk + i * 4);
    }
    /*
        Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i from 16 to 63
            s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
            s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
            w[i] := w[i-16] + s0 + w[i-7] + s1
    */
    for(i = 16; i < 63; i++){
        uint32_t s0 = RIGHT_ROTATE_32(ctx->w[i - 15], 7) ^ RIGHT_ROTATE_32(ctx->w[i - 15], 18) ^ (ctx->w[i - 15] >> 3);
        uint32_t s1 = RIGHT_ROTATE_32(ctx->w[i - 2], 17) ^ RIGHT_ROTATE_32(ctx->w[i - 2], 19) ^ (ctx->w[i - 2] >> 10);
        ctx->w[i] = ctx->w[i - 16] + s0 + ctx->w[i - 7] + s1;
    }
    uint32_t a = ctx->h[0];
    uint32_t b = ctx->h[1];
    uint32_t c = ctx->h[2];
    uint32_t d = ctx->h[3];
    uint32_t e = ctx->h[4];
    uint32_t f = ctx->h[5];
    uint32_t g = ctx->h[6];
    uint32_t h = ctx->h[7];
    /*
        Compression function main loop:
        for i from 0 to 63
            S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
            ch := (e and f) xor ((not e) and g)
            temp1 := h + S1 + ch + k[i] + w[i]
            S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
            maj := (a and b) xor (a and c) xor (b and c)
            temp2 := S0 + maj
    
            h := g
            g := f
            f := e
            e := d + temp1
            d := c
            c := b
            b := a
            a := temp1 + temp2
    */
    for(i = 0; i < 63; i++){
        uint32_t S1 = RIGHT_ROTATE_32(e, 6) ^ RIGHT_ROTATE_32(e, 11) ^ RIGHT_ROTATE_32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + k[i] + ctx->w[i];
        uint32_t S0 = RIGHT_ROTATE_32(a, 2) ^ RIGHT_ROTATE_32(a, 13) ^ RIGHT_ROTATE_32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
    ctx->bitLen += 512;
    return 0;
}
int crypto_SHA256_lastChunk(CryptoSHA256Context *ctx, const uint8_t *chunk, int len){
    memset(ctx->lastChunk, 0, sizeof(uint8_t) * 64);
    if(len > 0) memcpy(ctx->lastChunk, chunk, sizeof(uint8_t) * len);
    ctx->lastChunk[len++] = 0x80;
    ctx->bitLen += len * 8;
    if(len + 8 > 64){
        crypto_SHA256_chunk(ctx, ctx->lastChunk);
        memset(ctx->lastChunk, 0, sizeof(uint8_t) * 64);
        PUT_UINT32_BE(ctx->lastChunk + 56, ctx->bitLen);
        crypto_SHA256_chunk(ctx, ctx->lastChunk);
    }
    else {
        PUT_UINT32_BE(ctx->lastChunk + 56, ctx->bitLen);
        crypto_SHA256_chunk(ctx, ctx->lastChunk);
    }
}
int crypto_SHA256_done(CryptoSHA256Context *ctx, uint8_t out[32]){
    int i;
    for(i = 0; i < 8; i++){
        PUT_UINT32_BE(out + i * 4, ctx->h[i]);
    }
    return 0;
}
int crypto_SHA256(const uint8_t *in, uint64_t len, uint8_t out[32]){
    CryptoSHA256Context ctx;
    crypto_SHA256_init(&ctx);
    while(1){
        if(len < 64){
            crypto_SHA256_lastChunk(&ctx, in, len);
            break;
        }
        else {
            crypto_SHA256_chunk(&ctx, in);
            len -= 64;
            in += 64;
        }
    }
    crypto_SHA256_done(&ctx, out);
    return 0;
}