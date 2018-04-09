#ifndef __SHA256_H__
#define __SHA256_H__

typedef struct _SHA256Context {
    uint64_t bitLen;
    uint8_t lastChunk[64];
    uint32_t h[8];
    uint32_t w[64];
} CryptoSHA256Context;
int crypto_SHA256_init(CryptoSHA256Context *ctx);
int crypto_SHA256_chunk(CryptoSHA256Context *ctx, const uint8_t chunk[64]);
int crypto_SHA256_lastChunk(CryptoSHA256Context *ctx, const uint8_t *chunk, int len);
int crypto_SHA256_done(CryptoSHA256Context *ctx, uint8_t out[32]);

int crypto_SHA256(const uint8_t *in, uint64_t len, uint8_t out[32]);

#endif