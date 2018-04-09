#ifndef __SM4_H__
#define __SM4_H__
typedef unsigned long sm4_sk_t[32];
typedef struct _Crypto_SM4Arg {
    CryptoArg super;
    CryptoMeta meta;
    sm4_sk_t sk;
} Crypto_SM4Arg;

int crypto_SM4_init(Crypto_SM4Arg *arg, const unsigned char *key);

extern const CryptoMode *CryptoMode_SM4;
#endif