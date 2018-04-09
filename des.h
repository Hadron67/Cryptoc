#ifndef __DES_H__
#define __DES_H__

typedef struct _CryptoDESArg {
    CryptoArg super;
    CryptoMeta meta;
    uint64_t subKeys[16];
} CryptoDESArg;

int crypto_DES_init(CryptoDESArg *arg, const unsigned char *key);

extern const CryptoMode *CryptoMode_DES;

#endif