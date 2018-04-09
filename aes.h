#ifndef __AES_H__
#define __AES_H__
#ifndef __CRYPTOC_H__
#error "This file must be included with cryptoc.h"
#endif

typedef enum _AESKeyLen {
    CRYPTO_AES_KEY_UNSET,
    CRYPTO_AES_KEY_128,
    CRYPTO_AES_KEY_192,
    CRYPTO_AES_KEY_256
} Crypto_AESKeyLen;

typedef struct _CryptoAESMetadata {
    CryptoMeta super;
    Crypto_AESKeyLen keyLen;
} Crypto_AESMetadata;
typedef struct _CryptoAESArg {
    CryptoArg super;
    Crypto_AESMetadata meta;
    const uint8_t *key;
    unsigned char keys[256];
    int round;
} CryptoAESArg;

int crypto_AES_init(CryptoAESArg *arg, const uint8_t *key, Crypto_AESKeyLen keyLen);

extern const CryptoMode *CryptoMode_AES;
#endif