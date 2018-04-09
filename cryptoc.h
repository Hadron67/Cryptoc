#ifndef __CRYPTOC_H__
#define __CRYPTOC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

typedef struct _CryptoMode CryptoMode;

typedef struct _CryptoMeta {
    uint8_t modeID;
    size_t inputLen;
} CryptoMeta;
typedef struct _CryptoArg {
    CryptoMeta *meta;
    const CryptoMode *mode; 
} CryptoArg;

typedef int (*crypt_init_t)(CryptoArg *arg, const uint8_t *key);
typedef int (*crypt_onReadMeta_t)(CryptoArg *arg);
typedef int (*crypt_encrypt_t)(uint8_t *block, CryptoArg *arg);
typedef int (*crypt_decrypt_t)(uint8_t *block, CryptoArg *arg);
struct _CryptoMode {
    crypt_init_t init;
    crypt_encrypt_t encrypt;
    crypt_decrypt_t decrypt;
    crypt_onReadMeta_t onReadMeta;
    size_t metaSize;
    size_t argSize;
    unsigned int blockSize;
    uint8_t modeID;
};

#define CRYPTOC_DEF_MODE(id, prefix, modeName, metaName, argName, blockSize) \
static const CryptoMode mode = {                                             \
    (crypt_init_t)    prefix ## _init,                                       \
    (crypt_encrypt_t) prefix ## _encrypt,                                    \
    (crypt_decrypt_t) prefix ## _decrypt,                                    \
    (crypt_onReadMeta_t) prefix ## _onReadMeta,                              \
    sizeof(metaName),                                                        \
    sizeof(argName),                                                         \
    blockSize,                                                               \
    id                                                                       \
};                                                                           \
const CryptoMode *CryptoMode_ ## modeName = &mode;

#include "aes.h"
#include "sm4.h"
#include "des.h"
#include "sha256.h"

const CryptoMode *crypto_getMode(int id);
int crypto_setKey(CryptoArg *arg, const unsigned char *key);
int crypto_encrypt(FILE *in, FILE *out, CryptoArg *arg);
int crypto_decrypt(FILE *in, FILE *out, const uint8_t *key);

#ifdef __cplusplus
}
#endif

#endif