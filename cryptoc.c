#include <string.h>
#include "cryptoc.h"

typedef unsigned char byte;

int crypto_encrypt(FILE *in, FILE *out, CryptoArg *arg){
    size_t len = 0;
    const CryptoMode *mode = arg->mode;
    int i;
    byte *iv, *block;
    block = (byte *)malloc(sizeof(byte) * mode->blockSize * 2);
    iv = block + mode->blockSize;
    arg->meta->modeID = mode->modeID;

    fseek(out, mode->metaSize, SEEK_SET);
    memset(iv, 0, sizeof(byte) * mode->blockSize);
    while(!feof(in)){
        size_t rl = fread(block, sizeof(byte), mode->blockSize, in);
        if(rl > 0){
            len += rl;
            memset(block + rl, 0, sizeof(byte) * (mode->blockSize - rl));
            for(i = 0; i < mode->blockSize; i++)
                block[i] ^= iv[i];
            mode->encrypt(block, arg);
            fwrite(block, sizeof(byte) * mode->blockSize, 1, out);
            memcpy(iv, block, sizeof(byte) * mode->blockSize);
        }
    }
    arg->meta->inputLen = len;
    fseek(out, 0, SEEK_SET);
    fwrite(arg->meta, mode->metaSize, 1, out);
    free(block);
    return 0;
}
int crypto_decrypt(FILE *in, FILE *out, const uint8_t *key){
    CryptoMeta meta0;
    fread(&meta0, sizeof(CryptoMeta), 1, in);
    fseek(in, 0, SEEK_SET);
    const CryptoMode *mode = crypto_getMode(meta0.modeID);
    CryptoArg *arg = (CryptoArg *)malloc(mode->argSize);
    mode->init(arg, key);
    
    fread(arg->meta, mode->metaSize, 1, in);
    mode->onReadMeta(arg);
    byte *iv, *block, *temp;

    block = (byte *)malloc(sizeof(byte) * mode->blockSize * 3);
    iv = block + mode->blockSize;
    temp = iv + mode->blockSize;
    int i;
    size_t len = 0;

    memset(iv, 0, sizeof(byte) * mode->blockSize);
    while(!feof(in)){
        size_t rl = fread(block, sizeof(byte), mode->blockSize, in) * sizeof(byte);
        if(rl > 0){
            len += rl;
            memset(block + rl, 0, sizeof(byte) * (mode->blockSize - rl));
            memcpy(temp, block, sizeof(byte) * mode->blockSize);
            mode->decrypt(block, arg);
            for(i = 0; i < mode->blockSize; i++)
                block[i] ^= iv[i];
            memcpy(iv, temp, sizeof(byte) * mode->blockSize);
            if(len > arg->meta->inputLen){
                fwrite(block, arg->meta->inputLen - (len - mode->blockSize), 1, out);
            }
            else 
                fwrite(block, sizeof(byte) * mode->blockSize, 1, out);
        }
    }
    free(block);
    free(arg);
}
const CryptoMode *crypto_getMode(int id){
    switch(id){
        case 1: return CryptoMode_AES;
        case 2: return CryptoMode_DES;
        case 3: return CryptoMode_SM4;
        default: return NULL;
    }
}
