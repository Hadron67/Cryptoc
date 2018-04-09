#include "cryptoc.h"

static const unsigned int ip[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const unsigned int ip_inv[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25
};

static const unsigned int expand[] = {
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

static const unsigned int perm[] = {
    16, 7,  20, 21, 29, 12, 28, 17,
    1,  15, 23, 26, 5,  18, 31, 10,
    2,  8,  24, 14, 32, 27, 3,  9,
    19, 13, 30, 6,  22, 11, 4,  25
};

static const unsigned int perm1Left[] = {
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36
};
static const unsigned int perm1Right[] = {
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4
};

static const unsigned int perm2[] = {
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const unsigned char sBox[8][64] = {
    // s1
    14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
    0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
    4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
    15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13,
    // s2
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    // s3
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,

    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,

    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
};

static const unsigned int rotCount[] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static uint64_t permutation(const unsigned int *perm, unsigned int len, uint64_t l){
    int i;
    uint64_t ret = 0;
    for(i = 0; i < len; i++){
        if(l & (1L << (perm[i] - 1))){
            ret |= 1L << i;
        }
    }
    return ret;
}
static uint64_t rotKey(uint64_t key, int times){
    while(times --> 0){
        unsigned char t1 = !!(key & (1L << 55)), t2 = !!(key & (1L << 27));
        key <<= 1;
        key &= ~(1L << 28);
        if(t1)
            key |= 1L << 28;
        if(t2)
            key |= 1;
    }
    return key;
}
static int genKey(uint64_t key, uint64_t subKeys[16]){
    int i;
    uint32_t left, right;
    left = permutation(perm1Left, 28, key);
    right = permutation(perm1Right, 28, key);
    uint64_t temp = (uint64_t)left << 32 | right;
    for(i = 0; i < 16; i++){
        temp = rotKey(temp, rotCount[i]);
        subKeys[i] = permutation(perm2, 48, temp);
    }
    return 0;
}
static uint8_t sbox(const unsigned char sb[64], uint8_t s){
    int i = s >> 4 | (s & 1);
    int j = (s & 0b011110) >> 1;
    return sb[i * 16 + j];
}
static uint32_t feistel(uint64_t halfBlock, uint64_t subKey){
    uint64_t temp = permutation(expand, 48, halfBlock) ^ subKey;
    uint32_t ret = 0;
    int i;
    for(i = 0; i < 8; i++){
        ret |= (uint64_t)sbox(sBox[i], temp) << (7 - i) * 4;
    }
    return permutation(perm, 32, ret);
}
static uint64_t crypt(uint64_t block, uint64_t subKeys[16], int mode){
    block = permutation(ip, 64, block);
    uint32_t left = block >> 32, right = block & 0xffffffffL;
    int i;
    for(i = 0; i < 16; i++){
        uint64_t key = mode ? subKeys[15 - i] : subKeys[i];
        uint32_t temp = feistel(right, key) ^ left;
        if(i < 15){
            left = right;
            right = temp;
        }
        else {
            left = temp;
        }
    }
    uint64_t ret = permutation(ip_inv, 64, (uint64_t)left << 32 | right);
    return ret;
}

static uint64_t buffer2int(const unsigned char b[8]){
    uint64_t ret = 0;
    int i;
    for(i = 0; i < 8; i++){
        ret |= ((uint64_t)b[i] << i * 8);
    }
    return ret;
}
static int int2buffer(uint64_t t, unsigned char b[8]){
    int i;
    for(i = 0; i < 8; i++){
        b[i] = t & 0xff;
        t >>= 8;
    }
    return 0;
}
static int des_init(CryptoDESArg *arg, const uint8_t *key){
    arg->super.meta = (CryptoMeta *)&arg->meta;
    arg->super.mode = CryptoMode_DES;
    genKey(buffer2int(key), arg->subKeys);
    return 0;
}
static int des_onReadMeta(CryptoDESArg *arg){ /* nop */ }
static int des_encrypt(unsigned char *block, CryptoDESArg *arg){
    uint64_t b = crypt(buffer2int(block), arg->subKeys, 0);
    int2buffer(b, block);
    return 0;
}
static int des_decrypt(unsigned char *block, CryptoDESArg *arg){
    uint64_t b = crypt(buffer2int(block), arg->subKeys, 1);
    int2buffer(b, block);
    return 0;
}
int crypto_DES_init(CryptoDESArg *arg, const unsigned char *key){
    des_init(arg, key);
    return 0;
}
static const uint8_t des_id = 0x02;

CRYPTOC_DEF_MODE(0x02, des, DES, CryptoMeta, CryptoDESArg, 8);