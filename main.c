#include <string.h>
#include "cryptoc.h"

int desTest(int args, const char *argv[]){
    FILE *in;
    FILE *out;
    unsigned char key[128] = "hkm, soor";
    if(!strcmp(argv[1], "-d")){
        in = fopen(argv[2], "ro");
        out = fopen(argv[3], "wo");
        crypto_decrypt(in, out, key);
    }
    else {
        in = fopen(argv[1], "ro");
        out = fopen(argv[2], "wo");

        Crypto_SM4Arg arg;
        crypto_SM4_init(&arg, key);
        crypto_encrypt(in, out, (CryptoArg *)&arg);
    }
    fclose(in);
    fclose(out);
    return 0;
}

int shaTest(int args, const char *argv[]){
    int i;
    uint8_t out[32];
    crypto_SHA256(argv[1], strlen(argv[1]), out);
    for(i = 0; i < 32; i++){
        printf("%x ", out[i]);
    }
    printf("\n");
    return 0;
}

int main(int args, const char *argv[]){
    desTest(args, argv);
}