#include <stdlib.h>
#include <gcrypt.h>

#include "util.h"

unsigned char* sha256(char *val)
{
    int msglen, hashlen;
    unsigned char *hash;

    msglen = strlen(val);
    hashlen = HASH_LENGTH; //gcry_md_get_algo_dlen(GCRY_MD_SHA256);
    hash = malloc(hashlen);

    gcry_md_hash_buffer(GCRY_MD_SHA256, hash, val, msglen);

    return hash;
}

int rand256(void)
{
    int r;
    long end = RAND_MAX / 256;
    end *= 256;

    while((r = rand()) >= end);
    return r % 256;
}
