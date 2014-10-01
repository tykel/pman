#include <stdlib.h>
#include <gcrypt.h>
#include <openssl/evp.h>

#include "util.h"

unsigned char* sha256(char *val)
{
    int msglen, hashlen;
    unsigned char *hash;

    msglen = strlen(val);
    hashlen = SHA256_HASH_SIZE; //gcry_md_get_algo_dlen(GCRY_MD_SHA256);
    hash = malloc(hashlen);

    gcry_md_hash_buffer(GCRY_MD_SHA256, hash, val, msglen);

    return hash;
}

unsigned char* aes256_encrypt(char *val, char *password)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;
    gcry_cipher_hd_t hd;
    unsigned char *key, *enc, *paddedval, iv[EVP_MAX_IV_LENGTH];
    const unsigned char *salt = NULL;
    int buflen, paddedlen;

    key = malloc(SHA256_HASH_SIZE);
    buflen = strlen(val);
    if(buflen == 0)
        return NULL;

    if(buflen % 16)
        paddedlen = buflen + 16 - (buflen % 16);
    else
        paddedlen = buflen;
    paddedval = calloc(paddedlen, 0);
    strncpy(paddedval, val, buflen);
    enc = malloc(paddedlen);

    /* Generate a 32-byte key using SHA-256 hashing */
    OpenSSL_add_all_algorithms();
    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher) fprintf(stderr, "EVP_get_cipherbyname error\n");
    dgst = EVP_get_digestbyname("sha256");
    if(!dgst) fprintf(stderr, "EVP_get_digestbyname error\n");
    
    if(!EVP_BytesToKey(cipher, dgst, salt, (unsigned char*) password,
                strlen(password), 1, key, iv))
        fprintf(stderr, "EVP_BytesToKey failure\n");

    /* Encrypt the input buffer */
    gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd, key, SHA256_HASH_SIZE);
    gcry_cipher_setiv(hd, iv, EVP_MAX_IV_LENGTH);

    gcry_cipher_encrypt(hd, enc, paddedlen, paddedval, paddedlen);

    gcry_cipher_close(hd);
    free(key);
    
    return enc;
}

/*
unsigned char* aes256_encrypt(char *val, char *password)
{
    unsigned char *enc, initvec[16], *key;
    gcry_cipher_hd_t hd;
    int i;

    enc = malloc(SHA256_HASH_SIZE);
    key = malloc(SHA256_HASH_SIZE);
    key = sha256(password);
    memset(initvec, 0, 16);

    gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd, key, SHA256_HASH_SIZE);
    gcry_cipher_setiv(hd, initvec, 16);

    gcry_cipher_encrypt(hd, enc, SHA256_HASH_SIZE, key, 0);

    gcry_cipher_close(hd);
    free(key);

    return enc;
}
*/

unsigned char * aes256_decrypt(char *eval, char *key)
{
    return NULL;
}

int rand256(void)
{
    int r;
    long end = RAND_MAX / 256;
    end *= 256;

    while((r = rand()) >= end);
    return r % 256;
}
