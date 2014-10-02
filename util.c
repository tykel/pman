#include <stdlib.h>
#include <gcrypt.h>
#include <openssl/evp.h>

#include "util.h"

unsigned char* sha256(char *password, uint8_t *salt)
{
    int len;
    uint8_t *in, *out;

    len = strlen(password);
    in = malloc(len + SHA256_SALT_SIZE);
    memcpy(in, password, len);
    memcpy(in + len, salt, SHA256_SALT_SIZE);

    out = malloc(SHA256_HASH_SIZE);

    gcry_md_hash_buffer(GCRY_MD_SHA256, out, in, len + SHA256_SALT_SIZE);

    return out;
}

uint8_t* aes256_encrypt(char *in, char *password, uint8_t *salt, uint8_t *key,
        uint8_t *iv, int *paddedlen)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
    gcry_cipher_hd_t hd;
    uint8_t* out, *paddedval;
    int len, e = 0;

    /* Determine padding amount and copy input buffer to padded buffer */
    if((len = strlen(in)) == 0)
        return NULL;
    if(len % 16)
        *paddedlen = len + 16 - (len % 16);
    else
        *paddedlen = len;
    paddedval = calloc(*paddedlen, 0);
    memcpy(paddedval, in, len);
    out = malloc(*paddedlen);

    /* Generate a 32-byte key using SHA-256 hashing */
    OpenSSL_add_all_algorithms();
    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher) fprintf(stderr, "EVP_get_cipherbyname error\n");
    md = EVP_get_digestbyname("sha256");
    if(!md) fprintf(stderr, "EVP_get_digestbyname error\n");
    
    if(!EVP_BytesToKey(cipher, md, salt, (unsigned char*) password,
                strlen(password), 1, key, iv))
        fprintf(stderr, "EVP_BytesToKey failure\n");

    /* Encrypt the input buffer */
    e = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if(e) fprintf(stderr, "gcry_cipher_open error %x\n", e);
    e = gcry_cipher_setkey(hd, key, SHA256_HASH_SIZE);
    if(e) printf("gcry_cipher_setkey error %x\n", e);
    e = gcry_cipher_setiv(hd, iv, EVP_MAX_IV_LENGTH);
    if(e) printf("gcry_cipher_setiv error %x\n", e);

    e = gcry_cipher_encrypt(hd, out, *paddedlen, paddedval, *paddedlen);
    if(e) printf("gcry_cipher_encrypt error %x\n", e);

    gcry_cipher_close(hd);
    
    return out;
}

char* aes256_decrypt(uint8_t *in, int size, uint8_t *key, uint8_t *iv)
{
    gcry_cipher_hd_t hd;
    char *out;
    int i, e = 0;

    /* Decrypt the input buffer */
    e = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if(e) fprintf(stderr, "gcry_cipher_open error %x\n", e);
    e = gcry_cipher_setkey(hd, key, SHA256_HASH_SIZE);
    if(e) printf("gcry_cipher_setkey error %x\n", e);
    e = gcry_cipher_setiv(hd, iv, EVP_MAX_IV_LENGTH);
    if(e) printf("gcry_cipher_setiv error %x\n", e);

    e = gcry_cipher_decrypt(hd, out, size, in, size);
    if(e) printf("gcry_cipher_encrypt error %x\n", e);

    gcry_cipher_close(hd);

    return out;
}

int rand256(void)
{
    int r;
    long end = RAND_MAX / 256;
    end *= 256;

    while((r = rand()) >= end);
    return r % 256;
}
