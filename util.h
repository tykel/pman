#ifndef _UTIL_H
#define _UTIL_H

#include <inttypes.h>

#define BUFFER_SIZE 256
#define AES256_BLOCK_SIZE 16
#define AES256_KEY_SIZE 32
#define SHA256_HASH_SIZE 32
#define SHA256_SALT_SIZE 8

#define MAX(a,b) ((a) >= (b) ? (a) : (b))

uint8_t* sha256(char *, uint8_t *);
int rand256(void);

uint8_t* aes256_encrypt(char *, char *, uint8_t *, uint8_t *, uint8_t *, int *);
char* aes256_decrypt(uint8_t *, int, uint8_t *, uint8_t *);

#endif
