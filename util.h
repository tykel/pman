#ifndef _UTIL_H
#define _UTIL_H

#define BUFFER_SIZE 256
#define AES256_BLOCK_SIZE 16
#define AES256_KEY_SIZE 32
#define SHA256_HASH_SIZE 32
#define SHA256_SALT_SIZE 16

#define MAX(a,b) ((a) >= (b) ? (a) : (b))

unsigned char* sha256(char *);
int rand256(void);
unsigned char* aes256_encrypt(char *val, char *password);

#endif
