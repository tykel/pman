#ifndef _UTIL_H
#define _UTIL_H

#include <inttypes.h>

#define BUFFER_SIZE 256
#define AES256_BLOCK_SIZE 16
#define AES256_KEY_SIZE 32
#define SHA256_HASH_SIZE 32
#define SHA256_SALT_SIZE 8

#define MAX(a,b) ((a) >= (b) ? (a) : (b))

typedef struct encrypted_entry {
    uint8_t key[AES256_KEY_SIZE];
    uint8_t iv[AES256_BLOCK_SIZE];
    size_t size;
    uint8_t *e_data;
    uint8_t *d_data;
} encrypted_entry_t;

uint8_t* sha256(char *, uint8_t *);
int sha256ip(char *, uint8_t *, uint8_t *);
int rand256(void);
int generate_salt(uint8_t *);

int entry_aes256_encrypt(encrypted_entry_t *);
int entry_aes256_decrypt(encrypted_entry_t *);
int entry_load(char *, encrypted_entry_t *);
int entry_write(char *, encrypted_entry_t *);
int entry_generate_iv(encrypted_entry_t *);

#endif
