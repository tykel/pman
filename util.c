#include <stdlib.h>
#include <gcrypt.h>
#include <openssl/evp.h>
#include <sys/stat.h>

#include "util.h"

uint8_t* sha256(char *password, uint8_t *salt)
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

int sha256ip(char *password, uint8_t *salt, uint8_t *out)
{
    int len;
    uint8_t *in;

    len = strlen(password);
    in = malloc(len + SHA256_SALT_SIZE);
    memcpy(in, password, len);
    memcpy(in + len, salt, SHA256_SALT_SIZE);

    gcry_md_hash_buffer(GCRY_MD_SHA256, out, in, len + SHA256_SALT_SIZE);

    return 1;
}

int entry_aes256_encrypt(encrypted_entry_t *e)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
    gcry_cipher_hd_t hd;
    int err;

    /* Encrypt the input buffer */
    err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if(err) fprintf(stderr, "gcry_cipher_open error %x\n", err);
    err = gcry_cipher_setkey(hd, e->key, SHA256_HASH_SIZE);
    if(err) printf("gcry_cipher_setkey error %x\n", err);
    err = gcry_cipher_setiv(hd, e->iv, EVP_MAX_IV_LENGTH);
    if(err) printf("gcry_cipher_setiv error %x\n", err);

    err = gcry_cipher_encrypt(hd, e->e_data, e->size, e->d_data, e->size);
    if(err) printf("gcry_cipher_encrypt error %x\n", err);

    /* Remove the plaintext for security reasons */
    free(e->d_data);
    e->d_data = NULL;

    gcry_cipher_close(hd);
    
    return err;
}

int entry_aes256_decrypt(encrypted_entry_t *e)
{
    gcry_cipher_hd_t hd;
    int err = 0;

    /* Decrypt the input buffer */
    err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if(err) fprintf(stderr, "gcry_cipher_open error %x\n", err);
    err = gcry_cipher_setkey(hd, e->key, SHA256_HASH_SIZE);
    if(err) printf("gcry_cipher_setkey error %x\n", err);
    err = gcry_cipher_setiv(hd, e->iv, EVP_MAX_IV_LENGTH);
    if(err) printf("gcry_cipher_setiv error %x\n", err);

    err = gcry_cipher_decrypt(hd, e->d_data, e->size, e->e_data, e->size);
    if(err) printf("gcry_cipher_encrypt error %x\n", err);

    gcry_cipher_close(hd);

    return err;
}

int rand256(void)
{
    int r;
    long end = RAND_MAX / 256;
    end *= 256;

    while((r = rand()) >= end);
    return r % 256;
}

int entry_load(char *pathname, encrypted_entry_t* e) 
{
    struct stat st;
    FILE *fentry;
    size_t dlen;

    if((fentry = fopen(pathname, "rb")) == NULL)
        return 0;
    fstat(fileno(fentry), &st);
    dlen = st.st_size - AES256_BLOCK_SIZE;
    if(dlen < 0 || dlen % AES256_BLOCK_SIZE)
        return 0;
    
    if(fread(&e->iv, AES256_BLOCK_SIZE, 1, fentry) < AES256_BLOCK_SIZE)
        goto l_e_fail1;
    e->size = dlen;
    e->e_data = malloc(dlen);
    if(fread(e->e_data, dlen, 1, fentry) < dlen)
        goto l_e_fail2;
    e->d_data = NULL;

    fclose(fentry);

    return 1;

l_e_fail2:
    free(e->e_data);
l_e_fail1:
    return 0;
}

int entry_write(char *pathname, encrypted_entry_t *e)
{
    FILE* fentry;
    if((fentry = fopen(pathname, "rb")) == NULL)
        return 0;
    if(fwrite(e->iv, AES256_BLOCK_SIZE, 1, fentry) < AES256_BLOCK_SIZE)
        goto w_e_fail; 
    if(fwrite(e->e_data, e->size, 1, fentry) < e->size)
        goto w_e_fail;

    fclose(fentry);

    return 1;

w_e_fail:
    fclose(fentry);
    return 0;
}

/* entry_key_iv
 *
 * Generates a random AES-256 initialisation vector.
 */
int entry_generate_iv(encrypted_entry_t *e)
{
    int i;
    for(i = 0; i < AES256_BLOCK_SIZE; ++i)
        e->iv[i] = (uint8_t) rand256();

    return 1;
}
