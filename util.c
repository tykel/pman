#include <stdlib.h>
#include <gcrypt.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

/* Return a freshly allocated buffer with the password's salted SHA-256 hash */
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

/* Populate the @out buffer with the password's salted SHA-256 hash */
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

/* Encrypt the @e entry */
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

/* Decrypt the @e entry */
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

/* Generate a random number with uniform distribution in [0,256) */
int rand256(void)
{
    int fd, r;
    long end = RAND_MAX / 256;
    end *= 256;

    fd = open("/dev/urandom", O_RDONLY);
    while(read(fd, &r, sizeof(int)) >= end) ;
    close(fd);

    return r % 256;
}

/* Load an entry from @pathname and parse it into @e.
 * @e is NOT decrypted. */
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
    
    if(fread(e->iv, 1, AES256_BLOCK_SIZE, fentry) < AES256_BLOCK_SIZE)
        goto l_e_fail1;
    e->size = dlen;
    e->e_data = malloc(dlen);
    if(fread(e->e_data, 1, dlen, fentry) < dlen)
        goto l_e_fail2;
    e->d_data = NULL;

    fclose(fentry);

    return 1;

l_e_fail2:
    free(e->e_data);
l_e_fail1:
    return 0;
}

/* Write the entry @e to disk at @pathname. */
int entry_write(char *pathname, encrypted_entry_t *e)
{
    FILE* fentry;
    if((fentry = fopen(pathname, "wb")) == NULL)
        return 0;
    if(e->size < AES256_BLOCK_SIZE || e->e_data == NULL)
        return 0;
    if(fwrite(e->iv, 1, AES256_BLOCK_SIZE, fentry) < AES256_BLOCK_SIZE)
        goto w_e_fail; 
    if(fwrite(e->e_data, 1, e->size, fentry) < e->size)
        goto w_e_fail;

    fclose(fentry);

    return 1;

w_e_fail:
    fclose(fentry);
    return 0;
}

/* Generate a random AES-256 initialisation vector and put it in @e. */
int entry_generate_iv(encrypted_entry_t *e)
{
    int i;
    for(i = 0; i < AES256_BLOCK_SIZE; ++i)
        e->iv[i] = (uint8_t) rand256();

    return 1;
}

int generate_salt(uint8_t *salt)
{
    int i;
    
    if(salt == NULL)
        return 0;
    for(i = 0; i < SHA256_SALT_SIZE; ++i)
        salt[i] = (uint8_t) rand256();
    return SHA256_SALT_SIZE;
}
