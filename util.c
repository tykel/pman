#include <stdlib.h>
#include <gcrypt.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <gpg-error.h>

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
    dlen = st.st_size - SHA256_SALT_SIZE - AES256_BLOCK_SIZE - SHA256_HASH_SIZE;
    if(dlen < 0 || dlen % AES256_BLOCK_SIZE)
        return 0;
    
    if(fread(e->salt, 1, SHA256_SALT_SIZE, fentry) < SHA256_SALT_SIZE)
        goto l_e_fail1;
    if(fread(e->iv, 1, AES256_BLOCK_SIZE, fentry) < AES256_BLOCK_SIZE)
        goto l_e_fail1;
    e->size = dlen;
    e->e_data = malloc(dlen);
    if(fread(e->e_data, 1, dlen, fentry) < dlen)
        goto l_e_fail2;
    if(fread(e->mac, 1, SHA256_HASH_SIZE, fentry) < SHA256_HASH_SIZE)
        goto l_e_fail2;
    e->d_data = NULL;

    fclose(fentry);

    return 1;

l_e_fail2:
    free(e->e_data);
l_e_fail1:
    fclose(fentry);
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
    fwrite(e->salt, 1, SHA256_SALT_SIZE, fentry);
    if(fwrite(e->iv, 1, AES256_BLOCK_SIZE, fentry) < AES256_BLOCK_SIZE)
        goto w_e_fail; 
    if(fwrite(e->e_data, 1, e->size, fentry) < e->size)
        goto w_e_fail;
    if(fwrite(e->mac, 1, SHA256_HASH_SIZE, fentry) < SHA256_HASH_SIZE)
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

int entry_generate_salt(encrypted_entry_t *e)
{
    generate_salt(e->salt);
    return 1;
}

int entry_generate_key(encrypted_entry_t *e, char *password, int passlen)
{
    gcry_kdf_derive(password, passlen, GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
            e->salt, SHA256_SALT_SIZE, SHA256_ITERATIONS, AES256_KEY_SIZE, e->key);
    return 1;
}

void printarr(const char *s, uint8_t *data, size_t n)
{
    int i;

    printf("%s", s);
    for(i = 0; i < n; ++i)
        printf("%x", 0xff & data[i]);
    printf("\n");
}

int entry_generate_mac(encrypted_entry_t *e)
{
    gcry_mac_hd_t hd;
    size_t size = SHA256_HASH_SIZE;

    gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, GCRY_MAC_FLAG_SECURE, NULL);
    gcry_mac_setkey(hd, e->key, AES256_KEY_SIZE);
    gcry_mac_setiv(hd, e->iv, AES256_BLOCK_SIZE);
    gcry_mac_write(hd, e->e_data, e->size);
    gcry_mac_read(hd, e->mac, &size);
    gcry_mac_close(hd);

    return 1;
}

int entry_authenticate(encrypted_entry_t *e)
{
    unsigned int ret;
    gcry_mac_hd_t hd;
    unsigned char buffer[32];
    size_t size = 32;

    ret = gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, GCRY_MAC_FLAG_SECURE, NULL);
    ret = gcry_mac_setkey(hd, e->key, AES256_KEY_SIZE);
    ret = gcry_mac_setiv(hd, e->iv, AES256_BLOCK_SIZE);
    ret = gcry_mac_write(hd, e->e_data, e->size);
    gcry_mac_read(hd, buffer, &size);
    ret = gcry_mac_verify(hd, e->mac, SHA256_HASH_SIZE);
    gcry_mac_close(hd);

    return (ret & 65535) == 0;
}
