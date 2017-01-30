/* pman version 2*/
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <gcrypt.h>
#include <unistd.h>

#include "util.h"
#include "cmd.h"

#if defined _WIN32
#define PMAN_DIR_STRING "\\Users\\%s\\AppData\\Local\\pman"
#elif defined __APPLE__
#define PMAN_DIR_STRING "/Users/%s/.pman"
#else
#define PMAN_DIR_STRING "/home/%s/.pman"
#endif

char *user, *fn_dir;
int verbose = 0;
int quit = 0;

int main(int argc, char *argv[])
{
    char *password;
    int passlen;

    /* Miscelleneous setup */
    user = getenv("USER");
    fn_dir = malloc(BUFFER_SIZE);
    snprintf(fn_dir, BUFFER_SIZE, PMAN_DIR_STRING, user);
    
    /* Check password */
    if(authenticate(&password) != 0)
        return 1;
    passlen = strnlen(password, BUFFER_SIZE);

    /* Read and execute commands in a loop */
    do {
        read_cmd(password, passlen);
    } while(!quit);

    return 0;
}

char* getpassword(const char *prompt)
{
    struct termios term, defterm;
    char *line, *p;
    int fd;

    /* Change terminal attributes to disable echo.
     * This hides password input. */
    fd = fileno(stdin);
    if(!isatty(fd))
        fprintf(stderr, "warning: stdin is not a tty\n");
    tcgetattr(fd, &term);
    defterm = term;
    term.c_lflag &= ~ECHO;
    tcsetattr(fd, TCSANOW, &term);

    /* Allocate string buffer */
    line = malloc(BUFFER_SIZE);
    if(line == NULL) {
        fprintf(stderr, "error: malloc(%d) failure in getpassword()\n",
                BUFFER_SIZE);
        return NULL;
    }

    /* Print prompt string, if any */
    if(prompt != NULL)
        printf("%s", prompt);

    /* Get password, and null terminate */
    fgets(line, BUFFER_SIZE-1, stdin);
    if(ferror(stdin)) {
        fprintf(stderr, "error: fgets failure in getpassword()\n");
        free(line);
        return NULL;
    }
    for(p = line; p < (char *)(line + BUFFER_SIZE - 1); ++p) {
        if(*p == '\n') {
            *p = 0;
            break;
        }
    }
    line[BUFFER_SIZE - 1] = 0;
    printf("\n");
    
    /* Reset terminal attributes to their previous state */
    tcsetattr(fd, TCSANOW, &defterm);

    return line;
}

int authenticate(char **p)
{
    FILE *f_key, *f_salt;
    unsigned char key[AES256_KEY_SIZE], key_stored[AES256_KEY_SIZE];
    unsigned char salt[SHA256_SALT_SIZE];
    char *password, key_fn[BUFFER_SIZE], salt_fn[BUFFER_SIZE];
    int match, i, e, kl, sl, first;

    first = 0;

    snprintf(key_fn, BUFFER_SIZE, "%s/key", fn_dir);
    snprintf(salt_fn, BUFFER_SIZE, "%s/salt", fn_dir);
    f_key = fopen(key_fn, "rb");
    f_salt = fopen(salt_fn, "rb");
    first += (f_key == NULL) + (f_salt == NULL);
    /* A password and salt are stored, so we authenticate */
    if(!first) {
        /* Read salt and stored key for verification */
        kl = fread(key_stored, 1, AES256_KEY_SIZE, f_key);
        sl = fread(salt, 1, SHA256_SALT_SIZE, f_salt);
        fclose(f_key);
        fclose(f_salt);

        /* Check password */
        password = getpassword("Password: ");
        e = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, 
                salt, SHA256_SALT_SIZE, SHA256_ITERATIONS, AES256_KEY_SIZE, key);
        if(e) printf("gcry error: %d\n", e);
        for(i = 0, match = 1; i < AES256_KEY_SIZE; ++i)
            match = match && (key[i] == key_stored[i]);
        if(match)
            printf("Authentication OK, welcome\n");
        else {
            printf("Authentication failure\n");
            return 1;
        }
    /* One or both are missing, so we set up new ones */
    } else {
        char *cp;
        int match = 0;

        if(f_key) fclose(f_key);
        if(f_salt) fclose(f_salt);
        /* Prompt for new password */
        printf("No password set, prompting new one.\n");
        do {
            password = getpassword("Password: ");
            cp = getpassword("Confirm password: ");
            if(!strcmp(password, cp))
                match = 1;
            else
                printf("Passwords do not match, try again.\n");
        } while(!match);
        memset(cp, 0, BUFFER_SIZE);
        free(cp);

        /* Generate a salt and key from it */
        generate_salt(salt);
        gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
                salt, SHA256_SALT_SIZE, SHA256_ITERATIONS, AES256_KEY_SIZE, key);
        
        f_key = fopen(key_fn, "wb");
        fwrite(key, 1, AES256_KEY_SIZE, f_key);
        fclose(f_key);

        f_salt = fopen(salt_fn, "wb");
        fwrite(salt, 1, SHA256_SALT_SIZE, f_salt);
        fclose(f_salt);

        printf("New key stored.\n");
    }

    /* Allow the password to be passed back to the caller */
    *p = password;

    return 0;
}

