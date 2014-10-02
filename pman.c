#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "util.h"

char *user, *fn_dir;
int verbose = 0;
int quit = 0;

int check_pwd(uint8_t *, uint8_t *, uint8_t *);
int read_cmd(char *);
void sig_handler(int);

int main(int argc, char *argv[])
{
    const char *var = "USER";
    char cmd[BUFFER_SIZE];
    uint8_t salt[SHA256_SALT_SIZE] = {0}, iv[AES256_BLOCK_SIZE] = {0};
    uint8_t key[AES256_KEY_SIZE]; 
    int len, i;

    aes256_encrypt("h", "h", salt, key, iv, &len);

    /* Miscelleneous etup */
    user = getenv(var);
    fn_dir = malloc(BUFFER_SIZE);
    snprintf(fn_dir, BUFFER_SIZE, "/home/%s/.pman", user);
    if(verbose)
        printf("pman directory: %s\n", fn_dir);
    srand(time(NULL));
    if(signal(SIGINT, sig_handler) == SIG_ERR)
        fprintf(stderr, "warning: cannot catch Ctrl-C signal\n");

    /* Check password */
    if(check_pwd(salt, key, iv)) {
        /* Interpet commands until done */
        do {
            read_cmd(cmd);           
        } while(!quit);
    } else {
        fprintf(stderr, "Authentication failure\n");
    }
    
    return EXIT_SUCCESS;
}

int check_pwd(uint8_t *salt, uint8_t *key, uint8_t *iv)
{
    struct stat st;
    struct termios term, defterm;

    char *p, *vp, *line, *fn_pwd, *fn_salt;
    FILE *f_pwd, *f_salt;
    int i, cmp, plen, auth;

    auth = 1;

    /* Create string buffers. */
    fn_pwd = calloc(BUFFER_SIZE, 1);
    fn_salt = calloc(BUFFER_SIZE, 1);
    snprintf(fn_pwd, BUFFER_SIZE, "%s/pwd", fn_dir);
    snprintf(fn_salt, BUFFER_SIZE, "%s/salt", fn_dir);
    if(verbose)
        printf("password file: %s\n", fn_pwd);

    p = calloc(BUFFER_SIZE, 1);
    vp = calloc(BUFFER_SIZE, 1);
    line = calloc(BUFFER_SIZE, 1);
   
    /* Change terminal attributes to disable echo.
     * This hides password input.
     */
    tcgetattr(STDIN_FILENO, &term);
    defterm = term;
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);

    /* Password file (~/.pman/pwd) does not exist.
     * Prompt for a new password, and generate a new salt to hash it with.
     * Create ~/.pman if it does not exist.
     * Write ~/.pman/pwd and ~/.pman/salt for following uses.
     */
    if(stat(fn_pwd, &st) == -1) {
        int set = 0;
        
        for(i = 0; i < SHA256_SALT_SIZE; ++i)
            salt[i] = (unsigned char) rand256();
        
        printf("Password not set. Please create new one:\n");
        do {
            printf("Password: ");
            fgets(line, BUFFER_SIZE-1, stdin);
            sscanf(line, "%255[^\n]", p);
            memset(line, 0, BUFFER_SIZE);
            printf("\nConfirm Password: ");
            fgets(line, BUFFER_SIZE-1, stdin);
            sscanf(line, "%255[^\n]", vp);
            printf("\n");

            if(strncmp(p, vp, BUFFER_SIZE-1) != 0)
                printf("Passwords do not match! Try again:\n");
            else
                set = 1;
        } while(!set);

        key = sha256(p, salt);

        if(stat(fn_dir, &st) == -1) {
            if(mkdir(fn_dir, 0700) == -1)
                printf("error: %s (%d)\n", strerror(errno), errno);
        }

        f_pwd = fopen(fn_pwd, "wb");
        fwrite(key, 1, SHA256_HASH_SIZE, f_pwd);
        fclose(f_pwd);

        f_salt = fopen(fn_salt, "wb");
        fwrite(salt, 1, SHA256_SALT_SIZE, f_salt);
        fclose(f_salt);

        goto l_checked;
    }
    
    /* Password file does exist.
     * Query for password, and check hash with salt against stored password.
     * Reject if there is no match.
     */
    printf("Password: ");
    fgets(line, BUFFER_SIZE-1, stdin);
    sscanf(line, "%255[^\n]", p);
    printf("\n");
    plen = strlen(p);
    
    f_pwd = fopen(fn_pwd, "rb");
    fread(vp, 1, SHA256_HASH_SIZE, f_pwd);
    f_salt = fopen(fn_salt, "rb");
    fread(salt, 1, SHA256_SALT_SIZE, f_salt);
    
    key = sha256(p, salt);
    free(p);
        
    for(cmp = 1, i = 0; i < SHA256_HASH_SIZE; ++i)
        cmp &= key[i] == (unsigned char)vp[i];

    if(!cmp)
        auth = 0;
   
    /* Clear up our buffers. */
l_checked:
    free(fn_pwd);
    free(vp);
    free(line);

    tcsetattr(STDIN_FILENO, TCSANOW, &defterm);
    
    return auth;
}

int read_cmd(char *c)
{
    char *tok;
    char line[BUFFER_SIZE];
    
    printf("> ");
    fgets(line, BUFFER_SIZE-1, stdin);
    /* Check if a Ctrl-D signal was caught. */
    if(feof(stdin)) {
        quit = 1;
        printf("\n");
        return 1;
    }
    sscanf(line, "%255[^\n]", c);

    /* Start parsing the command string. */
    tok = strtok(c, " ");
    while(tok != NULL) {
        if(!strcmp(tok, "q") || !strcmp(tok, "quit")) {
            quit = 1;
            break;
        }
        else if(!strcmp(tok, "h") || !strcmp(tok, "help")) {
            printf("Commands: n[ew]  v[iew]  m[odify]  h[elp]  q[uit]\n");
            break;
        } else {
            printf("Unknown command\n");
            break;
        }

        tok = strtok(NULL, " ");
    }

    return 1;
}

void sig_handler(int signo)
{
    switch(signo) {
        case SIGINT:
            printf("\nCaught Ctrl-C. Exiting...\n");
            free(fn_dir);
            exit(0);
            break;
        default:
            break;
    }
}
