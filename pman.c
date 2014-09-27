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
int auth = 0;
int quit = 0;

const char xor_cipher[] = "fa3520a28b27bf07c2ae03267e4f5a11";

int check_pwd(void);
int read_cmd(char *);
void sig_handler(int signo);

int main(int argc, char *argv[])
{
    const char *var = "USER";
    char cmd[BUFFER_SIZE];
    
    user = getenv(var);
    fn_dir = malloc(BUFFER_SIZE);
    snprintf(fn_dir, BUFFER_SIZE, "/home/%s/.pman", user);
    if(verbose)
        printf("pman directory: %s\n", fn_dir);
    srand(time(NULL));
    if(signal(SIGINT, sig_handler) == SIG_ERR)
        fprintf(stderr, "warning: cannot catch Ctrl-C signal\n");

    if(check_pwd()) {
        do {
            read_cmd(cmd);           
        } while(!quit);
    }
    
    return EXIT_SUCCESS;
}

int check_pwd(void)
{
    struct stat st;
    struct termios term, defterm;
    char *p, *vp, *line, *fn_pwd, *fn_salt;
    unsigned char *hash;
    FILE *f_pwd, *f_salt;
    int i, cmp, plen;
    unsigned char salt[HASH_LENGTH];

    /* Create string buffers. */
    fn_pwd = malloc(BUFFER_SIZE);
    fn_salt = malloc(BUFFER_SIZE);
    snprintf(fn_pwd, BUFFER_SIZE, "%s/pwd", fn_dir);
    snprintf(fn_salt, BUFFER_SIZE, "%s/salt", fn_dir);
    if(verbose)
        printf("password file: %s\n", fn_pwd);

    hash = (unsigned char *) malloc(HASH_LENGTH);
    p = (char *) malloc(BUFFER_SIZE);
    vp = (char *) malloc(BUFFER_SIZE);
    line = (char *) malloc(BUFFER_SIZE);
   
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
        
        for(i = 0; i < HASH_LENGTH; ++i)
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

            if(strncmp(p, vp, BUFFER_SIZE-1) != 0) {
                printf("Passwords do not match! Try again:\n");
            } else {
                set = 1;
            }
        } while(!set);

        plen = strlen(p);
        for(i = 0; i < plen; ++i)
            p[i] ^= salt[i % HASH_LENGTH];
        
        hash = sha256(p);

        if(stat(fn_dir, &st) == -1) {
            if(mkdir(fn_dir, 0700) == -1) {
                printf("error: %s (%d)\n", strerror(errno), errno);
            }
        }

        f_pwd = fopen(fn_pwd, "wb");
        fwrite(hash, 1, HASH_LENGTH, f_pwd);
        fclose(f_pwd);

        f_salt = fopen(fn_salt, "wb");
        fwrite(salt, 1, HASH_LENGTH, f_salt);
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
    hash = sha256(p);
    
    f_pwd = fopen(fn_pwd, "rb");
    fread(vp, 1, HASH_LENGTH, f_pwd);
    f_salt = fopen(fn_salt, "rb");
    fread(salt, 1, HASH_LENGTH, f_salt);
    
    for(i = 0; i < plen; ++i)
        p[i] ^= salt[i % HASH_LENGTH];

    hash = sha256(p);
        
    for(cmp = 1, i = 0; i < HASH_LENGTH; ++i)
        cmp &= hash[i] == (unsigned char)vp[i];

    if(cmp)
        auth = !auth;
    else
        printf("Authentication failure\n");
   
    /* Clear up our buffers. */
l_checked:
    free(fn_pwd);
    free(hash);
    free(p);
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
