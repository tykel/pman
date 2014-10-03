#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>

#include "util.h"

char *user, *fn_dir;
int verbose = 0;
int quit = 0;

const char *var = "USER";

int check_pwd(uint8_t *, uint8_t *);
int read_cmd(char *, uint8_t *, uint8_t *);
int handle_cmd_new(uint8_t *);
int handle_cmd_list(void);
int handle_cmd_delete(void);
int handle_cmd_view(uint8_t *, char *);
void handle_cmd_clear(void);
void sig_handler(int);

int main(int argc, char *argv[])
{
    char cmd[BUFFER_SIZE];
    int len, i;
    uint8_t salt[SHA256_SALT_SIZE], key[AES256_KEY_SIZE];

    /* Miscelleneous setup */
    user = getenv(var);
    fn_dir = malloc(BUFFER_SIZE);
    snprintf(fn_dir, BUFFER_SIZE, "/home/%s/.pman", user);
    if(verbose)
        printf("pman directory: %s\n", fn_dir);
    srand(time(NULL));
    if(signal(SIGINT, sig_handler) == SIG_ERR)
        fprintf(stderr, "warning: cannot catch Ctrl-C signal\n");

    /* Check password */
    if(check_pwd(salt, key)) {
        /* Interpet commands until done */
        do {
            read_cmd(cmd, key, salt);           
        } while(!quit);
    } else {
        fprintf(stderr, "Authentication failure\n");
    }
    
    return EXIT_SUCCESS;
}

int check_pwd(uint8_t *salt, uint8_t *key)
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

        sha256ip(p, salt, key);
        free(p);

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
    
    sha256ip(p, salt, key);
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

#define PASS_az 1
#define PASS_AZ 2
#define PASS_09 4
#define PASS_SC 8 // Special characters: @!_-

int read_cmd(char *c, uint8_t *key, uint8_t *salt)
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
        } else if(!strcmp(tok, "h") || !strcmp(tok, "help")) {
            printf("Commands: n[ew] l[ist] v[iew] d[elete] c[lear] h[elp] q[uit]\n");
            break;
        } else if(!strcmp(tok, "n") || !strcmp(tok, "new")) {
            handle_cmd_new(key);
            break;
        } else if(!strcmp(tok, "l") || !strcmp(tok, "list")) {
            handle_cmd_list();
            break;
        } else if(!strcmp(tok, "d") || !strcmp(tok, "delete")) {
            handle_cmd_delete();
            break;
        } else if(!strcmp(tok, "v") || !strcmp(tok, "view")) {
            char *name = NULL;
            if((tok = strtok(NULL, " ")) != NULL)
                name = tok;
            handle_cmd_view(key, name);
            break;
        } else if(!strcmp(tok, "c") || !strcmp(tok, "clear")) {
            handle_cmd_clear();
            break;
        } else {
            printf("Unknown command\n");
            break;
        }

        tok = strtok(NULL, " ");
    }

    return 1;
}

void handle_cmd_clear(void)
{
    const char clear[] = {27, '[', '2', 'J', 0};
    printf("%s", clear);
}

int handle_cmd_new(uint8_t *key)
{
    char line[BUFFER_SIZE];
    char name[BUFFER_SIZE], params[BUFFER_SIZE], filename[BUFFER_SIZE];
    uint8_t pmask, *password;
    int len, err, i, valid = 0;
    unsigned plen;
    encrypted_entry_t e;
    
    /* Read a valid entry name */
    printf("New entry setup\n");
    do {
        printf("Name [a-zA-Z0-9_]: ");
        memset(name, 0, BUFFER_SIZE);
        memset(line, 0, BUFFER_SIZE);
        fgets(line, BUFFER_SIZE-1, stdin);
        sscanf(line, "%255[^\n]", name);
        len = strnlen(line, BUFFER_SIZE);
        if((err = strspn(line, "0123456789abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ_")) != len-1)
            printf("Invalid character at position %d, retry\n", err);
        else
            valid = 1;
    } while(!valid);

    /* Give the choice of manually entering a password */
    printf("Generate password randomly? [Y/n]: ");
    memset(line, 0, BUFFER_SIZE);
    fgets(line, BUFFER_SIZE-1, stdin);
    
    if(line[0] == 'y' || line[0] == 'Y') {
        /* Read desired password parameters */
        pmask = 0;
        printf("Add password settings (default=[a-z]):"
                " 1=[A-Z] 2=[0-9] 3=[!@_-]\n");
        do {
            printf("Selection: ");
            memset(params, 0, BUFFER_SIZE);
            memset(line, 0, BUFFER_SIZE);
            fgets(line, BUFFER_SIZE-1, stdin);
            sscanf(line, "%255[^\n]", params);
            for(i = 0; i < BUFFER_SIZE && params[i] != 0; ++i) {
                if(params[i] == '1') pmask |= PASS_AZ;
                else if(params[i] == '2') pmask |= PASS_09;
                else if(params[i] == '3') pmask |= PASS_SC;
                else if(params[i] != ' ') {
                    printf("Invalid character at position %d, retry\n", i);
                    valid = 0;
                }
            }
        } while(!valid);
        /* Add default a-z to mask */
        pmask |= PASS_az;
        printf("Using regex [%s%s%s%s]\n",
                pmask & PASS_az ? "a-z" : "",
                pmask & PASS_AZ ? "A-Z" : "",
                pmask & PASS_09 ? "0-9" : "",
                pmask & PASS_SC ? "@!_-" : "");

        /* Read desired password length */
        memset(params, 0, BUFFER_SIZE);
        memset(line, 0, BUFFER_SIZE);
        printf("Enter desired password length (default=10): ");
        fgets(line, BUFFER_SIZE-1, stdin);
        sscanf(line, "%255[^\n]", params);
        sscanf(params, "%u", &plen);
        if(plen == 0)
            plen = 10;
        printf("Using password length %d\n", plen);

        /* Generate a new password */
        password = calloc(plen, 1);
        do {
            for(i = 0; i < plen; ++i) {
                int accept = 0;
                unsigned n;
                do {
                    n = rand256();
                    if(pmask & PASS_az) accept += (n >= 'a' && n <= 'z');
                    if(pmask & PASS_AZ) accept += (n >= 'A' && n <= 'Z');
                    if(pmask & PASS_09) accept += (n >= '0' && n <= '9');
                    if(pmask & PASS_SC) accept += (n == '@' || n == '!' ||
                            n == '_' || n == '-');
                } while(!accept);
                password[i] = (char) n;
            }
            printf("Generated password: %s\nUse this one? [y/N]: ",
                    (char *) password);
            memset(line, 0, BUFFER_SIZE);
            memset(params, 0, BUFFER_SIZE);
            fgets(line, BUFFER_SIZE-1, stdin);
            sscanf(line, "%255[^\n]", params);
            if(!strcmp(params, "y") || !strcmp(params, "Y"))
                break;
        } while(1);
    } else {
        password = calloc(BUFFER_SIZE, 1);
        printf("Password: ");
        memset(line, 0, BUFFER_SIZE);
        memset(password, 0, BUFFER_SIZE);
        fgets(line, BUFFER_SIZE-1, stdin);
        sscanf(line, "%255[^\n]", password);
        plen = strnlen(password, BUFFER_SIZE);
    }
    
    /* Generate an entry and write it to file */
    snprintf(filename, BUFFER_SIZE, "%s/%s", fn_dir, name);
    e.size = (plen % AES256_BLOCK_SIZE) == 0 ? plen :
        (plen/AES256_BLOCK_SIZE)*AES256_BLOCK_SIZE + AES256_BLOCK_SIZE;
    memcpy(e.key, key, AES256_KEY_SIZE);
    e.d_data = calloc(e.size, 1);
    memcpy(e.d_data, password, plen);
    e.e_data = calloc(e.size, 1);

    entry_generate_iv(&e);
    entry_aes256_encrypt(&e);
    entry_write(filename, &e);
    
    printf("Entry written to %s.\n", filename);

    return 1;
}

int handle_cmd_list(void)
{
    struct dirent *di;
    DIR *d;

    if((d = opendir(fn_dir)) == NULL) {
        fprintf(stderr, "error: could not open dir %s\n", fn_dir);
        return 0;
    }
    while((di = readdir(d)) != NULL) {
        if(di->d_type == DT_REG && strcmp(di->d_name, "salt") &&
                strcmp(di->d_name, "pwd"))
            printf("%s ", di->d_name);
    }
    printf("\n");

    return 1;
}

int handle_cmd_view(uint8_t *key, char *cname)
{
    encrypted_entry_t e;
    struct stat st;
    char line[BUFFER_SIZE], name[BUFFER_SIZE];
    int start;

    if(cname != NULL) {
        snprintf(name, BUFFER_SIZE-1, "%s/%s", fn_dir, cname);
        if(stat(name, &st) == -1) {
            printf("Entry '%s' not found\n", name);
            return 0;
        }
    } else {
        snprintf(name, BUFFER_SIZE-1, "%s/", fn_dir);
        start = strlen(name);
        do {
            printf("Name: ");
            memset(line, 0, BUFFER_SIZE);
            memset(name + start, 0, BUFFER_SIZE);
            fgets(line, BUFFER_SIZE-1, stdin);
            sscanf(line, "%255[^\n]", (char *)(name + start));
        } while(stat(name, &st) == -1);
    }

    if(entry_load(name, &e) == 0) {
        printf("error: entry_load failed\n");
        return 1;
    }
    memcpy(e.key, key, AES256_KEY_SIZE);
    e.d_data = calloc(e.size, 1);
    entry_aes256_decrypt(&e);
    printf("Password = %s\n", e.d_data);

    return 1;
}

int handle_cmd_delete(void)
{
    char entry[BUFFER_SIZE];
    char line[BUFFER_SIZE], name[BUFFER_SIZE], confirm[BUFFER_SIZE];
    struct stat st;
    
    memset(entry, 0, BUFFER_SIZE);

    do {
        printf("Name: ");
        memset(line, 0, BUFFER_SIZE);
        memset(name, 0, BUFFER_SIZE);
        fgets(line, BUFFER_SIZE-1, stdin);
        sscanf(line, "%255[^\n]", name);
        snprintf(entry, BUFFER_SIZE-1, "%s/%s", fn_dir, name);
    } while(stat(entry, &st) == -1);

    printf("WARNING: This action is irreversible.\n");
    printf("Please type 'I AM CERTAIN' (excluding quotes) to delete %s.\n", name);
    do {
        printf("Confirm: ");
        memset(line, 0, BUFFER_SIZE);
        memset(confirm, 0, BUFFER_SIZE);
        fgets(line, BUFFER_SIZE-1, stdin);
        sscanf(line, "%255[^\n]", confirm);
    } while(strcmp(confirm, "I AM CERTAIN") != 0);
    unlink(entry);

    return 1;
}

void sig_handler(int signo)
{
    switch(signo) {
        case SIGINT:
            exit(0);
            break;
        default:
            break;
    }
}
