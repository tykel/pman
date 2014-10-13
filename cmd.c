#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "util.h"
#include "cmd.h"

int read_cmd(char *password, int passlen)
{
    char *tok;
    char line[BUFFER_SIZE], c[BUFFER_SIZE];
    unsigned char key[AES256_KEY_SIZE];
    
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
            handle_cmd_new(password, passlen);
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
            handle_cmd_view(name, password, passlen);
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

int handle_cmd_new(char *password, int passlen)
{
    char line[BUFFER_SIZE], *p, *cp;
    char name[BUFFER_SIZE], params[BUFFER_SIZE], filename[BUFFER_SIZE];
    uint8_t pmask, *key;
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
    
    if(line[0] != 'n' && line[0] != 'N') {
        /* Read desired password parameters */
        pmask = 0;
        printf("Add password settings (default=[a-z]):"
                " 1=[A-Z] 2=[0-9] 3=[! @ _ -]\n");
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
        printf("Using regex [%s %s %s %s]\n",
                pmask & PASS_az ? "a-z" : "",
                pmask & PASS_AZ ? "A-Z" : "",
                pmask & PASS_09 ? "0-9" : "",
                pmask & PASS_SC ? "@ ! _ -" : "");

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
        p = calloc(plen, 1);
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
                p[i] = (char) n;
            }
            printf("Generated password: %s\nUse this one? [y/N]: ",
                    (char *) p);
            memset(line, 0, BUFFER_SIZE);
            memset(params, 0, BUFFER_SIZE);
            fgets(line, BUFFER_SIZE-1, stdin);
            sscanf(line, "%255[^\n]", params);
            if(!strcmp(params, "y") || !strcmp(params, "Y"))
                break;
        } while(1);
    } else {
        int match = 0;
        do {
            p = getpassword("Password: ");
            cp = getpassword("Confirm password: ");
            if(strncmp(p, cp, BUFFER_SIZE) != 0)
                printf("Passwords do not match, try again\n");
            else
                match = 1;
        } while(!match);
        memset(cp, 0, BUFFER_SIZE);
        free(cp);

        plen = strnlen(p, BUFFER_SIZE);
    }
    
    /* Generate an entry and write it to file */
    entry_generate_salt(&e);
    entry_generate_key(&e, password, plen);

    snprintf(filename, BUFFER_SIZE, "%s/%s", fn_dir, name);
    e.size = (plen % AES256_BLOCK_SIZE) == 0 ? plen :
        (plen/AES256_BLOCK_SIZE)*AES256_BLOCK_SIZE + AES256_BLOCK_SIZE;
    printf("e.size: %d bytes\n", e.size);
    e.d_data = calloc(e.size, 1);
    memcpy(e.d_data, p, plen);
    e.e_data = calloc(e.size, 1);

    entry_generate_iv(&e);
    entry_aes256_encrypt(&e);
    entry_generate_mac(&e);
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
                strcmp(di->d_name, "key"))
            printf("%s ", di->d_name);
    }
    printf("\n");

    return 1;
}

int handle_cmd_view(char *cname, char *password, int passlen)
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
    printf("Loading...");
    fflush(stdout);
    entry_generate_key(&e, password, passlen);
    e.d_data = calloc(e.size, 1);
    entry_aes256_decrypt(&e);
    printf("\rPassword = %s\n", e.d_data);

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


