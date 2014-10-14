#ifndef PMAN_CMD_H
#define PMAN_CMD_H

#define PASS_az 1
#define PASS_AZ 2
#define PASS_09 4
#define PASS_SC 8 // Special characters: @!_-

int read_cmd(char *, int);
int handle_cmd_new(char *, int);
int handle_cmd_list(void);
int handle_cmd_delete(char *);
int handle_cmd_view(char *, char *, int);
void handle_cmd_clear(void);

extern char *fn_dir;
extern int quit;

#endif
