pman: pman.c util.c cmd.c
	gcc -O0 -g $^ -o $@ -lgcrypt -lgpg-error
