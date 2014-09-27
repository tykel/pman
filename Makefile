pman: pman.c util.c
	gcc -O0 -g $^ -o $@ -lgcrypt
