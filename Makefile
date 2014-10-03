pman: pman.c util.c
	gcc -O2 $^ -o $@ -lcrypto -lgcrypt
