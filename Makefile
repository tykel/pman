pman: pman.c util.c cmd.c
	gcc -O0 -g -I./libgpg-error/include -I./libgcrypt/include  $^ ./libgpg-error/lib/libgpg-error.la ./libgcrypt/lib/libgcrypt.la -o $@ -lgcrypt -lgpg-error
