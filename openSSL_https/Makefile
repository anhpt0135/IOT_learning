#export LD_LIBRARY_PATH=/usr/local/lib for openssl lib
platform=PC
target=https_client
#src=$(wildcard ./src/*.c)
src=./src/https_client.c
obj=$(src:*.c=*.o)

CFLAGS=-Wall -g -I. -I./src/include
ifeq ( $(platform), GM )
	LDFLAGS=-L./lib -lssl -lcrypto -lpthread
else
	LDFLAGS=-L./lib_PC -lssl -lcrypto -ldl -lmbedtls -lmbedcrypto -lmbedx509  -lpthread
endif


.PHONY: all clean $(target)
$(target):$(obj)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	
all:$(target)
	$(STRIP) $(target)
	
strip:
	$(STRIP) $(target)
	
clean:
	rm -rf ./src/*.o $(target)
